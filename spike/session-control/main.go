// roomctl — PROTOTYPE. Minimal session supervisor + deployment CLI for
// Profile-backed long-lived agent sessions in one Trusted Workstation.
// Answers map issue #8: open, identify, status, attach, send, clear,
// close, restore — with terminal control separate from Hub traffic.
package main

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// ---------- holder lifecycle ----------

func sockPath(name string) string { return filepath.Join(rootDir(), "sock", name+".sock") }
func pidPath(name string) string  { return filepath.Join(rootDir(), "run", name+".pid") }
func logPath(name string) string  { return filepath.Join(rootDir(), "logs", name+".log") }

func alive(pid int) bool {
	if pid <= 0 || syscall.Kill(pid, 0) != nil {
		return false
	}
	// kill(pid,0) also succeeds on zombies; this init does not reap promptly.
	if b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); err == nil {
		if i := bytes.LastIndexByte(b, ')'); i >= 0 && i+2 < len(b) {
			return b[i+2] != 'Z'
		}
	}
	return true
}

func holderPid(name string) int {
	b, err := os.ReadFile(pidPath(name))
	if err != nil {
		return 0
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	if !alive(pid) {
		return 0
	}
	return pid
}

// holderCall sends one verb line to the session holder and returns its
// one-line response. Attach is the exception: it keeps the connection.
func holderCall(name, verb string) (string, error) {
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return "", err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(c, verb); err != nil {
		return "", err
	}
	buf := make([]byte, 256)
	n, err := c.Read(buf)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(buf[:n])), nil
}

// spawnHolder detaches a per-session holder process owning the PTY + socket,
// then waits for it to prove the runtime started before reporting success.
func spawnHolder(name, mode string) error {
	for _, d := range []string{"sock", "run", "logs", "native"} {
		if err := os.MkdirAll(filepath.Join(rootDir(), d), 0o755); err != nil {
			return err
		}
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	hlogPath := filepath.Join(rootDir(), "logs", name+".holder.log")
	hlog, err := os.OpenFile(hlogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer hlog.Close()
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := exec.Command(self, "__holder", name, mode)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, hlog, hlog
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil { // reparented to init; holder self-cleans
		return err
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		_, _, up, err := ping(name)
		if err == nil {
			if up {
				return nil
			}
			// The holder answers only after spawning the runtime, so a
			// negative liveness answer means it died during boot.
			tail, _ := os.ReadFile(hlogPath)
			return fmt.Errorf("runtime for %q exited during boot: %s", name, strings.TrimSpace(string(tail)))
		}
		time.Sleep(100 * time.Millisecond)
	}
	tail, _ := os.ReadFile(hlogPath)
	return fmt.Errorf("holder for %q did not come up: %s", name, strings.TrimSpace(string(tail)))
}

// ping asks the holder for live state: "OK <holderPid> <runtimePid> <alive 0|1>".
func ping(name string) (holder, runtime int, up bool, err error) {
	resp, err := holderCall(name, "PING")
	if err != nil {
		return 0, 0, false, err
	}
	f := strings.Fields(resp)
	if len(f) == 4 && f[0] == "OK" {
		holder, _ = strconv.Atoi(f[1])
		runtime, _ = strconv.Atoi(f[2])
		up = f[3] == "1"
	}
	return holder, runtime, up, nil
}

// processState maps live evidence onto the #16 process axis.
// Turn/readiness is a separate adapter-owned axis and is never inferred here.
func processState(name string) string {
	_, _, up, err := ping(name)
	if err == nil {
		if up {
			return "RUNNING"
		}
		return "EXITED"
	}
	if holderPid(name) > 0 {
		return "DISCONNECTED" // holder alive, socket broken
	}
	return "EXITED"
}

// ---------- commands ----------

func cmdOpen(args []string) error {
	var name, profile, workdir string
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--profile":
			i++
			profile = args[i]
		case "--workdir":
			i++
			workdir = args[i]
		default:
			name = args[i]
		}
	}
	if name == "" || profile == "" {
		return errors.New("usage: roomctl open <name> --profile <p> [--workdir dir]")
	}
	p, err := loadProfile(profile)
	if err != nil {
		return err
	}
	if workdir == "" {
		workdir, _ = os.Getwd()
	}
	ctx := sessCtx{name: name, workdir: workdir}
	session := ctx.render(p.SessionTemplate)
	if err := withRegistry(func(reg map[string]*Entry) error {
		if e, ok := reg[name]; ok && e.State == "open" {
			return fmt.Errorf("session %q already open", name)
		}
		reg[name] = &Entry{
			Name: name, Profile: profile, Runtime: p.Runtime, Actor: p.Actor,
			Workdir: workdir, NativeSession: session, State: "open",
			CreatedAt: time.Now().UTC().Format(time.RFC3339),
		}
		return nil
	}); err != nil {
		return err
	}
	if err := spawnHolder(name, "fresh"); err != nil {
		withRegistry(func(reg map[string]*Entry) error { // never happened
			delete(reg, name)
			return nil
		})
		return err
	}
	fmt.Printf("opened %s (%s · %s · actor %s)\n", name, p.Runtime, profile, p.Actor)
	return nil
}

func snapshotEntries() ([]*Entry, error) {
	var out []*Entry
	err := withRegistry(func(reg map[string]*Entry) error {
		for _, e := range reg {
			c := *e
			out = append(out, &c)
		}
		return nil
	})
	return out, err
}

func cmdList() error {
	entries, err := snapshotEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		fmt.Printf("%-14s %-12s %-8s %-16s %-8s %s\n",
			e.Name, e.Profile, e.Runtime, e.Actor, e.State, e.NativeSession)
	}
	return nil
}

func cmdStatus(name string) error {
	show := func(e *Entry) {
		h, r, up, err := ping(e.Name)
		line := fmt.Sprintf("%s: process=%s profile=%s runtime=%s actor=%s session=%s",
			e.Name, processState(e.Name), e.Profile, e.Runtime, e.Actor, e.NativeSession)
		if err == nil {
			line += fmt.Sprintf(" holderPid=%d runtimePid=%d runtimeAlive=%v", h, r, up)
		}
		fmt.Println(line)
	}
	if name != "" {
		e, err := getEntry(name)
		if err != nil {
			return err
		}
		show(e)
		return nil
	}
	entries, err := snapshotEntries()
	if err != nil {
		return err
	}
	for _, e := range entries {
		show(e)
	}
	return nil
}

// cmdSend writes operator input to the session PTY (like typing), never Hub traffic.
func cmdSend(name, text string) error {
	if _, err := getEntry(name); err != nil {
		return err
	}
	resp, err := holderCall(name, "WRITE "+base64.StdEncoding.EncodeToString([]byte(text+"\r")))
	if err != nil {
		return fmt.Errorf("session not running: %w", err)
	}
	if resp != "OK" {
		return fmt.Errorf("write failed: %s", resp)
	}
	return nil
}

func cmdClose(name string) error {
	e, err := getEntry(name)
	if err != nil {
		return err
	}
	if _, err := holderCall(name, "CLOSE"); err != nil {
		if pid := holderPid(name); pid > 0 {
			syscall.Kill(-pid, syscall.SIGKILL) // ponytail: force path, holder group only
		}
	}
	return withRegistry(func(reg map[string]*Entry) error {
		reg[e.Name].State = "closed"
		return nil
	})
}

// cmdClear wipes conversational context: close runtime, mint a new native
// session handle, relaunch under the same identity and profile.
func cmdClear(name string) error {
	e, err := getEntry(name)
	if err != nil {
		return err
	}
	if e.State != "open" {
		return fmt.Errorf("session %q is closed; open a new session instead", name)
	}
	p, err := loadProfile(e.Profile)
	if err != nil {
		return err
	}
	if processState(name) == "RUNNING" {
		if err := cmdClose(name); err != nil {
			return err
		}
		time.Sleep(300 * time.Millisecond)
	}
	ctx := sessCtx{name: name, workdir: e.Workdir}
	fresh := ctx.render(p.SessionTemplate)
	if err := withRegistry(func(reg map[string]*Entry) error {
		reg[name].State = "open"
		reg[name].NativeSession = fresh
		return nil
	}); err != nil {
		return err
	}
	if err := spawnHolder(name, "fresh"); err != nil {
		withRegistry(func(reg map[string]*Entry) error { // keep the resumable handle
			reg[name].NativeSession = e.NativeSession
			return nil
		})
		return err
	}
	fmt.Printf("cleared %s (new native session %s)\n", name, fresh)
	return nil
}

// cmdRestore is two-phase per the settled restore decision: the registry is the
// topology (phase 1, already durable); each dead session is resumed through the
// runtime-native resume command (phase 2). Closed sessions are terminal and are
// never revived by restore.
func cmdRestore(name string) error {
	var targets []*Entry
	if name != "" {
		e, err := getEntry(name)
		if err != nil {
			return err
		}
		if e.State == "closed" {
			return fmt.Errorf("session %q is closed; open a new session instead", name)
		}
		targets = []*Entry{e}
	} else {
		entries, err := snapshotEntries()
		if err != nil {
			return err
		}
		for _, e := range entries {
			if e.State != "closed" {
				targets = append(targets, e)
			}
		}
	}
	var first error
	for _, e := range targets {
		if err := restoreOne(e); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func restoreOne(e *Entry) error {
	if st := processState(e.Name); st == "RUNNING" {
		fmt.Printf("%s: already RUNNING, skipped\n", e.Name)
		return nil
	}
	p, err := loadProfile(e.Profile)
	if err != nil {
		return err
	}
	mode := "fresh"
	if len(p.ResumeCommand) > 0 && e.NativeSession != "" {
		mode = "resume"
	}
	if err := spawnHolder(e.Name, mode); err != nil {
		return err
	}
	if err := withRegistry(func(reg map[string]*Entry) error {
		reg[e.Name].State = "open"
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("restored %s (%s)\n", e.Name, mode)
	return nil
}

func usage() {
	fmt.Fprint(os.Stderr, `roomctl — PROTOTYPE session supervisor (spike/session-control)

  roomctl open <name> --profile <p> [--workdir dir]   open a Profile-backed session
  roomctl list                                       identify all sessions
  roomctl status [name]                              process liveness (holder/pid signals)
  roomctl attach <name>                              operator terminal (Ctrl-] detaches)
  roomctl send <name> <text...>                      operator input, like typing
  roomctl clear <name>                               wipe context, keep identity/profile
  roomctl close <name>                               terminate the session (terminal)
  roomctl restore [name]                             runtime-native resume of dead open sessions

Hub Room traffic is out of scope here by design; adapters own that channel.
`)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "__holder":
		err = runHolder(os.Args[2], os.Args[3])
	case "open":
		err = cmdOpen(os.Args[2:])
	case "list":
		err = cmdList()
	case "status":
		name := ""
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		err = cmdStatus(name)
	case "attach":
		if len(os.Args) < 3 {
			usage()
		}
		err = cmdAttach(os.Args[2])
	case "send":
		if len(os.Args) < 4 {
			usage()
		}
		err = cmdSend(os.Args[2], strings.Join(os.Args[3:], " "))
	case "clear":
		if len(os.Args) < 3 {
			usage()
		}
		err = cmdClear(os.Args[2])
	case "close":
		if len(os.Args) < 3 {
			usage()
		}
		err = cmdClose(os.Args[2])
	case "restore":
		name := ""
		if len(os.Args) > 2 {
			name = os.Args[2]
		}
		err = cmdRestore(name)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "roomctl:", err)
		os.Exit(1)
	}
}
