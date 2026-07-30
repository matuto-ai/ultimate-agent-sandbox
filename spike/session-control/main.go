// roomctl — PROTOTYPE. Minimal session supervisor + deployment CLI for
// Profile-backed long-lived agent sessions in one Trusted Workstation.
// Answers map issue #8: open, identify, status, attach, send, clear,
// close, restore — with terminal control separate from Hub traffic.
package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
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

// ---------- durable identity: registry + declarative Runtime Launch Profiles ----------

type Entry struct {
	Name          string `json:"name"`
	Profile       string `json:"profile"`
	Runtime       string `json:"runtime"`
	Actor         string `json:"actor"` // Actor Identity for git/forge/hub attribution
	Workdir       string `json:"workdir"`
	NativeSession string `json:"nativeSession"` // runtime-native resume handle
	State         string `json:"state"`         // open | closed
	CreatedAt     string `json:"createdAt"`
}

type Profile struct {
	Name            string            `json:"name"`
	Runtime         string            `json:"runtime"`
	Actor           string            `json:"actor"`
	Command         []string          `json:"command"`
	ResumeCommand   []string          `json:"resumeCommand"` // empty: restore relaunches Command
	SessionTemplate string            `json:"sessionTemplate"`
	Env             map[string]string `json:"env"`
}

func rootDir() string {
	if v := os.Getenv("ROOMCTL_HOME"); v != "" {
		return v
	}
	return ".roomctl"
}

func profilesDir() string {
	if v := os.Getenv("ROOMCTL_PROFILES"); v != "" {
		return v
	}
	return "profiles"
}

func loadProfile(name string) (Profile, error) {
	var p Profile
	b, err := os.ReadFile(filepath.Join(profilesDir(), name+".json"))
	if err != nil {
		return p, fmt.Errorf("profile %q: %w", name, err)
	}
	return p, json.Unmarshal(b, &p)
}

// withRegistry runs fn under an exclusive flock on the registry.
func withRegistry(fn func(map[string]*Entry) error) error {
	if err := os.MkdirAll(rootDir(), 0o755); err != nil {
		return err
	}
	lk, err := os.OpenFile(filepath.Join(rootDir(), "lock"), os.O_CREATE|os.O_RDWR, 0o644)
	if err != nil {
		return err
	}
	defer lk.Close()
	if err := syscall.Flock(int(lk.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	defer syscall.Flock(int(lk.Fd()), syscall.LOCK_UN)
	reg := map[string]*Entry{}
	path := filepath.Join(rootDir(), "registry.json")
	if b, err := os.ReadFile(path); err == nil {
		if err := json.Unmarshal(b, &reg); err != nil {
			return fmt.Errorf("registry corrupt: %w", err)
		}
	}
	if err := fn(reg); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(reg, "", "  ")
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func getEntry(name string) (*Entry, error) {
	var e *Entry
	err := withRegistry(func(reg map[string]*Entry) error {
		if x, ok := reg[name]; ok {
			c := *x
			e = &c
		}
		return nil
	})
	if e == nil && err == nil {
		err = fmt.Errorf("no session %q", name)
	}
	return e, err
}

// ---------- placeholder rendering ----------

func uuid() string {
	var b [16]byte
	rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func render(s, name, session, workdir string) string {
	r := strings.NewReplacer(
		"{root}", rootDir(),
		"{name}", name,
		"{session}", session,
		"{workdir}", workdir,
		"{ts}", strconv.FormatInt(time.Now().Unix(), 10),
		"{uuid}", uuid(),
	)
	return r.Replace(s)
}

func renderArgv(argv []string, name, session, workdir string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = render(a, name, session, workdir)
	}
	return out
}

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

// spawnHolder detaches a per-session holder process owning the PTY + socket.
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
	hlog, err := os.OpenFile(filepath.Join(rootDir(), "logs", name+".holder.log"),
		os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer hlog.Close()
	devnull, _ := os.Open(os.DevNull)
	defer devnull.Close()
	cmd := exec.Command(self, "__holder", name, mode)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = devnull, hlog, hlog
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	return cmd.Start() // reparented to init; holder self-cleans
}

// ping asks the holder for live state: "OK <holderPid> <runtimePid> <alive 0|1>".
func ping(name string) (holder, runtime int, up bool, err error) {
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return 0, 0, false, err
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintln(c, "PING"); err != nil {
		return 0, 0, false, err
	}
	buf := make([]byte, 128)
	n, err := c.Read(buf)
	if err != nil {
		return 0, 0, false, err
	}
	f := strings.Fields(string(buf[:n]))
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
	session := render(p.SessionTemplate, name, "", workdir)
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
		return err
	}
	fmt.Printf("opened %s (%s · %s · actor %s)\n", name, p.Runtime, profile, p.Actor)
	return nil
}

func eachEntry(fn func(*Entry)) error {
	return withRegistry(func(reg map[string]*Entry) error {
		for _, e := range reg {
			fn(e)
		}
		return nil
	})
}

func cmdList() error {
	return eachEntry(func(e *Entry) {
		fmt.Printf("%-14s %-12s %-8s %-16s %-8s %s\n",
			e.Name, e.Profile, e.Runtime, e.Actor, e.State, e.NativeSession)
	})
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
	return eachEntry(show)
}

// cmdSend writes operator input to the session PTY (like typing), never Hub traffic.
func cmdSend(name, text string) error {
	if _, err := getEntry(name); err != nil {
		return err
	}
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return fmt.Errorf("session not running: %w", err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := fmt.Fprintf(c, "WRITE %s\n", base64.StdEncoding.EncodeToString([]byte(text+"\r"))); err != nil {
		return err
	}
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || !strings.HasPrefix(string(buf[:n]), "OK") {
		return fmt.Errorf("write failed: %s", strings.TrimSpace(string(buf[:n])))
	}
	return nil
}

func cmdClose(name string) error {
	e, err := getEntry(name)
	if err != nil {
		return err
	}
	if c, err := net.Dial("unix", sockPath(name)); err == nil {
		c.SetDeadline(time.Now().Add(5 * time.Second))
		fmt.Fprintln(c, "CLOSE")
		buf := make([]byte, 16)
		c.Read(buf)
		c.Close()
	} else if pid := holderPid(name); pid > 0 {
		syscall.Kill(-pid, syscall.SIGKILL) // ponytail: force path, holder group only
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
		return fmt.Errorf("session %q is closed; use restore", name)
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
	fresh := render(p.SessionTemplate, name, "", e.Workdir)
	if err := withRegistry(func(reg map[string]*Entry) error {
		reg[name].State = "open"
		reg[name].NativeSession = fresh
		return nil
	}); err != nil {
		return err
	}
	fmt.Printf("cleared %s (new native session %s)\n", name, fresh)
	return spawnHolder(name, "fresh")
}

// cmdRestore is two-phase per the settled restore decision: the registry is the
// topology (phase 1, already durable); each dead session is resumed through the
// runtime-native resume command (phase 2).
func cmdRestore(name string) error {
	restoreOne := func(e *Entry) error {
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
	if name != "" {
		e, err := getEntry(name)
		if err != nil {
			return err
		}
		return restoreOne(e)
	}
	var first error
	eachEntry(func(e *Entry) {
		if err := restoreOne(e); err != nil && first == nil {
			first = err
		}
	})
	return first
}

func usage() {
	fmt.Fprint(os.Stderr, `roomctl — PROTOTYPE session supervisor (spike/session-control)

  roomctl open <name> --profile <p> [--workdir dir]   open a Profile-backed session
  roomctl list                                       identify all sessions
  roomctl status [name]                              process state (native signals only)
  roomctl attach <name>                              operator terminal (Ctrl-] detaches)
  roomctl send <name> <text...>                      operator input, like typing
  roomctl clear <name>                               wipe context, keep identity/profile
  roomctl close <name>                               terminate the session
  roomctl restore [name]                             runtime-native resume of dead sessions

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
