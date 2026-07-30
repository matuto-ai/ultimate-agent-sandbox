package main

// Per-session holder: owns one PTY and one unix socket, runs the runtime,
// mirrors output to a scrollback log (operator observability, not transport).

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

func runHolder(name, mode string) error {
	e, err := getEntry(name)
	if err != nil {
		return err
	}
	p, err := loadProfile(e.Profile)
	if err != nil {
		return err
	}
	ctx := sessCtx{name: e.Name, session: e.NativeSession, workdir: e.Workdir}
	argv := ctx.argv(p.Command)
	if mode == "resume" && len(p.ResumeCommand) > 0 {
		argv = ctx.argv(p.ResumeCommand)
	}
	env := os.Environ()
	for k, v := range p.Env {
		env = append(env, k+"="+ctx.render(v))
	}

	master, slave, err := openPTY()
	if err != nil {
		return fmt.Errorf("pty: %w", err)
	}
	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Dir = e.Workdir
	cmd.Env = env
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 0}
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start %v: %w", argv, err)
	}
	slave.Close()
	runtimePid := cmd.Process.Pid

	os.Remove(sockPath(name))
	ln, err := net.Listen("unix", sockPath(name))
	if err != nil {
		cmd.Process.Kill()
		return err
	}
	os.WriteFile(pidPath(name), []byte(fmt.Sprint(os.Getpid())), 0o644)
	defer func() {
		ln.Close()
		os.Remove(sockPath(name))
		os.Remove(pidPath(name))
	}()

	log, err := os.OpenFile(logPath(name), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer log.Close()

	var mu sync.Mutex
	attached := map[net.Conn]bool{}
	broadcast := func(b []byte) {
		mu.Lock()
		for c := range attached {
			c.Write(b) // ponytail: slow reader blocks the pump; per-conn queues if it matters
		}
		mu.Unlock()
	}

	// PTY output → scrollback log + attached operators.
	go func() {
		buf := make([]byte, 8192)
		for {
			n, err := master.Read(buf)
			if n > 0 {
				log.Write(buf[:n])
				broadcast(buf[:n])
			}
			if err != nil {
				return
			}
		}
	}()

	// Runtime exit → holder exits; registry keeps the durable identity for restore.
	runtimeUp := true
	var upMu sync.Mutex
	go func() {
		cmd.Wait()
		upMu.Lock()
		runtimeUp = false
		upMu.Unlock()
		time.Sleep(200 * time.Millisecond) // let the pump drain
		ln.Close()
	}()

	for {
		c, err := ln.Accept()
		if err != nil {
			return nil // listener closed: runtime is gone, holder exits
		}
		go func(c net.Conn) {
			defer c.Close()
			line, err := bufio.NewReader(c).ReadString('\n')
			if err != nil {
				return
			}
			f := strings.Fields(strings.TrimSpace(line))
			if len(f) == 0 {
				return
			}
			switch f[0] {
			case "PING":
				upMu.Lock()
				up := runtimeUp
				upMu.Unlock()
				upNow := 0
				if up && alive(runtimePid) {
					upNow = 1
				}
				fmt.Fprintf(c, "OK %d %d %d\n", os.Getpid(), runtimePid, upNow)
			case "WRITE":
				if len(f) != 2 {
					fmt.Fprintln(c, "ERR usage")
					return
				}
				b, err := base64.StdEncoding.DecodeString(f[1])
				if err != nil {
					fmt.Fprintln(c, "ERR base64")
					return
				}
				if _, err := master.Write(b); err != nil {
					fmt.Fprintf(c, "ERR %v\n", err)
					return
				}
				fmt.Fprintln(c, "OK")
			case "ATTACH":
				fmt.Fprintln(c, "OK")
				if sb, err := os.ReadFile(logPath(name)); err == nil {
					c.Write(sb) // replay scrollback, then go live
				}
				mu.Lock()
				attached[c] = true
				mu.Unlock()
				io.Copy(master, c) // operator input → PTY until detach
				mu.Lock()
				delete(attached, c)
				mu.Unlock()
			case "CLOSE":
				syscall.Kill(-runtimePid, syscall.SIGTERM)
				fmt.Fprintln(c, "OK")
				go func() {
					time.Sleep(3 * time.Second)
					syscall.Kill(-runtimePid, syscall.SIGKILL) // ponytail: fixed grace, tune if runtimes need longer
				}()
			}
		}(c)
	}
}
