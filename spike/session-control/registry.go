package main

// Durable identity: the on-disk registry, declarative Runtime Launch
// Profiles, and placeholder rendering.

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

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

// sessCtx is the session context every template renders against.
type sessCtx struct {
	name, session, workdir string
}

func uuid() string {
	var b [16]byte
	rand.Read(b[:])
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

func (c sessCtx) render(s string) string {
	r := strings.NewReplacer(
		"{root}", rootDir(),
		"{name}", c.name,
		"{session}", c.session,
		"{workdir}", c.workdir,
		"{ts}", strconv.FormatInt(time.Now().Unix(), 10),
		"{uuid}", uuid(),
	)
	return r.Replace(s)
}

func (c sessCtx) argv(argv []string) []string {
	out := make([]string, len(argv))
	for i, a := range argv {
		out[i] = c.render(a)
	}
	return out
}
