// A disposable lifecycle fixture, not an agent or a production Workstation.
package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Probe only disposable fixture paths. No exhaustion, namespace operations, or
// host policy changes: these observations complement Docker's inspect values.
type boundaryProbe struct {
	UID            int               `json:"uid"`
	GID            int               `json:"gid"`
	Process        map[string]string `json:"process"`
	Cgroup         map[string]string `json:"cgroup"`
	Interfaces     []string          `json:"interfaces"`
	NetworkConnect string            `json:"network_connect"`
	RootWrite      string            `json:"root_write"`
	ProjectWrite   string            `json:"project_write"`
	Errors         []string          `json:"errors"`
}

func boundedRead(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return "", err
	}
	if int64(len(value)) > limit {
		return "", errors.New("oversized kernel observation")
	}
	return strings.TrimSpace(string(value)), nil
}

func errorCode(err error) string {
	for _, candidate := range []struct {
		err  error
		name string
	}{
		{syscall.EROFS, "EROFS"},
		{syscall.EACCES, "EACCES"},
		{syscall.EPERM, "EPERM"},
		{syscall.ENETUNREACH, "ENETUNREACH"},
		{syscall.ECONNREFUSED, "ECONNREFUSED"},
		{syscall.EHOSTUNREACH, "EHOSTUNREACH"},
		{syscall.EEXIST, "EEXIST"},
	} {
		if errors.Is(err, candidate.err) {
			return candidate.name
		}
	}
	return "OTHER_ERROR"
}

func probeWrite(directory string) string {
	path := filepath.Join(directory, ".boundary-probe-"+strconv.Itoa(os.Getpid()))
	// O_EXCL prevents touching an existing Project file. Remove only a file
	// created successfully by this probe, even if the boundary unexpectedly fails.
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errorCode(err)
	}
	closeErr := file.Close()
	removeErr := os.Remove(path)
	if closeErr != nil || removeErr != nil {
		return "UNEXPECTED_SUCCESS_CLEANUP_FAILED"
	}
	return "UNEXPECTED_SUCCESS"
}

func probe(project string) {
	result := boundaryProbe{
		UID: os.Geteuid(), GID: os.Getegid(),
		Process: map[string]string{}, Cgroup: map[string]string{},
		Interfaces: []string{}, Errors: []string{},
	}
	status, err := boundedRead("/proc/self/status", 65536)
	if err != nil {
		result.Errors = append(result.Errors, "PROCESS_STATUS_UNAVAILABLE")
	} else {
		for _, line := range strings.Split(status, "\n") {
			name, value, found := strings.Cut(line, ":")
			if !found {
				continue
			}
			switch name {
			case "CapEff", "CapBnd", "NoNewPrivs", "Seccomp":
				result.Process[name] = strings.TrimSpace(value)
			}
		}
	}
	for _, name := range []string{"memory.max", "pids.max", "cpu.max"} {
		value, err := boundedRead("/sys/fs/cgroup/"+name, 128)
		if err != nil {
			result.Errors = append(result.Errors, "CGROUP_UNAVAILABLE:"+name)
		} else {
			result.Cgroup[name] = value
		}
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		result.Errors = append(result.Errors, "INTERFACES_UNAVAILABLE")
	} else if len(interfaces) > 16 {
		result.Errors = append(result.Errors, "TOO_MANY_INTERFACES")
	} else {
		for _, entry := range interfaces {
			result.Interfaces = append(result.Interfaces, entry.Name)
		}
		sort.Strings(result.Interfaces)
	}
	// TEST-NET-1 is not a real service; network=none must fail locally with
	// ENETUNREACH, rather than a timeout being counted as isolation evidence.
	connection, err := net.DialTimeout("tcp4", "192.0.2.1:9", 300*time.Millisecond)
	if err != nil {
		result.NetworkConnect = errorCode(err)
	} else {
		connection.Close()
		result.NetworkConnect = "UNEXPECTED_SUCCESS"
	}
	result.RootWrite = probeWrite("/")
	result.ProjectWrite = probeWrite(project)
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		os.Exit(1)
	}
}

// Open only a marker-prefixed, bounded fixture file under harness-selected roots.
// This command is test-image functionality, not a production file/agent API.
func checkoutFile(root, checkout string, flags int) (*os.File, []byte) {
	fail := func(reason string) {
		json.NewEncoder(os.Stdout).Encode(map[string]string{"error": reason})
		os.Exit(3)
	}
	for _, path := range []string{root, checkout} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" {
			fail("INVALID_FIXTURE_PATH")
		}
	}
	relative, err := filepath.Rel(root, checkout)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		fail("OUTSIDE_FIXTURE_ROOT")
	}
	path := filepath.Join(checkout, "uas-checkout-fixture.txt")
	for _, candidate := range []string{root, checkout, path} {
		actual, err := filepath.EvalSymlinks(candidate)
		if err != nil {
			fail("FIXTURE_UNAVAILABLE")
		}
		if actual != candidate {
			fail("SYMLINK_FIXTURE_PATH")
		}
	}
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0)
	if err != nil {
		fail("FIXTURE_UNAVAILABLE")
	}
	file := os.NewFile(uintptr(fd), path)
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		fail("INVALID_FIXTURE_FILE")
	}
	content, err := io.ReadAll(io.LimitReader(file, 4097))
	if err != nil || len(content) > 4096 || !strings.HasPrefix(string(content), "uas-checkout-fixture-v1\n") {
		fail("INVALID_FIXTURE_CONTENT")
	}
	return file, content
}

func readCheckout(root, checkout string) {
	file, content := checkoutFile(root, checkout, syscall.O_RDONLY)
	defer file.Close()
	digest := sha256.Sum256(content)
	json.NewEncoder(os.Stdout).Encode(map[string]interface{}{
		"path": checkout, "file": "uas-checkout-fixture.txt", "bytes": len(content),
		"sha256": fmt.Sprintf("%x", digest), "uid": os.Geteuid(),
	})
}

// The bounded test-image writer touches only the same checked marker file.
// Parent exit intentionally leaves a child holding the file open: an exited
// Docker exec parent or revoked authority must NOT count as writer quiescence.
func writeCheckout(root, checkout string, spawn bool) {
	file, _ := checkoutFile(root, checkout, syscall.O_RDWR)
	defer file.Close()
	if spawn {
		null, err := os.OpenFile("/dev/null", os.O_RDWR, 0)
		if err != nil {
			panic(err)
		}
		defer null.Close()
		child, err := os.StartProcess("/fixture", []string{"/fixture", "--write-checkout", root, checkout},
			&os.ProcAttr{Files: []*os.File{null, null, null}})
		if err != nil {
			panic(err)
		}
		json.NewEncoder(os.Stdout).Encode(map[string]int{"child": child.Pid, "uid": os.Geteuid()})
		child.Release()
		return
	}
	// Docker Stop terminates the whole container, including this orphan writer.
	// A fixed deadline bounds it even if a failed test never reaches Stop.
	deadline := time.Now().Add(20 * time.Second)
	for counter := 1; time.Now().Before(deadline); counter++ {
		content := []byte(fmt.Sprintf("uas-checkout-fixture-v1\nworkstation writer uid=%d tick=%d\n", os.Geteuid(), counter))
		if _, err := file.WriteAt(content, 0); err != nil {
			panic(err)
		}
		if err := file.Truncate(int64(len(content))); err != nil {
			panic(err)
		}
		if err := file.Sync(); err != nil {
			panic(err)
		}
		time.Sleep(25 * time.Millisecond)
	}
}

func main() {
	if len(os.Args) == 4 && (os.Args[1] == "--write-checkout" || os.Args[1] == "--spawn-checkout-writer") {
		writeCheckout(os.Args[2], os.Args[3], os.Args[1] == "--spawn-checkout-writer")
		return
	}
	if len(os.Args) == 4 && os.Args[1] == "--read-checkout" {
		readCheckout(os.Args[2], os.Args[3])
		return
	}
	if len(os.Args) != 1 {
		if len(os.Args) != 3 || os.Args[1] != "--probe" ||
			!filepath.IsAbs(os.Args[2]) || filepath.Clean(os.Args[2]) != os.Args[2] {
			fmt.Fprintln(os.Stderr, "usage: fixture [--probe ABSOLUTE_PROJECT_DIRECTORY]")
			os.Exit(2)
		}
		probe(os.Args[2])
		return
	}
	value := 0
	if content, err := os.ReadFile("/state/starts"); err == nil {
		value, err = strconv.Atoi(strings.TrimSpace(string(content)))
		if err != nil {
			panic(err)
		}
	} else if !os.IsNotExist(err) {
		panic(err)
	}
	value++
	if err := os.WriteFile("/state/starts", []byte(strconv.Itoa(value)), 0600); err != nil {
		panic(err)
	}
	fmt.Printf("fixture start=%d uid=%d\n", value, os.Getuid())
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	<-signals
}
