// A disposable lifecycle fixture, not an agent or a production Workstation.
package main

import (
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

func main() {
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
