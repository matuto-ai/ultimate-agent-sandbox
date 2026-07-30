//go:build linux

package main

// Linux PTY + terminal raw mode, stdlib only (no x/sys dependency).

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"syscall"
	"unsafe"
)

func ioctl(fd uintptr, req uint, arg unsafe.Pointer) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(req), uintptr(arg))
	if errno != 0 {
		return errno
	}
	return nil
}

func openPTY() (master, slave *os.File, err error) {
	// O_NOCTTY: the holder is itself a session leader (Setsid at spawn);
	// without this the slave would become the holder's controlling tty and
	// the runtime child's Setctty would fail with EPERM.
	master, err = os.OpenFile("/dev/ptmx", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	var unlock uint32
	if err = ioctl(master.Fd(), 0x40045431, unsafe.Pointer(&unlock)); err != nil { // TIOCSPTLCK
		master.Close()
		return nil, nil, err
	}
	var n uint32
	if err = ioctl(master.Fd(), 0x80045430, unsafe.Pointer(&n)); err != nil { // TIOCGPTN
		master.Close()
		return nil, nil, err
	}
	slave, err = os.OpenFile("/dev/pts/"+strconv.Itoa(int(n)), os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		master.Close()
		return nil, nil, err
	}
	return master, slave, nil
}

func makeRaw(fd uintptr) (*syscall.Termios, error) {
	var old syscall.Termios
	if err := ioctl(fd, syscall.TCGETS, unsafe.Pointer(&old)); err != nil {
		return nil, err
	}
	raw := old
	raw.Iflag &^= syscall.BRKINT | syscall.ICRNL | syscall.INPCK | syscall.ISTRIP | syscall.IXON
	raw.Oflag &^= syscall.OPOST
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Cc[syscall.VMIN], raw.Cc[syscall.VTIME] = 1, 0
	if err := ioctl(fd, syscall.TCSETS, unsafe.Pointer(&raw)); err != nil {
		return nil, err
	}
	return &old, nil
}

func restoreTerm(fd uintptr, old *syscall.Termios) {
	ioctl(fd, syscall.TCSETS, unsafe.Pointer(old))
}

// cmdAttach bridges the operator terminal to the session PTY.
// Ctrl-] detaches; with a non-TTY stdin, EOF detaches (scripted use).
func cmdAttach(name string) error {
	if _, err := getEntry(name); err != nil {
		return err
	}
	c, err := net.Dial("unix", sockPath(name))
	if err != nil {
		return fmt.Errorf("session not running: %w", err)
	}
	if _, err := fmt.Fprintln(c, "ATTACH"); err != nil {
		c.Close()
		return err
	}
	line, err := bufio.NewReader(c).ReadString('\n')
	if err != nil || line != "OK\n" {
		c.Close()
		return fmt.Errorf("attach refused: %s", line)
	}

	var old *syscall.Termios
	if st, err := os.Stdin.Stat(); err == nil && st.Mode()&os.ModeCharDevice != 0 {
		if o, err := makeRaw(os.Stdin.Fd()); err == nil {
			old = o
			defer restoreTerm(os.Stdin.Fd(), old)
		}
	}

	done := make(chan struct{})
	var once sync.Once
	finish := func() { once.Do(func() { close(done) }) }

	go func() { // operator → PTY, Ctrl-] detaches
		buf := make([]byte, 4096)
		for {
			n, err := os.Stdin.Read(buf)
			if n > 0 {
				if i := bytes.IndexByte(buf[:n], 0x1d); i >= 0 {
					c.Write(buf[:i])
					finish()
					return
				}
				if _, werr := c.Write(buf[:n]); werr != nil {
					finish()
					return
				}
			}
			if err != nil {
				// stdin EOF: half-close so the holder finishes the scrollback
				// replay and live bridge, then closes us (scripted attach).
				if uc, ok := c.(*net.UnixConn); ok {
					uc.CloseWrite()
				}
				return
			}
		}
	}()
	go func() { // PTY → operator
		io.Copy(os.Stdout, c)
		c.Close()
		finish()
	}()
	<-done
	c.Close()
	if old != nil {
		fmt.Println("\r\n[detached]")
	}
	return nil
}
