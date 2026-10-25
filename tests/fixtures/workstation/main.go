// A disposable lifecycle fixture, not an agent or a production Workstation.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func main() {
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
