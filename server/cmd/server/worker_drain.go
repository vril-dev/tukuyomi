package main

import (
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
)

func newServerSignalChannel() (<-chan os.Signal, func(), error) {
	sigCh := make(chan os.Signal, 4)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	cleanup := func() {
		signal.Stop(sigCh)
	}
	if internalProcessRoleFromEnv(os.Environ()) != internalProcessRoleWorker {
		return sigCh, cleanup, nil
	}
	file, err := workerDrainFileFromEnv(os.Getenv)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	if file == nil {
		return sigCh, cleanup, nil
	}
	go watchWorkerDrain(file, sigCh)
	return sigCh, cleanup, nil
}

func workerDrainFileFromEnv(getenv func(string) string) (*os.File, error) {
	raw := strings.TrimSpace(getenv(workerDrainFDEnv))
	if raw == "" {
		return nil, nil
	}
	fd, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("parse %s: %w", workerDrainFDEnv, err)
	}
	if fd < 3 {
		return nil, fmt.Errorf("%s must be >= 3", workerDrainFDEnv)
	}
	file := os.NewFile(uintptr(fd), "tukuyomi-worker-drain")
	if file == nil {
		return nil, fmt.Errorf("open worker drain fd %d", fd)
	}
	return file, nil
}

func watchWorkerDrain(file *os.File, sigCh chan<- os.Signal) {
	defer file.Close()
	var buf [1]byte
	_, err := io.ReadFull(file, buf[:])
	if err != nil {
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			sigCh <- syscall.SIGTERM
		}
		return
	}
	if buf[0] == '1' {
		sigCh <- syscall.SIGTERM
		return
	}
	sigCh <- syscall.SIGTERM
}
