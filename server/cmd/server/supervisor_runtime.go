package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	defaultSupervisorReadyTimeout = 30 * time.Second
	defaultSupervisorStopTimeout  = 10 * time.Second
)

type managedWorkerProcess struct {
	cmd    *exec.Cmd
	waitCh chan error
}

func runSupervisorServer() error {
	if systemdActivationEnvPresent(os.Environ()) {
		return fmt.Errorf("supervisor mode does not support systemd socket activation until listener handoff is implemented")
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("resolve executable: %w", err)
	}

	worker, ready, err := startWorkerCandidate(context.Background(), executable, defaultSupervisorReadyTimeout)
	if err != nil {
		return err
	}
	log.Printf(
		"[SUPERVISOR] worker ready pid=%d listen=%s admin=%s tls=%t http3=%t version=%s go=%s",
		ready.PID,
		ready.ListenAddr,
		ready.AdminListenAddr,
		ready.TLSEnabled,
		ready.HTTP3Enabled,
		ready.Version,
		ready.GoVersion,
	)

	sigCh := make(chan os.Signal, 2)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigCh)

	select {
	case sig := <-sigCh:
		log.Printf("[SUPERVISOR] received %s; stopping worker", sig)
		return worker.Stop(defaultSupervisorStopTimeout)
	case err := <-worker.Wait():
		if err == nil {
			return fmt.Errorf("worker exited unexpectedly")
		}
		return fmt.Errorf("worker stopped unexpectedly: %w", err)
	}
}

func startWorkerCandidate(ctx context.Context, executable string, readyTimeout time.Duration) (*managedWorkerProcess, workerReadyMessage, error) {
	if readyTimeout <= 0 {
		readyTimeout = defaultSupervisorReadyTimeout
	}
	readyReader, readyWriter, err := os.Pipe()
	if err != nil {
		return nil, workerReadyMessage{}, fmt.Errorf("create readiness pipe: %w", err)
	}
	defer readyReader.Close()

	cmd, err := buildWorkerCommand(executable, readyWriter)
	if err != nil {
		_ = readyWriter.Close()
		return nil, workerReadyMessage{}, err
	}
	if err := cmd.Start(); err != nil {
		_ = readyWriter.Close()
		return nil, workerReadyMessage{}, fmt.Errorf("start worker: %w", err)
	}
	_ = readyWriter.Close()

	worker := &managedWorkerProcess{
		cmd:    cmd,
		waitCh: make(chan error, 1),
	}
	go func() {
		worker.waitCh <- cmd.Wait()
	}()

	readyCtx, cancel := context.WithTimeout(ctx, readyTimeout)
	defer cancel()
	ready, err := waitForWorkerReady(readyCtx, readyReader, worker.waitCh)
	if err != nil {
		_ = worker.Stop(defaultSupervisorStopTimeout)
		return nil, workerReadyMessage{}, err
	}
	return worker, ready, nil
}

func buildWorkerCommand(executable string, readyWriter *os.File) (*exec.Cmd, error) {
	executable = strings.TrimSpace(executable)
	if executable == "" {
		return nil, fmt.Errorf("worker executable path is empty")
	}
	if readyWriter == nil {
		return nil, fmt.Errorf("worker readiness writer is nil")
	}
	cmd := exec.Command(executable)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(
		workerProcessEnv(os.Environ()),
		serverInternalProcessRoleEnv+"="+internalProcessRoleWorker,
		workerReadyFDEnv+"=3",
	)
	cmd.ExtraFiles = []*os.File{readyWriter}
	return cmd, nil
}

func workerProcessEnv(env []string) []string {
	out := make([]string, 0, len(env)+1)
	for _, item := range env {
		name, _, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		switch name {
		case "LISTEN_FDS", "LISTEN_FDNAMES", "LISTEN_PID", serverInternalProcessRoleEnv, workerReadyFDEnv:
			continue
		default:
			out = append(out, item)
		}
	}
	return out
}

func systemdActivationEnvPresent(env []string) bool {
	for _, item := range env {
		name, value, found := strings.Cut(item, "=")
		if !found {
			continue
		}
		if name == "LISTEN_FDS" && strings.TrimSpace(value) != "" && strings.TrimSpace(value) != "0" {
			return true
		}
	}
	return false
}

func waitForWorkerReady(ctx context.Context, readyReader io.Reader, waitCh <-chan error) (workerReadyMessage, error) {
	if readyReader == nil {
		return workerReadyMessage{}, fmt.Errorf("worker readiness reader is nil")
	}
	readyCh := make(chan workerReadyResult, 1)
	go func() {
		var msg workerReadyMessage
		err := json.NewDecoder(readyReader).Decode(&msg)
		if err == nil {
			err = validateWorkerReadyMessage(msg)
		}
		readyCh <- workerReadyResult{msg: msg, err: err}
	}()

	select {
	case result := <-readyCh:
		if result.err != nil {
			return workerReadyMessage{}, fmt.Errorf("worker readiness failed: %w", result.err)
		}
		return result.msg, nil
	case err := <-waitCh:
		if err == nil {
			return workerReadyMessage{}, fmt.Errorf("worker exited before readiness")
		}
		return workerReadyMessage{}, fmt.Errorf("worker exited before readiness: %w", err)
	case <-ctx.Done():
		return workerReadyMessage{}, fmt.Errorf("worker readiness timeout: %w", ctx.Err())
	}
}

type workerReadyResult struct {
	msg workerReadyMessage
	err error
}

func (w *managedWorkerProcess) Wait() <-chan error {
	if w == nil {
		ch := make(chan error)
		close(ch)
		return ch
	}
	return w.waitCh
}

func (w *managedWorkerProcess) Stop(grace time.Duration) error {
	if w == nil || w.cmd == nil || w.cmd.Process == nil {
		return nil
	}
	if grace <= 0 {
		grace = defaultSupervisorStopTimeout
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	default:
	}
	if err := w.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		select {
		case waitErr := <-w.waitCh:
			return normalizeWorkerStopError(waitErr)
		default:
		}
		return err
	}
	select {
	case err := <-w.waitCh:
		return normalizeWorkerStopError(err)
	case <-time.After(grace):
		if err := w.cmd.Process.Kill(); err != nil {
			return err
		}
		return normalizeWorkerStopError(<-w.waitCh)
	}
}

func normalizeWorkerStopError(err error) error {
	if err == nil {
		return nil
	}
	if exitErr, ok := err.(*exec.ExitError); ok && exitErr.ExitCode() < 0 {
		return nil
	}
	return err
}
