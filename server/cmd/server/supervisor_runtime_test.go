package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func TestBuildWorkerCommand(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer reader.Close()
	defer writer.Close()

	cmd, err := buildWorkerCommand("/tmp/tukuyomi-test", writer)
	if err != nil {
		t.Fatalf("buildWorkerCommand: %v", err)
	}
	if got, want := cmd.Path, "/tmp/tukuyomi-test"; got != want {
		t.Fatalf("path=%q want=%q", got, want)
	}
	if len(cmd.Args) != 1 {
		t.Fatalf("args=%#v want no public worker command", cmd.Args)
	}
	if len(cmd.ExtraFiles) != 1 || cmd.ExtraFiles[0] != writer {
		t.Fatalf("extra files=%#v want readiness writer", cmd.ExtraFiles)
	}
	if !envContains(cmd.Env, serverInternalProcessRoleEnv+"="+internalProcessRoleWorker) {
		t.Fatalf("env missing %s=%s", serverInternalProcessRoleEnv, internalProcessRoleWorker)
	}
	if !envContains(cmd.Env, workerReadyFDEnv+"=3") {
		t.Fatalf("env missing %s=3", workerReadyFDEnv)
	}
}

func TestWorkerProcessEnvDropsInheritedActivation(t *testing.T) {
	t.Parallel()

	got := workerProcessEnv([]string{
		"LISTEN_FDS=4",
		"LISTEN_FDNAMES=public:admin",
		"LISTEN_PID=123",
		serverInternalProcessRoleEnv + "=" + internalProcessRoleSupervisor,
		workerReadyFDEnv + "=8",
		"KEEP=value",
	})
	if len(got) != 1 || got[0] != "KEEP=value" {
		t.Fatalf("env=%#v want only KEEP", got)
	}
}

func TestSystemdActivationEnvPresent(t *testing.T) {
	t.Parallel()

	if !systemdActivationEnvPresent([]string{"LISTEN_FDS=2"}) {
		t.Fatal("expected activation env")
	}
	if systemdActivationEnvPresent([]string{"LISTEN_FDS=0", "OTHER=1"}) {
		t.Fatal("did not expect inactive activation env")
	}
	if systemdActivationEnvPresent([]string{"LISTEN_FDNAMES=public"}) {
		t.Fatal("did not expect activation without LISTEN_FDS")
	}
}

func TestWaitForWorkerReady(t *testing.T) {
	t.Parallel()

	msg := workerReadyMessage{
		Protocol:   workerReadinessProtocol,
		PID:        99,
		GoVersion:  "go-test",
		ListenAddr: ":9090",
	}
	var buf bytes.Buffer
	if err := json.NewEncoder(&buf).Encode(msg); err != nil {
		t.Fatalf("encode: %v", err)
	}
	waitCh := make(chan error)
	got, err := waitForWorkerReady(context.Background(), &buf, waitCh)
	if err != nil {
		t.Fatalf("waitForWorkerReady: %v", err)
	}
	if got.PID != msg.PID || got.ListenAddr != msg.ListenAddr {
		t.Fatalf("ready=%#v want %#v", got, msg)
	}
}

func TestWaitForWorkerReadyReportsEarlyExit(t *testing.T) {
	t.Parallel()

	waitCh := make(chan error, 1)
	waitCh <- errors.New("boom")
	_, err := waitForWorkerReady(context.Background(), blockingReader{}, waitCh)
	if err == nil {
		t.Fatal("expected early exit error")
	}
}

func TestWaitForWorkerReadyTimeout(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	waitCh := make(chan error)
	_, err := waitForWorkerReady(ctx, blockingReader{}, waitCh)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

type blockingReader struct{}

func (blockingReader) Read([]byte) (int, error) {
	select {}
}

func envContains(env []string, want string) bool {
	for _, item := range env {
		if item == want {
			return true
		}
	}
	return false
}
