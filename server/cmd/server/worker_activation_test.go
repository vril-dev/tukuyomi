package main

import (
	"fmt"
	"os"
	"sync"
	"testing"
	"time"
)

func TestRunAfterWorkerActivationStartsImmediatelyWithoutGate(t *testing.T) {
	resetWorkerActivationGateForTest(t)
	started := false
	if err := runAfterWorkerActivation("test loop", func() { started = true }); err != nil {
		t.Fatalf("runAfterWorkerActivation: %v", err)
	}
	if !started {
		t.Fatal("start function was not called")
	}
}

func TestRunAfterWorkerActivationWaitsForGate(t *testing.T) {
	resetWorkerActivationGateForTest(t)
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer reader.Close()
	defer writer.Close()
	t.Setenv(serverInternalProcessRoleEnv, internalProcessRoleWorker)
	t.Setenv(workerActivateFDEnv, fmt.Sprintf("%d", reader.Fd()))

	started := make(chan struct{})
	if err := runAfterWorkerActivation("test loop", func() { close(started) }); err != nil {
		t.Fatalf("runAfterWorkerActivation: %v", err)
	}
	select {
	case <-started:
		t.Fatal("start function ran before activation")
	case <-time.After(25 * time.Millisecond):
	}
	if _, err := writer.Write([]byte("1")); err != nil {
		t.Fatalf("write activation: %v", err)
	}
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("start function did not run after activation")
	}
}

func resetWorkerActivationGateForTest(t *testing.T) {
	t.Helper()
	workerActivationGateOnce = sync.Once{}
	workerActivationGateInst = nil
	workerActivationGateErr = nil
	t.Cleanup(func() {
		workerActivationGateOnce = sync.Once{}
		workerActivationGateInst = nil
		workerActivationGateErr = nil
	})
}
