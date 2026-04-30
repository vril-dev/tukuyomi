package main

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestWorkerReadyNotifierWritesSingleMessage(t *testing.T) {
	t.Parallel()

	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	defer reader.Close()

	notifier := &workerReadyNotifier{file: writer}
	msg := workerReadyMessage{
		Protocol:   workerReadinessProtocol,
		PID:        123,
		GoVersion:  "go-test",
		ReadyAt:    "2026-04-29T00:00:00Z",
		ListenAddr: ":9090",
	}
	notifier.once.Do(func() {
		if err := json.NewEncoder(notifier.file).Encode(msg); err != nil {
			notifier.err = err
		}
		if err := notifier.file.Close(); err != nil && notifier.err == nil {
			notifier.err = err
		}
	})
	if notifier.err != nil {
		t.Fatalf("notify: %v", notifier.err)
	}

	var got workerReadyMessage
	if err := json.NewDecoder(reader).Decode(&got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got.Protocol != workerReadinessProtocol || got.PID != 123 || got.ListenAddr != ":9090" {
		t.Fatalf("unexpected message: %#v", got)
	}
}

func TestNewWorkerReadinessFromEnvRejectsInvalidFD(t *testing.T) {
	t.Setenv(workerReadyFDEnv, "2")
	_, err := newWorkerReadinessFromEnv()
	if err == nil || !strings.Contains(err.Error(), "must be >= 3") {
		t.Fatalf("err=%v want fd boundary error", err)
	}
}

func TestValidateWorkerReadyMessage(t *testing.T) {
	t.Parallel()

	msg := workerReadyMessage{
		Protocol:   workerReadinessProtocol,
		PID:        42,
		GoVersion:  "go-test",
		ListenAddr: ":9090",
	}
	if err := validateWorkerReadyMessage(msg); err != nil {
		t.Fatalf("validate: %v", err)
	}
	msg.Protocol = "other"
	if err := validateWorkerReadyMessage(msg); err == nil {
		t.Fatal("expected protocol error")
	}
}
