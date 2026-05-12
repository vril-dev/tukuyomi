package daemonruntime

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestSupervisorManualStopSurvivesReconcile(t *testing.T) {
	withTempCWD(t)
	root := writeTestDaemonApp(t, "manual-stop")
	sup := New(Options{})
	t.Cleanup(func() {
		if err := sup.Shutdown(); err != nil {
			t.Fatalf("shutdown daemon supervisor: %v", err)
		}
	})

	spec := Spec{
		AppID:         "manual-stop",
		ProcessID:     "manual-stop",
		Enabled:       true,
		AppRoot:       root,
		Command:       "bin/daemon",
		RestartPolicy: "on-failure",
	}
	if err := sup.Reconcile([]Spec{spec}); err != nil {
		t.Fatalf("reconcile start: %v", err)
	}
	waitDaemonStatus(t, sup, "manual-stop", func(status ProcessStatus) bool {
		return status.Running && status.PID > 0
	})

	if err := sup.StopProcess("manual-stop", []Spec{spec}); err != nil {
		t.Fatalf("stop: %v", err)
	}
	waitDaemonStatus(t, sup, "manual-stop", func(status ProcessStatus) bool {
		return !status.Running && status.LastAction == "manual_stopped"
	})

	if err := sup.Reconcile([]Spec{spec}); err != nil {
		t.Fatalf("reconcile after manual stop: %v", err)
	}
	waitDaemonStatus(t, sup, "manual-stop", func(status ProcessStatus) bool {
		return !status.Running && status.LastAction == "manual_stopped"
	})

	if err := sup.StartProcess("manual-stop", []Spec{spec}); err != nil {
		t.Fatalf("start after manual stop: %v", err)
	}
	firstPID := waitDaemonStatus(t, sup, "manual-stop", func(status ProcessStatus) bool {
		return status.Running && status.PID > 0
	}).PID

	if err := sup.ReloadProcess("manual-stop", []Spec{spec}); err != nil {
		t.Fatalf("restart: %v", err)
	}
	waitDaemonStatus(t, sup, "manual-stop", func(status ProcessStatus) bool {
		return status.Running && status.PID > 0 && status.PID != firstPID
	})
}

func TestSupervisorCapturesDaemonLogTail(t *testing.T) {
	withTempCWD(t)
	root := writeTestDaemonApp(t, "log-tail")
	sup := New(Options{})
	t.Cleanup(func() {
		if err := sup.Shutdown(); err != nil {
			t.Fatalf("shutdown daemon supervisor: %v", err)
		}
	})

	spec := Spec{
		AppID:     "log-tail",
		ProcessID: "log-tail",
		Enabled:   true,
		AppRoot:   root,
		Command:   "bin/daemon",
	}
	if err := sup.Reconcile([]Spec{spec}); err != nil {
		t.Fatalf("reconcile start: %v", err)
	}
	waitDaemonStatus(t, sup, "log-tail", func(status ProcessStatus) bool {
		return status.Running
	})

	var log ProcessLog
	waitUntil(t, func() bool {
		var err error
		log, err = sup.LogTail("log-tail", 0)
		return err == nil &&
			strings.Contains(log.Tail, "log-tail stdout") &&
			strings.Contains(log.Tail, "log-tail stderr")
	})
	if log.LogFile != "data/daemon-apps/log-tail/daemon-supervisor.log" {
		t.Fatalf("log file=%q", log.LogFile)
	}

	shortLog, err := sup.LogTail("log-tail", 12)
	if err != nil {
		t.Fatalf("short log: %v", err)
	}
	if !shortLog.Truncated || len(shortLog.Tail) > 12 {
		t.Fatalf("short log truncated=%v len=%d", shortLog.Truncated, len(shortLog.Tail))
	}
}

func writeTestDaemonApp(t *testing.T, label string) string {
	t.Helper()
	root := t.TempDir()
	binDir := filepath.Join(root, "bin")
	if err := os.MkdirAll(binDir, 0o755); err != nil {
		t.Fatalf("mkdir daemon bin: %v", err)
	}
	script := "#!/bin/sh\n" +
		"printf '" + label + " stdout\\n'\n" +
		"printf '" + label + " stderr\\n' >&2\n" +
		"trap 'exit 0' TERM INT\n" +
		"while :; do sleep 1; done\n"
	if err := os.WriteFile(filepath.Join(binDir, "daemon"), []byte(script), 0o755); err != nil {
		t.Fatalf("write daemon script: %v", err)
	}
	return root
}

func withTempCWD(t *testing.T) {
	t.Helper()
	old, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	next := t.TempDir()
	if err := os.Chdir(next); err != nil {
		t.Fatalf("chdir temp: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(old); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

func waitDaemonStatus(t *testing.T, sup *Supervisor, appID string, accept func(ProcessStatus) bool) ProcessStatus {
	t.Helper()
	var got ProcessStatus
	waitUntil(t, func() bool {
		for _, status := range sup.Snapshot() {
			if status.AppID == appID {
				got = status
				return accept(status)
			}
		}
		return false
	})
	return got
}

func waitUntil(t *testing.T, accept func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if accept() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition was not met before timeout")
}
