package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestEmitOperationalAccessLogsWritesParityFiles(t *testing.T) {
	tmp := t.TempDir()
	restore := saveLogFiles()
	defer restore()

	logFiles["intr"] = filepath.Join(tmp, "logs", "nginx", "interesting.ndjson")
	logFiles["accerr"] = filepath.Join(tmp, "logs", "nginx", "access-error.ndjson")

	emitOperationalAccessLogs(operationalLogEntry{
		Timestamp:      time.Date(2026, 4, 6, 3, 4, 5, 0, time.UTC),
		RequestID:      "req-1",
		IP:             "203.0.113.1",
		Country:        "jp",
		Method:         "GET",
		Path:           "/xmlrpc.php",
		Query:          "a=1",
		UserAgent:      "curl/8.5.0",
		Status:         403,
		UpstreamStatus: "403",
		Duration:       1500 * time.Millisecond,
		Event:          "waf_block",
	})

	for _, path := range []string{logFiles["intr"], logFiles["accerr"]} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		var line map[string]any
		if err := json.Unmarshal(raw, &line); err != nil {
			t.Fatalf("unmarshal %s: %v", path, err)
		}
		if got := line["event"]; got != "waf_block" {
			t.Fatalf("%s event=%v want=waf_block", path, got)
		}
		if got := line["country"]; got != "JP" {
			t.Fatalf("%s country=%v want=JP", path, got)
		}
		if got := line["path"]; got != "/xmlrpc.php" {
			t.Fatalf("%s path=%v want=/xmlrpc.php", path, got)
		}
	}
}

func TestEmitOperationalAccessLogsInterestingOnlyForHealthyWAFHit(t *testing.T) {
	tmp := t.TempDir()
	restore := saveLogFiles()
	defer restore()

	logFiles["intr"] = filepath.Join(tmp, "logs", "nginx", "interesting.ndjson")
	logFiles["accerr"] = filepath.Join(tmp, "logs", "nginx", "access-error.ndjson")

	emitOperationalAccessLogs(operationalLogEntry{
		Timestamp:      time.Now().UTC(),
		RequestID:      "req-2",
		IP:             "203.0.113.2",
		Country:        "US",
		Method:         "GET",
		Path:           "/api/whoami",
		Status:         200,
		UpstreamStatus: "200",
		Duration:       10 * time.Millisecond,
		WAFHit:         true,
		WAFRules:       "941100",
	})

	if _, err := os.Stat(logFiles["intr"]); err != nil {
		t.Fatalf("interesting log missing: %v", err)
	}
	if _, err := os.Stat(logFiles["accerr"]); !os.IsNotExist(err) {
		t.Fatalf("access-error log should stay absent, err=%v", err)
	}
}

func TestShouldWriteInterestingLogSignalsSuspiciousAndSlow(t *testing.T) {
	if !shouldWriteInterestingLog(operationalLogEntry{Path: "/.env", Status: 200}) {
		t.Fatal("suspicious path should be interesting")
	}
	if !shouldWriteInterestingLog(operationalLogEntry{Path: "/ok", Status: 200, Duration: slowRequestThreshold}) {
		t.Fatal("slow response should be interesting")
	}
	if shouldWriteInterestingLog(operationalLogEntry{Path: "/ok", Status: 200, Duration: 10 * time.Millisecond}) {
		t.Fatal("plain fast 200 response should not be interesting")
	}
}

func saveLogFiles() func() {
	prev := make(map[string]string, len(logFiles))
	for k, v := range logFiles {
		prev[k] = v
	}
	return func() {
		logFiles = prev
	}
}
