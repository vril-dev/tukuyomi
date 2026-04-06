package handler

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestInitLogOutputUpdatesActiveLogPaths(t *testing.T) {
	restore := saveLogOutputState()
	defer restore()

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "conf", "log-output.json")
	raw := `{
  "provider": "aws",
  "waf": {
    "mode": "stdout-ndjson",
    "file_path": "` + filepath.Join(tmp, "logs", "coraza", "waf.ndjson") + `"
  },
  "interesting": {
    "mode": "dual",
    "file_path": "` + filepath.Join(tmp, "logs", "nginx", "interesting-custom.ndjson") + `"
  },
  "access_error": {
    "mode": "file-ndjson",
    "file_path": "` + filepath.Join(tmp, "logs", "nginx", "access-error-custom.ndjson") + `"
  }
}`
	if err := os.MkdirAll(filepath.Dir(cfgPath), 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := InitLogOutput(cfgPath); err != nil {
		t.Fatalf("InitLogOutput: %v", err)
	}

	status := GetLogOutputStatus()
	if status.Provider != "aws" {
		t.Fatalf("provider=%q want=aws", status.Provider)
	}
	if got := logFiles["intr"]; got != filepath.Join(tmp, "logs", "nginx", "interesting-custom.ndjson") {
		t.Fatalf("interesting log path=%q", got)
	}
	if got := logFiles["accerr"]; got != filepath.Join(tmp, "logs", "nginx", "access-error-custom.ndjson") {
		t.Fatalf("access-error log path=%q", got)
	}
	if status.StdoutStreams != 2 {
		t.Fatalf("stdout streams=%d want=2", status.StdoutStreams)
	}
	if status.FileStreams != 2 {
		t.Fatalf("file streams=%d want=2", status.FileStreams)
	}
	if status.LocalReadCompatible {
		t.Fatal("stdout-only waf stream should disable local-read compatibility")
	}
}

func TestValidateLogOutputRawRejectsUnwritableFileTarget(t *testing.T) {
	restore := saveLogOutputState()
	defer restore()

	tmp := t.TempDir()
	blocker := filepath.Join(tmp, "not-a-dir")
	if err := os.WriteFile(blocker, []byte("x"), 0o644); err != nil {
		t.Fatalf("write blocker: %v", err)
	}

	raw := `{
  "provider": "custom",
  "waf": {
    "mode": "dual",
    "file_path": "` + filepath.Join(tmp, "logs", "coraza", "waf.ndjson") + `"
  },
  "interesting": {
    "mode": "file-ndjson",
    "file_path": "` + filepath.Join(blocker, "interesting.ndjson") + `"
  },
  "access_error": {
    "mode": "file-ndjson",
    "file_path": "` + filepath.Join(tmp, "logs", "nginx", "access-error.ndjson") + `"
  }
}`

	if _, err := ValidateLogOutputRaw(raw); err == nil {
		t.Fatal("expected writable target validation error")
	}
}

func TestEmitOperationalAccessLogsHonorsStdoutOnlyProfile(t *testing.T) {
	restore := saveLogOutputState()
	defer restore()

	tmp := t.TempDir()
	logOutputRuntime = &logOutputStatus{
		Path:     filepath.Join(tmp, "conf", "log-output.json"),
		Provider: "gcp",
		WAF: logOutputTarget{
			Mode:     logOutputModeDual,
			FilePath: filepath.Join(tmp, "logs", "coraza", "waf-events.ndjson"),
		},
		Interesting: logOutputTarget{
			Mode:     logOutputModeStdout,
			FilePath: filepath.Join(tmp, "logs", "nginx", "interesting.ndjson"),
		},
		AccessError: logOutputTarget{
			Mode:     logOutputModeDisable,
			FilePath: filepath.Join(tmp, "logs", "nginx", "access-error.ndjson"),
		},
		StdoutStreams:       2,
		FileStreams:         1,
		LocalReadCompatible: false,
	}

	prevWriter := log.Writer()
	defer log.SetOutput(prevWriter)
	var buf bytes.Buffer
	log.SetOutput(&buf)

	emitOperationalAccessLogs(operationalLogEntry{
		Timestamp:      time.Date(2026, 4, 6, 10, 11, 12, 0, time.UTC),
		RequestID:      "req-stdout",
		IP:             "203.0.113.8",
		Country:        "jp",
		Method:         "GET",
		Path:           "/xmlrpc.php",
		Status:         200,
		UpstreamStatus: "200",
		Duration:       25 * time.Millisecond,
	})

	if !strings.Contains(buf.String(), `"path":"/xmlrpc.php"`) {
		t.Fatalf("stdout log missing expected path: %s", buf.String())
	}
	if _, err := os.Stat(filepath.Join(tmp, "logs", "nginx", "interesting.ndjson")); !os.IsNotExist(err) {
		t.Fatalf("interesting file should stay absent in stdout mode, err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "logs", "nginx", "access-error.ndjson")); !os.IsNotExist(err) {
		t.Fatalf("access-error file should stay absent in disabled mode, err=%v", err)
	}
}

func saveLogOutputState() func() {
	logOutputMu.RLock()
	prevPath := logOutputPath
	var prevRuntime *logOutputStatus
	if logOutputRuntime != nil {
		copied := *logOutputRuntime
		prevRuntime = &copied
	}
	logOutputMu.RUnlock()

	prevLogFiles := make(map[string]string, len(logFiles))
	for k, v := range logFiles {
		prevLogFiles[k] = v
	}

	return func() {
		logOutputMu.Lock()
		logOutputPath = prevPath
		logOutputRuntime = prevRuntime
		logOutputMu.Unlock()
		logFiles = prevLogFiles
	}
}
