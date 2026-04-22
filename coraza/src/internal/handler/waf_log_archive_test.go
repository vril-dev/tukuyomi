package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tukuyomi/internal/config"
)

func TestWAFLogArchiveAppendThrottlesUnrotatedPrune(t *testing.T) {
	restore := saveWAFLogArchiveConfigForTest()
	defer restore()

	config.StorageBackend = "file"
	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = time.Second

	dir := t.TempDir()
	path := filepath.Join(dir, "waf-events.ndjson")
	archive := &wafLogArchive{}

	firstOld := writeOldArchiveForTest(t, path+".1.gz")
	if err := archive.Append(map[string]any{"event": "first"}, path); err != nil {
		t.Fatalf("Append first: %v", err)
	}
	if _, err := os.Stat(firstOld); !os.IsNotExist(err) {
		t.Fatalf("first old archive should be pruned, stat err=%v", err)
	}

	secondOld := writeOldArchiveForTest(t, path+".2.gz")
	if err := archive.Append(map[string]any{"event": "second"}, path); err != nil {
		t.Fatalf("Append second: %v", err)
	}
	if _, err := os.Stat(secondOld); err != nil {
		t.Fatalf("second old archive should remain during throttle window: %v", err)
	}

	archive.mu.Lock()
	archive.lastPrune[path] = time.Now().Add(-wafLogArchivePruneInterval - time.Second)
	archive.mu.Unlock()
	if err := archive.Append(map[string]any{"event": "third"}, path); err != nil {
		t.Fatalf("Append third: %v", err)
	}
	if _, err := os.Stat(secondOld); !os.IsNotExist(err) {
		t.Fatalf("second old archive should be pruned after throttle window, stat err=%v", err)
	}
}

func TestWAFLogArchiveAppendEncodedWritesRawJSONLine(t *testing.T) {
	restore := saveWAFLogArchiveConfigForTest()
	defer restore()

	config.StorageBackend = "file"
	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = 0

	path := filepath.Join(t.TempDir(), "waf-events.ndjson")
	raw := []byte(`{"event":"proxy_access","status":200}`)
	if err := (&wafLogArchive{}).AppendEncoded(raw, path); err != nil {
		t.Fatalf("AppendEncoded: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := string(raw) + "\n"
	if string(got) != want {
		t.Fatalf("log line=%q want=%q", string(got), want)
	}
}

func TestWAFLogArchiveAppendEncodedBatchWritesRawJSONLines(t *testing.T) {
	restore := saveWAFLogArchiveConfigForTest()
	defer restore()

	config.StorageBackend = "file"
	config.FileRotateBytes = 0
	config.FileMaxBytes = 0
	config.FileRetention = 0

	path := filepath.Join(t.TempDir(), "waf-events.ndjson")
	raws := [][]byte{
		[]byte(`{"event":"proxy_access","status":200}`),
		[]byte(`{"event":"proxy_access","status":201}`),
	}
	if err := (&wafLogArchive{}).AppendEncodedBatch(raws, path); err != nil {
		t.Fatalf("AppendEncodedBatch: %v", err)
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log: %v", err)
	}
	want := string(raws[0]) + "\n" + string(raws[1]) + "\n"
	if string(got) != want {
		t.Fatalf("log lines=%q want=%q", string(got), want)
	}
}

func writeOldArchiveForTest(t *testing.T, path string) string {
	t.Helper()
	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("write old archive: %v", err)
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatalf("chtimes old archive: %v", err)
	}
	return path
}

func saveWAFLogArchiveConfigForTest() func() {
	prevStorageBackend := config.StorageBackend
	prevFileRotateBytes := config.FileRotateBytes
	prevFileMaxBytes := config.FileMaxBytes
	prevFileRetention := config.FileRetention
	prevLogFile := config.LogFile

	return func() {
		config.StorageBackend = prevStorageBackend
		config.FileRotateBytes = prevFileRotateBytes
		config.FileMaxBytes = prevFileMaxBytes
		config.FileRetention = prevFileRetention
		config.LogFile = prevLogFile
	}
}
