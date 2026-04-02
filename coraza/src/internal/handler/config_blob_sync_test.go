package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSyncConfigBlobFilePath_SkipReloadWhenUnchanged(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "sample.conf")
	raw := []byte("hello\n")
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatalf("write file: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
	})
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	if err := store.UpsertConfigBlob("test_key", raw, "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	reloadCalls := 0
	err := syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey:        "test_key",
		Path:             path,
		SkipWriteIfEqual: true,
		Reload: func() error {
			reloadCalls++
			return nil
		},
	})
	if err != nil {
		t.Fatalf("sync config blob: %v", err)
	}
	if reloadCalls != 0 {
		t.Fatalf("reload should be skipped when blob/file unchanged, got=%d", reloadCalls)
	}
}
