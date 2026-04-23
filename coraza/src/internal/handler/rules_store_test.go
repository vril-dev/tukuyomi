package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/config"
)

func TestSyncRuleFilesStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "rules", "tukuyomi.conf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	fileRaw := "SecRuleEngine On\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	config.RulesFile = rulePath

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := SyncRuleFilesStorage(); err != nil {
		t.Fatalf("sync rule files storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	key := ruleFileConfigBlobKey(rulePath)
	gotRaw, _, found, err := store.GetConfigBlob(key)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatalf("expected rule config blob to be seeded (key=%s)", key)
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(fileRaw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), fileRaw)
	}
}

func TestSyncRuleFilesStorage_RestoresFileFromDB(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "rules", "tukuyomi.conf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	fileRaw := "SecRuleEngine DetectionOnly\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	config.RulesFile = rulePath

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	dbRaw := "SecRuleEngine On\n"
	key := ruleFileConfigBlobKey(rulePath)
	if err := store.UpsertConfigBlob(key, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncRuleFilesStorage(); err != nil {
		t.Fatalf("sync rule files storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(rulePath)
	if err != nil {
		t.Fatalf("read rule file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("rule file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}
}

func saveRulesFileConfigForTest() func() {
	oldRulesFile := config.RulesFile
	return func() {
		config.RulesFile = oldRulesFile
	}
}
