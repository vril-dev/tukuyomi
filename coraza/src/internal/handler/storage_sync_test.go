package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

func TestSyncBypassStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	bypassPath := filepath.Join(tmp, "waf.bypass")
	fileRaw := "/healthz\n"
	if err := os.WriteFile(bypassPath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write bypass file: %v", err)
	}
	config.BypassFile = bypassPath
	if err := bypassconf.Init(bypassPath, ""); err != nil {
		t.Fatalf("init bypass loader: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := SyncBypassStorage(); err != nil {
		t.Fatalf("sync bypass storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(bypassConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected bypass config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(fileRaw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), fileRaw)
	}
}

func TestSyncBypassStorage_RestoresFileAndRuntimeFromDB(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	bypassPath := filepath.Join(tmp, "waf.bypass")
	fileRaw := "/old\n"
	if err := os.WriteFile(bypassPath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write bypass file: %v", err)
	}
	config.BypassFile = bypassPath
	if err := bypassconf.Init(bypassPath, ""); err != nil {
		t.Fatalf("init bypass loader: %v", err)
	}

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
	dbRaw := "/api/\n"
	if err := store.UpsertConfigBlob(bypassConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncBypassStorage(); err != nil {
		t.Fatalf("sync bypass storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(bypassPath)
	if err != nil {
		t.Fatalf("read bypass file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}

	match := bypassconf.Match("example.com", "/api/test", false)
	if match.Action != bypassconf.ACTION_BYPASS {
		t.Fatalf("bypass runtime not reloaded from db blob: action=%v", match.Action)
	}
}

func TestSyncCRSDisabledStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.CRSEnable = false
	config.CRSDisabledFile = filepath.Join(tmp, "crs-disabled.conf")
	fileRaw := "# disabled list\nREQUEST-913-SCANNER-DETECTION.conf\n"
	if err := os.WriteFile(config.CRSDisabledFile, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write crs-disabled file: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := SyncCRSDisabledStorage(); err != nil {
		t.Fatalf("sync crs-disabled storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(crsDisabledConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected crs-disabled config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(fileRaw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), fileRaw)
	}
}

func TestSyncCRSDisabledStorage_RestoresFileFromDBWhenCRSDisabled(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.CRSEnable = false
	config.CRSDisabledFile = filepath.Join(tmp, "crs-disabled.conf")
	if err := os.WriteFile(config.CRSDisabledFile, []byte("REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n"), 0o644); err != nil {
		t.Fatalf("write crs-disabled file: %v", err)
	}

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
	dbRaw := "# from db\nREQUEST-913-SCANNER-DETECTION.conf\n"
	if err := store.UpsertConfigBlob(crsDisabledConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncCRSDisabledStorage(); err != nil {
		t.Fatalf("sync crs-disabled storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(config.CRSDisabledFile)
	if err != nil {
		t.Fatalf("read crs-disabled file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}
}

func saveBypassAndCRSConfigForTest() func() {
	oldBypass := config.BypassFile
	oldCRSEnable := config.CRSEnable
	oldCRSDisabled := config.CRSDisabledFile

	return func() {
		config.BypassFile = oldBypass
		config.CRSEnable = oldCRSEnable
		config.CRSDisabledFile = oldCRSDisabled
	}
}
