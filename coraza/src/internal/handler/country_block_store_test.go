package handler

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestParseCountryBlockRaw_Valid(t *testing.T) {
	got, err := ParseCountryBlockRaw(`
# comments
jp
US
UNKNOWN
JP
`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	want := []string{"JP", "UNKNOWN", "US"}
	if len(got) != len(want) {
		t.Fatalf("len(got)=%d want=%d got=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d]=%s want=%s (all=%v)", i, got[i], want[i], got)
		}
	}
}

func TestParseCountryBlockRaw_Invalid(t *testing.T) {
	if _, err := ParseCountryBlockRaw("JPN\n"); err == nil {
		t.Fatal("expected error for non alpha-2 code")
	}
	if _, err := ParseCountryBlockRaw("U1\n"); err == nil {
		t.Fatal("expected error for non alphabetic code")
	}
	if _, err := ParseCountryBlockRaw("JP US\n"); err == nil {
		t.Fatal("expected error for multiple tokens per line")
	}
}

func TestSyncCountryBlockStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveCountryBlockStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "country-block.conf")
	raw := "JP\nUS\n"
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write country-block file: %v", err)
	}
	if err := InitCountryBlock(path); err != nil {
		t.Fatalf("init country-block: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
	})

	if err := SyncCountryBlockStorage(); err != nil {
		t.Fatalf("sync country-block storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(countryBlockConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected country-block config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(raw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), raw)
	}
}

func TestSyncCountryBlockStorage_RestoresFileAndRuntimeFromDB(t *testing.T) {
	restore := saveCountryBlockStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "country-block.conf")
	fileRaw := "JP\n"
	if err := os.WriteFile(path, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write country-block file: %v", err)
	}
	if err := InitCountryBlock(path); err != nil {
		t.Fatalf("init country-block: %v", err)
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
	dbRaw := "US\nUNKNOWN\n"
	if err := store.UpsertConfigBlob(countryBlockConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncCountryBlockStorage(); err != nil {
		t.Fatalf("sync country-block storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read country-block file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}

	gotBlocked := GetBlockedCountries()
	wantBlocked := []string{"UNKNOWN", "US"}
	if !reflect.DeepEqual(gotBlocked, wantBlocked) {
		t.Fatalf("blocked countries=%v want=%v", gotBlocked, wantBlocked)
	}
}

func saveCountryBlockStateForTest() func() {
	countryBlockMu.RLock()
	oldPath := countryBlockPath
	oldBlocked := make(map[string]struct{}, len(blockedCountryCodes))
	for k, v := range blockedCountryCodes {
		oldBlocked[k] = v
	}
	countryBlockMu.RUnlock()

	return func() {
		countryBlockMu.Lock()
		countryBlockPath = oldPath
		blockedCountryCodes = oldBlocked
		countryBlockMu.Unlock()
	}
}
