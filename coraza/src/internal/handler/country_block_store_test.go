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

	if !reflect.DeepEqual(got.Default.BlockedCountries, []string{"JP", "UNKNOWN", "US"}) {
		t.Fatalf("default.blocked_countries=%v", got.Default.BlockedCountries)
	}
}

func TestParseCountryBlockRaw_JSON(t *testing.T) {
	got, err := ParseCountryBlockRaw(`{
  "default": {
    "blocked_countries": ["jp", "UNKNOWN"]
  },
  "hosts": {
    "admin.example.com": {
      "blocked_countries": ["US", "JP"]
    }
  }
}`)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := []string{"JP", "UNKNOWN", "US"}
	if !reflect.DeepEqual(flattenCountryBlockCodes(got), want) {
		t.Fatalf("flattenCountryBlockCodes()=%v want=%v", flattenCountryBlockCodes(got), want)
	}
	if _, ok := got.Hosts["admin.example.com"]; !ok {
		t.Fatalf("expected host scope, got %v", got.Hosts)
	}
}

func TestParseCountryBlockRaw_Invalid(t *testing.T) {
	cases := []string{
		"JPN\n",
		"U1\n",
		"JP US\n",
		`{"hosts":{"*.example.com":{"blocked_countries":["JP"]}}}`,
	}
	for _, raw := range cases {
		if _, err := ParseCountryBlockRaw(raw); err == nil {
			t.Fatalf("expected error for %q", raw)
		}
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
	if err := InitCountryBlock(path, ""); err != nil {
		t.Fatalf("init country-block: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
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
	if err := InitCountryBlock(path, ""); err != nil {
		t.Fatalf("init country-block: %v", err)
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

func TestInitCountryBlock_PrefersLegacyUntilPrimaryExists(t *testing.T) {
	restore := saveCountryBlockStateForTest()
	defer restore()

	tmp := t.TempDir()
	primary := filepath.Join(tmp, "country-block.json")
	legacy := filepath.Join(tmp, "country-block.conf")
	if err := os.WriteFile(legacy, []byte("JP\n"), 0o644); err != nil {
		t.Fatalf("write legacy country-block file: %v", err)
	}

	if err := InitCountryBlock(primary, legacy); err != nil {
		t.Fatalf("InitCountryBlock() error: %v", err)
	}
	if got := GetCountryBlockActivePath(); got != legacy {
		t.Fatalf("active path=%q want=%q", got, legacy)
	}
	if !IsCountryBlocked("example.com", false, "JP") {
		t.Fatal("expected JP to be blocked from legacy file")
	}
	if _, err := os.Stat(primary); !os.IsNotExist(err) {
		t.Fatalf("primary file should not be created implicitly, err=%v", err)
	}

	primaryRaw, err := MarshalCountryBlockJSON(countryBlockFile{Default: countryBlockScope{BlockedCountries: []string{"US"}}})
	if err != nil {
		t.Fatalf("MarshalCountryBlockJSON() error: %v", err)
	}
	if err := os.WriteFile(primary, primaryRaw, 0o644); err != nil {
		t.Fatalf("write primary country-block file: %v", err)
	}
	if err := ReloadCountryBlock(); err != nil {
		t.Fatalf("ReloadCountryBlock() error: %v", err)
	}
	if got := GetCountryBlockActivePath(); got != primary {
		t.Fatalf("active path=%q want=%q", got, primary)
	}
	if !IsCountryBlocked("example.com", false, "US") {
		t.Fatal("expected US to be blocked from primary file")
	}
	if IsCountryBlocked("example.com", false, "JP") {
		t.Fatal("did not expect JP to remain blocked after switching to primary file")
	}
}

func TestIsCountryBlocked_PrefersHostPortOverHostAndDefault(t *testing.T) {
	restore := saveCountryBlockStateForTest()
	defer restore()

	countryBlockMu.Lock()
	countryBlockState = compileCountryBlock(countryBlockFile{
		Default: countryBlockScope{BlockedCountries: []string{"JP"}},
		Hosts: map[string]countryBlockScope{
			"example.com":      {BlockedCountries: []string{"US"}},
			"example.com:8080": {BlockedCountries: []string{"KR"}},
		},
	})
	countryBlockMu.Unlock()

	if !IsCountryBlocked("example.com:8080", false, "KR") {
		t.Fatal("expected host:port override to block KR")
	}
	if IsCountryBlocked("example.com:8080", false, "US") {
		t.Fatal("did not expect bare host policy to apply when host:port override exists")
	}
	if !IsCountryBlocked("example.com", false, "US") {
		t.Fatal("expected bare host policy to block US")
	}
	if !IsCountryBlocked("other.example.com", false, "JP") {
		t.Fatal("expected default policy to block JP")
	}
}

func TestIsCountryBlocked_TreatsHTTPSDefaultPortAsEquivalent(t *testing.T) {
	restore := saveCountryBlockStateForTest()
	defer restore()

	countryBlockMu.Lock()
	countryBlockState = compileCountryBlock(countryBlockFile{
		Hosts: map[string]countryBlockScope{
			"example.com:443": {BlockedCountries: []string{"US"}},
		},
	})
	countryBlockMu.Unlock()

	if !IsCountryBlocked("example.com", true, "US") {
		t.Fatal("expected default HTTPS port to match :443 policy")
	}
}

func saveCountryBlockStateForTest() func() {
	countryBlockMu.RLock()
	oldPath := countryBlockPath
	oldLegacyPath := countryBlockLegacyPath
	oldActivePath := countryBlockActivePath
	oldState := cloneCompiledCountryBlock(countryBlockState)
	countryBlockMu.RUnlock()

	return func() {
		countryBlockMu.Lock()
		countryBlockPath = oldPath
		countryBlockLegacyPath = oldLegacyPath
		countryBlockActivePath = oldActivePath
		countryBlockState = oldState
		countryBlockMu.Unlock()
	}
}
