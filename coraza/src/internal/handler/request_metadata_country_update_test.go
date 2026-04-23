package handler

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func geoIPRepoRootPath() string {
	_, file, _, _ := runtime.Caller(0)
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", "..", ".."))
}

func loadSampleCountryMMDBBytes(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(geoIPRepoRootPath(), "data", "geoip", "country.mmdb"))
	if err != nil {
		t.Fatalf("read sample country mmdb: %v", err)
	}
	return raw
}

func TestParseRequestCountryGeoIPConfigAcceptsCountryEdition(t *testing.T) {
	raw := []byte(`
# comment
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-Country GeoLite2-City
`)
	summary, err := parseRequestCountryGeoIPConfig(raw)
	if err != nil {
		t.Fatalf("parseRequestCountryGeoIPConfig() error: %v", err)
	}
	if got, want := summary.SupportedCountryEdition, "GeoLite2-Country"; got != want {
		t.Fatalf("supported edition=%q want=%q", got, want)
	}
	if len(summary.EditionIDs) != 2 {
		t.Fatalf("edition ids=%v want two entries", summary.EditionIDs)
	}
}

func TestParseRequestCountryGeoIPConfigRejectsWithoutSupportedCountryEdition(t *testing.T) {
	raw := []byte(`
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-City
`)
	_, err := parseRequestCountryGeoIPConfig(raw)
	if err == nil {
		t.Fatal("expected error for config without supported country edition")
	}
}

func TestRequestCountryRuntimeMaybeRefreshFromManagedFileSwapsReaderState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write managed path: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{
			reader:      &maxminddb.Reader{},
			managedPath: path,
			sizeBytes:   99,
			modTime:     time.Unix(20, 0).UTC(),
		}, nil
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   path,
		dbSizeBytes:   1,
		dbModTime:     time.Unix(10, 0).UTC(),
	}
	rt.maybeRefreshFromManagedSource()

	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if got, want := rt.dbSizeBytes, int64(99); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if got := rt.dbModTime; !got.Equal(time.Unix(20, 0).UTC()) {
		t.Fatalf("dbModTime=%s want=%s", got, time.Unix(20, 0).UTC())
	}
	if rt.reader == nil {
		t.Fatal("expected reader to be refreshed")
	}
}

func TestRequestCountryRuntimeMaybeRefreshFromManagedFileKeepsOldStateOnReloadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write managed path: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{}, os.ErrPermission
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   path,
		dbSizeBytes:   1,
		dbModTime:     time.Unix(10, 0).UTC(),
	}
	rt.maybeRefreshFromManagedSource()

	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if got, want := rt.dbSizeBytes, int64(1); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if rt.lastError == "" {
		t.Fatal("expected lastError to be recorded")
	}
}

func TestBuildRequestCountryUpdateStatusUsesDBBackedConfigAndState(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}

	raw := []byte("AccountID 12345\nLicenseKey secret\nEditionIDs GeoLite2-Country GeoLite2-City\n")
	summary, err := parseRequestCountryGeoIPConfig(raw)
	if err != nil {
		t.Fatalf("parseRequestCountryGeoIPConfig: %v", err)
	}
	if _, _, err := store.writeRequestCountryGeoIPConfigVersion("", requestCountryGeoIPConfigVersion{
		Present: true,
		Raw:     raw,
		Summary: summary,
	}, configVersionSourceApply, "", "test config", 0); err != nil {
		t.Fatalf("writeRequestCountryGeoIPConfigVersion: %v", err)
	}
	if err := store.upsertRequestCountryUpdateState(requestCountryUpdateState{
		LastAttempt: "2026-04-23T09:00:00Z",
		LastSuccess: "2026-04-23T09:01:00Z",
		LastResult:  "success",
	}, time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("upsertRequestCountryUpdateState: %v", err)
	}

	status := buildRequestCountryUpdateStatus()
	if got, want := status.ManagedConfigPath, requestCountryGeoIPConfigStorageLabel; got != want {
		t.Fatalf("ManagedConfigPath=%q want=%q", got, want)
	}
	if !status.ConfigInstalled {
		t.Fatal("expected config to be installed")
	}
	if got, want := status.SupportedCountryEdition, "GeoLite2-Country"; got != want {
		t.Fatalf("SupportedCountryEdition=%q want=%q", got, want)
	}
	if len(status.EditionIDs) != 2 {
		t.Fatalf("EditionIDs=%v want 2 entries", status.EditionIDs)
	}
	if got, want := status.LastResult, "success"; got != want {
		t.Fatalf("LastResult=%q want=%q", got, want)
	}
}

func TestDefaultRunRequestCountryDBUpdateNowPersistsDBAssetAndState(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}

	rawConfig := []byte("AccountID 12345\nLicenseKey secret\nEditionIDs GeoLite2-Country\n")
	summary, err := parseRequestCountryGeoIPConfig(rawConfig)
	if err != nil {
		t.Fatalf("parseRequestCountryGeoIPConfig: %v", err)
	}
	if _, _, err := store.writeRequestCountryGeoIPConfigVersion("", requestCountryGeoIPConfigVersion{
		Present: true,
		Raw:     rawConfig,
		Summary: summary,
	}, configVersionSourceApply, "", "test config", 0); err != nil {
		t.Fatalf("writeRequestCountryGeoIPConfigVersion: %v", err)
	}

	truePath, err := exec.LookPath("true")
	if err != nil {
		t.Fatalf("LookPath(true): %v", err)
	}
	t.Setenv("GEOIPUPDATE_BIN", truePath)

	prevRun := requestCountryUpdateRun
	requestCountryUpdateRun = func(_ context.Context, _ string, configPath, databaseDir string) error {
		if _, err := os.Stat(configPath); err != nil {
			t.Fatalf("temp config path missing: %v", err)
		}
		mmdbPath := filepath.Join(databaseDir, "GeoLite2-Country.mmdb")
		return os.WriteFile(mmdbPath, loadSampleCountryMMDBBytes(t), 0o600)
	}
	defer func() { requestCountryUpdateRun = prevRun }()

	if err := defaultRunRequestCountryDBUpdateNow(context.Background()); err != nil {
		t.Fatalf("defaultRunRequestCountryDBUpdateNow: %v", err)
	}

	asset, _, found, err := store.loadActiveRequestCountryMMDBAsset()
	if err != nil {
		t.Fatalf("loadActiveRequestCountryMMDBAsset: %v", err)
	}
	if !found || !asset.Present || asset.SizeBytes == 0 {
		t.Fatalf("asset found=%v present=%v size=%d", found, asset.Present, asset.SizeBytes)
	}
	state, found, err := store.loadRequestCountryUpdateState()
	if err != nil {
		t.Fatalf("loadRequestCountryUpdateState: %v", err)
	}
	if !found {
		t.Fatal("expected update state row")
	}
	if got, want := state.LastResult, "success"; got != want {
		t.Fatalf("LastResult=%q want=%q", got, want)
	}
	if state.LastSuccess == "" {
		t.Fatal("expected LastSuccess to be set")
	}
}
