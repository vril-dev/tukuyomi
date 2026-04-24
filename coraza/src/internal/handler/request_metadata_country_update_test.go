package handler

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/maxmind/mmdbwriter"
	"github.com/maxmind/mmdbwriter/mmdbtype"
	"github.com/oschwald/maxminddb-golang"
)

func loadSampleCountryMMDBBytes(t *testing.T) []byte {
	t.Helper()
	writer, err := mmdbwriter.New(mmdbwriter.Options{
		BuildEpoch:              1,
		DatabaseType:            "GeoIP2-Country",
		Description:             map[string]string{"en": "tukuyomi request country test database"},
		IncludeReservedNetworks: true,
		IPVersion:               4,
		RecordSize:              24,
	})
	if err != nil {
		t.Fatalf("create sample country mmdb writer: %v", err)
	}
	_, network, err := net.ParseCIDR("203.0.113.0/24")
	if err != nil {
		t.Fatalf("parse sample country network: %v", err)
	}
	record := mmdbtype.Map{
		"country": mmdbtype.Map{
			"iso_code": mmdbtype.String("JP"),
		},
		"registered_country": mmdbtype.Map{
			"iso_code": mmdbtype.String("JP"),
		},
	}
	if err := writer.Insert(network, record); err != nil {
		t.Fatalf("insert sample country network: %v", err)
	}
	var buf bytes.Buffer
	if _, err := writer.WriteTo(&buf); err != nil {
		t.Fatalf("write sample country mmdb: %v", err)
	}
	return buf.Bytes()
}

func TestLoadSampleCountryMMDBBytesResolveCountry(t *testing.T) {
	reader, err := maxminddb.FromBytes(loadSampleCountryMMDBBytes(t))
	if err != nil {
		t.Fatalf("open sample country mmdb: %v", err)
	}
	defer reader.Close()

	var record requestCountryMMDBRecord
	if err := reader.Lookup(net.ParseIP("203.0.113.10"), &record); err != nil {
		t.Fatalf("lookup sample country: %v", err)
	}
	if got, want := record.Country.ISOCode, "JP"; got != want {
		t.Fatalf("sample country iso_code=%q want=%q", got, want)
	}
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

func TestRenderRequestCountryGeoIPConfigForCountryEditionFiltersNonCountryEditions(t *testing.T) {
	raw := []byte(`
# keep comments
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
ProductIDs GeoLite2-ASN
`)
	out, err := renderRequestCountryGeoIPConfigForCountryEdition(raw, "GeoLite2-Country")
	if err != nil {
		t.Fatalf("renderRequestCountryGeoIPConfigForCountryEdition: %v", err)
	}
	text := string(out)
	for _, want := range []string{"AccountID 12345", "LicenseKey secret", "EditionIDs GeoLite2-Country"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, text)
		}
	}
	for _, blocked := range []string{"GeoLite2-ASN", "GeoLite2-City", "ProductIDs"} {
		if strings.Contains(text, blocked) {
			t.Fatalf("rendered config still contains %q:\n%s", blocked, text)
		}
	}
}

func TestWriteManagedRequestCountryGeoIPConfigRequiresDBStoreWithoutFileFallback(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	raw := []byte("AccountID 12345\nLicenseKey secret\nEditionIDs GeoLite2-Country\n")
	err := writeManagedRequestCountryGeoIPConfigRaw(raw, configVersionSourceApply, "test geoip config upload")
	if !errors.Is(err, errConfigDBStoreRequired) {
		t.Fatalf("error=%v want %v", err, errConfigDBStoreRequired)
	}
	if _, statErr := os.Stat(managedRequestCountryGeoIPConfigPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("managed GeoIP config file should not be written without DB store, stat err=%v", statErr)
	}
}

func TestRequestCountryRuntimeMaybeRefreshFromManagedDBSwapsReaderState(t *testing.T) {
	initConfigDBStoreForTest(t)
	store := getLogsStatsStore()
	if _, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
		Present: true,
		Raw:     loadSampleCountryMMDBBytes(t),
	}, configVersionSourceApply, "", "test mmdb", 0); err != nil {
		t.Fatalf("writeRequestCountryMMDBAssetVersion: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{
			reader:      &maxminddb.Reader{},
			managedPath: requestCountryMMDBStorageLabel,
			versionID:   1,
			versionETag: "etag",
			sizeBytes:   99,
			modTime:     time.Unix(20, 0).UTC(),
		}, nil
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   requestCountryMMDBStorageLabel,
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

func TestRequestCountryRuntimeMaybeRefreshFromManagedDBKeepsOldStateOnReloadError(t *testing.T) {
	initConfigDBStoreForTest(t)
	store := getLogsStatsStore()
	if _, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
		Present: true,
		Raw:     loadSampleCountryMMDBBytes(t),
	}, configVersionSourceApply, "", "test mmdb reload error", 0); err != nil {
		t.Fatalf("writeRequestCountryMMDBAssetVersion: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{}, os.ErrPermission
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   requestCountryMMDBStorageLabel,
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
	t.Chdir(t.TempDir())

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}

	rawConfig := []byte("AccountID 12345\nLicenseKey secret\nEditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country\n")
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
		raw, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("temp config path missing: %v", err)
		}
		text := string(raw)
		if !strings.Contains(text, "EditionIDs GeoLite2-Country") {
			t.Fatalf("temp config missing country edition:\n%s", text)
		}
		for _, blocked := range []string{"GeoLite2-ASN", "GeoLite2-City"} {
			if strings.Contains(text, blocked) {
				t.Fatalf("temp config should not request %s:\n%s", blocked, text)
			}
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
