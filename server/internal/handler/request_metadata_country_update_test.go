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

	"tukuyomi/internal/requestmeta"
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
	_, loopback, err := net.ParseCIDR("127.0.0.0/8")
	if err != nil {
		t.Fatalf("parse loopback country network: %v", err)
	}
	if err := writer.Insert(loopback, record); err != nil {
		t.Fatalf("insert loopback country network: %v", err)
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

	var record requestmeta.CountryMMDBRecord
	if err := reader.Lookup(net.ParseIP("203.0.113.10"), &record); err != nil {
		t.Fatalf("lookup sample country: %v", err)
	}
	if got, want := record.Country.ISOCode, "JP"; got != want {
		t.Fatalf("sample country iso_code=%q want=%q", got, want)
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
	summary, parseErr := requestmeta.ParseGeoIPConfig(raw)
	if parseErr != nil {
		t.Fatalf("ParseGeoIPConfig: %v", parseErr)
	}
	err := writeManagedRequestCountryGeoIPConfigRaw(raw, summary, configVersionSourceApply, "test geoip config upload")
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
	rec, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
		Present: true,
		Raw:     loadSampleCountryMMDBBytes(t),
	}, configVersionSourceApply, "", "test mmdb", 0)
	if err != nil {
		t.Fatalf("writeRequestCountryMMDBAssetVersion: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	loaderState := loadedRequestCountryMMDBState{}
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		reader, err := maxminddb.FromBytes(loadSampleCountryMMDBBytes(t))
		if err != nil {
			return loadedRequestCountryMMDBState{}, err
		}
		loaderState.Reader = reader
		return loaderState, nil
	}
	t.Cleanup(func() {
		requestCountryMMDBLoader = prevLoader
		requestmeta.CloseCountryRuntime()
	})
	loaderState = loadedRequestCountryMMDBState{
		ManagedPath: requestCountryMMDBStorageLabel,
		VersionID:   0,
		VersionETag: "old",
		SizeBytes:   1,
		ModTime:     time.Unix(10, 0).UTC(),
	}
	if err := reloadRequestCountryRuntime("mmdb"); err != nil {
		t.Fatalf("reloadRequestCountryRuntime: %v", err)
	}
	loaderState = loadedRequestCountryMMDBState{
		ManagedPath: requestCountryMMDBStorageLabel,
		VersionID:   rec.VersionID,
		VersionETag: rec.ETag,
		SizeBytes:   99,
		ModTime:     time.Unix(20, 0).UTC(),
	}
	if _, _, err := lookupRequestCountryMMDB("203.0.113.10"); err != nil {
		t.Fatalf("lookupRequestCountryMMDB: %v", err)
	}

	status := RequestCountryRuntimeStatusSnapshot()
	if got, want := status.DBSizeBytes, int64(99); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if got, want := status.DBModTime, time.Unix(20, 0).UTC().Format(time.RFC3339Nano); got != want {
		t.Fatalf("dbModTime=%s want=%s", got, want)
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
	loaderErr := error(nil)
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		if loaderErr != nil {
			return loadedRequestCountryMMDBState{}, loaderErr
		}
		reader, err := maxminddb.FromBytes(loadSampleCountryMMDBBytes(t))
		if err != nil {
			return loadedRequestCountryMMDBState{}, err
		}
		return loadedRequestCountryMMDBState{
			Reader:      reader,
			ManagedPath: requestCountryMMDBStorageLabel,
			VersionID:   0,
			VersionETag: "old",
			SizeBytes:   1,
			ModTime:     time.Unix(10, 0).UTC(),
		}, nil
	}
	t.Cleanup(func() {
		requestCountryMMDBLoader = prevLoader
		requestmeta.CloseCountryRuntime()
	})
	if err := reloadRequestCountryRuntime("mmdb"); err != nil {
		t.Fatalf("reloadRequestCountryRuntime: %v", err)
	}
	loaderErr = os.ErrPermission
	if _, _, err := lookupRequestCountryMMDB("203.0.113.10"); err != nil {
		t.Fatalf("lookupRequestCountryMMDB: %v", err)
	}

	status := RequestCountryRuntimeStatusSnapshot()
	if got, want := status.DBSizeBytes, int64(1); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if status.LastError == "" {
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
	summary, err := requestmeta.ParseGeoIPConfig(raw)
	if err != nil {
		t.Fatalf("ParseGeoIPConfig: %v", err)
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
	summary, err := requestmeta.ParseGeoIPConfig(rawConfig)
	if err != nil {
		t.Fatalf("ParseGeoIPConfig: %v", err)
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
