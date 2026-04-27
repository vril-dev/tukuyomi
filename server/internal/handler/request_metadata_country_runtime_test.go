package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func loadTestAppConfig(t *testing.T) config.AppConfigFile {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := config.LoadAppConfigFile(path)
	if err != nil {
		t.Fatalf("LoadAppConfigFile() error: %v", err)
	}
	return cfg
}

func TestValidateRequestCountryRuntimeConfigAllowsHeaderModeWithoutDB(t *testing.T) {
	cfg := loadTestAppConfig(t)
	cfg.RequestMeta.Country.Mode = "header"
	if err := ValidateRequestCountryRuntimeConfig(cfg); err != nil {
		t.Fatalf("ValidateRequestCountryRuntimeConfig() error: %v", err)
	}
}

func TestValidateRequestCountryRuntimeConfigRejectsMMDBWithoutInstalledDB(t *testing.T) {
	initConfigDBStoreForTest(t)

	cfg := loadTestAppConfig(t)
	cfg.RequestMeta.Country.Mode = "mmdb"
	err := ValidateRequestCountryRuntimeConfig(cfg)
	if err == nil {
		t.Fatal("expected error for missing managed mmdb")
	}
	if !strings.Contains(err.Error(), managedRequestCountryMMDBPath()) {
		t.Fatalf("error=%q does not mention managed path %q", err, managedRequestCountryMMDBPath())
	}
}

func TestImportAppConfigStorageRejectsMMDBModeWithoutDBAsset(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)

	cfgPath := filepath.Join(dir, "config.json")
	raw := `{
  "storage": {
    "db_driver": "sqlite",
    "db_path": "db/tukuyomi.db",
    "db_dsn": "",
    "db_retention_days": 30,
    "db_sync_interval_sec": 0
  },
  "request_metadata": {
    "country": {
      "mode": "mmdb"
    }
  }
}
`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", filepath.Join(dir, "settings-store.db"), "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	assertNoActiveAppConfig := func(stage string) {
		t.Helper()
		if _, found, err := store.loadActiveConfigVersion(appConfigDomain); err != nil {
			t.Fatalf("%s: loadActiveConfigVersion: %v", stage, err)
		} else if found {
			t.Fatalf("%s: app_config should not be activated after failed mmdb validation", stage)
		}
	}

	if err := store.UpsertConfigBlob(appConfigBlobKey, []byte(raw), "", time.Unix(1, 0).UTC()); err != nil {
		t.Fatalf("UpsertConfigBlob: %v", err)
	}
	if _, _, _, err := loadAppConfigStorage(true); err == nil {
		t.Fatal("expected legacy app_config import to reject mmdb mode without DB asset")
	} else if !strings.Contains(err.Error(), requestCountryMMDBStorageLabel) {
		t.Fatalf("legacy error=%q does not mention %q", err, requestCountryMMDBStorageLabel)
	}
	assertNoActiveAppConfig("legacy")
	if _, _, found, err := store.GetConfigBlob(appConfigBlobKey); err != nil {
		t.Fatalf("GetConfigBlob: %v", err)
	} else if !found {
		t.Fatal("legacy app_config blob should remain after failed validation")
	}
	if err := store.DeleteConfigBlob(appConfigBlobKey); err != nil {
		t.Fatalf("DeleteConfigBlob: %v", err)
	}

	if _, _, _, err := loadAppConfigStorage(true); err == nil {
		t.Fatal("expected app_config bootstrap seed to reject mmdb mode without DB asset")
	} else if !strings.Contains(err.Error(), requestCountryMMDBStorageLabel) {
		t.Fatalf("seed error=%q does not mention %q", err, requestCountryMMDBStorageLabel)
	}
	assertNoActiveAppConfig("seed")

	if err := importRequestCountryStorage(); err != nil {
		t.Fatalf("importRequestCountryStorage: %v", err)
	}
	if err := importAppConfigStorage(); err == nil {
		t.Fatal("expected app_config import to reject mmdb mode without DB asset")
	} else if !strings.Contains(err.Error(), requestCountryMMDBStorageLabel) {
		t.Fatalf("import error=%q does not mention %q", err, requestCountryMMDBStorageLabel)
	}
	assertNoActiveAppConfig("import")
}

func TestValidateRequestCountryRuntimeConfigAcceptsMMDBWithDBAsset(t *testing.T) {
	cfg := loadTestAppConfig(t)
	cfg.RequestMeta.Country.Mode = "mmdb"

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	if _, _, err := store.writeRequestCountryMMDBAssetVersion("", requestCountryMMDBAssetVersion{
		Present: true,
		Raw:     loadSampleCountryMMDBBytes(t),
	}, configVersionSourceApply, "", "test mmdb", 0); err != nil {
		t.Fatalf("writeRequestCountryMMDBAssetVersion: %v", err)
	}

	if err := ValidateRequestCountryRuntimeConfig(cfg); err != nil {
		t.Fatalf("ValidateRequestCountryRuntimeConfig() error: %v", err)
	}
}

func TestReplaceManagedCountryMMDBRawRequiresDBStoreWithoutFileFallback(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	err := replaceManagedCountryMMDBRaw(loadSampleCountryMMDBBytes(t), configVersionSourceApply, "test mmdb upload")
	if !errors.Is(err, errConfigDBStoreRequired) {
		t.Fatalf("error=%v want %v", err, errConfigDBStoreRequired)
	}
	if _, statErr := os.Stat(managedRequestCountryMMDBPath()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("managed mmdb file should not be written without DB store, stat err=%v", statErr)
	}
}

func TestDeleteRequestCountryDBRejectsWhenModeIsMMDB(t *testing.T) {
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "mmdb"
	defer func() { config.RequestCountryMode = prevMode }()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodDelete, "/tukuyomi-api/request-country-db", nil)

	DeleteRequestCountryDB(ctx)
	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusConflict, rec.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &payload); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if got := payload["error"]; got == nil {
		t.Fatalf("missing error payload: %#v", payload)
	}
}

func TestPutRequestCountryModeRequiresIfMatch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/request-country-mode", bytes.NewBufferString(`{"mode":"header"}`))
	req.Header.Set("Content-Type", "application/json")
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	PutRequestCountryMode(ctx)

	if rec.Code != http.StatusPreconditionRequired {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusPreconditionRequired, rec.Body.String())
	}
}

func TestPutRequestCountryModePersistsNormalizedHeaderMode(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfgPath := writeSettingsConfigFixture(t)
	cfg, err := config.LoadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadAppConfigFile() error: %v", err)
	}
	cfg.RequestMeta.Country.Mode = "HEADER"
	raw, err := config.MarshalAppConfigFile(cfg)
	if err != nil {
		t.Fatalf("MarshalAppConfigFile() error: %v", err)
	}
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("rewrite config fixture: %v", err)
	}
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)

	currentRaw, etag, _, err := loadSettingsAppConfig()
	if err != nil {
		t.Fatalf("loadSettingsAppConfig() error: %v", err)
	}
	if etag == "" || currentRaw == "" {
		t.Fatalf("settings seed missing etag/raw")
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/request-country-mode", bytes.NewBufferString(`{"mode":"header"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = req

	PutRequestCountryMode(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	saved, err := loadSettingsAppConfigOnly()
	if err != nil {
		t.Fatalf("reload saved config: %v", err)
	}
	if got, want := strings.ToLower(strings.TrimSpace(saved.RequestMeta.Country.Mode)), "header"; got != want {
		t.Fatalf("saved request country mode=%q want=%q", got, want)
	}

	var out requestCountryDBStatusResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.ConfigETag == "" {
		t.Fatal("expected config etag in response")
	}
	if got, want := out.ConfiguredMode, "header"; got != want {
		t.Fatalf("configured_mode=%q want=%q", got, want)
	}
}
