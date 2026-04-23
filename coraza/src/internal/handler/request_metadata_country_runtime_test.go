package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
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
	if etag != bypassconf.ComputeETag([]byte(currentRaw)) {
		t.Fatalf("settings etag mismatch")
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
