package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestBuildPublicEngineSingleListenerKeepsAdminRoutes(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	publicEngine, err := buildPublicEngine(nil, nil, false)
	if err != nil {
		t.Fatalf("buildPublicEngine(single) error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	publicEngine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestBuildPublicHandlerSingleListenerKeepsAdminRoutes(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	publicHandler, err := buildPublicHandler(nil, nil, false)
	if err != nil {
		t.Fatalf("buildPublicHandler(single) error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	publicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestBuildPublicHandlerSingleListenerClearsResponseCacheStore(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	t.Chdir(t.TempDir())
	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{"enabled":false,"store_dir":"cache/response","max_bytes":1048576}`), 0o600); err != nil {
		t.Fatalf("write cache store config: %v", err)
	}
	if err := handler.InitResponseCacheRuntime(cacheStoreCfgPath); err != nil {
		t.Fatalf("init response cache runtime: %v", err)
	}

	publicHandler, err := buildPublicHandler(nil, nil, false)
	if err != nil {
		t.Fatalf("buildPublicHandler(single) error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/cache-store/clear", strings.NewReader(`{}`))
	req.RemoteAddr = "127.0.0.1:12345"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-API-Key", config.APIKeyPrimary)
	publicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"ok":true`) {
		t.Fatalf("response body missing ok=true: %s", rec.Body.String())
	}
}

func TestBuildPublicEngineSplitListenerReturns404ForAdminRoutes(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	publicEngine, err := buildPublicEngine(nil, nil, true)
	if err != nil {
		t.Fatalf("buildPublicEngine(split) error = %v", err)
	}

	for _, path := range []string{
		config.APIBasePath + "/auth/session",
		config.UIBasePath,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		publicEngine.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("path=%q status=%d want=%d body=%s", path, rec.Code, http.StatusNotFound, rec.Body.String())
		}
	}
}

func TestBuildPublicHandlerSplitListenerReturns404ForAdminRoutes(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	publicHandler, err := buildPublicHandler(nil, nil, true)
	if err != nil {
		t.Fatalf("buildPublicHandler(split) error = %v", err)
	}

	for _, path := range []string{
		config.APIBasePath + "/auth/session",
		config.UIBasePath,
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "127.0.0.1:12345"
		publicHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusNotFound {
			t.Fatalf("path=%q status=%d want=%d body=%s", path, rec.Code, http.StatusNotFound, rec.Body.String())
		}
	}
}

func TestBuildPublicHandlerKeepsHealthzOnPublicListener(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	publicHandler, err := buildPublicHandler(nil, nil, true)
	if err != nil {
		t.Fatalf("buildPublicHandler(split) error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	publicHandler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func TestBuildAdminEngineDoesNotProxyPublicTraffic(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	adminEngine, err := buildAdminEngine(nil)
	if err != nil {
		t.Fatalf("buildAdminEngine() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/public-proxy-target", nil)
	adminEngine.ServeHTTP(rec, req)

	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusNotFound, rec.Body.String())
	}
}

func TestBuildAdminEngineExposesAdminRoutes(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	adminEngine, err := buildAdminEngine(nil)
	if err != nil {
		t.Fatalf("buildAdminEngine() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	adminEngine.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
}

func saveListenerConfigForTest() func() {
	prevAPIBasePath := config.APIBasePath
	prevUIBasePath := config.UIBasePath
	prevAPIAuthDisable := config.APIAuthDisable
	prevAPIKeyPrimary := config.APIKeyPrimary
	prevAPIKeySecondary := config.APIKeySecondary
	prevAPICORSOrigins := append([]string(nil), config.APICORSOrigins...)

	config.APIBasePath = "/tukuyomi-api"
	config.UIBasePath = "/tukuyomi-ui"
	config.APIAuthDisable = false
	config.APIKeyPrimary = "test-admin-key-123456"
	config.APIKeySecondary = ""
	config.APICORSOrigins = nil

	return func() {
		config.APIBasePath = prevAPIBasePath
		config.UIBasePath = prevUIBasePath
		config.APIAuthDisable = prevAPIAuthDisable
		config.APIKeyPrimary = prevAPIKeyPrimary
		config.APIKeySecondary = prevAPIKeySecondary
		config.APICORSOrigins = prevAPICORSOrigins
	}
}
