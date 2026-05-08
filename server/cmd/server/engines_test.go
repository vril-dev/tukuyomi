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

func TestBuildPublicHandlerSingleListenerDeniesUntrustedAdminSurface(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	config.AdminExternalMode = "deny_external"
	config.AdminTrustedCIDRs = []string{"127.0.0.1/32", "::1/128", "219.104.164.92/32"}
	config.AdminTrustForwardedFor = false
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	publicHandler, err := buildPublicHandler(nil, nil, false)
	if err != nil {
		t.Fatalf("buildPublicHandler(single) error = %v", err)
	}

	for _, path := range []string{
		config.UIBasePath + "/login",
		config.APIBasePath + "/auth/session",
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.RemoteAddr = "122.100.25.195:45678"
		publicHandler.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Fatalf("path=%q status=%d want=%d body=%s", path, rec.Code, http.StatusForbidden, rec.Body.String())
		}
	}
}

func TestBuildPublicHandlerSingleListenerClearsResponseCacheStore(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()
	config.APIAuthDisable = true

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

func TestBuildAdminEngineExposesRuntimeAppsWithoutVhostsAlias(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()

	adminEngine, err := buildAdminEngine(nil)
	if err != nil {
		t.Fatalf("buildAdminEngine() error = %v", err)
	}

	routes := map[string]struct{}{}
	for _, route := range adminEngine.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}
	for _, want := range []string{
		"GET " + config.APIBasePath + "/runtime-apps",
		"POST " + config.APIBasePath + "/runtime-apps/validate",
		"PUT " + config.APIBasePath + "/runtime-apps",
		"POST " + config.APIBasePath + "/runtime-apps/rollback",
	} {
		if _, ok := routes[want]; !ok {
			t.Fatalf("missing route %s", want)
		}
	}
	for _, legacy := range []string{
		"GET " + config.APIBasePath + "/vhosts",
		"POST " + config.APIBasePath + "/vhosts/validate",
		"PUT " + config.APIBasePath + "/vhosts",
		"POST " + config.APIBasePath + "/vhosts/rollback",
	} {
		if _, ok := routes[legacy]; ok {
			t.Fatalf("unexpected legacy route %s", legacy)
		}
	}
}

func saveListenerConfigForTest() func() {
	prevAPIBasePath := config.APIBasePath
	prevUIBasePath := config.UIBasePath
	prevAPIAuthDisable := config.APIAuthDisable
	prevAPICORSOrigins := append([]string(nil), config.APICORSOrigins...)
	prevAdminExternalMode := config.AdminExternalMode
	prevAdminTrustedCIDRs := append([]string(nil), config.AdminTrustedCIDRs...)
	prevAdminTrustForwardedFor := config.AdminTrustForwardedFor

	config.APIBasePath = "/tukuyomi-api"
	config.UIBasePath = "/tukuyomi-ui"
	config.APIAuthDisable = false
	config.APICORSOrigins = nil
	config.AdminExternalMode = "full_external"
	config.AdminTrustedCIDRs = nil
	config.AdminTrustForwardedFor = false
	_ = handler.InitAdminGuards()

	return func() {
		config.APIBasePath = prevAPIBasePath
		config.UIBasePath = prevUIBasePath
		config.APIAuthDisable = prevAPIAuthDisable
		config.APICORSOrigins = prevAPICORSOrigins
		config.AdminExternalMode = prevAdminExternalMode
		config.AdminTrustedCIDRs = prevAdminTrustedCIDRs
		config.AdminTrustForwardedFor = prevAdminTrustForwardedFor
		_ = handler.InitAdminGuards()
	}
}
