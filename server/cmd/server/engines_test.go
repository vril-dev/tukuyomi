package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/middleware"
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
	config.AdminTrustedCIDRs = []string{"127.0.0.1/32", "::1/128", "198.51.100.10/32"}
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
		req.RemoteAddr = "203.0.113.25:45678"
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

func TestPublicHandlerRejectsExcessRequestHeadersBeforeConcurrencyGuards(t *testing.T) {
	restore := saveListenerConfigForTest()
	defer restore()
	prevMaxHeaderCount := config.ServerMaxHeaderCount
	config.ServerMaxHeaderCount = 4
	defer func() { config.ServerMaxHeaderCount = prevMaxHeaderCount }()

	for _, tc := range []struct {
		name  string
		build func(*middleware.ConcurrencyGuard) (http.Handler, error)
	}{
		{name: "global", build: func(g *middleware.ConcurrencyGuard) (http.Handler, error) { return buildPublicHandler(g, nil, false) }},
		{name: "proxy", build: func(g *middleware.ConcurrencyGuard) (http.Handler, error) { return buildPublicHandler(nil, g, false) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A full guard: any request that reaches it gets 503.
			guard := middleware.NewConcurrencyGuard(1, tc.name)
			if held := guard.AcquireContext(context.Background()); !held.Allowed {
				t.Fatalf("could not fill the %s concurrency guard", tc.name)
			}
			defer guard.Release()
			publicHandler, err := tc.build(guard)
			if err != nil {
				t.Fatalf("buildPublicHandler error = %v", err)
			}
			assertHeaderLimitBeforeGuard(t, publicHandler)
		})
	}
}

func assertHeaderLimitBeforeGuard(t *testing.T, publicHandler http.Handler) {
	t.Helper()
	newRequest := func(values int) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/app", nil)
		req.RemoteAddr = "198.51.100.7:40000"
		for i := 0; i < values; i++ {
			req.Header.Add("X-Repeat", "v")
		}
		return req
	}

	rec := httptest.NewRecorder()
	publicHandler.ServeHTTP(rec, newRequest(4))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("at the limit: status=%d want=%d (reaches the guard) body=%s", rec.Code, http.StatusServiceUnavailable, rec.Body.String())
	}

	rec = httptest.NewRecorder()
	publicHandler.ServeHTTP(rec, newRequest(5))
	if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Fatalf("over the limit: status=%d want=%d body=%s", rec.Code, http.StatusRequestHeaderFieldsTooLarge, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "request header fields too large") {
		t.Fatalf("over the limit: body=%s", rec.Body.String())
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
