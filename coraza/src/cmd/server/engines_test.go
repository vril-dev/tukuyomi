package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"tukuyomi/internal/config"
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
	prevAPICORSOrigins := append([]string(nil), config.APICORSOrigins...)

	config.APIBasePath = "/tukuyomi-api"
	config.UIBasePath = "/tukuyomi-ui"
	config.APIAuthDisable = false
	config.APICORSOrigins = nil

	return func() {
		config.APIBasePath = prevAPIBasePath
		config.UIBasePath = prevUIBasePath
		config.APIAuthDisable = prevAPIAuthDisable
		config.APICORSOrigins = prevAPICORSOrigins
	}
}
