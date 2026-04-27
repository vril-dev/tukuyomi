package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestProxyRuleAdminEndpointsUseNormalizedPaths(t *testing.T) {
	got := proxyRuleAdminEndpoints("/tukuyomi-api")
	want := []string{
		"/tukuyomi-api/proxy-rules",
		"/tukuyomi-api/proxy-rules/audit",
		"/tukuyomi-api/proxy-rules/validate",
		"/tukuyomi-api/proxy-rules/probe",
		"/tukuyomi-api/proxy-rules/dry-run",
		"/tukuyomi-api/proxy-rules/rollback-preview",
		"/tukuyomi-api/proxy-rules/rollback",
	}
	if len(got) != len(want) {
		t.Fatalf("endpoints=%d want=%d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("endpoint[%d]=%q want=%q", i, got[i], want[i])
		}
	}
}

func TestRegisterProxyRuleAdminRoutesDoesNotExposeLegacyColonPaths(t *testing.T) {
	gin.SetMode(gin.TestMode)

	r := gin.New()
	api := r.Group("/tukuyomi-api")

	func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				t.Fatalf("registerProxyRuleAdminRoutes panicked: %v", recovered)
			}
		}()
		registerProxyRuleAdminRoutes(api)
	}()

	routes := map[string]struct{}{}
	for _, route := range r.Routes() {
		routes[route.Method+" "+route.Path] = struct{}{}
	}

	for _, want := range []string{
		"GET /tukuyomi-api/proxy-rules",
		"GET /tukuyomi-api/proxy-rules/audit",
		"POST /tukuyomi-api/proxy-rules/validate",
		"POST /tukuyomi-api/proxy-rules/probe",
		"POST /tukuyomi-api/proxy-rules/dry-run",
		"GET /tukuyomi-api/proxy-rules/rollback-preview",
		"POST /tukuyomi-api/proxy-rules/rollback",
		"PUT /tukuyomi-api/proxy-rules",
	} {
		if _, ok := routes[want]; !ok {
			t.Fatalf("missing route %s", want)
		}
	}

	for _, legacy := range []string{
		"GET /tukuyomi-api/proxy-rules:audit",
		"POST /tukuyomi-api/proxy-rules:validate",
		"POST /tukuyomi-api/proxy-rules:probe",
		"POST /tukuyomi-api/proxy-rules:dry-run",
		"GET /tukuyomi-api/proxy-rules:rollback-preview",
		"POST /tukuyomi-api/proxy-rules:rollback",
		"POST /tukuyomi-api/proxy-rules:action",
	} {
		if _, ok := routes[legacy]; ok {
			t.Fatalf("unexpected legacy route %s", legacy)
		}
	}
}

func TestNewBaseEngineDisablesFrameworkRequestLogByDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldWriter := gin.DefaultWriter
	oldRequestLogEnabled := config.RequestLogEnabled
	defer func() {
		gin.DefaultWriter = oldWriter
		config.RequestLogEnabled = oldRequestLogEnabled
	}()

	var logBuffer bytes.Buffer
	gin.DefaultWriter = &logBuffer
	config.RequestLogEnabled = false

	r, err := newBaseEngine(nil)
	if err != nil {
		t.Fatalf("newBaseEngine() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}
	if got := logBuffer.String(); got != "" {
		t.Fatalf("framework request log=%q want empty by default", got)
	}
}

func TestNewBaseEngineCanEnableFrameworkRequestLog(t *testing.T) {
	gin.SetMode(gin.TestMode)
	oldWriter := gin.DefaultWriter
	oldRequestLogEnabled := config.RequestLogEnabled
	defer func() {
		gin.DefaultWriter = oldWriter
		config.RequestLogEnabled = oldRequestLogEnabled
	}()

	var logBuffer bytes.Buffer
	gin.DefaultWriter = &logBuffer
	config.RequestLogEnabled = true

	r, err := newBaseEngine(nil)
	if err != nil {
		t.Fatalf("newBaseEngine() error = %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}
	if got := logBuffer.String(); !strings.Contains(got, "/healthz") {
		t.Fatalf("framework request log=%q want /healthz", got)
	}
}
