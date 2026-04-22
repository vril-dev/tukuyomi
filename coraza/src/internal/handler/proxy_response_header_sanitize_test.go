package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateProxyRulesRawNormalizesResponseHeaderSanitizeConfig(t *testing.T) {
	cfg, err := ValidateProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "response_header_sanitize": {
    "mode": " AUTO ",
    "custom_remove": [" x-powered-by ", "Server", " server "],
    "custom_keep": [" x-envoy-internal ", "Server", "x-envoy-internal"],
    "debug_log": true
  }
}`)
	if err != nil {
		t.Fatalf("ValidateProxyRulesRaw: %v", err)
	}
	if cfg.ResponseHeaderSanitize.Mode != proxyResponseHeaderSanitizeModeAuto {
		t.Fatalf("mode=%q", cfg.ResponseHeaderSanitize.Mode)
	}
	if got := strings.Join(cfg.ResponseHeaderSanitize.CustomRemove, ","); got != "Server,X-Powered-By" {
		t.Fatalf("custom_remove=%q", got)
	}
	if got := strings.Join(cfg.ResponseHeaderSanitize.CustomKeep, ","); got != "Server,X-Envoy-Internal" {
		t.Fatalf("custom_keep=%q", got)
	}
	if !cfg.ResponseHeaderSanitize.DebugLog {
		t.Fatal("debug_log should be true")
	}
	if _, ok := cfg.responseHeaderSanitizePolicy.RemoveSet["Server"]; !ok {
		t.Fatal("custom_remove should win over custom_keep")
	}
	if _, ok := cfg.responseHeaderSanitizePolicy.RemoveSet["X-Envoy-Internal"]; ok {
		t.Fatal("custom_keep should exempt default auto removals")
	}
	if _, ok := cfg.responseHeaderSanitizePolicy.RemoveSet["X-Powered-By"]; !ok {
		t.Fatal("embedded default list should remove X-Powered-By")
	}
}

func TestValidateProxyRulesRawRejectsInvalidResponseHeaderSanitizeConfig(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name: "unknown mode",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "response_header_sanitize": { "mode": "sometimes" }
}`,
			wantErr: "response_header_sanitize.mode must be one of auto|manual|off",
		},
		{
			name: "blank custom remove entry",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "response_header_sanitize": { "custom_remove": ["   "] }
}`,
			wantErr: "response_header_sanitize.custom_remove must not contain blank header names",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := ValidateProxyRulesRaw(tt.raw); err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%v want substring %q", err, tt.wantErr)
			}
		})
	}
}

func TestBuildProxyResponseHeaderSanitizePolicyModes(t *testing.T) {
	autoPolicy := buildProxyResponseHeaderSanitizePolicy(normalizeProxyResponseHeaderSanitizeConfig(ProxyResponseHeaderSanitizeConfig{
		Mode:         proxyResponseHeaderSanitizeModeAuto,
		CustomKeep:   []string{"Server"},
		CustomRemove: []string{"X-Test-Leak"},
	}))
	if _, ok := autoPolicy.RemoveSet["Server"]; ok {
		t.Fatal("custom_keep should remove Server from auto mode default set")
	}
	if _, ok := autoPolicy.RemoveSet["X-Test-Leak"]; !ok {
		t.Fatal("custom_remove should be added in auto mode")
	}
	if _, ok := autoPolicy.RemoveSet["X-Powered-By"]; !ok {
		t.Fatal("embedded default set should be active in auto mode")
	}

	manualPolicy := buildProxyResponseHeaderSanitizePolicy(normalizeProxyResponseHeaderSanitizeConfig(ProxyResponseHeaderSanitizeConfig{
		Mode:         proxyResponseHeaderSanitizeModeManual,
		CustomKeep:   []string{"Server"},
		CustomRemove: []string{"X-Test-Leak"},
	}))
	if len(manualPolicy.RemoveSet) != 1 {
		t.Fatalf("manual remove count=%d want=1", len(manualPolicy.RemoveSet))
	}
	if _, ok := manualPolicy.RemoveSet["X-Test-Leak"]; !ok {
		t.Fatal("manual mode should remove custom_remove only")
	}
	if _, ok := manualPolicy.RemoveSet["X-Powered-By"]; ok {
		t.Fatal("manual mode should ignore embedded default set")
	}

	offPolicy := buildProxyResponseHeaderSanitizePolicy(normalizeProxyResponseHeaderSanitizeConfig(ProxyResponseHeaderSanitizeConfig{
		Mode:         proxyResponseHeaderSanitizeModeOff,
		CustomRemove: []string{"X-Test-Leak"},
		CustomKeep:   []string{"X-Powered-By"},
	}))
	if len(offPolicy.RemoveSet) != 1 {
		t.Fatalf("off remove count=%d want=1", len(offPolicy.RemoveSet))
	}
	if _, ok := offPolicy.RemoveSet["X-Test-Leak"]; !ok {
		t.Fatal("off mode should still apply custom_remove")
	}
	if _, ok := offPolicy.RemoveSet["X-Powered-By"]; ok {
		t.Fatal("off mode should ignore custom_keep and embedded defaults")
	}
}

func TestPlanProxyResponseHeaderProcessing(t *testing.T) {
	offPolicy := buildProxyResponseHeaderSanitizePolicy(normalizeProxyResponseHeaderSanitizeConfig(ProxyResponseHeaderSanitizeConfig{
		Mode: proxyResponseHeaderSanitizeModeOff,
	}))
	liveOff := planProxyResponseHeaderProcessing(proxyResponseHeaderPolicySurfaceLive, offPolicy)
	if liveOff.NeedsHeaderIteration() {
		t.Fatal("live off mode without custom_remove should skip header iteration")
	}

	cacheOff := planProxyResponseHeaderProcessing(proxyResponseHeaderPolicySurfaceCacheReplay, offPolicy)
	if !cacheOff.NeedsHeaderIteration() {
		t.Fatal("cache replay should still require header iteration for hard safety")
	}
	if !cacheOff.HardSafety {
		t.Fatal("cache replay should keep hard safety enabled")
	}

	offCustomRemove := buildProxyResponseHeaderSanitizePolicy(normalizeProxyResponseHeaderSanitizeConfig(ProxyResponseHeaderSanitizeConfig{
		Mode:         proxyResponseHeaderSanitizeModeOff,
		CustomRemove: []string{"X-Test-Leak"},
	}))
	liveOffCustomRemove := planProxyResponseHeaderProcessing(proxyResponseHeaderPolicySurfaceLive, offCustomRemove)
	if !liveOffCustomRemove.NeedsHeaderIteration() {
		t.Fatal("live off mode with custom_remove should still require feature sanitize work")
	}
	if !liveOffCustomRemove.FeatureSanitize {
		t.Fatal("live off mode with custom_remove should flag feature sanitize work")
	}
}

func TestSanitizeProxyCachedResponseHeaderKeepsHardSafetyWhenFeatureLayerIsOff(t *testing.T) {
	rt := &proxyRuntime{
		cfg: normalizeProxyRulesConfig(ProxyRulesConfig{
			Upstreams: []ProxyUpstream{{
				Name:    "primary",
				URL:     "http://127.0.0.1:8080",
				Weight:  1,
				Enabled: true,
			}},
			ResponseHeaderSanitize: ProxyResponseHeaderSanitizeConfig{
				Mode: proxyResponseHeaderSanitizeModeOff,
			},
		}),
	}
	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = rt
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	out := sanitizeProxyCachedResponseHeader(http.Header{
		"Date":             {"Mon, 01 Apr 2026 00:00:00 GMT"},
		"Server":           {"origin"},
		"Set-Cookie":       {"a=b"},
		"Content-Type":     {"text/plain"},
		"X-Powered-By":     {"php"},
		"X-Tukuyomi-Cache": {"MISS"},
	}, nil, proxyResponseHeaderPolicySurfaceCacheReplay)

	if got := out.Get("Date"); got != "" {
		t.Fatalf("date=%q", got)
	}
	if got := out.Get("Set-Cookie"); got != "" {
		t.Fatalf("set-cookie=%q", got)
	}
	if got := out.Get("X-Tukuyomi-Cache"); got != "" {
		t.Fatalf("x-tukuyomi-cache=%q", got)
	}
	if got := out.Get("Server"); got != "origin" {
		t.Fatalf("server=%q", got)
	}
	if got := out.Get("X-Powered-By"); got != "php" {
		t.Fatalf("x-powered-by=%q", got)
	}
}

func TestProxyResponseSanitizeWriterStripsDefaultHeaders(t *testing.T) {
	cfg := normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{{
			Name:    "primary",
			URL:     "http://127.0.0.1:8080",
			Weight:  1,
			Enabled: true,
		}},
		ResponseHeaderSanitize: ProxyResponseHeaderSanitizeConfig{
			Mode: proxyResponseHeaderSanitizeModeAuto,
		},
	})
	rt := &proxyRuntime{effectiveCfg: cfg}
	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = rt
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	rec := httptest.NewRecorder()
	rec.Header().Set("Server", "origin")
	rec.Header().Set("X-Powered-By", "php")
	rec.Header().Set("Content-Type", "text/plain")

	w := wrapProxyResponseSanitizeWriter(rec, req)
	w.WriteHeader(http.StatusOK)

	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("Server=%q want empty", got)
	}
	if got := rec.Header().Get("X-Powered-By"); got != "" {
		t.Fatalf("X-Powered-By=%q want empty", got)
	}
	if got := rec.Header().Get("Content-Type"); got == "" {
		t.Fatal("Content-Type should remain")
	}
}

func TestFilterProxyResponseHeadersLogsConfiguredRemovalsWithoutValues(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/app", nil)
	req.RemoteAddr = "203.0.113.7:44321"
	req = req.WithContext(withProxyRouteDecision(req.Context(), proxyRouteDecision{
		RouteName:           "service-a",
		SelectedUpstream:    "primary",
		SelectedUpstreamURL: "http://app.internal:8080",
	}))

	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	filtered := filterProxyResponseHeaders(http.Header{
		"server":       {"nginx"},
		"x-powered-by": {"php"},
		"content-type": {"text/plain"},
	}, proxyResponseHeaderSanitizePolicy{
		Mode:      proxyResponseHeaderSanitizeModeAuto,
		DebugLog:  true,
		RemoveSet: proxyResponseHeaderNameSet("Server", "X-Powered-By"),
	}, proxyResponseHeaderFilterOptions{
		Request: req,
		Surface: "live_proxy_response",
	})

	if got := filtered.Header.Get("Content-Type"); got != "text/plain" {
		t.Fatalf("content-type=%q", got)
	}
	if got := filtered.Header.Get("Server"); got != "" {
		t.Fatalf("server=%q", got)
	}
	if got := strings.Join(filtered.PolicyRemoved, ","); got != "Server,X-Powered-By" {
		t.Fatalf("removed=%q", got)
	}

	logOutput := buf.String()
	if !strings.Contains(logOutput, `"event":"proxy_response_header_sanitize"`) {
		t.Fatalf("missing sanitize log: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"mode":"auto"`) {
		t.Fatalf("missing mode in log: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"path":"/app"`) {
		t.Fatalf("missing path in log: %s", logOutput)
	}
	if !strings.Contains(logOutput, `"removed_headers":["Server","X-Powered-By"]`) {
		t.Fatalf("missing removed header names: %s", logOutput)
	}
	if strings.Contains(logOutput, "nginx") || strings.Contains(logOutput, "php") {
		t.Fatalf("log should not include header values: %s", logOutput)
	}
}
