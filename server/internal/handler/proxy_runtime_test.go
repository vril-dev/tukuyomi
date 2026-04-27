package handler

import (
	"bytes"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/proxyaccesslog"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestValidateProxyRulesRaw(t *testing.T) {
	good := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 200,
  "force_http2": false,
  "disable_compression": false,
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/healthz",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}`

	cfg, err := ValidateProxyRulesRaw(good)
	if err != nil {
		t.Fatalf("ValidateProxyRulesRaw(good): %v", err)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].URL != "http://127.0.0.1:8080" {
		t.Fatalf("unexpected upstreams: %#v", cfg.Upstreams)
	}
	if cfg.UpstreamKeepAliveSec != defaultProxyUpstreamKeepAliveSec {
		t.Fatalf("upstream_keepalive_sec=%d want=%d", cfg.UpstreamKeepAliveSec, defaultProxyUpstreamKeepAliveSec)
	}
	if cfg.ErrorHTMLFile != "" || cfg.ErrorRedirectURL != "" {
		t.Fatalf("unexpected default proxy error config: %#v", cfg)
	}
	if cfg.EmitUpstreamNameRequestHeader {
		t.Fatal("emit_upstream_name_request_header should default to false")
	}
	if cfg.AccessLogMode != proxyaccesslog.ModeFull {
		t.Fatalf("access_log_mode=%q want %q", cfg.AccessLogMode, proxyaccesslog.ModeFull)
	}

	bad := strings.Replace(good, "http://127.0.0.1:8080", "ftp://127.0.0.1:8080", 1)
	if _, err := ValidateProxyRulesRaw(bad); err == nil {
		t.Fatal("expected invalid scheme error")
	}

	badPath := strings.Replace(good, `"/healthz"`, `"healthz"`, 1)
	if _, err := ValidateProxyRulesRaw(badPath); err != nil {
		t.Fatalf("health_check_path should be normalized: %v", err)
	}

	tlsBad := strings.Replace(good, `"tls_client_cert": ""`, `"tls_client_cert": "/tmp/cert.pem"`, 1)
	if _, err := ValidateProxyRulesRaw(tlsBad); err == nil {
		t.Fatal("expected mTLS pair validation error")
	}

	badRedirect := strings.Replace(good, `"health_check_timeout_sec": 2`, `"health_check_timeout_sec": 2, "error_redirect_url": "maintenance"`, 1)
	if _, err := ValidateProxyRulesRaw(badRedirect); err == nil {
		t.Fatal("expected error_redirect_url validation error")
	}

	badKeepAlive := strings.Replace(good, `"idle_conn_timeout": 90,`, "\"idle_conn_timeout\": 90,\n  \"upstream_keepalive_sec\": -1,", 1)
	if _, err := ValidateProxyRulesRaw(badKeepAlive); err == nil {
		t.Fatal("expected upstream_keepalive_sec validation error")
	}

	badAccessLogMode := strings.Replace(good, `"flush_interval_ms": 0,`, `"flush_interval_ms": 0, "access_log_mode": "verbose",`, 1)
	if _, err := ValidateProxyRulesRaw(badAccessLogMode); err == nil {
		t.Fatal("expected access_log_mode validation error")
	}
}

func TestValidateProxyRulesRawRejectsMissingErrorHTMLFile(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "error_html_file": "/does/not/exist.html"
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected missing error_html_file validation error")
	}
}

func TestProxyUpstreamKeepAliveDuration(t *testing.T) {
	if got := proxyUpstreamKeepAliveDuration(ProxyRulesConfig{}); got != defaultProxyUpstreamKeepAliveSec*time.Second {
		t.Fatalf("default keepalive=%s want=%s", got, defaultProxyUpstreamKeepAliveSec*time.Second)
	}
	if got := proxyUpstreamKeepAliveDuration(ProxyRulesConfig{UpstreamKeepAliveSec: 45}); got != 45*time.Second {
		t.Fatalf("configured keepalive=%s want=45s", got)
	}
}

func TestValidateProxyRulesRawRejectsErrorHTMLAndRedirectTogether(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "error_html_file": "/tmp/maintenance.html",
  "error_redirect_url": "/maintenance"
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected mutually exclusive proxy error config validation error")
	}
}

func TestValidateProxyRulesRawRejectsMixedH2CUpstreams(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "https://127.0.0.1:8443", "weight": 1, "enabled": true }
  ],
  "h2c_upstream": true
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected mixed h2c validation error")
	}
}

func TestValidateProxyRulesRawRejectsH2CWithMTLS(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "h2c_upstream": true,
  "tls_client_cert": "/tmp/client.crt",
  "tls_client_key": "/tmp/client.key"
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected h2c + mtls validation error")
	}
}

func TestValidateProxyRulesRawAllowsH2CWhenDisabledHTTPSUpstreamExists(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "enabled": true },
    { "name": "standby", "url": "https://127.0.0.1:8443", "enabled": false }
  ],
  "h2c_upstream": true
}`
	if _, err := ValidateProxyRulesRaw(raw); err != nil {
		t.Fatalf("expected disabled https upstream to be ignored: %v", err)
	}
}

func TestValidateProxyRulesRawAllowsEmptyConfig(t *testing.T) {
	cfg, err := ValidateProxyRulesRaw(`{}`)
	if err != nil {
		t.Fatalf("ValidateProxyRulesRaw(empty): %v", err)
	}
	if len(cfg.Upstreams) != 0 {
		t.Fatalf("upstreams=%#v", cfg.Upstreams)
	}
	if cfg.DefaultRoute != nil {
		t.Fatalf("default_route=%#v want=nil", cfg.DefaultRoute)
	}
}

func TestInitProxyRuntimeAllowsEmptyConfigButRouteResolutionFails(t *testing.T) {
	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(proxyPath, []byte("{}\n"), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}

	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime(empty): %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	if _, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth()); err == nil {
		t.Fatal("expected missing proxy target error")
	} else if !strings.Contains(err.Error(), "no proxy targets available") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestProxyRulesApplyAndRollback(t *testing.T) {
	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 200,
  "force_http2": false,
  "disable_compression": false,
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, initial)

	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, etag, cfg, _, depth := ProxyRulesSnapshot()
	if etag == "" {
		t.Fatal("etag should not be empty")
	}
	if depth != 0 {
		t.Fatalf("initial rollback depth=%d want=0", depth)
	}
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].URL != "http://127.0.0.1:8081" {
		t.Fatalf("initial upstreams=%#v", cfg.Upstreams)
	}

	next := strings.Replace(initial, "127.0.0.1:8081", "127.0.0.1:8082", 1)
	next = strings.Replace(next, `"force_http2": false`, `"force_http2": true`, 1)
	newETag, newCfg, err := ApplyProxyRulesRaw(etag, next)
	if err != nil {
		t.Fatalf("ApplyProxyRulesRaw: %v", err)
	}
	initialPrepared, err := prepareProxyRulesRaw(initial)
	if err != nil {
		t.Fatalf("prepareProxyRulesRaw(initial): %v", err)
	}
	if newETag == etag {
		t.Fatal("etag should change after update")
	}
	if !newCfg.ForceHTTP2 {
		t.Fatal("force_http2 should be true after apply")
	}
	if len(newCfg.Upstreams) != 1 || newCfg.Upstreams[0].URL != "http://127.0.0.1:8082" {
		t.Fatalf("updated upstreams=%#v", newCfg.Upstreams)
	}
	preview, err := ProxyRollbackPreview()
	if err != nil {
		t.Fatalf("ProxyRollbackPreview: %v", err)
	}
	if preview.Raw != initialPrepared.raw {
		t.Fatalf("preview raw mismatch: %q", preview.Raw)
	}
	if preview.ETag != etag {
		t.Fatalf("preview etag=%q want=%q", preview.ETag, etag)
	}
	_, _, _, _, depth = ProxyRulesSnapshot()
	if depth != 1 {
		t.Fatalf("preview should not consume rollback stack, depth=%d", depth)
	}

	if _, _, err := ApplyProxyRulesRaw("stale-etag", next); err == nil {
		t.Fatal("expected etag conflict")
	}

	rolledETag, rolledCfg, _, err := RollbackProxyRules()
	if err != nil {
		t.Fatalf("RollbackProxyRules: %v", err)
	}
	if rolledETag == "" {
		t.Fatal("rollback etag should not be empty")
	}
	if len(rolledCfg.Upstreams) != 1 || rolledCfg.Upstreams[0].URL != "http://127.0.0.1:8081" {
		t.Fatalf("rolled upstreams=%#v", rolledCfg.Upstreams)
	}
	if rolledCfg.ForceHTTP2 {
		t.Fatal("force_http2 should be false after rollback")
	}
	if _, err := ProxyRollbackPreview(); err == nil {
		t.Fatal("expected empty rollback preview after rollback consumed only snapshot")
	}
}

func TestProxyRulesApplyAndRollbackPersistNormalizedDB(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer func() {
		_ = InitLogsStatsStore(false, "", 0)
	}()

	proxyPath := filepath.Join(tmp, "proxy.json")
	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	importProxyRuntimeDBForTest(t, initial)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	active, rec, found, err := getLogsStatsStore().loadActiveProxyConfig()
	if err != nil {
		t.Fatalf("loadActiveProxyConfig: %v", err)
	}
	if !found {
		t.Fatal("normalized proxy config should be imported before startup")
	}
	if rec.Generation != 1 {
		t.Fatalf("generation=%d want 1", rec.Generation)
	}
	if len(active.Upstreams) != 1 || !strings.Contains(active.Upstreams[0].URL, "8081") {
		t.Fatalf("active upstreams after seed=%#v want 8081", active.Upstreams)
	}
	_, etag, _, _, _ := ProxyRulesSnapshot()
	next := strings.Replace(initial, "127.0.0.1:8081", "127.0.0.1:8082", 1)
	if _, _, err := ApplyProxyRulesRaw(etag, next); err != nil {
		t.Fatalf("ApplyProxyRulesRaw: %v", err)
	}
	active, rec, found, err = getLogsStatsStore().loadActiveProxyConfig()
	if err != nil {
		t.Fatalf("loadActiveProxyConfig after apply: %v", err)
	}
	if !found {
		t.Fatal("normalized proxy config should exist after apply")
	}
	if rec.Generation != 2 {
		t.Fatalf("generation=%d want 2", rec.Generation)
	}
	if len(active.Upstreams) != 1 || !strings.Contains(active.Upstreams[0].URL, "8082") {
		t.Fatalf("active upstreams after apply=%#v want 8082", active.Upstreams)
	}
	if _, _, _, err := RollbackProxyRules(); err != nil {
		t.Fatalf("RollbackProxyRules: %v", err)
	}
	active, rec, found, err = getLogsStatsStore().loadActiveProxyConfig()
	if err != nil {
		t.Fatalf("loadActiveProxyConfig after rollback: %v", err)
	}
	if !found {
		t.Fatal("normalized proxy config should exist after rollback")
	}
	if rec.Generation != 3 {
		t.Fatalf("generation=%d want 3", rec.Generation)
	}
	if rec.RestoredFromVersionID == 0 {
		t.Fatal("rollback generation should record restored_from_version_id")
	}
	if len(active.Upstreams) != 1 || !strings.Contains(active.Upstreams[0].URL, "8081") {
		t.Fatalf("active upstreams after rollback=%#v want 8081", active.Upstreams)
	}
}

func TestInitProxyRuntimeUsesDBBlobBeforeSeedFile(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer func() {
		_ = InitLogsStatsStore(false, "", 0)
	}()

	proxyPath := filepath.Join(tmp, "proxy.json")
	fileRaw := `{"upstreams":[{"name":"file","url":"http://127.0.0.1:8081","weight":1,"enabled":true}]}`
	dbRaw := `{"upstreams":[{"name":"db","url":"http://127.0.0.1:8082","weight":1,"enabled":true}]}`
	if err := os.WriteFile(proxyPath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write proxy seed: %v", err)
	}
	prepared, err := prepareProxyRulesRaw(dbRaw)
	if err != nil {
		t.Fatalf("prepare db raw: %v", err)
	}
	if err := getLogsStatsStore().UpsertConfigBlob(proxyRulesConfigBlobKey, []byte(prepared.raw), prepared.etag, time.Now().UTC()); err != nil {
		t.Fatalf("upsert proxy_rules: %v", err)
	}
	seedUpstreamRuntimeDBForTest(t, prepared.cfg)

	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, _, cfg, _, _ := ProxyRulesSnapshot()
	if len(cfg.Upstreams) != 1 || cfg.Upstreams[0].Name != "db" {
		t.Fatalf("upstreams=%#v want db blob", cfg.Upstreams)
	}
}

func TestProxyProbe(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
	}()

	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://` + ln.Addr().String() + `", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 200,
  "force_http2": false,
  "disable_compression": false,
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2
}`

	cfg, addr, latency, err := ProxyProbe(raw, "", 2*time.Second)
	if err != nil {
		t.Fatalf("ProxyProbe: %v", err)
	}
	if len(cfg.Upstreams) == 0 || cfg.Upstreams[0].URL == "" {
		t.Fatal("probe should return proxy config")
	}
	if addr == "" {
		t.Fatal("probe address should not be empty")
	}
	if latency < 0 {
		t.Fatalf("latency=%d", latency)
	}
}

func TestProxyProbeUsesDefaultRouteTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
	}()

	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": "http://%s", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 5,
  "response_header_timeout": 10,
  "idle_conn_timeout": 90,
  "max_idle_conns": 100,
  "max_idle_conns_per_host": 100,
  "max_conns_per_host": 200,
  "force_http2": false,
  "disable_compression": false,
  "expect_continue_timeout": 1,
  "tls_insecure_skip_verify": false,
  "tls_client_cert": "",
  "tls_client_key": "",
  "buffer_request_body": false,
  "max_response_buffer_bytes": 0,
  "flush_interval_ms": 0,
  "health_check_path": "/",
  "health_check_interval_sec": 15,
  "health_check_timeout_sec": 2,
  "default_route": {
    "name": "default",
    "enabled": true,
    "action": {
      "upstream": "primary"
    }
  }
}`, ln.Addr().String())

	cfg, addr, latency, err := ProxyProbe(raw, "", 2*time.Second)
	if err != nil {
		t.Fatalf("ProxyProbe: %v", err)
	}
	if cfg.DefaultRoute == nil || cfg.DefaultRoute.Action.Upstream != "primary" {
		t.Fatalf("probe should preserve default_route target: %#v", cfg.DefaultRoute)
	}
	if addr != ln.Addr().String() {
		t.Fatalf("probe addr=%q want=%q", addr, ln.Addr().String())
	}
	if latency < 0 {
		t.Fatalf("latency=%d", latency)
	}
}

func TestProxyProbeUsesNamedUpstreamTarget(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})}
	go func() {
		_ = srv.Serve(ln)
	}()
	defer func() {
		_ = srv.Close()
	}()

	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:18080", "weight": 1, "enabled": true },
    { "name": "target", "url": "http://%s", "weight": 1, "enabled": true }
  ]
}`, ln.Addr().String())

	_, addr, latency, err := ProxyProbe(raw, "target", 2*time.Second)
	if err != nil {
		t.Fatalf("ProxyProbe(target): %v", err)
	}
	if addr != ln.Addr().String() {
		t.Fatalf("probe addr=%q want=%q", addr, ln.Addr().String())
	}
	if latency < 0 {
		t.Fatalf("latency=%d", latency)
	}
}

func TestProxyProbeRejectsStaticUpstreamTargets(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "docs", "url": "static://docs-static", "weight": 1, "enabled": true }
  ]
}`

	_, addr, _, err := ProxyProbe(raw, "docs", 2*time.Second)
	if err == nil {
		t.Fatal("expected static probe error")
	}
	if !strings.Contains(err.Error(), "static upstream targets do not support network probing") {
		t.Fatalf("unexpected error: %v", err)
	}
	if addr != "static://docs-static" {
		t.Fatalf("probe addr=%q want=%q", addr, "static://docs-static")
	}
}

func TestProxyProbeSupportsFCGIUnixSocketTargets(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "php-fpm.sock")
	ln, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen unix: %v", err)
	}
	defer ln.Close()

	go func() {
		for {
			conn, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	raw := `{
  "upstreams": [
    { "name": "php", "url": "fcgi:///` + filepath.ToSlash(socketPath) + `", "weight": 1, "enabled": true }
  ]
}`

	_, addr, latency, err := ProxyProbe(raw, "php", 2*time.Second)
	if err != nil {
		t.Fatalf("ProxyProbe(php unix): %v", err)
	}
	if addr != socketPath {
		t.Fatalf("probe addr=%q want=%q", addr, socketPath)
	}
	if latency < 0 {
		t.Fatalf("latency=%d", latency)
	}
}

func TestPrepareProxyRulesRawDoesNotBindConfiguredUpstreamToVhost(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	currentRaw := `{
  "upstreams": [
    { "name": "app", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(currentRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	vhosts := VhostConfigFile{
		Vhosts: []VhostConfig{
			{
				Name:               "app",
				Mode:               "php-fpm",
				Hostname:           "127.0.0.1",
				ListenPort:         9401,
				DocumentRoot:       "data/vhosts/samples/php-site/public",
				RuntimeID:          "php83",
				GeneratedTarget:    "vhost-1",
				LinkedUpstreamName: "app",
			},
		},
	}

	nextRaw := `{}`
	prepared, err := prepareProxyRulesRawWithSitesAndVhosts(nextRaw, SiteConfigFile{}, vhosts)
	if err != nil {
		t.Fatalf("prepareProxyRulesRawWithSitesAndVhosts: %v", err)
	}
	if _, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app"); ok {
		t.Fatal("configured upstream app should not be synthesized from linked_upstream_name")
	}
	for _, route := range prepared.effectiveCfg.Routes {
		if route.Name != "vhost:app" {
			continue
		}
		if route.Action.Upstream != "vhost-1" {
			t.Fatalf("generated vhost route upstream=%q want vhost-1", route.Action.Upstream)
		}
		return
	}
	t.Fatal("generated vhost route missing")
}

func TestBuildProxyTransportUsesH2CPriorKnowledge(t *testing.T) {
	sawMajor := make(chan int, 1)
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sawMajor <- r.ProtoMajor:
		default:
		}
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer server.Close()

	cfg, err := ValidateProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "` + server.URL + `", "weight": 1, "enabled": true }
  ],
  "force_http2": true,
  "h2c_upstream": true,
  "health_check_path": "/healthz"
}`)
	if err != nil {
		t.Fatalf("ValidateProxyRulesRaw: %v", err)
	}

	client := &http.Client{Transport: buildProxyTransport(cfg)}
	resp, err := client.Get(server.URL + "/bench")
	if err != nil {
		t.Fatalf("client.Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("unexpected status: %d", resp.StatusCode)
	}

	select {
	case major := <-sawMajor:
		if major != 2 {
			t.Fatalf("proto major=%d want=2", major)
		}
	default:
		t.Fatal("expected upstream request to be observed")
	}
}

func TestProxyHealthCheckRequestSupportsH2CUpstream(t *testing.T) {
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if r.ProtoMajor != 2 {
			t.Fatalf("proto major=%d want=2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
	}), &http2.Server{}))
	defer server.Close()

	cfg, _, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "`+server.URL+`", "weight": 1, "enabled": true }
  ],
  "h2c_upstream": true,
  "health_check_path": "/healthz"
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}

	statusCode, _, err := checkProxyBackendHealth(cfg, mustURL(server.URL), proxyGlobalTransportProfile(cfg, proxyHTTP2ModeH2C))
	if err != nil {
		t.Fatalf("checkProxyBackendHealth: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", statusCode, http.StatusOK)
	}
}

func TestValidateProxyRulesRawRejectsHealthCheckHeadersWithoutPath(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "enabled": true }
  ],
  "health_check_headers": {
    "X-Health-Token": "ready"
  }
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected health_check_headers without health_check_path to fail")
	}
}

func TestValidateProxyRulesRawRejectsHealthCheckExpectedBodyAndRegexTogether(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "enabled": true }
  ],
  "health_check_path": "/healthz",
  "health_check_expected_body": "ok",
  "health_check_expected_body_regex": "ready"
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected mutually exclusive health-check body matchers to fail")
	}
}

func TestValidateProxyRulesRawRejectsInvalidHealthCheckExpectedBodyRegex(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "enabled": true }
  ],
  "health_check_path": "/healthz",
  "health_check_expected_body_regex": "["
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected invalid health-check regex to fail")
	}
}

func TestProxyHealthCheckRequestSupportsHeadersAndExpectedBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		if got := r.Header.Get("X-Health-Token"); got != "ready" {
			t.Fatalf("x-health-token=%q want=ready", got)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer smoke" {
			t.Fatalf("authorization=%q want=%q", got, "Bearer smoke")
		}
		_, _ = w.Write([]byte("state=ready\n"))
	}))
	defer server.Close()

	cfg, _, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "`+server.URL+`", "weight": 1, "enabled": true }
  ],
  "health_check_path": "/healthz",
  "health_check_headers": {
    "X-Health-Token": "ready",
    "Authorization": "Bearer smoke"
  },
  "health_check_expected_body": "state=ready"
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}

	statusCode, latencyMS, err := checkProxyBackendHealth(cfg, mustURL(server.URL), proxyGlobalTransportProfile(cfg, proxyHTTP2ModeDefault))
	if err != nil {
		t.Fatalf("checkProxyBackendHealth: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", statusCode, http.StatusOK)
	}
	if latencyMS < 0 {
		t.Fatalf("latency=%d", latencyMS)
	}

	backends, err := buildProxyBackendStates(cfg, nil)
	if err != nil {
		t.Fatalf("buildProxyBackendStates: %v", err)
	}
	monitor := &upstreamHealthMonitor{
		cfg:      cfg,
		backends: backends,
		status:   upstreamHealthStatus{Status: "disabled"},
	}
	monitor.applyConfigLocked(cfg)
	status := monitor.Snapshot()
	if got := status.HealthCheckHeaders["X-Health-Token"]; got != "ready" {
		t.Fatalf("status health header=%q want=ready", got)
	}
	if !status.HealthCheckExpectedBodyConfigured {
		t.Fatal("expected body matcher should be visible in status")
	}
	if status.HealthCheckExpectedBodyRegexConfigured {
		t.Fatal("unexpected regex matcher flag in status")
	}
}

func TestProxyHealthCheckRequestSupportsExpectedBodyRegex(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("version=2026.04.16\nready=true\n"))
	}))
	defer server.Close()

	cfg, _, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "`+server.URL+`", "weight": 1, "enabled": true }
  ],
  "health_check_path": "/healthz",
  "health_check_expected_body_regex": "ready=true"
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}

	statusCode, _, err := checkProxyBackendHealth(cfg, mustURL(server.URL), proxyGlobalTransportProfile(cfg, proxyHTTP2ModeDefault))
	if err != nil {
		t.Fatalf("checkProxyBackendHealth: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", statusCode, http.StatusOK)
	}
}

func TestProxyHealthCheckRequestFailsWhenExpectedBodyDoesNotMatch(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("state=starting\n"))
	}))
	defer server.Close()

	cfg, _, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    { "name": "primary", "url": "`+server.URL+`", "weight": 1, "enabled": true }
  ],
  "health_check_path": "/healthz",
  "health_check_expected_body": "state=ready"
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}

	statusCode, latencyMS, err := checkProxyBackendHealth(cfg, mustURL(server.URL), proxyGlobalTransportProfile(cfg, proxyHTTP2ModeDefault))
	if err == nil {
		t.Fatal("expected health-check body mismatch to fail")
	}
	if !strings.Contains(err.Error(), "expected text") {
		t.Fatalf("unexpected error: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", statusCode, http.StatusOK)
	}
	if latencyMS < 0 {
		t.Fatalf("latency=%d", latencyMS)
	}
}

func TestValidateProxyRulesRawRejectsUpstreamTLSOnHTTPUpstream(t *testing.T) {
	raw := `{
  "upstreams": [
    {
      "name": "primary",
      "url": "http://127.0.0.1:8080",
      "enabled": true,
      "tls": {
        "server_name": "backend.internal"
      }
    }
  ]
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected upstream tls on non-https upstream to fail")
	}
}

func TestCheckProxyBackendHealthSupportsPerUpstreamTLSBundleAndSNI(t *testing.T) {
	certFile, keyFile := writeSiteTestTLSFiles(t, []string{"backend.internal"})
	serverCert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("load server key pair: %v", err)
	}
	var seenServerName string
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			t.Fatalf("unexpected path: %s", r.URL.Path)
		}
		_, _ = w.Write([]byte("ok"))
	}))
	server.TLS = &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetConfigForClient: func(chi *tls.ClientHelloInfo) (*tls.Config, error) {
			seenServerName = chi.ServerName
			return &tls.Config{
				MinVersion:   tls.VersionTLS12,
				Certificates: []tls.Certificate{serverCert},
			}, nil
		},
	}
	server.StartTLS()
	defer server.Close()

	raw := fmt.Sprintf(`{
  "upstreams": [
    {
      "name": "primary",
      "url": %q,
      "enabled": true,
      "tls": {
        "server_name": "backend.internal",
        "ca_bundle": %q,
        "min_version": "tls1.2",
        "max_version": "tls1.3"
      }
    }
  ],
  "health_check_path": "/healthz"
}`, server.URL, certFile)
	cfg, _, _, _, err := parseProxyRulesRaw(raw, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	profile := proxyConfiguredUpstreamTransportProfile(cfg, &cfg.Upstreams[0], cfg.Upstreams[0].HTTP2Mode)
	statusCode, _, err := checkProxyBackendHealth(cfg, mustURL(server.URL), profile)
	if err != nil {
		t.Fatalf("checkProxyBackendHealth: %v", err)
	}
	if statusCode != http.StatusOK {
		t.Fatalf("status=%d want=%d", statusCode, http.StatusOK)
	}
	if seenServerName != "backend.internal" {
		t.Fatalf("server name=%q want=backend.internal", seenServerName)
	}
}

func TestProxyConfiguredUpstreamTransportProfilePrefersPerUpstreamClientCertPair(t *testing.T) {
	globalCertFile, globalKeyFile := writeSiteTestTLSFiles(t, []string{"global.internal"})
	upstreamCertFile, upstreamKeyFile := writeSiteTestTLSFiles(t, []string{"upstream.internal"})
	cfg, _, _, _, err := parseProxyRulesRaw(fmt.Sprintf(`{
  "upstreams": [
    {
      "name": "primary",
      "url": "https://backend.internal:8443",
      "enabled": true,
      "tls": {
        "client_cert": %q,
        "client_key": %q
      }
    }
  ],
  "tls_client_cert": %q,
  "tls_client_key": %q
}`, upstreamCertFile, upstreamKeyFile, globalCertFile, globalKeyFile), SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}

	profile := proxyConfiguredUpstreamTransportProfile(cfg, &cfg.Upstreams[0], cfg.Upstreams[0].HTTP2Mode)
	tlsCfg, err := buildProxyTLSClientConfigForProfile(profile.TLS)
	if err != nil {
		t.Fatalf("buildProxyTLSClientConfigForProfile: %v", err)
	}
	if len(tlsCfg.Certificates) != 1 {
		t.Fatalf("certificates=%d want=1", len(tlsCfg.Certificates))
	}
	expected, err := tls.LoadX509KeyPair(upstreamCertFile, upstreamKeyFile)
	if err != nil {
		t.Fatalf("load expected upstream key pair: %v", err)
	}
	if len(expected.Certificate) == 0 || len(tlsCfg.Certificates[0].Certificate) == 0 {
		t.Fatal("expected certificate chain to be loaded")
	}
	if !bytes.Equal(tlsCfg.Certificates[0].Certificate[0], expected.Certificate[0]) {
		t.Fatal("expected per-upstream client certificate to override global certificate")
	}
}

func TestServeProxyRoutesToDirectH2CUpstream(t *testing.T) {
	sawMajor := make(chan int, 1)
	server := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case sawMajor <- r.ProtoMajor:
		default:
		}
		w.Header().Set("X-Upstream-Proto", r.Proto)
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer server.Close()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "` + server.URL + `", "weight": 1, "enabled": true }
  ],
  "h2c_upstream": true,
  "routes": [
    {
      "name": "bench",
      "match": {
        "path": { "type": "prefix", "value": "/bench" }
      },
      "action": {
        "upstream": "primary"
      }
    }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 1); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/bench", nil)
	req.Host = "proxy.local"
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	resp := rec.Result()
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, http.StatusNoContent, rec.Body.String())
	}
	if got := resp.Header.Get("X-Upstream-Proto"); !strings.HasPrefix(got, "HTTP/2") {
		t.Fatalf("x-upstream-proto=%q", got)
	}
	select {
	case major := <-sawMajor:
		if major != 2 {
			t.Fatalf("proto major=%d want=2", major)
		}
	default:
		t.Fatal("expected route request to hit upstream")
	}
}

func TestValidateProxyRulesRawAllowsMixedPerUpstreamHTTP2Topologies(t *testing.T) {
	raw := `{
  "tls_insecure_skip_verify": true,
  "upstreams": [
    { "name": "tls", "url": "https://127.0.0.1:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c", "url": "http://127.0.0.1:8080", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}`
	if _, err := ValidateProxyRulesRaw(raw); err != nil {
		t.Fatalf("expected mixed upstream http2 modes to validate: %v", err)
	}
}

func TestValidateProxyRulesRawRejectsRouteH2COverrideForHTTPSUpstream(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "bad-h2c",
      "match": {
        "path": { "type": "prefix", "value": "/bad" }
      },
      "action": {
        "upstream": "primary",
        "upstream_http2_mode": "h2c_prior_knowledge"
      }
    }
  ]
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil || !strings.Contains(err.Error(), "is not supported on route targets") {
		t.Fatalf("expected route h2c https validation error, got: %v", err)
	}
}

func TestServeProxyRoutesMixedHTTP2Topologies(t *testing.T) {
	tlsProto := make(chan string, 1)
	tlsServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case tlsProto <- r.Proto:
		default:
		}
		w.Header().Set("X-Upstream-Proto", r.Proto)
		w.WriteHeader(http.StatusNoContent)
	}))
	tlsServer.EnableHTTP2 = true
	tlsServer.StartTLS()
	defer tlsServer.Close()

	h2cProto := make(chan string, 1)
	h2cServer := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case h2cProto <- r.Proto:
		default:
		}
		w.Header().Set("X-Upstream-Proto", r.Proto)
		w.WriteHeader(http.StatusNoContent)
	}), &http2.Server{}))
	defer h2cServer.Close()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	raw := `{
  "tls_insecure_skip_verify": true,
  "upstreams": [
    { "name": "tls", "url": "` + tlsServer.URL + `", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c", "url": "` + h2cServer.URL + `", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ],
  "routes": [
    {
      "name": "tls-route",
      "match": {
        "path": { "type": "prefix", "value": "/tls" }
      },
      "action": {
        "upstream": "tls"
      }
    },
    {
      "name": "h2c-route",
      "match": {
        "path": { "type": "prefix", "value": "/h2c" }
      },
      "action": {
        "upstream": "h2c"
      }
    }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 1); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	t.Run("tls upstream", func(t *testing.T) {
		cfg := currentProxyConfig()
		if got := cfg.Upstreams[0].HTTP2Mode; got != proxyHTTP2ModeForceAttempt {
			t.Fatalf("tls upstream http2_mode=%q", got)
		}
		req := httptest.NewRequest(http.MethodGet, "http://proxy.local/tls", nil)
		req.Host = "proxy.local"
		decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision: %v", err)
		}
		if decision.SelectedTransportKey == "" {
			t.Fatal("expected selected transport key for tls route")
		}
		if decision.SelectedHTTP2Mode != proxyHTTP2ModeForceAttempt {
			t.Fatalf("tls selected http2 mode=%q", decision.SelectedHTTP2Mode)
		}
		profiles, err := proxyTransportProfileCatalog(currentProxyConfig())
		if err != nil {
			t.Fatalf("proxyTransportProfileCatalog: %v", err)
		}
		if _, ok := profiles[decision.SelectedTransportKey]; !ok {
			t.Fatalf("missing tls transport profile for key %q", decision.SelectedTransportKey)
		}
		transports, err := buildProxyTransportSet(currentProxyConfig(), profiles)
		if err != nil {
			t.Fatalf("buildProxyTransportSet: %v", err)
		}
		if _, ok := transports[decision.SelectedTransportKey]; !ok {
			t.Fatalf("missing tls transport for key %q", decision.SelectedTransportKey)
		}
		if _, ok := proxyRoundTripperForCandidate(profiles, transports, decision.SelectedTransportKey, decision.SelectedTransportKey, decision.SelectedHTTP2Mode).(*nativeHTTP2Transport); !ok {
			t.Fatalf("expected nativeHTTP2Transport for tls route")
		}
		req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
		rec := httptest.NewRecorder()
		ServeProxy(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, http.StatusNoContent, rec.Body.String())
		}
		if got := resp.Header.Get("X-Upstream-Proto"); !strings.HasPrefix(got, "HTTP/2") {
			t.Fatalf("tls x-upstream-proto=%q", got)
		}
		select {
		case proto := <-tlsProto:
			if !strings.HasPrefix(proto, "HTTP/2") {
				t.Fatalf("tls proto=%q", proto)
			}
		default:
			t.Fatal("expected tls upstream request to be observed")
		}
	})

	t.Run("h2c upstream", func(t *testing.T) {
		cfg := currentProxyConfig()
		if got := cfg.Upstreams[1].HTTP2Mode; got != proxyHTTP2ModeH2C {
			t.Fatalf("h2c upstream http2_mode=%q", got)
		}
		req := httptest.NewRequest(http.MethodGet, "http://proxy.local/h2c", nil)
		req.Host = "proxy.local"
		decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision: %v", err)
		}
		if decision.SelectedTransportKey == "" {
			t.Fatal("expected selected transport key for h2c route")
		}
		if decision.SelectedHTTP2Mode != proxyHTTP2ModeH2C {
			t.Fatalf("h2c selected http2 mode=%q", decision.SelectedHTTP2Mode)
		}
		profiles, err := proxyTransportProfileCatalog(currentProxyConfig())
		if err != nil {
			t.Fatalf("proxyTransportProfileCatalog: %v", err)
		}
		if _, ok := profiles[decision.SelectedTransportKey]; !ok {
			t.Fatalf("missing h2c transport profile for key %q", decision.SelectedTransportKey)
		}
		transports, err := buildProxyTransportSet(currentProxyConfig(), profiles)
		if err != nil {
			t.Fatalf("buildProxyTransportSet: %v", err)
		}
		if _, ok := transports[decision.SelectedTransportKey]; !ok {
			t.Fatalf("missing h2c transport for key %q", decision.SelectedTransportKey)
		}
		if _, ok := transports[decision.SelectedTransportKey].(*nativeHTTP2Transport); !ok {
			t.Fatalf("selected h2c transport key %q does not map to native http2 transport", decision.SelectedTransportKey)
		}
		if _, ok := proxyRoundTripperForCandidate(profiles, transports, decision.SelectedTransportKey, decision.SelectedTransportKey, decision.SelectedHTTP2Mode).(*nativeHTTP2Transport); !ok {
			t.Fatalf("expected nativeHTTP2Transport for h2c route")
		}
		req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
		rec := httptest.NewRecorder()
		ServeProxy(rec, req)
		resp := rec.Result()
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("status=%d want=%d body=%s", resp.StatusCode, http.StatusNoContent, rec.Body.String())
		}
		if got := resp.Header.Get("X-Upstream-Proto"); !strings.HasPrefix(got, "HTTP/2") {
			t.Fatalf("h2c x-upstream-proto=%q", got)
		}
		select {
		case proto := <-h2cProto:
			if !strings.HasPrefix(proto, "HTTP/2") {
				t.Fatalf("h2c proto=%q", proto)
			}
		default:
			t.Fatal("expected h2c upstream request to be observed")
		}
	})
}

func TestProxyRoundTripperForCandidateDoesNotFallbackToDefaultTransport(t *testing.T) {
	rt := proxyRoundTripperForCandidate(nil, nil, "missing", "", proxyHTTP2ModeDefault)
	if _, ok := rt.(proxyStaticErrorTransport); !ok {
		t.Fatalf("transport=%T want proxyStaticErrorTransport", rt)
	}
	req := httptest.NewRequest(http.MethodGet, "http://backend.example/", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("RoundTrip succeeded for missing proxy transport")
	}
}
