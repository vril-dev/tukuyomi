package handler

import (
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestServeProxySupportsCustomErrorHTML(t *testing.T) {
	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	htmlPath := filepath.Join(tmp, "proxy-error.html")
	htmlBody := "<html><body><h1>backend unavailable</h1></body></html>"
	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o644); err != nil {
		t.Fatalf("write html file: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://` + addr + `", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 1,
  "response_header_timeout": 1,
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
  "health_check_timeout_sec": 2,
  "error_html_file": "` + htmlPath + `"
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}

	if err := InitProxyRuntime(proxyPath, 1); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	reqHTML := httptest.NewRequest(http.MethodGet, "http://example.test/app", nil)
	reqHTML.Header.Set("Accept", "text/html")
	recHTML := httptest.NewRecorder()
	ServeProxy(recHTML, reqHTML)
	resHTML := recHTML.Result()
	bodyHTML, _ := io.ReadAll(resHTML.Body)
	resHTML.Body.Close()
	if resHTML.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected html status: %d", resHTML.StatusCode)
	}
	if ct := resHTML.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("unexpected html content-type: %q", ct)
	}
	if string(bodyHTML) != htmlBody {
		t.Fatalf("unexpected html body: %q", string(bodyHTML))
	}

	reqJSON := httptest.NewRequest(http.MethodGet, "http://example.test/app", nil)
	reqJSON.Header.Set("Accept", "application/json")
	recJSON := httptest.NewRecorder()
	ServeProxy(recJSON, reqJSON)
	resJSON := recJSON.Result()
	bodyJSON, _ := io.ReadAll(resJSON.Body)
	resJSON.Body.Close()
	if resJSON.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected json status: %d", resJSON.StatusCode)
	}
	if ct := resJSON.Header.Get("Content-Type"); !strings.Contains(ct, "text/plain") {
		t.Fatalf("unexpected plain-text content-type: %q", ct)
	}
	if !strings.Contains(string(bodyJSON), "Service Unavailable") {
		t.Fatalf("unexpected plain-text body: %q", string(bodyJSON))
	}
}

func TestServeProxyRedirectsGETRequestsToMaintenanceURL(t *testing.T) {
	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen failed: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://` + addr + `", "weight": 1, "enabled": true }
  ],
  "dial_timeout": 1,
  "response_header_timeout": 1,
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
  "health_check_timeout_sec": 2,
  "error_redirect_url": "/maintenance"
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}

	if err := InitProxyRuntime(proxyPath, 1); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/app", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	res := rec.Result()
	res.Body.Close()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("unexpected redirect status: %d", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "/maintenance" {
		t.Fatalf("unexpected redirect location: %q", got)
	}
}
