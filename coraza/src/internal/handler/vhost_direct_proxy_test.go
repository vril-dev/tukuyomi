package handler

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"tukuyomi/internal/cacheconf"
)

func TestWriteDirectProxyResponsePreservesContextRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/index.php", nil)
	req = req.WithContext(context.WithValue(req.Context(), ctxKeyReqID, "req-direct-context"))
	rec := httptest.NewRecorder()
	rec.Header().Set("X-Request-ID", "req-writer")
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
			"X-Request-ID": []string{"req-upstream"},
		},
		Body:    io.NopCloser(strings.NewReader("ok")),
		Request: req,
	}

	if err := writeDirectProxyResponse(rec, req, resp); err != nil {
		t.Fatalf("writeDirectProxyResponse: %v", err)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-direct-context" {
		t.Fatalf("X-Request-ID=%q want req-direct-context", got)
	}
	if got := rec.Body.String(); got != "ok" {
		t.Fatalf("body=%q want ok", got)
	}
}

func TestWriteDirectProxyResponseFallsBackToInboundRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/index.php", nil)
	req.Header.Set("X-Request-ID", "req-inbound")
	rec := httptest.NewRecorder()
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/plain"}},
		Body:       io.NopCloser(strings.NewReader("ok")),
		Request:    req,
	}

	if err := writeDirectProxyResponse(rec, req, resp); err != nil {
		t.Fatalf("writeDirectProxyResponse: %v", err)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-inbound" {
		t.Fatalf("X-Request-ID=%q want req-inbound", got)
	}
}

func TestServeProxyServesStaticVhostAssets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("static-index\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(index): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "app.js"), []byte("console.log('ok');\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(app.js): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/app.js", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "console.log('ok');") {
		t.Fatalf("unexpected body=%q", rec.Body.String())
	}
}

func TestServeProxyWithCacheCachesStaticVhostAssets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "test.html"), []byte("static cache body\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(test.html): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	cacheStorePath := filepath.Join(t.TempDir(), "cache-store.json")
	cacheStoreDir := t.TempDir()
	if err := os.WriteFile(cacheStorePath, []byte(`{"enabled":true,"store_dir":`+strconv.Quote(cacheStoreDir)+`,"max_bytes":1048576}`), 0o600); err != nil {
		t.Fatalf("write cache store: %v", err)
	}
	if err := InitResponseCacheRuntime(cacheStorePath); err != nil {
		t.Fatalf("InitResponseCacheRuntime: %v", err)
	}
	previousRules := cacheconf.Get()
	t.Cleanup(func() {
		if previousRules != nil {
			cacheconf.Set(previousRules)
			return
		}
		emptyRules, _ := cacheconf.LoadFromString("")
		cacheconf.Set(emptyRules)
	})
	rules, err := cacheconf.LoadFromString(`ALLOW prefix=/test.html methods=GET,HEAD ttl=600 vary=Accept-Encoding`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rules)

	for i, want := range []string{"MISS", "HIT"} {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/test.html", nil)
		decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision %d: %v", i+1, err)
		}
		req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
		rec := httptest.NewRecorder()
		ServeProxyWithCacheHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d status=%d body=%s", i+1, rec.Code, rec.Body.String())
		}
		if got := rec.Header().Get(proxyResponseCacheHeader); got != want {
			t.Fatalf("request %d %s=%q want=%q headers=%v", i+1, proxyResponseCacheHeader, got, want, rec.Header())
		}
	}
	_, _, _, stats := ResponseCacheSnapshot()
	if stats.Stores != 1 || stats.EntryCount != 1 || stats.Hits != 1 || stats.Misses != 1 {
		t.Fatalf("cache stats stores=%d entries=%d hits=%d misses=%d", stats.Stores, stats.EntryCount, stats.Hits, stats.Misses)
	}
}

func TestServeProxyServesStaticVhostAssetsViaLinkedBackendPool(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "app.js"), []byte("console.log('linked');\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(app.js): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "docs-pool",
      "members": ["docs"]
    }
  ],
  "default_route": {
    "action": {
      "backend_pool": "docs-pool"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/app.js", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if decision.SelectedUpstream != "docs" {
		t.Fatalf("selected_upstream=%q want=%q", decision.SelectedUpstream, "docs")
	}
	if !strings.Contains(rec.Body.String(), "console.log('linked');") {
		t.Fatalf("unexpected body=%q", rec.Body.String())
	}
}

func TestServeProxyStreamsLargeStaticVhostAssets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	largeBody := bytes.Repeat([]byte("a"), 2*1024*1024)
	if err := os.WriteFile(filepath.Join(docroot, "large.txt"), largeBody, 0o644); err != nil {
		t.Fatalf("WriteFile(large.txt): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/large.txt", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body-prefix=%q", rec.Code, rec.Body.String()[:min(128, rec.Body.Len())])
	}
	if rec.Body.Len() != len(largeBody) {
		t.Fatalf("body len=%d want=%d", rec.Body.Len(), len(largeBody))
	}
	if got := rec.Header().Get("Content-Length"); got != strconv.Itoa(len(largeBody)) {
		t.Fatalf("content-length=%q want=%d", got, len(largeBody))
	}
}

func TestServeProxyStaticVhostReturnsValidatorsAndNotModified(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	filePath := filepath.Join(docroot, "app.js")
	if err := os.WriteFile(filePath, []byte("console.log('ok');\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(app.js): %v", err)
	}
	modTime := time.Date(2026, 4, 16, 12, 34, 56, 0, time.UTC)
	if err := os.Chtimes(filePath, modTime, modTime); err != nil {
		t.Fatalf("Chtimes(app.js): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/app.js", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	etag := rec.Header().Get("ETag")
	lastModified := rec.Header().Get("Last-Modified")
	if etag == "" {
		t.Fatal("missing ETag")
	}
	if lastModified == "" {
		t.Fatal("missing Last-Modified")
	}
	if got := rec.Header().Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("cache-control=%q", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x-content-type-options=%q", got)
	}

	notModifiedReq := httptest.NewRequest(http.MethodGet, "http://docs.example.com/app.js", nil)
	notModifiedReq.Header.Set("If-None-Match", etag)
	notModifiedDecision, err := resolveProxyRouteDecision(notModifiedReq, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision(not-modified): %v", err)
	}
	notModifiedReq = notModifiedReq.WithContext(withProxyRouteDecision(notModifiedReq.Context(), notModifiedDecision))
	notModifiedRec := httptest.NewRecorder()
	ServeProxy(notModifiedRec, notModifiedReq)
	if notModifiedRec.Code != http.StatusNotModified {
		t.Fatalf("if-none-match status=%d body=%q", notModifiedRec.Code, notModifiedRec.Body.String())
	}

	ifModifiedReq := httptest.NewRequest(http.MethodGet, "http://docs.example.com/app.js", nil)
	ifModifiedReq.Header.Set("If-Modified-Since", lastModified)
	ifModifiedDecision, err := resolveProxyRouteDecision(ifModifiedReq, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision(if-modified-since): %v", err)
	}
	ifModifiedReq = ifModifiedReq.WithContext(withProxyRouteDecision(ifModifiedReq.Context(), ifModifiedDecision))
	ifModifiedRec := httptest.NewRecorder()
	ServeProxy(ifModifiedRec, ifModifiedReq)
	if ifModifiedRec.Code != http.StatusNotModified {
		t.Fatalf("if-modified-since status=%d body=%q", ifModifiedRec.Code, ifModifiedRec.Body.String())
	}
}

func TestServeProxyStaticVhostBlocksSymlinkEscape(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	secretPath := filepath.Join(tmp, "secret.txt")
	if err := os.WriteFile(secretPath, []byte("do-not-serve\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(secret): %v", err)
	}
	linkPath := filepath.Join(docroot, "secret.txt")
	if err := os.Symlink(secretPath, linkPath); err != nil {
		if errors.Is(err, syscall.EPERM) || errors.Is(err, syscall.ENOTSUP) {
			t.Skipf("symlink unsupported: %v", err)
		}
		t.Fatalf("Symlink(secret): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/secret.txt", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "do-not-serve") {
		t.Fatalf("symlink escape leaked body=%q", rec.Body.String())
	}
}

func TestServeProxyStaticVhostBlocksHiddenPathsByDefault(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".env"), []byte("APP_KEY=secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.env): %v", err)
	}
	if err := os.MkdirAll(filepath.Join(docroot, ".git"), 0o755); err != nil {
		t.Fatalf("MkdirAll(.git): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".git", "config"), []byte("[core]\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.git/config): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	for _, requestPath := range []string{"/.env", "/.git/config"} {
		req := httptest.NewRequest(http.MethodGet, "http://docs.example.com"+requestPath, nil)
		decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision(%s): %v", requestPath, err)
		}
		req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
		rec := httptest.NewRecorder()
		ServeProxy(rec, req)
		if rec.Code != http.StatusNotFound {
			t.Fatalf("path=%s status=%d body=%q", requestPath, rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "APP_KEY=secret") || strings.Contains(rec.Body.String(), "[core]") {
			t.Fatalf("path=%s leaked body=%q", requestPath, rec.Body.String())
		}
	}
}

func TestServeProxyStaticVhostAllowsWellKnownPaths(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	wellKnownDir := filepath.Join(docroot, ".well-known", "acme-challenge")
	if err := os.MkdirAll(wellKnownDir, 0o755); err != nil {
		t.Fatalf("MkdirAll(.well-known): %v", err)
	}
	if err := os.WriteFile(filepath.Join(wellKnownDir, "token"), []byte("challenge-ok\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(token): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "docs"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/.well-known/acme-challenge/token", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "challenge-ok") {
		t.Fatalf("unexpected body=%q", rec.Body.String())
	}
}

func TestConfiguredStaticUpstreamCanBecomeImplicitPrimaryTarget(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "static")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("static-index\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(index): %v", err)
	}

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9401,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "docs", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://localhost:9090/", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "static-index") {
		t.Fatalf("unexpected body=%q", rec.Body.String())
	}
}

func TestServeProxyRunsFastCGITryFilesAndStaticAssets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "php-app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.php"), []byte("<?php echo 'index';"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.php): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "style.css"), []byte("body{color:#123;}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(style.css): %v", err)
	}

	listener, address := startTestFastCGIServer(t, "tcp", "127.0.0.1:0")
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	inventory := defaultPHPRuntimeInventoryRaw
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": ` + strconv.Itoa(port) + `,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "app-php",
      "linked_upstream_name": "app",
      "runtime_id": "php82"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "app", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "app"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	staticReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/style.css", nil)
	staticDecision, err := resolveProxyRouteDecision(staticReq, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision(static): %v", err)
	}
	staticReq = staticReq.WithContext(withProxyRouteDecision(staticReq.Context(), staticDecision))
	staticRec := httptest.NewRecorder()
	ServeProxy(staticRec, staticReq)
	if staticRec.Code != http.StatusOK {
		t.Fatalf("static status=%d body=%s", staticRec.Code, staticRec.Body.String())
	}
	if !strings.Contains(staticRec.Body.String(), "color:#123") {
		t.Fatalf("unexpected static body=%q", staticRec.Body.String())
	}

	phpReq := httptest.NewRequest(http.MethodGet, "http://app.example.com/users?id=7", nil)
	phpDecision, err := resolveProxyRouteDecision(phpReq, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision(php): %v", err)
	}
	phpReq = phpReq.WithContext(withProxyRouteDecision(phpReq.Context(), phpDecision))
	phpRec := httptest.NewRecorder()
	ServeProxy(phpRec, phpReq)
	if phpRec.Code != http.StatusOK {
		t.Fatalf("php status=%d body=%s", phpRec.Code, phpRec.Body.String())
	}
	body := phpRec.Body.String()
	if !strings.Contains(body, "script=/index.php") || !strings.Contains(body, "uri=/users?id=7") || !strings.Contains(body, "query=id=7") {
		t.Fatalf("unexpected php body=%q", body)
	}
}

func TestServeProxyReturnsGeneric500ForFastCGIStderrOnly(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "php-app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.php"), []byte("<?php syntax error"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.php): %v", err)
	}

	listener, address := startTestFastCGIServerFunc(t, "tcp", "127.0.0.1:0", func(conn net.Conn) {
		defer conn.Close()
		if _, _, err := readTestFastCGIRequest(conn); err != nil {
			panic(fmt.Sprintf("readTestFastCGIRequest: %v", err))
		}
		stderr := "PHP Parse error: syntax error, unexpected token in /app/index.php on line 1"
		if err := writeFastCGIRecord(conn, fcgiStderr, fcgiRequestID, []byte(stderr)); err != nil {
			panic(fmt.Sprintf("write stderr: %v", err))
		}
		if err := writeFastCGIRecord(conn, fcgiStderr, fcgiRequestID, nil); err != nil {
			panic(fmt.Sprintf("write stderr eof: %v", err))
		}
		if err := writeFastCGIRecord(conn, fcgiEndRequest, fcgiRequestID, make([]byte, 8)); err != nil {
			panic(fmt.Sprintf("write end request: %v", err))
		}
	})
	defer listener.Close()
	_, portText, _ := net.SplitHostPort(address)
	port, _ := strconv.Atoi(portText)

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": ` + strconv.Itoa(port) + `,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "app-php",
      "linked_upstream_name": "app",
      "runtime_id": "php82"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    { "name": "app", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "default_route": {
    "action": {
      "upstream": "app"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/index.php", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status=%d want=500 body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PHP Parse error") {
		t.Fatalf("client body leaked php stderr: %q", rec.Body.String())
	}
}

func TestServeProxyRunsFastCGIOverUnixSocket(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "php-app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.php"), []byte("<?php echo 'index';"), 0o644); err != nil {
		t.Fatalf("WriteFile(index.php): %v", err)
	}

	socketPath := filepath.Join(tmp, "php-fpm.sock")
	listener, _ := startTestFastCGIServer(t, "unix", socketPath)
	defer listener.Close()

	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	inventory := defaultPHPRuntimeInventoryRaw
	if err := os.WriteFile(inventoryPath, []byte(inventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9402,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "app-php",
      "linked_upstream_name": "app",
      "runtime_id": "php82"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := `{
  "upstreams": [
    {
      "name": "app",
      "url": "fcgi:///` + filepath.ToSlash(socketPath) + `",
      "enabled": true
    }
  ],
  "default_route": {
    "action": {
      "upstream": "app"
    }
  }
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://app.example.com/index.php/extra?lang=ja", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, "script=/index.php") || !strings.Contains(body, "path_info=/extra") || !strings.Contains(body, "query=lang=ja") {
		t.Fatalf("unexpected body=%q", body)
	}
}

func startTestFastCGIServer(t *testing.T, network string, address string) (net.Listener, string) {
	return startTestFastCGIServerFunc(t, network, address, handleTestFastCGIConn)
}

func startTestFastCGIServerFunc(t *testing.T, network string, address string, handler func(net.Conn)) (net.Listener, string) {
	t.Helper()
	if network == "unix" {
		_ = os.Remove(address)
	}
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("net.Listen(%s, %s): %v", network, address, err)
	}
	t.Cleanup(func() {
		_ = listener.Close()
		if network == "unix" {
			_ = os.Remove(address)
		}
	})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := listener.Accept()
			if err != nil {
				if ne, ok := err.(net.Error); ok && ne.Temporary() {
					time.Sleep(10 * time.Millisecond)
					continue
				}
				return
			}
			go handler(conn)
		}
	}()
	t.Cleanup(func() {
		_ = listener.Close()
		wg.Wait()
	})
	return listener, listener.Addr().String()
}

func handleTestFastCGIConn(conn net.Conn) {
	defer conn.Close()
	params, body, err := readTestFastCGIRequest(conn)
	if err != nil {
		panic(fmt.Sprintf("readTestFastCGIRequest: %v", err))
	}
	responseBody := fmt.Sprintf(
		"script=%s\nuri=%s\npath_info=%s\nquery=%s\nmethod=%s\nbody=%s\n",
		params["SCRIPT_NAME"],
		params["REQUEST_URI"],
		params["PATH_INFO"],
		params["QUERY_STRING"],
		params["REQUEST_METHOD"],
		string(body),
	)
	stdout := "Status: 200 OK\r\nContent-Type: text/plain\r\n\r\n" + responseBody
	if err := writeFastCGIRecord(conn, fcgiStdout, fcgiRequestID, []byte(stdout)); err != nil {
		panic(fmt.Sprintf("write stdout: %v", err))
	}
	if err := writeFastCGIRecord(conn, fcgiStdout, fcgiRequestID, nil); err != nil {
		panic(fmt.Sprintf("write stdout eof: %v", err))
	}
	if err := writeFastCGIRecord(conn, fcgiEndRequest, fcgiRequestID, make([]byte, 8)); err != nil {
		panic(fmt.Sprintf("write end request: %v", err))
	}
}

func readTestFastCGIRequest(r io.Reader) (map[string]string, []byte, error) {
	header := make([]byte, 8)
	params := make(map[string]string)
	var body bytes.Buffer
	for {
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, nil, err
		}
		contentLength := int(header[4])<<8 | int(header[5])
		paddingLength := int(header[6])
		content := make([]byte, contentLength)
		if _, err := io.ReadFull(r, content); err != nil {
			return nil, nil, err
		}
		if paddingLength > 0 {
			if _, err := io.CopyN(io.Discard, r, int64(paddingLength)); err != nil {
				return nil, nil, err
			}
		}
		switch header[1] {
		case fcgiParams:
			if contentLength == 0 {
				continue
			}
			if err := parseTestFastCGIParams(content, params); err != nil {
				return nil, nil, err
			}
		case fcgiStdin:
			if contentLength == 0 {
				return params, body.Bytes(), nil
			}
			body.Write(content)
		}
	}
}

func parseTestFastCGIParams(content []byte, out map[string]string) error {
	for offset := 0; offset < len(content); {
		nameLen, next, err := readTestFastCGILength(content, offset)
		if err != nil {
			return err
		}
		offset = next
		valueLen, next, err := readTestFastCGILength(content, offset)
		if err != nil {
			return err
		}
		offset = next
		if offset+nameLen+valueLen > len(content) {
			return io.ErrUnexpectedEOF
		}
		name := content[offset : offset+nameLen]
		offset += nameLen
		value := content[offset : offset+valueLen]
		offset += valueLen
		out[string(name)] = string(value)
	}
	return nil
}

func readTestFastCGILength(content []byte, offset int) (int, int, error) {
	if offset >= len(content) {
		return 0, offset, io.ErrUnexpectedEOF
	}
	b := content[offset]
	offset++
	if b&0x80 == 0 {
		return int(b), offset, nil
	}
	if offset+3 > len(content) {
		return 0, offset, io.ErrUnexpectedEOF
	}
	return int(b&0x7f)<<24 | int(content[offset])<<16 | int(content[offset+1])<<8 | int(content[offset+2]), offset + 3, nil
}
