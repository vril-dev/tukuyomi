package handler

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/andybalholm/brotli"
	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"

	"tukuyomi/internal/cacheconf"
)

func TestProxyResponseCompressionGzip(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := strings.Repeat("hello proxy compression ", 32)
	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"origin-strong-etag"`)
		_, _ = w.Write([]byte(`{"payload":"` + payload + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/products", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("content-encoding=%q want gzip", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("vary=%q want Accept-Encoding", got)
	}
	if got := res.Header.Get("ETag"); got != `W/"origin-strong-etag"` {
		t.Fatalf("etag=%q", got)
	}
	gz, err := gzip.NewReader(res.Body)
	if err != nil {
		t.Fatalf("new gzip reader: %v", err)
	}
	body, err := io.ReadAll(gz)
	_ = gz.Close()
	if err != nil {
		t.Fatalf("read gzipped body: %v", err)
	}
	if !bytes.Contains(body, []byte(payload)) {
		t.Fatalf("gzip body missing payload: %q", string(body))
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("unexpected upstream count: %d", got)
	}
}

func TestProxyResponseCompressionSkipsWithoutAcceptEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payload":"` + strings.Repeat("plain response ", 24) + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	res, err := client.Get(srv.URL + "/v1/products")
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("content-encoding=%q want empty", got)
	}
	if got := res.Header.Get("Vary"); !strings.Contains(got, "Accept-Encoding") {
		t.Fatalf("vary=%q want Accept-Encoding", got)
	}
}

func TestProxyResponseCompressionNegotiatesBrotli(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := strings.Repeat("brotli proxy compression ", 32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payload":"` + payload + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/products", nil)
	req.Header.Set("Accept-Encoding", "br, gzip")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("content-encoding=%q want br", got)
	}
	body, err := io.ReadAll(brotli.NewReader(res.Body))
	if err != nil {
		t.Fatalf("read brotli body: %v", err)
	}
	if !bytes.Contains(body, []byte(payload)) {
		t.Fatalf("brotli body missing payload: %q", string(body))
	}
}

func TestProxyResponseCompressionNegotiatesConfiguredOrder(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := strings.Repeat("zstd proxy compression ", 32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payload":"` + payload + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["zstd", "br", "gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/products", nil)
	req.Header.Set("Accept-Encoding", "gzip, br, zstd")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	if got := res.Header.Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("content-encoding=%q want zstd", got)
	}
	zr, err := zstd.NewReader(res.Body)
	if err != nil {
		t.Fatalf("new zstd reader: %v", err)
	}
	body, err := io.ReadAll(zr)
	zr.Close()
	if err != nil {
		t.Fatalf("read zstd body: %v", err)
	}
	if !bytes.Contains(body, []byte(payload)) {
		t.Fatalf("zstd body missing payload: %q", string(body))
	}
}

func TestProxyResponseCompressionPassesThroughPrecompressedResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	payload := []byte(`{"payload":"` + strings.Repeat("origin gzip ", 40) + `"}`)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write(payload); err != nil {
		t.Fatalf("write gzip payload: %v", err)
	}
	if err := gz.Close(); err != nil {
		t.Fatalf("close gzip payload: %v", err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Encoding", "gzip")
		w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
		_, _ = w.Write(buf.Bytes())
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/products", nil)
	req.Header.Set("Accept-Encoding", "gzip")
	res, err := client.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if got := res.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("content-encoding=%q want gzip", got)
	}
	if !bytes.Equal(body, buf.Bytes()) {
		t.Fatal("proxy should pass through upstream gzip payload unchanged")
	}
}

func TestProxyResponseCompressionCacheVaryByAcceptEncoding(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payload":"` + strings.Repeat("cacheable response ", 20) + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["br", "gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	cacheStoreDir := t.TempDir()
	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{"enabled":true,"store_dir":`+strconv.Quote(cacheStoreDir)+`,"max_bytes":1048576}`), 0o600); err != nil {
		t.Fatalf("write cache store config: %v", err)
	}
	if err := InitResponseCacheRuntime(cacheStoreCfgPath); err != nil {
		t.Fatalf("init response cache runtime: %v", err)
	}
	rs, err := cacheconf.LoadFromString(`ALLOW prefix=/static methods=GET,HEAD ttl=60`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rs)

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	compressedClient := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req1.Header.Set("Accept-Encoding", "br")
	res1, err := compressedClient.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer res1.Body.Close()
	if got := res1.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("first cache header=%q want MISS", got)
	}
	if got := res1.Header.Get("Content-Encoding"); got != "br" {
		t.Fatalf("first content-encoding=%q want br", got)
	}

	plainClient := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	res2, err := plainClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("second cache header=%q want MISS", got)
	}
	if got := res2.Header.Get("Content-Encoding"); got != "" {
		t.Fatalf("second content-encoding=%q want empty", got)
	}

	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req3.Header.Set("Accept-Encoding", "br")
	res3, err := compressedClient.Do(req3)
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	defer res3.Body.Close()
	if got := res3.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("third cache header=%q want HIT", got)
	}

	req4, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req4.Header.Set("Accept-Encoding", "gzip")
	res4, err := compressedClient.Do(req4)
	if err != nil {
		t.Fatalf("fourth request failed: %v", err)
	}
	defer res4.Body.Close()
	if got := res4.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("fourth cache header=%q want MISS", got)
	}
	if got := res4.Header.Get("Content-Encoding"); got != "gzip" {
		t.Fatalf("fourth content-encoding=%q want gzip", got)
	}
	if got := upstreamRequests.Load(); got != 3 {
		t.Fatalf("unexpected upstream count: %d", got)
	}
}

func TestProxyResponseCompressionStatusSnapshotTracksAlgorithms(t *testing.T) {
	gin.SetMode(gin.TestMode)

	baseline := proxyResponseCompressionStatusSnapshot()
	payload := strings.Repeat("status compression ", 32)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"payload":"` + payload + `"}`))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1048576,
  "response_compression": {
    "enabled": true,
    "algorithms": ["zstd", "br", "gzip"],
    "min_bytes": 1,
    "mime_types": ["application/json"]
  }
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	client := &http.Client{Transport: &http.Transport{DisableCompression: true}}
	for _, acceptEncoding := range []string{"gzip", "br", "zstd"} {
		req, _ := http.NewRequest(http.MethodGet, srv.URL+"/v1/products", nil)
		req.Header.Set("Accept-Encoding", acceptEncoding)
		res, err := client.Do(req)
		if err != nil {
			t.Fatalf("request failed for %s: %v", acceptEncoding, err)
		}
		_ = res.Body.Close()
		if got := res.Header.Get("Content-Encoding"); got != acceptEncoding {
			t.Fatalf("content-encoding=%q want %s", got, acceptEncoding)
		}
	}

	after := proxyResponseCompressionStatusSnapshot()
	if got := after.CompressedTotal - baseline.CompressedTotal; got != 3 {
		t.Fatalf("compressed total delta=%d want 3", got)
	}
	for _, algorithm := range []string{"gzip", "br", "zstd"} {
		if got := after.CompressedByAlgorithm[algorithm] - baseline.CompressedByAlgorithm[algorithm]; got != 1 {
			t.Fatalf("compressed_by_algorithm[%s] delta=%d want 1", algorithm, got)
		}
	}
}

func TestValidateProxyRulesRawRejectsCompressionWithoutBuffering(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 0,
  "response_compression": {
    "enabled": true,
    "algorithms": ["gzip"],
    "min_bytes": 128
  }
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil {
		t.Fatal("expected validation error for response compression without buffering")
	}
}

func TestValidateProxyRulesRawRejectsUnsupportedCompressionAlgorithm(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "max_response_buffer_bytes": 1024,
  "response_compression": {
    "enabled": true,
    "algorithms": ["brotli"],
    "min_bytes": 128
  }
}`
	if _, err := ValidateProxyRulesRaw(raw); err == nil || !strings.Contains(err.Error(), "unsupported value") {
		t.Fatalf("expected unsupported algorithm error, got %v", err)
	}
}

func TestProxyResponseCompressionAlgorithmMetricsDisabledOrUninitialized(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cases := []struct {
		name string
		rt   *proxyRuntime
	}{
		{
			name: "disabled",
			rt: &proxyRuntime{
				cfg: normalizeProxyRulesConfig(ProxyRulesConfig{
					Upstreams: []ProxyUpstream{{
						Name:    "primary",
						URL:     "http://127.0.0.1:8080",
						Weight:  1,
						Enabled: true,
					}},
					MaxResponseBufferBytes: 1024,
					ResponseCompression: ProxyResponseCompressionConfig{
						Enabled: false,
					},
				}),
			},
		},
		{
			name: "uninitialized",
			rt:   nil,
		},
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			proxyRuntimeMu.Lock()
			proxyRt = tc.rt
			proxyRuntimeMu.Unlock()

			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			MetricsHandler(c)

			body := rec.Body.String()
			if !strings.Contains(body, "tukuyomi_proxy_response_compression_enabled 0\n") {
				t.Fatalf("compression enabled gauge should be 0:\n%s", body)
			}
			for _, algorithm := range supportedProxyResponseCompressionAlgorithms {
				line := `tukuyomi_proxy_response_compression_algorithm_enabled{algorithm="` + algorithm + `"} 0`
				if !strings.Contains(body, line) {
					t.Fatalf("missing disabled algorithm metric %q in body:\n%s", line, body)
				}
			}
		})
	}
}
