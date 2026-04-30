package handler

import (
	"crypto/sha256"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/cacheconf"
)

func TestServeProxyWithCacheHitAndClear(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstreamCookie := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		select {
		case upstreamCookie <- r.Header.Get("Cookie"):
		default:
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Server", "upstream")
		w.Header().Set("X-Powered-By", "php")
		w.Header().Set("X-Internal-Leak", "origin")
		_, _ = w.Write([]byte("hello proxy cache"))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{
  "upstreams": [
    { "name": "primary", "url": `+strconv.Quote(upstream.URL)+`, "weight": 1, "enabled": true }
  ],
  "response_header_sanitize": {
    "mode": "auto",
    "custom_remove": ["X-Internal-Leak"]
  }
}`), 0o600); err != nil {
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

	rs, err := cacheconf.LoadFromString(`ALLOW prefix=/static methods=GET,HEAD ttl=60 vary=Accept-Encoding`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rs)

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req1.Header.Set("Accept-Encoding", "gzip")
	req1.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "admin-session"})
	req1.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: "admin-csrf"})
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer res1.Body.Close()
	if got := res1.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("unexpected first cache header: %q", got)
	}
	if got := res1.Header.Get("Server"); got != "" {
		t.Fatalf("unexpected first server header: %q", got)
	}
	if got := res1.Header.Get("X-Powered-By"); got != "" {
		t.Fatalf("unexpected first x-powered-by header: %q", got)
	}
	if got := res1.Header.Get("X-Internal-Leak"); got != "" {
		t.Fatalf("unexpected first custom removed header: %q", got)
	}
	select {
	case got := <-upstreamCookie:
		if got != "" {
			t.Fatalf("unexpected admin cookie forwarded upstream: %q", got)
		}
	default:
		t.Fatal("expected upstream cookie observation")
	}

	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req2.Header.Set("Accept-Encoding", "gzip")
	req2.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "admin-session"})
	req2.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: "admin-csrf"})
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("unexpected second cache header: %q", got)
	}
	if got := res2.Header.Get("Server"); got != "" {
		t.Fatalf("unexpected second server header: %q", got)
	}
	if got := res2.Header.Get("X-Powered-By"); got != "" {
		t.Fatalf("unexpected second x-powered-by header: %q", got)
	}
	if got := res2.Header.Get("X-Internal-Leak"); got != "" {
		t.Fatalf("unexpected second custom removed header: %q", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("unexpected upstream count before clear: %d", got)
	}

	clearResult, err := ClearResponseCache()
	if err != nil {
		t.Fatalf("clear cache: %v", err)
	}
	if clearResult.ClearedEntries != 1 {
		t.Fatalf("unexpected cleared entries: %d", clearResult.ClearedEntries)
	}

	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req3.Header.Set("Accept-Encoding", "gzip")
	res3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("third request failed: %v", err)
	}
	defer res3.Body.Close()
	if got := res3.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("unexpected third cache header: %q", got)
	}
	if got := upstreamRequests.Load(); got != 2 {
		t.Fatalf("unexpected upstream count after clear: %d", got)
	}
}

func TestClearResponseCacheRemovesDiskFilesWhenDisabled(t *testing.T) {
	tmp := t.TempDir()
	t.Chdir(tmp)

	cacheDir := filepath.Join("cache", "response")
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		t.Fatalf("mkdir cache dir: %v", err)
	}
	cacheKey := strings.Repeat("a", sha256.Size*2)
	bodyPath := filepath.Join(cacheDir, cacheKey+".body")
	metaPath := filepath.Join(cacheDir, cacheKey+".json")
	keepPath := filepath.Join(cacheDir, ".gitignore")
	foreignJSONPath := filepath.Join(cacheDir, "operator-note.json")
	if err := os.WriteFile(bodyPath, []byte("cached body"), 0o600); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := os.WriteFile(metaPath, []byte(`{"not":"loaded"}`), 0o600); err != nil {
		t.Fatalf("write meta: %v", err)
	}
	if err := os.WriteFile(keepPath, []byte("*\n"), 0o600); err != nil {
		t.Fatalf("write keep file: %v", err)
	}
	if err := os.WriteFile(foreignJSONPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write foreign json: %v", err)
	}

	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{"enabled":false,"store_dir":"cache/response","max_bytes":1048576}`), 0o600); err != nil {
		t.Fatalf("write cache store config: %v", err)
	}
	if err := InitResponseCacheRuntime(cacheStoreCfgPath); err != nil {
		t.Fatalf("init response cache runtime: %v", err)
	}

	clearResult, err := ClearResponseCache()
	if err != nil {
		t.Fatalf("clear cache: %v", err)
	}
	if clearResult.ClearedEntries != 1 {
		t.Fatalf("cleared entries=%d want 1", clearResult.ClearedEntries)
	}
	for _, path := range []string{bodyPath, metaPath} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("cache file %s still exists or stat failed: %v", path, err)
		}
	}
	for _, path := range []string{keepPath, foreignJSONPath} {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("non-cache file should remain: %s: %v", path, err)
		}
	}
}

func TestServeProxyWithCacheStoresHeadWithoutPoisoningGet(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var headRequests atomic.Int32
	var getRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
		w.Header().Set("X-Accel-Expires", "600")
		switch r.Method {
		case http.MethodHead:
			headRequests.Add(1)
			return
		default:
			getRequests.Add(1)
			_, _ = w.Write([]byte("get body"))
		}
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{"upstreams":[{"name":"primary","url":`+strconv.Quote(upstream.URL)+`,"weight":1,"enabled":true}]}`), 0o600); err != nil {
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

	rs, err := cacheconf.LoadFromString(`ALLOW exact=/test.html methods=GET,HEAD ttl=60 vary=Accept-Encoding`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rs)

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	head1, _ := http.NewRequest(http.MethodHead, srv.URL+"/test.html", nil)
	res1, err := http.DefaultClient.Do(head1)
	if err != nil {
		t.Fatalf("first HEAD failed: %v", err)
	}
	_ = res1.Body.Close()
	if got := res1.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("first HEAD cache header=%q want MISS", got)
	}

	head2, _ := http.NewRequest(http.MethodHead, srv.URL+"/test.html", nil)
	res2, err := http.DefaultClient.Do(head2)
	if err != nil {
		t.Fatalf("second HEAD failed: %v", err)
	}
	_ = res2.Body.Close()
	if got := res2.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("second HEAD cache header=%q want HIT", got)
	}
	if got := headRequests.Load(); got != 1 {
		t.Fatalf("HEAD upstream requests=%d want 1", got)
	}

	res3, err := http.Get(srv.URL + "/test.html")
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	body3, _ := io.ReadAll(res3.Body)
	_ = res3.Body.Close()
	if got := res3.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("GET cache header after HEAD-only cache=%q want MISS", got)
	}
	if string(body3) != "get body" {
		t.Fatalf("GET body=%q want get body", string(body3))
	}
	if got := getRequests.Load(); got != 1 {
		t.Fatalf("GET upstream requests=%d want 1", got)
	}

	head3, _ := http.NewRequest(http.MethodHead, srv.URL+"/test.html", nil)
	res4, err := http.DefaultClient.Do(head3)
	if err != nil {
		t.Fatalf("third HEAD failed: %v", err)
	}
	_ = res4.Body.Close()
	if got := res4.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("third HEAD cache header=%q want HIT", got)
	}
	if got := headRequests.Load(); got != 1 {
		t.Fatalf("HEAD upstream requests after GET cache=%d want 1", got)
	}
}

func TestServeProxyWithCacheBypassesConditionalRequestWithoutMiss(t *testing.T) {
	gin.SetMode(gin.TestMode)

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("ETag", `W/"cache-validator"`)
		if strings.TrimSpace(r.Header.Get("If-None-Match")) != "" {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		_, _ = w.Write([]byte("conditional body"))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{"upstreams":[{"name":"primary","url":`+strconv.Quote(upstream.URL)+`,"weight":1,"enabled":true}]}`), 0o600); err != nil {
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

	rs, err := cacheconf.LoadFromString(`ALLOW prefix=/static methods=GET,HEAD ttl=60 vary=Accept-Encoding`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rs)

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req.Header.Set("If-None-Match", `W/"cache-validator"`)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("conditional request failed: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusNotModified {
		t.Fatalf("status=%d want 304", res.StatusCode)
	}
	if got := res.Header.Get(proxyResponseCacheHeader); got != "" {
		t.Fatalf("cache header=%q want empty", got)
	}
	_, _, _, stats := ResponseCacheSnapshot()
	if stats.Misses != 0 || stats.Stores != 0 || stats.Hits != 0 || stats.EntryCount != 0 {
		t.Fatalf("conditional request should bypass stats, got misses=%d stores=%d hits=%d entries=%d", stats.Misses, stats.Stores, stats.Hits, stats.EntryCount)
	}
}

func TestProxyCacheCookieBypassIgnoresOnlyAdminCookies(t *testing.T) {
	adminOnly := httptest.NewRequest(http.MethodGet, "http://example.test/static/app.js", nil)
	adminOnly.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "admin-session"})
	adminOnly.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: "admin-csrf"})
	adminOnly.AddCookie(&http.Cookie{Name: adminauth.CenterSessionCookieName, Value: "center-session"})
	adminOnly.AddCookie(&http.Cookie{Name: adminauth.CenterCSRFCookieName, Value: "center-csrf"})
	stripAdminAuthCookiesFromProxyRequest(adminOnly)
	if got := adminOnly.Header.Get("Cookie"); got != "" {
		t.Fatalf("admin cookie header after strip=%q want empty", got)
	}
	if shouldBypassProxyResponseCache(adminOnly) {
		t.Fatal("admin-only cookies should not force response cache bypass")
	}

	appCookie := httptest.NewRequest(http.MethodGet, "http://example.test/static/app.js", nil)
	appCookie.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: "admin-session"})
	appCookie.AddCookie(&http.Cookie{Name: "app_session", Value: "user-session"})
	stripAdminAuthCookiesFromProxyRequest(appCookie)
	if got := appCookie.Header.Get("Cookie"); got != "app_session=user-session" {
		t.Fatalf("application cookie header after strip=%q want app_session=user-session", got)
	}
	if !shouldBypassProxyResponseCache(appCookie) {
		t.Fatal("application cookies must still force response cache bypass")
	}
}

func TestServeProxyWithCache_HostScopeReplacesDefault(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("hello host scoped cache"))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{"upstreams":[{"name":"primary","url":`+strconv.Quote(upstream.URL)+`,"weight":1,"enabled":true}]}`), 0o600); err != nil {
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

	rs, err := cacheconf.LoadFromString(`{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": { "type": "prefix", "value": "/static" },
        "methods": ["GET", "HEAD"],
        "ttl": 60
      }
    ]
  },
  "hosts": {
    "admin.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": { "type": "prefix", "value": "/static" },
          "methods": ["GET", "HEAD"],
          "ttl": 60
        }
      ]
    }
  }
}`)
	if err != nil {
		t.Fatalf("load cache rules: %v", err)
	}
	cacheconf.Set(rs)

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req1, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req1.Host = "www.example.com"
	res1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer res1.Body.Close()
	if got := res1.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("www first cache header=%q want MISS", got)
	}

	req2, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req2.Host = "www.example.com"
	res2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("www second cache header=%q want HIT", got)
	}

	req3, _ := http.NewRequest(http.MethodGet, srv.URL+"/static/app.js", nil)
	req3.Host = "admin.example.com"
	res3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("admin request failed: %v", err)
	}
	defer res3.Body.Close()
	if got := res3.Header.Get(proxyResponseCacheHeader); got != "" {
		t.Fatalf("admin cache header=%q want empty", got)
	}
	if got := upstreamRequests.Load(); got != 2 {
		t.Fatalf("upstream requests=%d want 2", got)
	}
}

func TestServeProxyWithMemoryFrontCache(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("memory-front:" + r.URL.Path))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{"upstreams":[{"name":"primary","url":`+strconv.Quote(upstream.URL)+`,"weight":1,"enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	cacheStoreDir := t.TempDir()
	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{
  "enabled": true,
  "store_dir": `+strconv.Quote(cacheStoreDir)+`,
  "max_bytes": 1048576,
  "memory_enabled": true,
  "memory_max_bytes": 4096,
  "memory_max_entries": 8
}`), 0o600); err != nil {
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

	res1, err := http.Get(srv.URL + "/static/a.js")
	if err != nil {
		t.Fatalf("first request failed: %v", err)
	}
	defer res1.Body.Close()
	if got := res1.Header.Get(proxyResponseCacheHeader); got != "MISS" {
		t.Fatalf("first cache header=%q want MISS", got)
	}

	res2, err := http.Get(srv.URL + "/static/a.js")
	if err != nil {
		t.Fatalf("second request failed: %v", err)
	}
	defer res2.Body.Close()
	if got := res2.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("second cache header=%q want HIT", got)
	}
	if got := upstreamRequests.Load(); got != 1 {
		t.Fatalf("upstream requests=%d want 1", got)
	}

	_, _, _, stats := ResponseCacheSnapshot()
	if !stats.MemoryEnabled {
		t.Fatal("expected memory cache enabled")
	}
	if stats.MemoryEntryCount != 1 {
		t.Fatalf("memory entry count=%d want 1", stats.MemoryEntryCount)
	}
	if stats.MemoryHits != 1 {
		t.Fatalf("memory hits=%d want 1", stats.MemoryHits)
	}
	if stats.MemoryStores != 1 {
		t.Fatalf("memory stores=%d want 1", stats.MemoryStores)
	}
}

func TestServeProxyWithMemoryFrontFallsBackToDisk(t *testing.T) {
	gin.SetMode(gin.TestMode)

	var upstreamRequests atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamRequests.Add(1)
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(strings.Repeat(r.URL.Path+" ", 16)))
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	if err := os.WriteFile(proxyCfgPath, []byte(`{"upstreams":[{"name":"primary","url":`+strconv.Quote(upstream.URL)+`,"weight":1,"enabled":true}]}`), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 8); err != nil {
		t.Fatalf("init proxy runtime: %v", err)
	}

	cacheStoreDir := t.TempDir()
	cacheStoreCfgPath := filepath.Join(t.TempDir(), "cache-store.json")
	if err := os.WriteFile(cacheStoreCfgPath, []byte(`{
  "enabled": true,
  "store_dir": `+strconv.Quote(cacheStoreDir)+`,
  "max_bytes": 1048576,
  "memory_enabled": true,
  "memory_max_bytes": 4096,
  "memory_max_entries": 1
}`), 0o600); err != nil {
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

	for _, path := range []string{"/static/a.js", "/static/b.js"} {
		res, err := http.Get(srv.URL + path)
		if err != nil {
			t.Fatalf("prime request failed for %s: %v", path, err)
		}
		if got := res.Header.Get(proxyResponseCacheHeader); got != "MISS" {
			t.Fatalf("prime cache header for %s = %q want MISS", path, got)
		}
		_ = res.Body.Close()
	}

	res3, err := http.Get(srv.URL + "/static/a.js")
	if err != nil {
		t.Fatalf("fallback request failed: %v", err)
	}
	defer res3.Body.Close()
	if got := res3.Header.Get(proxyResponseCacheHeader); got != "HIT" {
		t.Fatalf("fallback cache header=%q want HIT", got)
	}
	if got := upstreamRequests.Load(); got != 2 {
		t.Fatalf("upstream requests=%d want 2", got)
	}

	_, _, _, stats := ResponseCacheSnapshot()
	if stats.MemoryEntryCount != 1 {
		t.Fatalf("memory entry count=%d want 1", stats.MemoryEntryCount)
	}
	if stats.MemoryEvictions == 0 {
		t.Fatal("expected memory eviction after second key")
	}
	if stats.MemoryMisses == 0 {
		t.Fatal("expected memory miss when rehydrating from disk")
	}
}
