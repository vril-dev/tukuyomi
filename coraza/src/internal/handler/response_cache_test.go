package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/corazawaf/coraza/v3"
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

func TestProxyHandlerServesResponseFromInMemoryCache(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("X-Upstream-Hit", "true")
		_, _ = w.Write([]byte("hello-from-upstream-" + string(rune('0'+n))))
	}))
	defer upstream.Close()

	config.AppURL = upstream.URL
	config.APIBasePath = "/tukuyomi-api"
	config.ForwardInternalResponseHeaders = false
	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	ConfigureResponseCache()
	cacheconf.Set(&cacheconf.Ruleset{
		Rules: []cacheconf.Rule{{
			Kind:    "ALLOW",
			Prefix:  "/",
			Methods: map[string]bool{"GET": true, "HEAD": true},
			TTL:     60,
		}},
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	res1 := mustProxyRequest(t, srv.URL+"/hello", "", "")
	if got := res1.Header.Get(responseCacheStatusHeader); got != responseCacheStatusMiss {
		t.Fatalf("first response cache status=%q want=%q", got, responseCacheStatusMiss)
	}
	body1 := readBody(t, res1)
	if body1 != "hello-from-upstream-1" {
		t.Fatalf("first body=%q", body1)
	}

	res2 := mustProxyRequest(t, srv.URL+"/hello", "", "")
	if got := res2.Header.Get(responseCacheStatusHeader); got != responseCacheStatusHit {
		t.Fatalf("second response cache status=%q want=%q", got, responseCacheStatusHit)
	}
	body2 := readBody(t, res2)
	if body2 != body1 {
		t.Fatalf("cached body=%q want=%q", body2, body1)
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want=1", got)
	}
}

func TestProxyHandlerDoesNotStoreSetCookieResponses(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "cookie"})
		_, _ = w.Write([]byte("set-cookie-" + string(rune('0'+n))))
	}))
	defer upstream.Close()

	config.AppURL = upstream.URL
	config.APIBasePath = "/tukuyomi-api"
	config.ForwardInternalResponseHeaders = false
	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	ConfigureResponseCache()
	cacheconf.Set(&cacheconf.Ruleset{
		Rules: []cacheconf.Rule{{
			Kind:    "ALLOW",
			Prefix:  "/",
			Methods: map[string]bool{"GET": true, "HEAD": true},
			TTL:     60,
		}},
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	res1 := mustProxyRequest(t, srv.URL+"/session", "", "")
	if got := res1.Header.Get(responseCacheStatusHeader); got != responseCacheStatusBypass {
		t.Fatalf("first response cache status=%q want=%q", got, responseCacheStatusBypass)
	}
	_ = readBody(t, res1)

	res2 := mustProxyRequest(t, srv.URL+"/session", "", "")
	if got := res2.Header.Get(responseCacheStatusHeader); got != responseCacheStatusBypass {
		t.Fatalf("second response cache status=%q want=%q", got, responseCacheStatusBypass)
	}
	_ = readBody(t, res2)

	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream hits=%d want=2", got)
	}
}

func TestBuildResponseCachePlanRejectsUnsafeRequests(t *testing.T) {
	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	ConfigureResponseCache()
	cacheconf.Set(&cacheconf.Ruleset{
		Rules: []cacheconf.Rule{{
			Kind:    "ALLOW",
			Prefix:  "/",
			Methods: map[string]bool{"GET": true, "HEAD": true},
			TTL:     60,
		}},
	})

	reqAuth := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	reqAuth.Header.Set("Authorization", "Bearer demo")
	if plan := buildResponseCachePlan(reqAuth); plan != nil {
		t.Fatal("authorization request should bypass response cache")
	}

	reqCookie := httptest.NewRequest(http.MethodGet, "http://example.test/private", nil)
	reqCookie.Header.Set("Cookie", "sid=demo")
	if plan := buildResponseCachePlan(reqCookie); plan != nil {
		t.Fatal("cookie request should bypass response cache")
	}

	reqPost := httptest.NewRequest(http.MethodPost, "http://example.test/private", nil)
	if plan := buildResponseCachePlan(reqPost); plan != nil {
		t.Fatal("post request should bypass response cache")
	}
}

func saveResponseCacheRuntimeConfig() func() {
	oldAppURL := config.AppURL
	oldAPIBasePath := config.APIBasePath
	oldForwardInternal := config.ForwardInternalResponseHeaders
	oldMode := config.ResponseCacheMode
	oldMaxEntries := config.ResponseCacheMaxEntries
	oldMaxBodyBytes := config.ResponseCacheMaxBodyBytes
	oldProxy := proxy
	oldOnce := proxyInitOnce
	oldWAF := waf.WAF
	oldRules := cacheconf.Get()

	testWAF, err := coraza.NewWAF(coraza.NewWAFConfig())
	if err == nil {
		waf.WAF = testWAF
	}
	proxy = nil
	proxyInitOnce = sync.Once{}

	return func() {
		config.AppURL = oldAppURL
		config.APIBasePath = oldAPIBasePath
		config.ForwardInternalResponseHeaders = oldForwardInternal
		config.ResponseCacheMode = oldMode
		config.ResponseCacheMaxEntries = oldMaxEntries
		config.ResponseCacheMaxBodyBytes = oldMaxBodyBytes
		proxy = oldProxy
		proxyInitOnce = oldOnce
		waf.WAF = oldWAF
		if oldRules != nil {
			cacheconf.Set(oldRules)
		} else {
			cacheconf.Set(&cacheconf.Ruleset{})
		}
		ConfigureResponseCache()
	}
}

func mustProxyRequest(t *testing.T, url, authHeader, cookieHeader string) *http.Response {
	t.Helper()

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "protected.example.test"
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	return res
}

func readBody(t *testing.T, res *http.Response) string {
	t.Helper()
	defer res.Body.Close()
	body, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	return string(body)
}
