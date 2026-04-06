package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

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
	config.ResponseCacheStaleSeconds = 30
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = time.Second
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
	config.ResponseCacheStaleSeconds = 30
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = time.Second
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
	config.ResponseCacheStaleSeconds = 30
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = time.Second
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

func TestProxyHandlerCoalescesConcurrentCacheMisses(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHits.Add(1)
		time.Sleep(150 * time.Millisecond)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = w.Write([]byte("shared-cache-body"))
	}))
	defer upstream.Close()

	config.AppURL = upstream.URL
	config.APIBasePath = "/tukuyomi-api"
	config.ForwardInternalResponseHeaders = false
	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	config.ResponseCacheStaleSeconds = 30
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = time.Second
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

	const requestCount = 6
	start := make(chan struct{})
	type result struct {
		status string
		body   string
		err    error
	}
	results := make(chan result, requestCount)

	var wg sync.WaitGroup
	for i := 0; i < requestCount; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			res, err := mustProxyRequestWithClient(http.DefaultClient, srv.URL+"/coalesced", "", "")
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{
				status: res.Header.Get(responseCacheStatusHeader),
				body:   readBody(t, res),
			}
		}()
	}

	close(start)
	wg.Wait()
	close(results)

	missCount := 0
	hitCount := 0
	for r := range results {
		if r.err != nil {
			t.Fatalf("proxy request failed: %v", r.err)
		}
		if r.body != "shared-cache-body" {
			t.Fatalf("unexpected cached body %q", r.body)
		}
		switch r.status {
		case responseCacheStatusMiss:
			missCount++
		case responseCacheStatusHit:
			hitCount++
		default:
			t.Fatalf("unexpected cache status %q", r.status)
		}
	}

	if got := upstreamHits.Load(); got != 1 {
		t.Fatalf("upstream hits=%d want=1", got)
	}
	if missCount != 1 {
		t.Fatalf("miss count=%d want=1", missCount)
	}
	if hitCount != requestCount-1 {
		t.Fatalf("hit count=%d want=%d", hitCount, requestCount-1)
	}

	status := GetResponseCacheStatus()
	if status.CoalescedWaits < requestCount-1 {
		t.Fatalf("coalesced waits=%d want-at-least=%d", status.CoalescedWaits, requestCount-1)
	}
	if status.Misses != 1 {
		t.Fatalf("miss metric=%d want=1", status.Misses)
	}
}

func TestProxyHandlerServesStaleAndRefreshesInBackground(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	refreshStarted := make(chan struct{}, 1)
	allowRefresh := make(chan struct{})
	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch n {
		case 1:
			_, _ = w.Write([]byte("body-v1"))
		default:
			select {
			case refreshStarted <- struct{}{}:
			default:
			}
			<-allowRefresh
			_, _ = w.Write([]byte("body-v2"))
		}
	}))
	defer upstream.Close()

	config.AppURL = upstream.URL
	config.APIBasePath = "/tukuyomi-api"
	config.ForwardInternalResponseHeaders = false
	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	config.ResponseCacheStaleSeconds = 5
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = 2 * time.Second
	ConfigureResponseCache()
	cacheconf.Set(&cacheconf.Ruleset{
		Rules: []cacheconf.Rule{{
			Kind:    "ALLOW",
			Prefix:  "/",
			Methods: map[string]bool{"GET": true, "HEAD": true},
			TTL:     1,
		}},
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	res1 := mustProxyRequest(t, srv.URL+"/stale", "", "")
	if got := res1.Header.Get(responseCacheStatusHeader); got != responseCacheStatusMiss {
		t.Fatalf("first response cache status=%q want=%q", got, responseCacheStatusMiss)
	}
	if body := readBody(t, res1); body != "body-v1" {
		t.Fatalf("first body=%q", body)
	}

	time.Sleep(1100 * time.Millisecond)

	type result struct {
		res  *http.Response
		err  error
	}
	resultCh := make(chan result, 1)
	go func() {
		res, err := mustProxyRequestWithClient(http.DefaultClient, srv.URL+"/stale", "", "")
		resultCh <- result{res: res, err: err}
	}()

	var staleRes *http.Response
	select {
	case got := <-resultCh:
		if got.err != nil {
			t.Fatalf("stale request failed: %v", got.err)
		}
		staleRes = got.res
	case <-time.After(200 * time.Millisecond):
		t.Fatal("stale serve blocked on background refresh")
	}

	if got := staleRes.Header.Get(responseCacheStatusHeader); got != responseCacheStatusStale {
		t.Fatalf("stale response cache status=%q want=%q", got, responseCacheStatusStale)
	}
	if body := readBody(t, staleRes); body != "body-v1" {
		t.Fatalf("stale body=%q want=%q", body, "body-v1")
	}

	select {
	case <-refreshStarted:
	case <-time.After(200 * time.Millisecond):
		t.Fatal("background refresh did not start")
	}
	close(allowRefresh)

	deadline := time.Now().Add(time.Second)
	for upstreamHits.Load() < 2 || GetResponseCacheStatus().Stores < 2 {
		if time.Now().After(deadline) {
			t.Fatal("background refresh did not store the refreshed entry in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	res3 := mustProxyRequest(t, srv.URL+"/stale", "", "")
	if got := res3.Header.Get(responseCacheStatusHeader); got != responseCacheStatusHit {
		t.Fatalf("refreshed response cache status=%q want=%q", got, responseCacheStatusHit)
	}
	if body := readBody(t, res3); body != "body-v2" {
		t.Fatalf("refreshed body=%q want=%q", body, "body-v2")
	}

	status := GetResponseCacheStatus()
	if status.StaleHits < 1 {
		t.Fatalf("stale hits=%d want>=1", status.StaleHits)
	}
	if status.StaleRefreshes < 1 {
		t.Fatalf("stale refreshes=%d want>=1", status.StaleRefreshes)
	}
	if status.StaleFailures != 0 {
		t.Fatalf("stale failures=%d want=0", status.StaleFailures)
	}
}

func TestProxyHandlerKeepsServingStaleAfterRefreshFailure(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveResponseCacheRuntimeConfig()
	defer restore()

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := upstreamHits.Add(1)
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if n == 1 {
			_, _ = w.Write([]byte("body-v1"))
			return
		}
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte("upstream-failed"))
	}))
	defer upstream.Close()

	config.AppURL = upstream.URL
	config.APIBasePath = "/tukuyomi-api"
	config.ForwardInternalResponseHeaders = false
	config.ResponseCacheMode = "memory"
	config.ResponseCacheMaxEntries = 16
	config.ResponseCacheMaxBodyBytes = 4096
	config.ResponseCacheStaleSeconds = 5
	config.ResponseCacheRefreshTimeout = time.Second
	config.ResponseCacheRefreshBackoff = 2 * time.Second
	ConfigureResponseCache()
	cacheconf.Set(&cacheconf.Ruleset{
		Rules: []cacheconf.Rule{{
			Kind:    "ALLOW",
			Prefix:  "/",
			Methods: map[string]bool{"GET": true, "HEAD": true},
			TTL:     1,
		}},
	})

	router := gin.New()
	router.Any("/*path", ProxyHandler)
	srv := httptest.NewServer(router)
	defer srv.Close()

	res1 := mustProxyRequest(t, srv.URL+"/stale-fail", "", "")
	if got := res1.Header.Get(responseCacheStatusHeader); got != responseCacheStatusMiss {
		t.Fatalf("first response cache status=%q want=%q", got, responseCacheStatusMiss)
	}
	if body := readBody(t, res1); body != "body-v1" {
		t.Fatalf("first body=%q", body)
	}

	time.Sleep(1100 * time.Millisecond)

	res2 := mustProxyRequest(t, srv.URL+"/stale-fail", "", "")
	if got := res2.Header.Get(responseCacheStatusHeader); got != responseCacheStatusStale {
		t.Fatalf("second response cache status=%q want=%q", got, responseCacheStatusStale)
	}
	if body := readBody(t, res2); body != "body-v1" {
		t.Fatalf("stale body after refresh failure=%q want=%q", body, "body-v1")
	}

	deadline := time.Now().Add(time.Second)
	for {
		status := GetResponseCacheStatus()
		if upstreamHits.Load() >= 2 && status.StaleFailures >= 1 && status.InflightKeys == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("refresh failure attempt did not settle in time")
		}
		time.Sleep(10 * time.Millisecond)
	}

	res3 := mustProxyRequest(t, srv.URL+"/stale-fail", "", "")
	if got := res3.Header.Get(responseCacheStatusHeader); got != responseCacheStatusStale {
		t.Fatalf("third response cache status=%q want=%q", got, responseCacheStatusStale)
	}
	if body := readBody(t, res3); body != "body-v1" {
		t.Fatalf("stale body should remain after refresh failure, got=%q", body)
	}

	status := GetResponseCacheStatus()
	if got := upstreamHits.Load(); got != 2 {
		t.Fatalf("upstream hits during backoff=%d want=2", got)
	}
	if status.StaleFailures < 1 {
		t.Fatalf("stale failures=%d want>=1", status.StaleFailures)
	}
	if status.BackoffSkips < 1 {
		t.Fatalf("backoff skips=%d want>=1", status.BackoffSkips)
	}

	time.Sleep(2100 * time.Millisecond)

	res4 := mustProxyRequest(t, srv.URL+"/stale-fail", "", "")
	if got := res4.Header.Get(responseCacheStatusHeader); got != responseCacheStatusStale {
		t.Fatalf("fourth response cache status=%q want=%q", got, responseCacheStatusStale)
	}
	if body := readBody(t, res4); body != "body-v1" {
		t.Fatalf("stale body after backoff expiry should remain old body, got=%q", body)
	}

	deadline = time.Now().Add(time.Second)
	for upstreamHits.Load() < 3 || GetResponseCacheStatus().StaleFailures < 2 {
		if time.Now().After(deadline) {
			t.Fatal("refresh retry after backoff did not complete in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func saveResponseCacheRuntimeConfig() func() {
	oldAppURL := config.AppURL
	oldAPIBasePath := config.APIBasePath
	oldForwardInternal := config.ForwardInternalResponseHeaders
	oldMode := config.ResponseCacheMode
	oldMaxEntries := config.ResponseCacheMaxEntries
	oldMaxBodyBytes := config.ResponseCacheMaxBodyBytes
	oldStaleSeconds := config.ResponseCacheStaleSeconds
	oldRefreshTimeout := config.ResponseCacheRefreshTimeout
	oldRefreshBackoff := config.ResponseCacheRefreshBackoff
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
		config.ResponseCacheStaleSeconds = oldStaleSeconds
		config.ResponseCacheRefreshTimeout = oldRefreshTimeout
		config.ResponseCacheRefreshBackoff = oldRefreshBackoff
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

	res, err := mustProxyRequestWithClient(http.DefaultClient, url, authHeader, cookieHeader)
	if err != nil {
		t.Fatalf("proxy request failed: %v", err)
	}
	return res
}

func mustProxyRequestWithClient(client *http.Client, url, authHeader, cookieHeader string) (*http.Response, error) {
	if client == nil {
		client = http.DefaultClient
	}

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Host = "protected.example.test"
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}
	if cookieHeader != "" {
		req.Header.Set("Cookie", cookieHeader)
	}

	return client.Do(req)
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
