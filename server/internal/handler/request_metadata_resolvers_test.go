package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"

	"tukuyomi/internal/config"
	"tukuyomi/internal/requestmeta"
)

type testRequestMetadataResolver struct {
	name    string
	resolve func(*http.Request, *requestmeta.ResolverContext) error
}

func (r testRequestMetadataResolver) Name() string {
	return r.name
}

func (r testRequestMetadataResolver) Resolve(req *http.Request, ctx *requestmeta.ResolverContext) error {
	if r.resolve == nil {
		return nil
	}
	return r.resolve(req, ctx)
}

func initMMDBRequestMetadataRuntimeForTest(t *testing.T) {
	t.Helper()
	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		reader, err := maxminddb.FromBytes(loadSampleCountryMMDBBytes(t))
		if err != nil {
			return loadedRequestCountryMMDBState{}, err
		}
		return loadedRequestCountryMMDBState{
			Reader:      reader,
			ManagedPath: managedRequestCountryMMDBPath(),
			VersionID:   1,
			VersionETag: "test",
			SizeBytes:   1,
		}, nil
	}
	t.Cleanup(func() {
		requestCountryMMDBLoader = prevLoader
		requestmeta.CloseCountryRuntime()
	})
	if err := reloadRequestCountryRuntime("mmdb"); err != nil {
		t.Fatalf("reloadRequestCountryRuntime: %v", err)
	}
}

func TestNewRequestMetadataResolversBuiltins(t *testing.T) {
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "header"
	t.Cleanup(func() { config.RequestCountryMode = prevMode })

	resolvers := newRequestMetadataResolvers()
	if len(resolvers) != 2 {
		t.Fatalf("resolver count=%d want=2", len(resolvers))
	}
	if got := resolvers[0].Name(); got != "header_country" {
		t.Fatalf("resolver[0]=%q want=%q", got, "header_country")
	}
	if got := resolvers[1].Name(); got != "mmdb_country" {
		t.Fatalf("resolver[1]=%q want=%q", got, "mmdb_country")
	}
}

func TestRunRequestMetadataResolversResolvesCountryFromHeader(t *testing.T) {
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "header"
	t.Cleanup(func() { config.RequestCountryMode = prevMode })

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)
	c.Request.Header.Set("X-Country-Code", "jp")

	ctx := requestmeta.NewResolverContext("10.0.0.1")
	ctx.PeerTrusted = true
	if err := requestmeta.RunResolvers(c.Request, newRequestMetadataResolvers(), ctx); err != nil {
		t.Fatalf("RunResolvers() error: %v", err)
	}
	if ctx.Country != "JP" {
		t.Fatalf("country=%q want=%q", ctx.Country, "JP")
	}
	if ctx.CountrySource != requestmeta.CountrySourceHeader {
		t.Fatalf("countrySource=%q want=%q", ctx.CountrySource, requestmeta.CountrySourceHeader)
	}
}

func TestRunRequestMetadataResolversResolvesCountryFromMMDBRuntime(t *testing.T) {
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "mmdb"
	t.Cleanup(func() { config.RequestCountryMode = prevMode })
	initMMDBRequestMetadataRuntimeForTest(t)

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	ctx := requestmeta.NewResolverContext("203.0.113.9")
	if err := requestmeta.RunResolvers(c.Request, newRequestMetadataResolvers(), ctx); err != nil {
		t.Fatalf("RunResolvers() error: %v", err)
	}
	if ctx.Country != "JP" {
		t.Fatalf("country=%q want=%q", ctx.Country, "JP")
	}
	if ctx.CountrySource != requestmeta.CountrySourceMMDB {
		t.Fatalf("countrySource=%q want=%q", ctx.CountrySource, requestmeta.CountrySourceMMDB)
	}
}

func TestRunRequestMetadataResolversBeforeRequestSecurityPluginUse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	metadataCtx := requestmeta.NewResolverContext("10.0.0.1")
	order := make([]string, 0, 2)
	resolvers := []requestmeta.Resolver{
		testRequestMetadataResolver{
			name: "first",
			resolve: func(_ *http.Request, ctx *requestmeta.ResolverContext) error {
				order = append(order, "metadata")
				ctx.Country = "JP"
				ctx.CountrySource = requestmeta.CountrySourceHeader
				return nil
			},
		},
	}
	if err := requestmeta.RunResolvers(c.Request, resolvers, metadataCtx); err != nil {
		t.Fatalf("RunResolvers() error: %v", err)
	}

	var pluginSawCountry string
	plugins := []requestSecurityPlugin{
		testRequestSecurityPlugin{
			name:    "active",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, ctx *requestSecurityPluginContext) bool {
				order = append(order, "security")
				pluginSawCountry = ctx.Country
				return true
			},
		},
	}
	securityCtx := newRequestSecurityPluginContext("req-1", metadataCtx.ClientIP, metadataCtx.Country, time.Unix(1, 0))
	if ok := runRequestSecurityPlugins(newProxyServeContextFromGin(c), requestSecurityPluginPhasePreWAF, plugins, securityCtx); !ok {
		t.Fatal("expected request_security plugin chain to continue")
	}
	if len(order) != 2 || order[0] != "metadata" || order[1] != "security" {
		t.Fatalf("unexpected order: %#v", order)
	}
	if pluginSawCountry != "JP" {
		t.Fatalf("plugin saw country=%q want=%q", pluginSawCountry, "JP")
	}
}

func TestProxyHandlerCountryBlockUsesResolvedCountryFromMetadataResolver(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "header"
	defer func() { config.RequestCountryMode = prevMode }()

	restoreCountry := saveCountryBlockStateForTest()
	defer restoreCountry()
	trustForwardedClientIPForTest(t, requestmeta.HeaderXForwardedFor, "127.0.0.0/8", "::1/128")

	countryPath := filepath.Join(t.TempDir(), "country-block.conf")
	if err := os.WriteFile(countryPath, []byte("JP\n"), 0o600); err != nil {
		t.Fatalf("write country block file: %v", err)
	}
	if err := InitCountryBlock(countryPath, ""); err != nil {
		t.Fatalf("InitCountryBlock() error: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}}
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime() error: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	req, err := http.NewRequest(http.MethodGet, srv.URL+"/demo", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("X-Country-Code", "jp")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", res.StatusCode, http.StatusForbidden)
	}

	config.ServerForwardedClientIPEnabled = false
	if err := InitClientIPRuntime(); err != nil {
		t.Fatalf("InitClientIPRuntime: %v", err)
	}
	untrustedReq, err := http.NewRequest(http.MethodGet, srv.URL+"/demo", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	untrustedReq.Header.Set("X-Country-Code", "jp")
	untrustedRes, err := http.DefaultClient.Do(untrustedReq)
	if err != nil {
		t.Fatalf("do untrusted request: %v", err)
	}
	defer untrustedRes.Body.Close()
	if untrustedRes.StatusCode != http.StatusOK {
		t.Fatalf("country header from an untrusted peer status=%d want=%d", untrustedRes.StatusCode, http.StatusOK)
	}
}

func TestProxyHandlerRateLimitUsesResolvedCountryFromMMDBMetadata(t *testing.T) {
	gin.SetMode(gin.TestMode)
	prevMode := config.RequestCountryMode
	config.RequestCountryMode = "mmdb"
	defer func() { config.RequestCountryMode = prevMode }()

	restoreRateLimit := saveRateLimitStateForTest()
	defer restoreRateLimit()
	initMMDBRequestMetadataRuntimeForTest(t)

	rateLimitPath := filepath.Join(t.TempDir(), "rate-limit.json")
	rateLimitRaw := `{
  "enabled": true,
  "default_policy": {
    "enabled": true,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "country",
    "action": {
      "status": 429,
      "retry_after_seconds": 60
    }
  }
}`
	if err := os.WriteFile(rateLimitPath, []byte(rateLimitRaw), 0o600); err != nil {
		t.Fatalf("write rate limit file: %v", err)
	}
	if err := InitRateLimit(rateLimitPath); err != nil {
		t.Fatalf("InitRateLimit() error: %v", err)
	}

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}}
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime() error: %v", err)
	}

	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	for i, want := range []int{http.StatusOK, http.StatusTooManyRequests} {
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/demo", nil)
		if err != nil {
			t.Fatalf("new request %d: %v", i, err)
		}
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request %d: %v", i, err)
		}
		_ = res.Body.Close()
		if res.StatusCode != want {
			t.Fatalf("request %d status=%d want=%d", i, res.StatusCode, want)
		}
	}
}

// trustForwardedClientIPForTest trusts forwarded headers from the given
// CIDRs (httptest servers connect from loopback) and restores the runtime.
func trustForwardedClientIPForTest(t *testing.T, header string, cidrs ...string) {
	t.Helper()
	prevEnabled := config.ServerForwardedClientIPEnabled
	prevHeader := config.ServerForwardedClientIPHeader
	prevCIDRs := append([]string(nil), config.ServerForwardedClientIPTrustedCIDRs...)
	t.Cleanup(func() {
		config.ServerForwardedClientIPEnabled = prevEnabled
		config.ServerForwardedClientIPHeader = prevHeader
		config.ServerForwardedClientIPTrustedCIDRs = prevCIDRs
		if err := InitClientIPRuntime(); err != nil {
			t.Errorf("restore InitClientIPRuntime: %v", err)
		}
	})
	config.ServerForwardedClientIPEnabled = true
	config.ServerForwardedClientIPHeader = header
	config.ServerForwardedClientIPTrustedCIDRs = cidrs
	if err := InitClientIPRuntime(); err != nil {
		t.Fatalf("InitClientIPRuntime: %v", err)
	}
}

func TestInitClientIPRuntimeRejectsInvalidSettings(t *testing.T) {
	prevEnabled := config.ServerForwardedClientIPEnabled
	prevHeader := config.ServerForwardedClientIPHeader
	prevCIDRs := append([]string(nil), config.ServerForwardedClientIPTrustedCIDRs...)
	defer func() {
		config.ServerForwardedClientIPEnabled = prevEnabled
		config.ServerForwardedClientIPHeader = prevHeader
		config.ServerForwardedClientIPTrustedCIDRs = prevCIDRs
		_ = InitClientIPRuntime()
	}()
	for _, tc := range []struct {
		header string
		cidrs  []string
		want   string
	}{
		{header: "X-Forwarded-For", cidrs: nil, want: "trusted_cidrs is required"},
		{header: "X-Forwarded-For", cidrs: []string{"10.0.0.0/33"}, want: "invalid CIDR"},
		{header: "Forwarded", cidrs: []string{"10.0.0.0/8"}, want: "header must be one of"},
	} {
		config.ServerForwardedClientIPEnabled = true
		config.ServerForwardedClientIPHeader = tc.header
		config.ServerForwardedClientIPTrustedCIDRs = tc.cidrs
		if err := InitClientIPRuntime(); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("InitClientIPRuntime(%q, %v) err=%v want %q", tc.header, tc.cidrs, err, tc.want)
		}
	}
}

func TestResolveProxyClientIPUsesTrustedProxyHeader(t *testing.T) {
	trustForwardedClientIPForTest(t, requestmeta.HeaderXForwardedFor, "127.0.0.0/8")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:4000"
	req.Header.Set("X-Forwarded-For", "10.0.0.5, 198.51.100.7")
	req.Header.Set("X-Real-IP", "10.0.0.6")
	if got, trusted := resolveProxyClientIP(req); got != "198.51.100.7" || !trusted {
		t.Fatalf("resolveProxyClientIP=%q trusted=%v want 198.51.100.7 true", got, trusted)
	}

	req.RemoteAddr = "203.0.113.9:4000"
	if got, trusted := resolveProxyClientIP(req); got != "203.0.113.9" || trusted {
		t.Fatalf("untrusted peer resolveProxyClientIP=%q trusted=%v want 203.0.113.9 false", got, trusted)
	}
}

func TestResolveProxyClientIPIgnoresHeadersByDefaultAndWarnsOncePerMinute(t *testing.T) {
	if err := InitClientIPRuntime(); err != nil {
		t.Fatalf("InitClientIPRuntime: %v", err)
	}
	lastIgnoredForwardedHeaderWarning.Store(0)

	var logs bytes.Buffer
	prevOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOutput)

	for i := 0; i < 3; i++ {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		req.Header.Set("X-Forwarded-For", "198.51.100.7\nforged")
		if got, trusted := resolveProxyClientIP(req); got != "203.0.113.9" || trusted {
			t.Fatalf("resolveProxyClientIP=%q trusted=%v want the peer", got, trusted)
		}
	}
	if got := strings.Count(logs.String(), "[PROXY][CLIENT_IP][WARN]"); got != 1 {
		t.Fatalf("warnings=%d want 1 logs=%s", got, logs.String())
	}
	if strings.Contains(logs.String(), "198.51.100.7") || strings.Contains(logs.String(), "forged") {
		t.Fatalf("warning logged the header value: %s", logs.String())
	}
}

func TestProxyRouteSelectionValueClientIPUsesResolvedAddress(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4000"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	if got := proxyRouteSelectionValue(req, "client_ip", ""); got != "203.0.113.9" {
		t.Fatalf("client_ip hash value without a resolved address=%q want the peer", got)
	}
	gin.SetMode(gin.TestMode)
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = req
	pc := newProxyServeContextFromGin(c)
	setWAFContext(pc, "req-1", "198.51.100.20", "UNKNOWN", requestmeta.CountrySourceUnknown, false, "")
	if got := proxyRouteSelectionValue(pc.Request, "client_ip", ""); got != "198.51.100.20" {
		t.Fatalf("client_ip hash value=%q want the resolved address", got)
	}
}

func TestProxyHandlerRateLimitKeysOnResolvedClientIP(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreRateLimit := saveRateLimitStateForTest()
	defer restoreRateLimit()
	if err := InitClientIPRuntime(); err != nil {
		t.Fatalf("InitClientIPRuntime: %v", err)
	}

	rateLimitPath := filepath.Join(t.TempDir(), "rate-limit.json")
	rateLimitRaw := `{
  "enabled": true,
  "default_policy": {
    "enabled": true,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {
      "status": 429,
      "retry_after_seconds": 60
    }
  }
}`
	if err := os.WriteFile(rateLimitPath, []byte(rateLimitRaw), 0o600); err != nil {
		t.Fatalf("write rate limit file: %v", err)
	}
	if err := InitRateLimit(rateLimitPath); err != nil {
		t.Fatalf("InitRateLimit() error: %v", err)
	}
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()
	proxyCfgPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": ` + strconv.Quote(upstream.URL) + `, "weight": 1, "enabled": true }
  ],
  "default_route": {"name":"fallback","action":{"upstream":"primary"}}
}`
	if err := os.WriteFile(proxyCfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyCfgPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime() error: %v", err)
	}
	r := gin.New()
	r.NoRoute(ProxyHandler)
	srv := httptest.NewServer(r)
	defer srv.Close()

	send := func(forwardedFor string) int {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, srv.URL+"/demo", nil)
		if err != nil {
			t.Fatalf("new request: %v", err)
		}
		req.Header.Set("X-Forwarded-For", forwardedFor)
		req.Header.Set("X-Real-IP", forwardedFor)
		res, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("do request: %v", err)
		}
		_ = res.Body.Close()
		return res.StatusCode
	}

	// Untrusted peer: changing the headers does not give a new bucket.
	if got := send("198.51.100.1"); got != http.StatusOK {
		t.Fatalf("first untrusted request status=%d want=%d", got, http.StatusOK)
	}
	if got := send("198.51.100.2"); got != http.StatusTooManyRequests {
		t.Fatalf("second untrusted request with a new header value status=%d want=%d", got, http.StatusTooManyRequests)
	}

	// Trusted proxy: each forwarded client has its own bucket.
	trustForwardedClientIPForTest(t, requestmeta.HeaderXForwardedFor, "127.0.0.0/8", "::1/128")
	for _, client := range []string{"198.51.100.3", "198.51.100.4"} {
		if got := send(client); got != http.StatusOK {
			t.Fatalf("trusted proxy request for %s status=%d want=%d", client, got, http.StatusOK)
		}
	}
	if got := send("198.51.100.3"); got != http.StatusTooManyRequests {
		t.Fatalf("repeat trusted proxy request status=%d want=%d", got, http.StatusTooManyRequests)
	}
}
