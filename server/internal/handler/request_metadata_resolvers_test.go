package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
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
  ]
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
  ]
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
