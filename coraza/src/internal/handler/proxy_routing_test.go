package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustValidateProxyRulesRaw(t *testing.T, raw string) ProxyRulesConfig {
	t.Helper()
	cfg, err := ValidateProxyRulesRaw(raw)
	if err != nil {
		t.Fatalf("ValidateProxyRulesRaw: %v", err)
	}
	return cfg
}

func mustResolveProxyRouteDecision(t *testing.T, cfg ProxyRulesConfig, host string, path string) proxyRouteDecision {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, "http://proxy.local"+path, nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Host = host
	decision, err := resolveProxyRouteDecision(req, cfg, nil)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	return decision
}

func TestValidateProxyRulesRawWithRoutes(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "svc-a", "url": "http://127.0.0.1:8081", "enabled": true },
    { "name": "fallback", "url": "http://127.0.0.1:8082", "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["API.EXAMPLE.COM.", "*.EXAMPLE.NET."],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "svc-a",
        "path_rewrite": { "prefix": "/service-a/" },
        "request_headers": {
          "set": { "X-Service": "service-a" },
          "add": { "X-Route": "service-a" },
          "remove": ["X-Debug"]
        },
        "response_headers": {
          "set": { "x-frame-options": "DENY" },
          "remove": ["x-powered-by"]
        }
      }
    }
  ],
  "default_route": {
    "name": "fallback",
    "action": {
      "upstream": "fallback"
    }
  }
}`

	cfg := mustValidateProxyRulesRaw(t, raw)
	if len(cfg.Routes) != 1 {
		t.Fatalf("routes=%d", len(cfg.Routes))
	}
	if cfg.Routes[0].Match.Path == nil || cfg.Routes[0].Match.Path.Value != "/servicea" {
		t.Fatalf("unexpected normalized path match: %#v", cfg.Routes[0].Match.Path)
	}
	if cfg.Routes[0].Match.Hosts[0] != "api.example.com" || cfg.Routes[0].Match.Hosts[1] != "*.example.net" {
		t.Fatalf("unexpected normalized hosts: %#v", cfg.Routes[0].Match.Hosts)
	}
	if cfg.Routes[0].Action.PathRewrite == nil || cfg.Routes[0].Action.PathRewrite.Prefix != "/service-a" {
		t.Fatalf("unexpected normalized path rewrite: %#v", cfg.Routes[0].Action.PathRewrite)
	}
	if cfg.Routes[0].Action.ResponseHeaders == nil || cfg.Routes[0].Action.ResponseHeaders.Set["X-Frame-Options"] != "DENY" {
		t.Fatalf("unexpected normalized response headers: %#v", cfg.Routes[0].Action.ResponseHeaders)
	}
	if cfg.DefaultRoute == nil || cfg.DefaultRoute.Name != "fallback" {
		t.Fatalf("unexpected default route: %#v", cfg.DefaultRoute)
	}
}

func TestProxyRouteResolutionOrderAndDryRun(t *testing.T) {
	routedRaw := `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "route", "url": "http://route.internal:8080", "weight": 1, "enabled": true },
    { "name": "default", "url": "http://default.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "route",
        "path_rewrite": { "prefix": "/" }
      }
    }
  ],
  "default_route": {
    "name": "fallback",
    "action": {
      "upstream": "default"
    }
  }
}`
	upstreamFallbackRaw := `{
  "upstreams": [
    { "name": "primary", "url": "http://fallback.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "primary",
        "path_rewrite": { "prefix": "/" }
      }
    }
  ]
}`

	tests := []struct {
		name              string
		cfg               ProxyRulesConfig
		host              string
		path              string
		wantSource        string
		wantRoute         string
		wantRewrittenPath string
		wantUpstream      string
		wantUpstreamURL   string
		wantFinalURL      string
	}{
		{
			name:              "route wins over default and upstreams",
			cfg:               mustValidateProxyRulesRaw(t, routedRaw),
			host:              "api.example.com",
			path:              "/servicea/users",
			wantSource:        "route",
			wantRoute:         "service-a",
			wantRewrittenPath: "/users",
			wantUpstream:      "route",
			wantUpstreamURL:   "http://route.internal:8080",
			wantFinalURL:      "http://route.internal:8080/users",
		},
		{
			name:              "default route wins when no explicit route matches",
			cfg:               mustValidateProxyRulesRaw(t, routedRaw),
			host:              "www.example.com",
			path:              "/other",
			wantSource:        "default_route",
			wantRoute:         "fallback",
			wantRewrittenPath: "/other",
			wantUpstream:      "default",
			wantUpstreamURL:   "http://default.internal:8080",
			wantFinalURL:      "http://default.internal:8080/other",
		},
		{
			name:              "upstream fallback is used when default route is absent",
			cfg:               mustValidateProxyRulesRaw(t, upstreamFallbackRaw),
			host:              "www.example.com",
			path:              "/other",
			wantSource:        "upstream",
			wantRoute:         "upstream",
			wantRewrittenPath: "/other",
			wantUpstream:      "primary",
			wantUpstreamURL:   "http://fallback.internal:8080",
			wantFinalURL:      "http://fallback.internal:8080/other",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustResolveProxyRouteDecision(t, tt.cfg, tt.host, tt.path)
			dryRun, err := proxyRouteDryRun(tt.cfg, tt.host, tt.path)
			if err != nil {
				t.Fatalf("proxyRouteDryRun: %v", err)
			}

			if got := string(decision.Source); got != tt.wantSource {
				t.Fatalf("decision source=%s want=%s", got, tt.wantSource)
			}
			if got := dryRun.Source; got != tt.wantSource {
				t.Fatalf("dry-run source=%s want=%s", got, tt.wantSource)
			}
			if got := decision.RouteName; got != tt.wantRoute {
				t.Fatalf("decision route=%s want=%s", got, tt.wantRoute)
			}
			if got := dryRun.RouteName; got != tt.wantRoute {
				t.Fatalf("dry-run route=%s want=%s", got, tt.wantRoute)
			}
			if got := decision.RewrittenPath; got != tt.wantRewrittenPath {
				t.Fatalf("decision rewritten_path=%s want=%s", got, tt.wantRewrittenPath)
			}
			if got := dryRun.RewrittenPath; got != tt.wantRewrittenPath {
				t.Fatalf("dry-run rewritten_path=%s want=%s", got, tt.wantRewrittenPath)
			}
			if got := decision.SelectedUpstream; got != tt.wantUpstream {
				t.Fatalf("decision selected_upstream=%s want=%s", got, tt.wantUpstream)
			}
			if got := dryRun.SelectedUpstream; got != tt.wantUpstream {
				t.Fatalf("dry-run selected_upstream=%s want=%s", got, tt.wantUpstream)
			}
			if got := decision.SelectedUpstreamURL; got != tt.wantUpstreamURL {
				t.Fatalf("decision selected_upstream_url=%s want=%s", got, tt.wantUpstreamURL)
			}
			if got := dryRun.SelectedUpstreamURL; got != tt.wantUpstreamURL {
				t.Fatalf("dry-run selected_upstream_url=%s want=%s", got, tt.wantUpstreamURL)
			}
			if got := finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery); got != tt.wantFinalURL {
				t.Fatalf("decision final_url=%s want=%s", got, tt.wantFinalURL)
			}
			if got := dryRun.FinalURL; got != tt.wantFinalURL {
				t.Fatalf("dry-run final_url=%s want=%s", got, tt.wantFinalURL)
			}
		})
	}
}

func TestProxyRouteBackendPoolsBindSelectionPerRoute(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "localhost1", "url": "http://localhost1:8080", "weight": 1, "enabled": true },
    { "name": "localhost2", "url": "http://localhost2:8080", "weight": 1, "enabled": true },
    { "name": "localhost3", "url": "http://localhost3:8080", "weight": 1, "enabled": true },
    { "name": "localhost4", "url": "http://localhost4:8080", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-localhost",
      "strategy": "round_robin",
      "members": ["localhost1", "localhost2"]
    },
    {
      "name": "site-app",
      "strategy": "round_robin",
      "members": ["localhost3", "localhost4"]
    }
  ],
  "routes": [
    {
      "name": "localhost-site",
      "priority": 10,
      "match": {
        "hosts": ["localhost"]
      },
      "action": {
        "backend_pool": "site-localhost"
      }
    },
    {
      "name": "app-site",
      "priority": 20,
      "match": {
        "hosts": ["app"]
      },
      "action": {
        "backend_pool": "site-app"
      }
    }
  ]
}`)

	localhostDecision := mustResolveProxyRouteDecision(t, cfg, "localhost", "/")
	if localhostDecision.RouteName != "localhost-site" {
		t.Fatalf("localhost route=%s", localhostDecision.RouteName)
	}
	if localhostDecision.SelectedUpstream != "localhost1" && localhostDecision.SelectedUpstream != "localhost2" {
		t.Fatalf("localhost selected_upstream=%s", localhostDecision.SelectedUpstream)
	}
	if strings.Contains(localhostDecision.SelectedUpstreamURL, "localhost3") || strings.Contains(localhostDecision.SelectedUpstreamURL, "localhost4") {
		t.Fatalf("localhost selected_upstream_url leaked other pool: %s", localhostDecision.SelectedUpstreamURL)
	}

	appDecision := mustResolveProxyRouteDecision(t, cfg, "app", "/")
	if appDecision.RouteName != "app-site" {
		t.Fatalf("app route=%s", appDecision.RouteName)
	}
	if appDecision.SelectedUpstream != "localhost3" && appDecision.SelectedUpstream != "localhost4" {
		t.Fatalf("app selected_upstream=%s", appDecision.SelectedUpstream)
	}
	if strings.Contains(appDecision.SelectedUpstreamURL, "localhost1") || strings.Contains(appDecision.SelectedUpstreamURL, "localhost2") {
		t.Fatalf("app selected_upstream_url leaked other pool: %s", appDecision.SelectedUpstreamURL)
	}

	dryRun, err := proxyRouteDryRun(cfg, "app", "/")
	if err != nil {
		t.Fatalf("proxyRouteDryRun: %v", err)
	}
	if dryRun.RouteName != "app-site" {
		t.Fatalf("dry_run route=%s", dryRun.RouteName)
	}
	if dryRun.SelectedUpstream != "localhost3" && dryRun.SelectedUpstream != "localhost4" {
		t.Fatalf("dry_run selected_upstream=%s", dryRun.SelectedUpstream)
	}
}

func TestProxyBackendPoolStickySessionSelectsCookieBackend(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "blue", "url": "http://blue.internal:8080", "weight": 1, "enabled": true },
    { "name": "green", "url": "http://green.internal:8080", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-api",
      "strategy": "round_robin",
      "members": ["blue", "green"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 60,
        "path": "/",
        "http_only": true,
        "same_site": "lax"
      }
    }
  ],
  "routes": [
    {
      "name": "api",
      "priority": 10,
      "match": { "hosts": ["api.example.com"] },
      "action": { "backend_pool": "site-api" }
    }
  ]
}`)

	first := mustResolveProxyRouteDecision(t, cfg, "api.example.com", "/")
	if first.SelectedUpstream == "" {
		t.Fatal("first request did not select upstream")
	}
	cookie := proxyStickySessionCookie(cfg.BackendPools[0].StickySession, first.SelectedUpstream, time.Now().UTC())
	if cookie == nil {
		t.Fatal("sticky cookie was not built")
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Host = "api.example.com"
	req.AddCookie(cookie)
	second, err := resolveProxyRouteDecision(req, cfg, nil)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	if second.SelectedUpstream != first.SelectedUpstream {
		t.Fatalf("sticky selected_upstream=%s want=%s", second.SelectedUpstream, first.SelectedUpstream)
	}
}

func TestProxyBackendPoolStickySessionRejectsTamperedCookie(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "blue", "url": "http://blue.internal:8080", "enabled": true },
    { "name": "green", "url": "http://green.internal:8080", "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-api",
      "members": ["blue", "green"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 60,
        "path": "/"
      }
    }
  ],
  "routes": [
    {
      "name": "api",
      "priority": 10,
      "match": { "hosts": ["api.example.com"] },
      "action": { "backend_pool": "site-api" }
    }
  ]
}`)
	cookie := proxyStickySessionCookie(cfg.BackendPools[0].StickySession, "blue", time.Now().UTC())
	if cookie == nil {
		t.Fatal("sticky cookie was not built")
	}
	if _, ok := parseProxyStickySessionCookieValue(cookie.Name, cookie.Value+"x", time.Now().UTC()); ok {
		t.Fatal("tampered sticky cookie should be rejected")
	}
}

func TestProxyBackendPoolStickySessionRejectsExpiredCookie(t *testing.T) {
	now := time.Unix(time.Now().UTC().Unix(), 0)
	value := buildProxyStickySessionCookieValue("tky_lb_site_api", "blue", now)
	if _, ok := parseProxyStickySessionCookieValue("tky_lb_site_api", value, now); ok {
		t.Fatal("expired sticky cookie should be rejected")
	}
}

func TestProxyBackendPoolStickySessionEncodesUpstreamNameDelimiter(t *testing.T) {
	now := time.Now().UTC()
	value := buildProxyStickySessionCookieValue("tky_lb_site_api", "blue|west", now.Add(time.Minute))
	got, ok := parseProxyStickySessionCookieValue("tky_lb_site_api", value, now)
	if !ok {
		t.Fatal("encoded sticky cookie should parse")
	}
	if got != "blue|west" {
		t.Fatalf("upstream=%q want blue|west", got)
	}
}

func TestProxyBackendPoolStickySessionIgnoresUnavailableBackend(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "blue", "url": "http://blue.internal:8080", "enabled": true },
    { "name": "green", "url": "http://green.internal:8080", "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-api",
      "members": ["blue", "green"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 60,
        "path": "/"
      }
    }
  ],
  "routes": [
    {
      "name": "api",
      "priority": 10,
      "match": { "hosts": ["api.example.com"] },
      "action": { "backend_pool": "site-api" }
    }
  ]
}`)

	candidates, options, err := buildProxyRouteTargetCandidates(cfg, cfg.Routes[0].Action)
	if err != nil {
		t.Fatalf("buildProxyRouteTargetCandidates: %v", err)
	}
	if len(candidates) != 2 {
		t.Fatalf("candidates=%d want=2", len(candidates))
	}

	cookie := proxyStickySessionCookie(cfg.BackendPools[0].StickySession, "blue", time.Now().UTC())
	if cookie == nil {
		t.Fatal("sticky cookie was not built")
	}
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.Host = "api.example.com"
	req.AddCookie(cookie)

	health := &upstreamHealthMonitor{
		cfg: cfg,
		backends: []*proxyBackendState{
			{
				Key:        candidates[0].Key,
				Name:       "blue",
				Enabled:    true,
				AdminState: upstreamAdminStateDraining,
				Healthy:    true,
				Weight:     1,
			},
			{
				Key:        candidates[1].Key,
				Name:       "green",
				Enabled:    true,
				AdminState: upstreamAdminStateEnabled,
				Healthy:    true,
				Weight:     1,
			},
		},
	}
	ordered := orderProxyRouteCandidates(req, candidates, options, health)
	if len(ordered) == 0 {
		t.Fatal("no ordered candidates")
	}
	if got := ordered[0].Name; got != "green" {
		t.Fatalf("selected candidate=%q want green", got)
	}
}

func TestProxyBackendPoolStickySessionValidation(t *testing.T) {
	_, err := ValidateProxyRulesRaw(`{
  "upstreams": [
    { "name": "blue", "url": "http://blue.internal:8080", "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-api",
      "members": ["blue"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 60,
        "path": "/",
        "same_site": "none"
      }
    }
  ]
}`)
	if err == nil {
		t.Fatal("expected SameSite=None without secure validation error")
	}
	if !strings.Contains(err.Error(), "secure must be true") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServeProxyEmitsBackendPoolStickyCookie(t *testing.T) {
	blue := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("blue"))
	}))
	defer blue.Close()
	green := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("green"))
	}))
	defer green.Close()

	proxyPath := filepath.Join(t.TempDir(), "proxy.json")
	raw := fmt.Sprintf(`{
  "upstreams": [
    { "name": "blue", "url": %q, "enabled": true },
    { "name": "green", "url": %q, "enabled": true }
  ],
  "backend_pools": [
    {
      "name": "site-api",
      "strategy": "round_robin",
      "members": ["blue", "green"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 60,
        "path": "/",
        "http_only": true,
        "same_site": "lax"
      }
    }
  ],
  "routes": [
    {
      "name": "api",
      "priority": 10,
      "match": { "hosts": ["api.example.com"] },
      "action": { "backend_pool": "site-api" }
    }
  ]
}`, blue.URL, green.URL)
	if err := os.WriteFile(proxyPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req.Host = "api.example.com"
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolve first route: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	firstBody := rec.Body.String()
	if firstBody != "blue" && firstBody != "green" {
		t.Fatalf("unexpected first body=%q", firstBody)
	}
	result := rec.Result()
	defer result.Body.Close()
	var stickyCookie *http.Cookie
	for _, cookie := range result.Cookies() {
		if cookie.Name == "tky_lb_site_api" {
			stickyCookie = cookie
			break
		}
	}
	if stickyCookie == nil {
		t.Fatal("sticky Set-Cookie was not emitted")
	}
	if !stickyCookie.HttpOnly {
		t.Fatal("sticky cookie should be HttpOnly")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://proxy.local/", nil)
	req2.Host = "api.example.com"
	req2.AddCookie(stickyCookie)
	decision2, err := resolveProxyRouteDecision(req2, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolve second route: %v", err)
	}
	req2 = req2.WithContext(withProxyRouteDecision(req2.Context(), decision2))
	rec2 := httptest.NewRecorder()
	ServeProxy(rec2, req2)
	if secondBody := rec2.Body.String(); secondBody != firstBody {
		t.Fatalf("sticky response body=%q want=%q", secondBody, firstBody)
	}
}

func TestProxyRouteDecisionIncludesHTTP2Mode(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "tls_insecure_skip_verify": true,
  "upstreams": [
    { "name": "tls", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c", "url": "http://h2c.internal:8080", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ],
  "routes": [
    {
      "name": "tls-route",
      "priority": 20,
      "match": {
        "path": { "type": "prefix", "value": "/tls" }
      },
      "action": {
        "upstream": "tls"
      }
    },
    {
      "name": "h2c-route",
      "priority": 10,
      "match": {
        "path": { "type": "prefix", "value": "/h2c" }
      },
      "action": {
        "upstream": "h2c"
      }
    }
  ]
}`)

	tlsDecision := mustResolveProxyRouteDecision(t, cfg, "api.example.com", "/tls/demo")
	if got := tlsDecision.SelectedHTTP2Mode; got != proxyHTTP2ModeForceAttempt {
		t.Fatalf("tls SelectedHTTP2Mode=%q want=%q", got, proxyHTTP2ModeForceAttempt)
	}
	tlsDryRun, err := proxyRouteDryRun(cfg, "api.example.com", "/tls/demo")
	if err != nil {
		t.Fatalf("proxyRouteDryRun tls: %v", err)
	}
	if got := tlsDryRun.SelectedHTTP2Mode; got != proxyHTTP2ModeForceAttempt {
		t.Fatalf("tls dry-run SelectedHTTP2Mode=%q want=%q", got, proxyHTTP2ModeForceAttempt)
	}

	h2cDecision := mustResolveProxyRouteDecision(t, cfg, "api.example.com", "/h2c/demo")
	if got := h2cDecision.SelectedHTTP2Mode; got != proxyHTTP2ModeH2C {
		t.Fatalf("h2c SelectedHTTP2Mode=%q want=%q", got, proxyHTTP2ModeH2C)
	}
	h2cDryRun, err := proxyRouteDryRun(cfg, "api.example.com", "/h2c/demo")
	if err != nil {
		t.Fatalf("proxyRouteDryRun h2c: %v", err)
	}
	if got := h2cDryRun.SelectedHTTP2Mode; got != proxyHTTP2ModeH2C {
		t.Fatalf("h2c dry-run SelectedHTTP2Mode=%q want=%q", got, proxyHTTP2ModeH2C)
	}
}

func TestProxyRoutePrefixRewriteBoundaries(t *testing.T) {
	match := normalizeProxyRoutePathMatch(&ProxyRoutePathMatch{Type: "prefix", Value: "/servicea/"})
	tests := []struct {
		name          string
		originalPath  string
		rewritePrefix string
		wantPath      string
	}{
		{name: "prefix root no trailing slash", originalPath: "/servicea", rewritePrefix: "/", wantPath: "/"},
		{name: "prefix root trailing slash", originalPath: "/servicea/", rewritePrefix: "/", wantPath: "/"},
		{name: "prefix nested path to root", originalPath: "/servicea/foo", rewritePrefix: "/", wantPath: "/foo"},
		{name: "prefix preserved", originalPath: "/servicea/foo", rewritePrefix: "/servicea/", wantPath: "/servicea/foo"},
		{name: "prefix renamed", originalPath: "/servicea/foo", rewritePrefix: "/service-a/", wantPath: "/service-a/foo"},
		{name: "prefix renamed no double slash", originalPath: "/servicea/", rewritePrefix: "/service-a/", wantPath: "/service-a/"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := rewriteProxyRoutePath(tt.originalPath, match, tt.rewritePrefix)
			if err != nil {
				t.Fatalf("rewriteProxyRoutePath: %v", err)
			}
			if got != tt.wantPath {
				t.Fatalf("rewritten_path=%s want=%s", got, tt.wantPath)
			}
			if strings.Contains(got, "//") && got != "/" {
				t.Fatalf("rewritten_path contains double slash: %s", got)
			}
		})
	}
}

func TestProxyRoutePreservesEncodedSuffixOnRewrite(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "route", "url": "http://route.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "route",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}`)

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/servicea/%2Fetc", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Host = "api.example.com"

	decision, err := resolveProxyRouteDecision(req, cfg, nil)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	if decision.RewrittenPath != "/service-a//etc" {
		t.Fatalf("rewritten_path=%s", decision.RewrittenPath)
	}
	if decision.RewrittenRawPath != "/service-a/%2Fetc" {
		t.Fatalf("rewritten_raw_path=%s", decision.RewrittenRawPath)
	}
	if got := finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery); got != "http://route.internal:8080/service-a/%2Fetc" {
		t.Fatalf("final_url=%s", got)
	}
}

func TestValidateProxyRulesRawWithRegexRoute(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a-regex",
      "priority": 10,
      "match": {
        "path": { "type": "regex", "value": "^/servicea/(users|orders)/[0-9]+$" }
      },
      "action": {
        "upstream": "secondary"
      }
    }
  ]
}`)

	if got := cfg.Routes[0].Match.Path.Type; got != "regex" {
		t.Fatalf("path.type=%s", got)
	}
	if got := cfg.Routes[0].Match.Path.Value; got != "^/servicea/(users|orders)/[0-9]+$" {
		t.Fatalf("path.value=%s", got)
	}
	if cfg.Routes[0].Match.Path.compiled == nil {
		t.Fatal("compiled regex is nil")
	}
}

func TestProxyRouteRegexMatchAndPriority(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "prefix", "url": "http://prefix.internal:8080", "weight": 1, "enabled": true },
    { "name": "regex", "url": "http://regex.internal:8080", "weight": 1, "enabled": true },
    { "name": "regex-priority", "url": "http://regex-priority.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "prefix-first",
      "priority": 10,
      "match": {
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "prefix"
      }
    },
    {
      "name": "regex-second",
      "priority": 20,
      "match": {
        "path": { "type": "regex", "value": "^/servicea/(users|orders)/[0-9]+$" }
      },
      "action": {
        "upstream": "regex"
      }
    },
    {
      "name": "regex-high-priority",
      "priority": 5,
      "match": {
        "hosts": ["regex.example.com"],
        "path": { "type": "regex", "value": "^/servicea/(users|orders)/[0-9]+$" }
      },
      "action": {
        "upstream": "regex-priority"
      }
    }
  ]
}`)

	tests := []struct {
		name       string
		host       string
		path       string
		wantRoute  string
		wantSource string
		wantFinal  string
	}{
		{
			name:       "prefix route wins when it has lower priority number",
			host:       "www.example.com",
			path:       "/servicea/users/42",
			wantRoute:  "prefix-first",
			wantSource: "route",
			wantFinal:  "http://prefix.internal:8080/servicea/users/42",
		},
		{
			name:       "regex route wins when it has the highest priority",
			host:       "regex.example.com",
			path:       "/servicea/orders/7",
			wantRoute:  "regex-high-priority",
			wantSource: "route",
			wantFinal:  "http://regex-priority.internal:8080/servicea/orders/7",
		},
		{
			name:       "regex route does not match unrelated path",
			host:       "regex.example.com",
			path:       "/servicea/orders/not-a-number",
			wantRoute:  "prefix-first",
			wantSource: "route",
			wantFinal:  "http://prefix.internal:8080/servicea/orders/not-a-number",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision := mustResolveProxyRouteDecision(t, cfg, tt.host, tt.path)
			if got := decision.RouteName; got != tt.wantRoute {
				t.Fatalf("route=%s want=%s", got, tt.wantRoute)
			}
			if got := string(decision.Source); got != tt.wantSource {
				t.Fatalf("source=%s want=%s", got, tt.wantSource)
			}
			if got := finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery); got != tt.wantFinal {
				t.Fatalf("final_url=%s want=%s", got, tt.wantFinal)
			}

			dryRun, err := proxyRouteDryRun(cfg, tt.host, tt.path)
			if err != nil {
				t.Fatalf("proxyRouteDryRun: %v", err)
			}
			if got := dryRun.RouteName; got != tt.wantRoute {
				t.Fatalf("dry-run route=%s want=%s", got, tt.wantRoute)
			}
			if got := dryRun.FinalURL; got != tt.wantFinal {
				t.Fatalf("dry-run final_url=%s want=%s", got, tt.wantFinal)
			}
		})
	}
}

func TestProxyRouteHostRewrite(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "route", "url": "http://route.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "host-rewrite",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "route",
        "host_rewrite": "service-a.internal"
      }
    }
  ]
}`)

	decision := mustResolveProxyRouteDecision(t, cfg, "api.example.com", "/servicea/users")
	if got := decision.RewrittenHost; got != "service-a.internal" {
		t.Fatalf("rewritten_host=%s", got)
	}

	dryRun, err := proxyRouteDryRun(cfg, "api.example.com", "/servicea/users")
	if err != nil {
		t.Fatalf("proxyRouteDryRun: %v", err)
	}
	if got := dryRun.RewrittenHost; got != "service-a.internal" {
		t.Fatalf("dry-run rewritten_host=%s", got)
	}
	if got := dryRun.FinalURL; got != "http://route.internal:8080/servicea/users" {
		t.Fatalf("dry-run final_url=%s", got)
	}
}

func TestProxyRouteUpstreamFallbackUsesTargetHost(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true }
  ]
}`)

	decision := mustResolveProxyRouteDecision(t, cfg, "proxy.local:9090", "/")
	if got := decision.RewrittenHost; got != "primary.internal:8080" {
		t.Fatalf("rewritten_host=%s", got)
	}

	dryRun, err := proxyRouteDryRun(cfg, "proxy.local:9090", "/")
	if err != nil {
		t.Fatalf("proxyRouteDryRun: %v", err)
	}
	if got := dryRun.RewrittenHost; got != "primary.internal:8080" {
		t.Fatalf("dry-run rewritten_host=%s", got)
	}
}

func TestProxyRouteQueryRewriteAndDryRun(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "route", "url": "http://route.internal:8080?origin=1", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "query-rewrite",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "route",
        "path_rewrite": { "prefix": "/" },
        "query_rewrite": {
          "remove": ["debug"],
          "remove_prefixes": ["utm_"],
          "set": { "lang": "ja" },
          "add": { "preview": "1" }
        }
      }
    }
  ]
}`)

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/servicea/users?lang=en&utm_source=ads&debug=true&tag=base", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req.Host = "api.example.com"

	decision, err := resolveProxyRouteDecision(req, cfg, nil)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	if decision.OriginalQuery != "lang=en&utm_source=ads&debug=true&tag=base" {
		t.Fatalf("original_query=%s", decision.OriginalQuery)
	}
	if decision.RewrittenQuery != "lang=ja&preview=1&tag=base" {
		t.Fatalf("rewritten_query=%s", decision.RewrittenQuery)
	}
	if got := finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery); got != "http://route.internal:8080/users?origin=1&lang=ja&preview=1&tag=base" {
		t.Fatalf("final_url=%s", got)
	}

	dryRun, err := proxyRouteDryRun(cfg, "api.example.com", "/servicea/users?lang=en&utm_source=ads&debug=true&tag=base")
	if err != nil {
		t.Fatalf("proxyRouteDryRun: %v", err)
	}
	if dryRun.OriginalQuery != "lang=en&utm_source=ads&debug=true&tag=base" {
		t.Fatalf("dry-run original_query=%s", dryRun.OriginalQuery)
	}
	if dryRun.RewrittenQuery != "lang=ja&preview=1&tag=base" {
		t.Fatalf("dry-run rewritten_query=%s", dryRun.RewrittenQuery)
	}
	if dryRun.FinalURL != "http://route.internal:8080/users?origin=1&lang=ja&preview=1&tag=base" {
		t.Fatalf("dry-run final_url=%s", dryRun.FinalURL)
	}
}

func TestProxyRouteCanaryHashSelectionStable(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true },
    { "name": "canary", "url": "http://canary.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "canary",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "primary",
        "canary_upstream": "canary",
        "canary_weight_percent": 25,
        "hash_policy": "header",
        "hash_key": "X-User"
      }
    }
  ]
}`)

	resolveForHeader := func(value string) proxyRouteDecision {
		req, err := http.NewRequest(http.MethodGet, "http://proxy.local/servicea/users", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.Host = "api.example.com"
		req.Header.Set("X-User", value)
		decision, err := resolveProxyRouteDecision(req, cfg, nil)
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision: %v", err)
		}
		return decision
	}

	first := resolveForHeader("user-42")
	second := resolveForHeader("user-42")
	if first.SelectedUpstreamURL != second.SelectedUpstreamURL {
		t.Fatalf("hash selection not stable: %s vs %s", first.SelectedUpstreamURL, second.SelectedUpstreamURL)
	}

	sawPrimary := false
	sawCanary := false
	for i := 0; i < 128; i++ {
		decision := resolveForHeader(fmt.Sprintf("user-%d", i))
		switch decision.SelectedUpstreamURL {
		case "http://primary.internal:8080":
			sawPrimary = true
		case "http://canary.internal:8080":
			sawCanary = true
		}
		if sawPrimary && sawCanary {
			break
		}
	}
	if !sawPrimary || !sawCanary {
		t.Fatalf("expected canary hash routing to reach both upstreams, sawPrimary=%v sawCanary=%v", sawPrimary, sawCanary)
	}
}

func TestProxyGlobalHashPolicyKeepsStickySelection(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "hash_policy": "cookie",
  "hash_key": "session",
  "upstreams": [
    { "name": "blue", "url": "http://blue.internal:8080", "weight": 1, "enabled": true },
    { "name": "green", "url": "http://green.internal:8080", "weight": 1, "enabled": true }
  ]
}`)

	resolveForCookie := func(value string) proxyRouteDecision {
		req, err := http.NewRequest(http.MethodGet, "http://proxy.local/anything", nil)
		if err != nil {
			t.Fatalf("http.NewRequest: %v", err)
		}
		req.AddCookie(&http.Cookie{Name: "session", Value: value})
		decision, err := resolveProxyRouteDecision(req, cfg, nil)
		if err != nil {
			t.Fatalf("resolveProxyRouteDecision: %v", err)
		}
		return decision
	}

	first := resolveForCookie("abc")
	second := resolveForCookie("abc")
	if first.SelectedUpstream != second.SelectedUpstream {
		t.Fatalf("sticky selection changed: %s vs %s", first.SelectedUpstream, second.SelectedUpstream)
	}
}

func TestProxyRouteHostMatchBoundaries(t *testing.T) {
	tests := []struct {
		name     string
		patterns []string
		host     string
		want     bool
	}{
		{name: "exact host match", patterns: []string{"api.example.com"}, host: "api.example.com", want: true},
		{name: "exact host strips port, case, and trailing dot", patterns: []string{"api.example.com"}, host: "API.EXAMPLE.COM.:443", want: true},
		{name: "wildcard does not match bare suffix", patterns: []string{"*.example.com"}, host: "example.com", want: false},
		{name: "wildcard matches single label", patterns: []string{"*.example.com"}, host: "a.example.com", want: true},
		{name: "wildcard matches deeper labels", patterns: []string{"*.example.com"}, host: "a.b.example.com", want: true},
		{name: "wildcard strips port and trailing dot", patterns: []string{"*.example.com."}, host: "A.B.EXAMPLE.COM.:8443", want: true},
		{name: "empty host does not match", patterns: []string{"api.example.com"}, host: "", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := proxyRouteHostsMatch(normalizeProxyRouteHosts(tt.patterns), tt.host)
			if got != tt.want {
				t.Fatalf("matched=%v want=%v", got, tt.want)
			}
		})
	}
}

func TestValidateProxyRulesRawRejectsInvalidActionUpstream(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name: "unknown upstream name",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "upstream": "missing-upstream" }
    }
  ]
}`,
			wantErr: "must reference a configured upstream name",
		},
		{
			name: "unsupported upstream scheme",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "upstream": "ftp://127.0.0.1:21" }
    }
  ]
}`,
			wantErr: "must reference a configured upstream name",
		},
		{
			name: "relative upstream URL",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "upstream": "/relative" }
    }
  ]
}`,
			wantErr: "must reference a configured upstream name",
		},
		{
			name: "explicit upstream required when no upstreams are configured",
			raw: `{
  "routes": [
    {
      "priority": 10,
      "match": {
        "path": { "type": "prefix", "value": "/" }
      },
      "action": {}
    }
  ]
}`,
			wantErr: "routes[0].action.upstream is required when no upstreams are configured",
		},
		{
			name: "unknown backend pool",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "backend_pool": "missing-pool" }
    }
  ]
}`,
			wantErr: "backend_pool must reference a configured backend pool",
		},
		{
			name: "backend pool conflicts with explicit upstream",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-primary", "members": ["primary"] }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "backend_pool": "site-primary",
        "upstream": "primary"
      }
    }
  ]
}`,
			wantErr: "backend_pool conflicts with routes[0].action.upstream",
		},
		{
			name: "backend pool member must reference named upstream only",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-primary", "members": ["http://127.0.0.1:8080"] }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "backend_pool": "site-primary" }
    }
  ]
}`,
			wantErr: "must reference a configured upstream name",
		},
		{
			name: "backend pool rejects disabled upstream member",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": false },
    { "name": "secondary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-primary", "members": ["primary", "secondary"] }
  ],
  "routes": [
    {
      "priority": 10,
      "action": { "backend_pool": "site-primary" }
    }
  ]
}`,
			wantErr: "references disabled upstream",
		},
		{
			name: "invalid regex path",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "match": {
        "path": { "type": "regex", "value": "^(foo$" }
      },
      "action": {
        "upstream": "primary"
      }
    }
  ]
}`,
			wantErr: "regex compile error",
		},
		{
			name: "regex path rewrite is rejected",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "match": {
        "path": { "type": "regex", "value": "^/servicea/.+$" }
      },
      "action": {
        "upstream": "primary",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}`,
			wantErr: "does not support regex path matches",
		},
		{
			name: "host rewrite must not include scheme",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "upstream": "primary",
        "host_rewrite": "https://service-a.internal"
      }
    }
  ]
}`,
			wantErr: "host rewrite must not include scheme",
		},
		{
			name: "host rewrite must not use wildcard",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "upstream": "primary",
        "host_rewrite": "*.service-a.internal"
      }
    }
  ]
}`,
			wantErr: "host rewrite does not support wildcards",
		},
		{
			name: "query rewrite rejects conflicting key",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "upstream": "primary",
        "query_rewrite": {
          "set": { "lang": "ja" },
          "remove": ["lang"]
        }
      }
    }
  ]
}`,
			wantErr: "query_rewrite.remove.lang conflicts with routes[0].action.query_rewrite.set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateProxyRulesRaw(tt.raw)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error=%q want substring=%q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestValidateProxyRulesRawRejectsUnknownBackendName(t *testing.T) {
	_, err := ValidateProxyRulesRaw(`{
  "default_route": {
    "action": {
      "upstream": "missing"
    }
  }
}`)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), `must reference a configured upstream name`) {
		t.Fatalf("error=%q", err.Error())
	}
}

func TestValidateProxyRulesRawRejectsRestrictedRouteHeaders(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		wantErr string
	}{
		{
			name: "reject host set",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "request_headers": {
          "set": { "Host": "malicious.example" }
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route request_headers",
		},
		{
			name: "reject x-forwarded add",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "request_headers": {
          "add": { "x-forwarded-for": "1.2.3.4" }
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route request_headers",
		},
		{
			name: "reject x-tukuyomi-upstream-name set",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "request_headers": {
          "set": { "X-Tukuyomi-Upstream-Name": "spoofed" }
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route request_headers",
		},
		{
			name: "reject hop-by-hop remove",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "request_headers": {
          "remove": ["cOnNection"]
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route request_headers",
		},
		{
			name: "reject content-length response set",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "response_headers": {
          "set": { "Content-Length": "1" }
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route response_headers",
		},
		{
			name: "reject set-cookie response remove",
			raw: `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "priority": 10,
      "action": {
        "response_headers": {
          "remove": ["Set-Cookie"]
        }
      }
    }
  ]
}`,
			wantErr: "header is not allowed in route response_headers",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ValidateProxyRulesRaw(tt.raw)
			if err == nil {
				t.Fatal("expected validation error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error=%q want substring=%q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestProxyRouteFallbackToUpstreamsWithoutRoutes(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://primary.internal:8080", "weight": 1, "enabled": true }
  ],
  "load_balancing_strategy": "round_robin"
}`)

	decision := mustResolveProxyRouteDecision(t, cfg, "api.example.com", "/healthz")
	if got := string(decision.Source); got != "upstream" {
		t.Fatalf("source=%s", got)
	}
	if decision.RouteName != "upstream" {
		t.Fatalf("route_name=%s", decision.RouteName)
	}
	if decision.SelectedUpstream != "primary" {
		t.Fatalf("selected_upstream=%s", decision.SelectedUpstream)
	}
	if got := finalProxyRouteURL(decision.Target, decision.RewrittenPath, decision.RewrittenRawPath, decision.RewrittenQuery); got != "http://primary.internal:8080/healthz" {
		t.Fatalf("final_url=%s", got)
	}

	dryRun, err := proxyRouteDryRun(cfg, "api.example.com", "/healthz")
	if err != nil {
		t.Fatalf("proxyRouteDryRun: %v", err)
	}
	if dryRun.Source != "upstream" {
		t.Fatalf("dry-run source=%s", dryRun.Source)
	}
	if dryRun.FinalURL != "http://primary.internal:8080/healthz" {
		t.Fatalf("dry-run final_url=%s", dryRun.FinalURL)
	}
}

func TestAppendProxyRouteLogFields_ClassificationOnlyOmitsSelectedTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/servicea/users?lang=ja", nil)
	req.Host = "api.example.com"
	req = req.WithContext(withProxyRouteClassification(req.Context(), proxyRouteClassification{
		Source:           proxyRouteResolutionRoute,
		RouteName:        "service-a",
		OriginalHost:     "api.example.com",
		OriginalPath:     "/servicea/users",
		OriginalQuery:    "lang=ja",
		RewrittenHost:    "service-a.internal",
		RewrittenPath:    "/service-a/users",
		RewrittenRawPath: "/service-a/users",
		RewrittenQuery:   "lang=ja",
		LogSelection:     true,
	}))

	evt := map[string]any{
		"event": "country_block",
	}
	appendProxyRouteLogFields(evt, req)

	if got := anyToString(evt["selected_route"]); got != "service-a" {
		t.Fatalf("selected_route=%q want=service-a", got)
	}
	if got := anyToString(evt["selected_upstream"]); got != "" {
		t.Fatalf("selected_upstream=%q want empty", got)
	}
	if got := anyToString(evt["selected_upstream_url"]); got != "" {
		t.Fatalf("selected_upstream_url=%q want empty", got)
	}
	if got := anyToString(evt["rewritten_host"]); got != "service-a.internal" {
		t.Fatalf("rewritten_host=%q want=service-a.internal", got)
	}
}

func TestAppendProxyRouteLogFields_TransportSelectionAddsSelectedTarget(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/servicea/users?lang=ja", nil)
	req.Host = "api.example.com"
	req = req.WithContext(withProxyRouteClassification(req.Context(), proxyRouteClassification{
		Source:           proxyRouteResolutionRoute,
		RouteName:        "service-a",
		OriginalHost:     "api.example.com",
		OriginalPath:     "/servicea/users",
		OriginalQuery:    "lang=ja",
		RewrittenHost:    "service-a.internal",
		RewrittenPath:    "/service-a/users",
		RewrittenRawPath: "/service-a/users",
		RewrittenQuery:   "lang=ja",
		LogSelection:     true,
	}))
	req = req.WithContext(withProxyRouteTransportSelection(req.Context(), proxyRouteTransportSelection{
		SelectedUpstream:    "svc-a",
		SelectedUpstreamURL: "http://svc-a.internal:8080",
		RewrittenHost:       "service-a.internal",
		StickySession: ProxyStickySessionConfig{
			Enabled:    true,
			CookieName: "tky_lb_service_a",
			TTLSeconds: 60,
			Path:       "/",
		},
		StickySessionHit: true,
	}))

	evt := map[string]any{
		"event": "proxy_access",
	}
	appendProxyRouteLogFields(evt, req)

	if got := anyToString(evt["selected_route"]); got != "service-a" {
		t.Fatalf("selected_route=%q want=service-a", got)
	}
	if got := anyToString(evt["selected_upstream"]); got != "svc-a" {
		t.Fatalf("selected_upstream=%q want=svc-a", got)
	}
	if got := anyToString(evt["selected_upstream_url"]); got != "http://svc-a.internal:8080" {
		t.Fatalf("selected_upstream_url=%q want=http://svc-a.internal:8080", got)
	}
	if got := boolValue(evt["sticky_session"]); !got {
		t.Fatalf("sticky_session=%v want=true", got)
	}
	if got := anyToString(evt["sticky_session_cookie_name"]); got != "tky_lb_service_a" {
		t.Fatalf("sticky_session_cookie_name=%q want=tky_lb_service_a", got)
	}
	if got := boolValue(evt["sticky_session_hit"]); !got {
		t.Fatalf("sticky_session_hit=%v want=true", got)
	}
}

func TestServeProxyAppliesRouteRewriteAndHeaders(t *testing.T) {
	var gotPath string
	var gotQuery string
	var gotSet string
	var gotAdd string
	var gotRemoved string
	var gotHost string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotSet = r.Header.Get("X-Service")
		gotAdd = r.Header.Get("X-Route")
		gotRemoved = r.Header.Get("X-Debug")
		gotHost = r.Host
		w.Header().Set("X-Upstream-Replace", "origin")
		w.Header().Add("X-Upstream-Add", "origin")
		w.Header().Set("X-Upstream-Remove", "remove-me")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "` + upstream.URL + `", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "service-a",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "host_rewrite": "service-a.internal",
        "path_rewrite": { "prefix": "/service-a/" },
        "query_rewrite": {
          "remove": ["debug"],
          "remove_prefixes": ["utm_"],
          "set": { "lang": "ja" },
          "add": { "preview": "1" }
        },
        "request_headers": {
          "set": { "X-Service": "service-a" },
          "add": { "X-Route": "service-a" },
          "remove": ["X-Debug"]
        },
        "response_headers": {
          "set": { "X-Upstream-Replace": "rewritten", "X-Route-Response": "service-a" },
          "add": { "X-Upstream-Add": "added" },
          "remove": ["X-Upstream-Remove"]
        }
      }
    }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/servicea/users?lang=en&utm_source=ads&debug=true&tag=base", nil)
	req.Host = "api.example.com"
	req.Header.Set("X-Debug", "remove-me")
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	rec := httptest.NewRecorder()
	ServeProxy(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if gotPath != "/service-a/users" {
		t.Fatalf("path=%s", gotPath)
	}
	if gotQuery != "lang=ja&preview=1&tag=base" {
		t.Fatalf("query=%s", gotQuery)
	}
	if gotSet != "service-a" {
		t.Fatalf("X-Service=%s", gotSet)
	}
	if gotAdd != "service-a" {
		t.Fatalf("X-Route=%s", gotAdd)
	}
	if gotRemoved != "" {
		t.Fatalf("X-Debug=%s", gotRemoved)
	}
	if gotHost != "service-a.internal" {
		t.Fatalf("Host=%s", gotHost)
	}
	if got := rec.Header().Get("X-Upstream-Replace"); got != "rewritten" {
		t.Fatalf("X-Upstream-Replace=%s", got)
	}
	if got := rec.Header().Values("X-Upstream-Add"); len(got) != 2 || got[0] != "origin" || got[1] != "added" {
		t.Fatalf("X-Upstream-Add=%v", got)
	}
	if got := rec.Header().Get("X-Upstream-Remove"); got != "" {
		t.Fatalf("X-Upstream-Remove=%s", got)
	}
	if got := rec.Header().Get("X-Route-Response"); got != "service-a" {
		t.Fatalf("X-Route-Response=%s", got)
	}
}

func TestServeProxyResponseHeaderSanitizeWinsAfterRouteHeaders(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Server", "upstream")
		w.Header().Set("X-Powered-By", "php")
		w.Header().Set("X-Response-Ok", "1")
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "` + upstream.URL + `", "weight": 1, "enabled": true }
  ],
  "response_header_sanitize": {
    "mode": "auto",
    "custom_remove": ["X-Internal-Leak"]
  },
  "routes": [
    {
      "name": "sanitize-last",
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "response_headers": {
          "set": {
            "Server": "route-reintroduced",
            "X-Internal-Leak": "true",
            "X-Response-Ok": "route"
          },
          "add": {
            "X-Powered-By": "route"
          }
        }
      }
    }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
		t.Fatalf("write proxy.json: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/servicea/users", nil)
	req.Host = "api.example.com"
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	rec := httptest.NewRecorder()
	ServeProxy(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d", rec.Code)
	}
	if got := rec.Header().Get("Server"); got != "" {
		t.Fatalf("server=%q", got)
	}
	if got := rec.Header().Get("X-Powered-By"); got != "" {
		t.Fatalf("x-powered-by=%q", got)
	}
	if got := rec.Header().Get("X-Internal-Leak"); got != "" {
		t.Fatalf("x-internal-leak=%q", got)
	}
	if got := rec.Header().Get("X-Response-Ok"); got != "route" {
		t.Fatalf("x-response-ok=%q", got)
	}
}
