package handler

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/config"
)

func TestParseSiteConfigRawRejectsOverlappingHosts(t *testing.T) {
	raw := `{
  "sites": [
    {
      "name": "wildcard",
      "enabled": false,
      "hosts": ["*.example.com"],
      "default_upstream": "http://wildcard.internal:8080",
      "tls": {"mode": "legacy"}
    },
    {
      "name": "exact",
      "enabled": false,
      "hosts": ["api.example.com"],
      "default_upstream": "http://exact.internal:8080",
      "tls": {"mode": "legacy"}
    }
  ]
}`

	_, _, _, err := parseSiteConfigRaw(raw)
	if err == nil {
		t.Fatal("expected overlapping host validation error")
	}
	if !strings.Contains(err.Error(), `overlaps "*.example.com"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPrepareProxyRulesRawWithSitesRespectsRoutePrecedence(t *testing.T) {
	raw := `{
  "upstreams": [
    { "name": "primary", "url": "http://legacy.internal:8080", "weight": 1, "enabled": true },
    { "name": "admin", "url": "http://admin.internal:8080", "weight": 1, "enabled": true },
    { "name": "fallback", "url": "http://default.internal:8080", "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "explicit-admin",
      "priority": 100,
      "match": {
        "hosts": ["blog.example.com"],
        "path": {"type": "prefix", "value": "/admin"}
      },
      "action": {
        "upstream": "admin"
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
	sites := SiteConfigFile{
		Sites: []SiteConfig{
			{
				Name:            "blog",
				Hosts:           []string{"blog.example.com"},
				DefaultUpstream: "http://site.internal:8080",
				TLS:             SiteTLSConfig{Mode: "legacy"},
			},
		},
	}

	prepared, err := prepareProxyRulesRawWithSites(raw, sites)
	if err != nil {
		t.Fatalf("prepareProxyRulesRawWithSites: %v", err)
	}

	admin := mustResolveProxyRouteDecision(t, prepared.effectiveCfg, "blog.example.com", "/admin/users")
	if admin.RouteName != "explicit-admin" {
		t.Fatalf("admin route=%q want=%q", admin.RouteName, "explicit-admin")
	}
	if admin.SelectedUpstreamURL != "http://admin.internal:8080" {
		t.Fatalf("admin upstream=%q", admin.SelectedUpstreamURL)
	}

	siteCatchAll := mustResolveProxyRouteDecision(t, prepared.effectiveCfg, "blog.example.com", "/blog")
	if siteCatchAll.RouteName != "site:blog" {
		t.Fatalf("site route=%q want=%q", siteCatchAll.RouteName, "site:blog")
	}
	if siteCatchAll.SelectedUpstreamURL != "http://site.internal:8080" {
		t.Fatalf("site upstream=%q", siteCatchAll.SelectedUpstreamURL)
	}

	fallback := mustResolveProxyRouteDecision(t, prepared.effectiveCfg, "other.example.com", "/blog")
	if fallback.RouteName != "fallback" {
		t.Fatalf("fallback route=%q want=%q", fallback.RouteName, "fallback")
	}
	if fallback.SelectedUpstreamURL != "http://default.internal:8080" {
		t.Fatalf("fallback upstream=%q", fallback.SelectedUpstreamURL)
	}
}

func TestPrepareProxyRulesRawRejectsExplicitRouteToSiteGeneratedTarget(t *testing.T) {
	raw := `{
  "routes": [
    {
      "name": "explicit-site-target",
      "priority": 10,
      "match": {
        "hosts": ["blog.example.com"]
      },
      "action": {
        "upstream": "site:blog"
      }
    }
  ]
}`
	sites := SiteConfigFile{
		Sites: []SiteConfig{
			{
				Name:            "blog",
				Hosts:           []string{"blog.example.com"},
				DefaultUpstream: "http://site.internal:8080",
				TLS:             SiteTLSConfig{Mode: "legacy"},
			},
		},
	}

	_, err := prepareProxyRulesRawWithSites(raw, sites)
	if err == nil {
		t.Fatal("expected explicit route to generated Site target to be rejected")
	}
	if !strings.Contains(err.Error(), "routes[0].action.upstream must reference a configured direct upstream name") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTLSBindingConfigRawAcceptsManualWildcardCertificate(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	certFile, keyFile := writeSiteTestTLSFiles(t, []string{"*.example.com"})

	raw := `{
  "bindings": [
    {
      "name": "wildcard",
      "hosts": ["*.example.com"],
      "mode": "manual",
      "cert_file": ` + jsonStringForSiteTest(certFile) + `,
      "key_file": ` + jsonStringForSiteTest(keyFile) + `
    }
  ]
}`

	cfg, statuses, err := ValidateTLSBindingConfigRaw(raw)
	if err != nil {
		t.Fatalf("ValidateTLSBindingConfigRaw: %v", err)
	}
	if len(cfg.Bindings) != 1 || len(statuses) != 1 {
		t.Fatalf("unexpected counts cfg=%d statuses=%d", len(cfg.Bindings), len(statuses))
	}
	if statuses[0].Status != "covered" {
		t.Fatalf("status=%q want=%q", statuses[0].Status, "covered")
	}
	if statuses[0].Mode != "manual" {
		t.Fatalf("mode=%q want=%q", statuses[0].Mode, "manual")
	}
	if statuses[0].CertNotAfter == "" {
		t.Fatal("cert_not_after should not be empty")
	}
}

func TestValidateTLSBindingConfigRawRejectsACMEWildcardHost(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true

	raw := `{
  "bindings": [
    {
      "name": "wildcard-acme",
      "hosts": ["*.example.com"],
      "mode": "acme"
    }
  ]
}`

	_, _, err := ValidateTLSBindingConfigRaw(raw)
	if err == nil {
		t.Fatal("expected acme wildcard validation error")
	}
	if !strings.Contains(err.Error(), "supports exact hosts only") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTLSBindingConfigRawRejectsACMEIPAddressHost(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true

	raw := `{
  "bindings": [
    {
      "name": "ip-acme",
      "hosts": ["192.0.2.10"],
      "mode": "acme"
    }
  ]
}`

	_, _, err := ValidateTLSBindingConfigRaw(raw)
	if err == nil {
		t.Fatal("expected acme IP address validation error")
	}
	if !strings.Contains(err.Error(), "does not support IP address host") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTLSBindingConfigRawRejectsACMEWithoutPort80HTTPListener(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerPublicListenersConfigured = true
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: ":9090", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: ":443", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
	}

	raw := `{
  "bindings": [
    {
      "name": "center",
      "hosts": ["center.example.com"],
      "mode": "acme"
    }
  ]
}`

	_, _, err := ValidateTLSBindingConfigRaw(raw)
	if err == nil {
		t.Fatal("expected acme port 80 validation error")
	}
	if !strings.Contains(err.Error(), "requires an enabled HTTP public listener on port 80") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateTLSBindingConfigRawAllowsACMEWithoutSite(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerPublicListenersConfigured = true
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: ":9090", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: ":443", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "http", ListenAddr: ":80", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorRedirect, RedirectTo: "https", Enabled: true},
	}

	raw := `{
  "bindings": [
    {
      "name": "center",
      "hosts": ["center.example.com"],
      "mode": "acme"
    }
  ]
}`

	cfg, statuses, err := ValidateTLSBindingConfigRaw(raw)
	if err != nil {
		t.Fatalf("ValidateTLSBindingConfigRaw: %v", err)
	}
	if len(cfg.Bindings) != 1 || len(statuses) != 1 {
		t.Fatalf("unexpected counts cfg=%d statuses=%d", len(cfg.Bindings), len(statuses))
	}
	if statuses[0].Mode != "acme" || statuses[0].Status != "covered" {
		t.Fatalf("unexpected status: %+v", statuses[0])
	}
}

func TestValidateTLSBindingConfigRawRejectsInvalidACMEEmail(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true

	raw := `{
  "bindings": [
    {
      "name": "blog",
      "hosts": ["blog.example.com"],
      "mode": "acme",
      "acme": {"email": "not an email"}
    }
  ]
}`

	_, _, err := ValidateTLSBindingConfigRaw(raw)
	if err == nil {
		t.Fatal("expected acme email validation error")
	}
	if !strings.Contains(err.Error(), "acme.email") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateSiteConfigRawRejectsMissingDefaultUpstream(t *testing.T) {
	raw := `{
  "sites": [
    {
      "name": "center",
      "hosts": ["center.example.com"]
    }
  ]
}`
	_, _, err := ValidateSiteConfigRaw(raw)
	if err == nil {
		t.Fatal("expected missing default upstream validation error")
	}
	if !strings.Contains(err.Error(), "default_upstream is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSiteConfigNormalizedJSONOmitsLegacyTLS(t *testing.T) {
	raw := `{
  "sites": [
    {
      "name": "proxy-route-host",
      "hosts": ["www.example.com"],
      "default_upstream": "http://backend.internal:8080",
      "tls": {"mode": "acme"}
    }
  ]
}`
	cfg, _, err := ValidateSiteConfigRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSiteConfigRaw: %v", err)
	}
	normalized := mustJSON(cfg)
	if strings.Contains(normalized, `"tls"`) {
		t.Fatalf("site config JSON must stay routing-only, got: %s", normalized)
	}
	if !strings.Contains(normalized, `"default_upstream"`) {
		t.Fatalf("site config JSON should retain routing data, got: %s", normalized)
	}
}

func TestEffectiveServerTLSACMEProfilesIncludeEnabledTLSBindings(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerPublicListenersConfigured = true
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: ":9090", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: ":443", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "http", ListenAddr: ":80", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorRedirect, RedirectTo: "https", Enabled: true},
	}

	tmp := t.TempDir()
	tlsPath := filepath.Join(tmp, "tls-bindings.json")
	raw := `{
  "bindings": [
    {
      "name": "blog",
      "hosts": ["blog.example.com"],
      "mode": "acme",
      "acme": {"environment": "staging", "email": "ops@example.com"}
    },
    {
      "name": "disabled",
      "enabled": false,
      "hosts": ["disabled.example.com"],
      "mode": "acme"
    }
  ]
}`
	if err := os.WriteFile(tlsPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile(tls-bindings): %v", err)
	}
	if err := InitTLSBindingRuntime(tlsPath, 2); err != nil {
		t.Fatalf("InitTLSBindingRuntime: %v", err)
	}

	profiles := EffectiveServerTLSACMEProfilesForTLSBindings(currentTLSBindingConfig())
	if len(profiles) != 1 {
		t.Fatalf("profiles=%#v want one", profiles)
	}
	if profiles[0].Environment != siteTLSACMEEnvironmentStaging || profiles[0].Email != "ops@example.com" {
		t.Fatalf("profile=%#v", profiles[0])
	}
	domains := EffectiveServerTLSACMEDomains()
	if !slices.Contains(domains, "blog.example.com") {
		t.Fatalf("domains=%v missing blog.example.com", domains)
	}
	if slices.Contains(domains, "disabled.example.com") {
		t.Fatalf("domains=%v should not include disabled.example.com", domains)
	}
}

func TestInitSiteRuntimeLoadsDBBlobWithoutRestoringFile(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer func() {
		_ = InitLogsStatsStore(false, "", 0)
	}()

	raw := `{
  "sites": [
    {
      "name": "db-site",
      "enabled": false,
      "hosts": ["db.example.com"],
      "default_upstream": "http://db.internal:8080",
      "tls": {"mode": "legacy"}
    }
  ]
}`
	store := getLogsStatsStore()
	if err := store.UpsertConfigBlob(siteConfigBlobKey, []byte(raw), "", time.Now().UTC()); err != nil {
		t.Fatalf("UpsertConfigBlob: %v", err)
	}

	sitePath := filepath.Join(tmp, "conf", "sites.json")
	if err := InitSiteRuntime(sitePath, 2); err != nil {
		t.Fatalf("InitSiteRuntime: %v", err)
	}
	_, _, cfg, statuses, _ := SiteConfigSnapshot()
	if len(cfg.Sites) != 1 || cfg.Sites[0].Name != "db-site" {
		t.Fatalf("sites cfg=%+v", cfg.Sites)
	}
	if len(statuses) != 1 || statuses[0].Name != "db-site" {
		t.Fatalf("statuses=%+v", statuses)
	}
	if _, err := os.Stat(sitePath); !os.IsNotExist(err) {
		t.Fatalf("site file should not be restored, stat err=%v", err)
	}
}

func TestValidateTLSBindingConfigRawLegacyRequiresListenerCertificate(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true

	raw := `{
  "bindings": [
    {
      "name": "blog",
      "hosts": ["blog.example.com"],
      "mode": "legacy"
    }
  ]
}`

	_, _, err := ValidateTLSBindingConfigRaw(raw)
	if err == nil {
		t.Fatal("expected legacy listener certificate validation error")
	}
	if !strings.Contains(err.Error(), `legacy listener certificate is not configured`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestApplyTLSBindingConfigRawReloadsServerTLSRuntime(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerPublicListenersConfigured = true
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: ":9090", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: ":443", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "http", ListenAddr: ":80", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorRedirect, RedirectTo: "https", Enabled: true},
	}

	etag, _ := initTLSBindingRuntimeForTest(t, defaultTLSBindingConfigRaw)
	var (
		called     bool
		gotDomains []string
		gotStatus  []TLSBindingRuntimeStatus
	)
	SetServerTLSReloadHook(func(bindings TLSBindingConfigFile, statuses []TLSBindingRuntimeStatus) error {
		called = true
		gotDomains = EffectiveServerTLSACMEDomainsForTLSBindings(bindings)
		gotStatus = cloneTLSBindingRuntimeStatuses(statuses)
		return nil
	})

	raw := `{
  "bindings": [
    {
      "name": "blog",
      "hosts": ["blog.example.com"],
      "mode": "acme",
      "acme": {"environment": "staging"}
    }
  ]
}`

	newETag, cfg, statuses, err := ApplyTLSBindingConfigRaw(etag, raw)
	if err != nil {
		t.Fatalf("ApplyTLSBindingConfigRaw: %v", err)
	}
	if newETag == etag {
		t.Fatal("etag should change after apply")
	}
	if !called {
		t.Fatal("expected tls reload hook to be called")
	}
	if !slices.Contains(gotDomains, "blog.example.com") {
		t.Fatalf("gotDomains=%v missing blog.example.com", gotDomains)
	}
	if len(gotStatus) != 1 || gotStatus[0].Mode != "acme" {
		t.Fatalf("gotStatus=%#v", gotStatus)
	}
	if gotStatus[0].ACMEEnvironment != siteTLSACMEEnvironmentStaging {
		t.Fatalf("gotStatus[0].ACMEEnvironment=%q", gotStatus[0].ACMEEnvironment)
	}
	if len(cfg.Bindings) != 1 || len(statuses) != 1 {
		t.Fatalf("unexpected cfg/status counts: %d/%d", len(cfg.Bindings), len(statuses))
	}
	dbCfg, _, found, err := getLogsStatsStore().loadActiveTLSBindingConfig()
	if err != nil || !found {
		t.Fatalf("load active tls bindings config found=%v err=%v", found, err)
	}
	if len(dbCfg.Bindings) != 1 || !slices.Contains(dbCfg.Bindings[0].Hosts, "blog.example.com") {
		t.Fatalf("tls bindings DB was not updated: %#v", dbCfg.Bindings)
	}
}

func TestApplyTLSBindingConfigRawRollsBackWhenTLSReloadFails(t *testing.T) {
	restore := setSiteTLSGlobalsForTest(t)
	defer restore()

	config.ServerTLSEnabled = true
	config.ServerPublicListenersConfigured = true
	config.ServerPublicListeners = []config.ServerPublicListener{
		{Name: "setup", ListenAddr: ":9090", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "https", ListenAddr: ":443", Protocol: config.PublicListenerProtocolHTTPS, HTTPBehavior: config.PublicListenerHTTPBehaviorServe, Enabled: true},
		{Name: "http", ListenAddr: ":80", Protocol: config.PublicListenerProtocolHTTP, HTTPBehavior: config.PublicListenerHTTPBehaviorRedirect, RedirectTo: "https", Enabled: true},
	}

	etag, _ := initTLSBindingRuntimeForTest(t, defaultTLSBindingConfigRaw)
	SetServerTLSReloadHook(func(bindings TLSBindingConfigFile, statuses []TLSBindingRuntimeStatus) error {
		if len(bindings.Bindings) > 0 {
			return errors.New("tls reload failed")
		}
		return nil
	})

	raw := `{
  "bindings": [
    {
      "name": "blog",
      "hosts": ["blog.example.com"],
      "mode": "acme"
    }
  ]
}`

	if _, _, _, err := ApplyTLSBindingConfigRaw(etag, raw); err == nil {
		t.Fatal("expected tls reload error")
	}

	currentRaw, currentETag, cfg, statuses, rollbackDepth := TLSBindingConfigSnapshot()
	if currentETag == "" {
		t.Fatal("etag should not be empty after failed apply rollback")
	}
	if strings.Contains(currentRaw, `"blog.example.com"`) {
		t.Fatalf("raw should not contain failed tls binding update: %q", currentRaw)
	}
	if len(cfg.Bindings) != 0 || len(statuses) != 0 {
		t.Fatalf("unexpected cfg/status after rollback: %#v %#v", cfg, statuses)
	}
	if rollbackDepth != 0 {
		t.Fatalf("rollbackDepth=%d want=0", rollbackDepth)
	}
	dbCfg, _, found, err := getLogsStatsStore().loadActiveTLSBindingConfig()
	if err != nil || !found {
		t.Fatalf("load active tls binding config found=%v err=%v", found, err)
	}
	if len(dbCfg.Bindings) != 0 {
		t.Fatalf("tls binding DB should be restored, got: %#v", dbCfg.Bindings)
	}
}

func TestSiteHostsMatchUsesSingleLabelWildcard(t *testing.T) {
	if !siteHostsMatch([]string{"*.example.com"}, "api.example.com") {
		t.Fatal("expected single-label wildcard match")
	}
	if siteHostsMatch([]string{"*.example.com"}, "deep.api.example.com") {
		t.Fatal("wildcard should not match deeper labels")
	}
}

func setSiteTLSGlobalsForTest(t *testing.T) func() {
	t.Helper()

	prevEnabled := config.ServerTLSEnabled
	prevCertFile := config.ServerTLSCertFile
	prevKeyFile := config.ServerTLSKeyFile
	prevACMEEnabled := config.ServerTLSACMEEnabled
	prevACMEDomains := append([]string(nil), config.ServerTLSACMEDomains...)
	prevPublicListenersConfigured := config.ServerPublicListenersConfigured
	prevPublicListeners := append([]config.ServerPublicListener(nil), config.ServerPublicListeners...)
	prevSiteConfigFile := config.SiteConfigFile
	prevTLSBindingConfigFile := config.TLSBindingConfigFile
	prevProxyConfigFile := config.ProxyConfigFile
	serverTLSRuntimeMu.RLock()
	prevReload := serverTLSReload
	serverTLSRuntimeMu.RUnlock()
	siteRuntimeMu.RLock()
	prevSiteRt := siteRt
	siteRuntimeMu.RUnlock()
	tlsBindingRuntimeMu.RLock()
	prevTLSBindingRt := tlsBindingRt
	tlsBindingRuntimeMu.RUnlock()
	proxyRuntimeMu.RLock()
	prevProxyRt := proxyRt
	proxyRuntimeMu.RUnlock()

	return func() {
		config.ServerTLSEnabled = prevEnabled
		config.ServerTLSCertFile = prevCertFile
		config.ServerTLSKeyFile = prevKeyFile
		config.ServerTLSACMEEnabled = prevACMEEnabled
		config.ServerTLSACMEDomains = prevACMEDomains
		config.ServerPublicListenersConfigured = prevPublicListenersConfigured
		config.ServerPublicListeners = prevPublicListeners
		config.SiteConfigFile = prevSiteConfigFile
		config.TLSBindingConfigFile = prevTLSBindingConfigFile
		config.ProxyConfigFile = prevProxyConfigFile
		serverTLSRuntimeMu.Lock()
		serverTLSReload = prevReload
		serverTLSRuntimeMu.Unlock()
		siteRuntimeMu.Lock()
		siteRt = prevSiteRt
		siteRuntimeMu.Unlock()
		tlsBindingRuntimeMu.Lock()
		tlsBindingRt = prevTLSBindingRt
		tlsBindingRuntimeMu.Unlock()
		proxyRuntimeMu.Lock()
		proxyRt = prevProxyRt
		proxyRuntimeMu.Unlock()
	}
}

func initTLSBindingRuntimeForTest(t *testing.T, raw string) (string, string) {
	t.Helper()

	tmp := t.TempDir()
	tlsPath := filepath.Join(tmp, "tls-bindings.json")
	if err := os.WriteFile(tlsPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("WriteFile(tls-bindings): %v", err)
	}
	config.TLSBindingConfigFile = tlsPath
	initConfigDBStoreForTest(t)
	prepared, err := prepareTLSBindingConfigRaw(raw)
	if err != nil {
		t.Fatalf("prepareTLSBindingConfigRaw: %v", err)
	}
	if _, err := getLogsStatsStore().writeTLSBindingConfigVersion("", prepared.cfg, configVersionSourceImport, "", "test tls bindings import", 0); err != nil {
		t.Fatalf("writeTLSBindingConfigVersion: %v", err)
	}
	if err := InitTLSBindingRuntime(tlsPath, 2); err != nil {
		t.Fatalf("InitTLSBindingRuntime: %v", err)
	}
	_, etag, _, _, _ := TLSBindingConfigSnapshot()
	return etag, tlsPath
}

func initSiteAndProxyRuntimeForTest(t *testing.T, siteRaw string) (string, string, string) {
	t.Helper()

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	sitesPath := filepath.Join(tmp, "sites.json")
	proxyRaw := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("WriteFile(proxy): %v", err)
	}
	if err := os.WriteFile(sitesPath, []byte(siteRaw), 0o600); err != nil {
		t.Fatalf("WriteFile(sites): %v", err)
	}
	config.ProxyConfigFile = proxyPath
	config.SiteConfigFile = sitesPath
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, proxyRaw)
	importSiteRuntimeDBForTest(t, siteRaw)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	if err := InitSiteRuntime(sitesPath, 2); err != nil {
		t.Fatalf("InitSiteRuntime: %v", err)
	}
	_, etag, _, _, _ := SiteConfigSnapshot()
	return etag, sitesPath, proxyPath
}

func writeSiteTestTLSFiles(t *testing.T, dnsNames []string) (string, string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	commonName := "localhost"
	if len(dnsNames) > 0 {
		commonName = dnsNames[0]
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: commonName,
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              append([]string(nil), dnsNames...),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	dir := t.TempDir()
	certFile := filepath.Join(dir, "server.crt")
	keyFile := filepath.Join(dir, "server.key")
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(certFile, certPEM, 0o600); err != nil {
		t.Fatalf("write certificate: %v", err)
	}
	if err := os.WriteFile(keyFile, keyPEM, 0o600); err != nil {
		t.Fatalf("write private key: %v", err)
	}
	return certFile, keyFile
}

func jsonStringForSiteTest(v string) string {
	return `"` + strings.ReplaceAll(v, `\`, `\\`) + `"`
}
