package handler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type fakeProxyDNSLookup struct {
	mu     sync.RWMutex
	ips    []net.IPAddr
	srv    []*net.SRV
	ipErr  error
	srvErr error
}

func (f *fakeProxyDNSLookup) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	return append([]net.IPAddr(nil), f.ips...), nil
}

func (f *fakeProxyDNSLookup) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error) {
	f.mu.RLock()
	defer f.mu.RUnlock()
	if f.srvErr != nil {
		return "", nil, f.srvErr
	}
	return "", append([]*net.SRV(nil), f.srv...), nil
}

func withFakeProxyDNSLookup(t *testing.T, lookup proxyDNSLookup) {
	t.Helper()
	prev := proxyDNSLookupProvider
	proxyDNSLookupProvider = lookup
	t.Cleanup(func() {
		proxyDNSLookupProvider = prev
	})
}

func TestProxyDiscoveryDNSMaterializesAddressTargets(t *testing.T) {
	withFakeProxyDNSLookup(t, &fakeProxyDNSLookup{ips: []net.IPAddr{
		{IP: net.ParseIP("127.0.0.10")},
		{IP: net.ParseIP("2001:db8::10")},
	}})
	_, cfg, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "record_types": ["A", "AAAA"],
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ],
  "default_route": { "name": "fallback", "action": { "upstream": "app" } }
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	t.Cleanup(health.Close)
	status := health.Snapshot()
	if len(status.Backends) != 2 {
		t.Fatalf("backends=%#v", status.Backends)
	}
	urls := []string{status.Backends[0].URL, status.Backends[1].URL}
	if !containsExactString(urls, "http://127.0.0.10:8080") || !containsExactString(urls, "http://[2001:db8::10]:8080") {
		t.Fatalf("discovered urls=%#v", urls)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	decision, err := resolveProxyRouteDecision(req, cfg, health)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	if decision.SelectedUpstream != "app" || !strings.HasPrefix(decision.SelectedUpstreamURL, "http://") {
		t.Fatalf("unexpected decision: upstream=%q url=%q", decision.SelectedUpstream, decision.SelectedUpstreamURL)
	}
}

func TestProxyDiscoverySRVMaterializesServiceTargets(t *testing.T) {
	withFakeProxyDNSLookup(t, &fakeProxyDNSLookup{srv: []*net.SRV{
		{Target: "api-a.default.svc.cluster.local.", Port: 8081, Priority: 10},
		{Target: "api-b.default.svc.cluster.local.", Port: 8082, Priority: 20},
	}})
	_, cfg, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    {
      "name": "api",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns_srv",
        "service": "http",
        "proto": "tcp",
        "name": "api.default.svc.cluster.local",
        "scheme": "https",
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ],
  "default_route": { "name": "fallback", "action": { "upstream": "api" } }
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	t.Cleanup(health.Close)
	status := health.Snapshot()
	urls := make([]string, 0, len(status.Backends))
	for _, backend := range status.Backends {
		urls = append(urls, backend.URL)
	}
	if !containsExactString(urls, "https://api-a.default.svc.cluster.local:8081") || !containsExactString(urls, "https://api-b.default.svc.cluster.local:8082") {
		t.Fatalf("discovered srv urls=%#v", urls)
	}
}

func TestProxyDiscoveryKeepsLastGoodTargetsOnFailure(t *testing.T) {
	lookup := &fakeProxyDNSLookup{ips: []net.IPAddr{{IP: net.ParseIP("127.0.0.20")}}}
	withFakeProxyDNSLookup(t, lookup)
	_, cfg, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ],
  "default_route": { "name": "fallback", "action": { "upstream": "app" } }
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	t.Cleanup(health.Close)
	lookup.mu.Lock()
	lookup.ipErr = errors.New("dns down")
	lookup.ips = nil
	lookup.mu.Unlock()
	if err := health.Update(cfg); err != nil {
		t.Fatalf("health.Update: %v", err)
	}
	status := health.Snapshot()
	if len(status.Backends) != 1 || status.Backends[0].URL != "http://127.0.0.20:8080" {
		t.Fatalf("last-good backends=%#v", status.Backends)
	}
	if len(status.Discovery) != 1 || status.Discovery[0].LastError == "" {
		t.Fatalf("discovery status=%#v", status.Discovery)
	}
}

func TestProxyDiscoveryInitialFailureHasNoTargets(t *testing.T) {
	withFakeProxyDNSLookup(t, &fakeProxyDNSLookup{ipErr: errors.New("dns unavailable")})
	_, cfg, _, _, err := parseProxyRulesRaw(`{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ],
  "default_route": { "name": "fallback", "action": { "upstream": "app" } }
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	t.Cleanup(health.Close)
	if got := len(health.Snapshot().Backends); got != 0 {
		t.Fatalf("backends=%d want 0", got)
	}
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	if _, err := resolveProxyRouteDecision(req, cfg, health); err == nil || !strings.Contains(err.Error(), "no proxy targets available") {
		t.Fatalf("expected no proxy targets, got %v", err)
	}
}

func TestProxyDiscoveryValidationRejectsUnsafeConfig(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "url conflict",
			raw:  `{"upstreams":[{"name":"app","url":"http://127.0.0.1:8080","discovery":{"type":"dns","hostname":"app","scheme":"http","port":8080}}]}`,
			want: "url conflicts",
		},
		{
			name: "unsupported scheme",
			raw:  `{"upstreams":[{"name":"app","discovery":{"type":"dns","hostname":"app","scheme":"fcgi","port":8080}}]}`,
			want: "scheme must be http or https",
		},
		{
			name: "invalid timeout",
			raw:  `{"upstreams":[{"name":"app","discovery":{"type":"dns","hostname":"app","scheme":"http","port":8080,"timeout_ms":1}}]}`,
			want: "timeout_ms must be between",
		},
		{
			name: "hostname must not include port",
			raw:  `{"upstreams":[{"name":"app","discovery":{"type":"dns","hostname":"app.internal:8080","scheme":"http","port":8080}}]}`,
			want: "must be a DNS name",
		},
		{
			name: "hostname must be dns label safe",
			raw:  `{"upstreams":[{"name":"app","discovery":{"type":"dns","hostname":"-app.internal","scheme":"http","port":8080}}]}`,
			want: "labels must not start or end with hyphen",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, _, _, _, err := parseProxyRulesRaw(tc.raw, SiteConfigFile{}, VhostConfigFile{})
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err=%v want %q", err, tc.want)
			}
		})
	}
}

func TestUpstreamHealthMonitorCloseCancelsProbe(t *testing.T) {
	started := make(chan struct{})
	cancelled := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(cancelled)
	}))
	t.Cleanup(srv.Close)
	monitor := newUpstreamHealthMonitorForTest(t, ProxyRulesConfig{
		Upstreams:           []ProxyUpstream{{Name: "app", URL: srv.URL, Enabled: true}},
		HealthCheckPath:     "/healthz",
		HealthCheckTimeout:  60,
		HealthCheckInterval: 60,
	})
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("health probe did not start")
	}
	closed := make(chan struct{})
	go func() {
		monitor.Close()
		close(closed)
	}()
	select {
	case <-monitor.stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not signal shutdown")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join the health monitor")
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the health probe")
	}
	status := monitor.Snapshot()
	if status.LastError != "" || status.ConsecutiveFailures != 0 {
		t.Fatalf("shutdown recorded a health failure: %+v", status)
	}
	if len(status.Backends) != 1 || status.Backends[0].LastError != "" || status.Backends[0].ConsecutiveFailures != 0 {
		t.Fatalf("shutdown recorded a backend failure: %+v", status.Backends)
	}
	monitor.Close()
}

type blockingProxyDNSLookup struct {
	defaultProxyDNSLookup
	started   chan struct{}
	cancelled chan struct{}
	release   chan struct{}
}

func (f *blockingProxyDNSLookup) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	close(f.started)
	<-ctx.Done()
	close(f.cancelled)
	<-f.release
	return nil, ctx.Err()
}

func TestUpstreamHealthMonitorCloseWaitsForUpdate(t *testing.T) {
	lookup := &blockingProxyDNSLookup{started: make(chan struct{}), cancelled: make(chan struct{}), release: make(chan struct{})}
	withFakeProxyDNSLookup(t, lookup)
	monitor := newUpstreamHealthMonitorForTest(t, ProxyRulesConfig{
		Upstreams: []ProxyUpstream{{Name: "app", URL: "http://127.0.0.1:8080", Enabled: true}},
	})
	var releaseOnce sync.Once
	releaseLookup := func() { releaseOnce.Do(func() { close(lookup.release) }) }
	t.Cleanup(releaseLookup)
	updated := make(chan error, 1)
	go func() {
		updated <- monitor.Update(ProxyRulesConfig{
			Upstreams: []ProxyUpstream{{
				Name: "app", Enabled: true,
				Discovery: ProxyDiscoveryConfig{
					Type: "dns", Hostname: "app.example.test", Scheme: "http", Port: 8080,
					TimeoutMS: 5000, RefreshIntervalSec: 60,
				},
			}},
		})
	}()
	select {
	case <-lookup.started:
	case <-time.After(2 * time.Second):
		t.Fatal("discovery update did not start")
	}
	closed := make(chan struct{})
	go func() {
		monitor.Close()
		close(closed)
	}()
	select {
	case <-monitor.stopCh:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not signal shutdown")
	}
	select {
	case <-lookup.cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not cancel the discovery lookup")
	}
	select {
	case <-closed:
		t.Fatal("Close returned before the in-flight update finished")
	default:
	}
	releaseLookup()
	select {
	case err := <-updated:
		if err == nil {
			t.Fatal("Update must reject publication after Close")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Update did not finish")
	}
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not join the update")
	}
	if err := monitor.Update(ProxyRulesConfig{}); err == nil {
		t.Fatal("closed monitor accepted another update")
	}
	monitor.Close()
}
