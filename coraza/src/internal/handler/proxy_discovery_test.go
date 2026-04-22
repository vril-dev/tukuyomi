package handler

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type fakeProxyDNSLookup struct {
	ips    []net.IPAddr
	srv    []*net.SRV
	ipErr  error
	srvErr error
}

func (f *fakeProxyDNSLookup) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	if f.ipErr != nil {
		return nil, f.ipErr
	}
	return append([]net.IPAddr(nil), f.ips...), nil
}

func (f *fakeProxyDNSLookup) LookupSRV(ctx context.Context, service string, proto string, name string) (string, []*net.SRV, error) {
	if f.srvErr != nil {
		return "", nil, f.srvErr
	}
	return "", append([]*net.SRV(nil), f.srv...), nil
}

func withFakeProxyDNSLookup(t *testing.T, lookup *fakeProxyDNSLookup) {
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
  ]
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
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
  ]
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
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
  ]
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	lookup.ipErr = errors.New("dns down")
	lookup.ips = nil
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
  ]
}`, SiteConfigFile{}, VhostConfigFile{})
	if err != nil {
		t.Fatalf("parseProxyRulesRaw: %v", err)
	}
	health, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
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
