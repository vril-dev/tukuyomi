package handler

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestDynamicProxyTransportRetriesAndOpensCircuit(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	var fallbackHits int
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer fallback.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "retry_attempts": 1,
  "retry_status_codes": [503],
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [503],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "fallback", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL, fallback.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	transport, err := newDynamicProxyTransport(cfg, tracker)
	if err != nil {
		t.Fatalf("newDynamicProxyTransport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	decision := proxyRouteDecision{
		RewrittenHost: "proxy.local",
		RewrittenPath: "/demo",
		OrderedTargets: []proxyRouteTargetCandidate{
			{
				Key:     proxyBackendLookupKey("primary", primary.URL),
				Name:    "primary",
				Target:  mustURL(primary.URL),
				Weight:  1,
				Managed: true,
			},
			{
				Key:     proxyBackendLookupKey("fallback", fallback.URL),
				Name:    "fallback",
				Target:  mustURL(fallback.URL),
				Weight:  1,
				Managed: true,
			},
		},
		RetryPolicy: proxyBuildRetryPolicy(cfg),
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.StatusCode; got != http.StatusOK {
		t.Fatalf("status=%d want=%d", got, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q want=ok", string(body))
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("primaryHits=%d fallbackHits=%d want 1/1", primaryHits, fallbackHits)
	}

	nextReq, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	nextDecision, err := resolveProxyRouteDecision(nextReq, cfg, tracker)
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	if nextDecision.SelectedUpstream != "fallback" {
		t.Fatalf("selected_upstream=%s want=fallback", nextDecision.SelectedUpstream)
	}

	snapshot := tracker.Snapshot()
	var primaryState upstreamBackendStatus
	for _, backend := range snapshot.Backends {
		if backend.Name == "primary" {
			primaryState = backend
			break
		}
	}
	if primaryState.CircuitState != "open" {
		t.Fatalf("primary circuit_state=%q want=open", primaryState.CircuitState)
	}
}

func TestDynamicProxyTransportRetriesWithH2CUpstreams(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		if r.ProtoMajor != 2 {
			t.Fatalf("primary proto major=%d want=2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}), &http2.Server{}))
	defer primary.Close()

	var fallbackHits int
	fallback := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits++
		if r.ProtoMajor != 2 {
			t.Fatalf("fallback proto major=%d want=2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}), &http2.Server{}))
	defer fallback.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "retry_attempts": 1,
  "retry_status_codes": [503],
  "h2c_upstream": true,
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [503],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "fallback", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL, fallback.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	transport, err := newDynamicProxyTransport(cfg, tracker)
	if err != nil {
		t.Fatalf("newDynamicProxyTransport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	decision := proxyRouteDecision{
		RewrittenHost: "proxy.local",
		RewrittenPath: "/demo",
		OrderedTargets: []proxyRouteTargetCandidate{
			{
				Key:       proxyBackendLookupKey("primary", primary.URL),
				Name:      "primary",
				Target:    mustURL(primary.URL),
				Weight:    1,
				Managed:   true,
				HTTP2Mode: proxyHTTP2ModeH2C,
			},
			{
				Key:       proxyBackendLookupKey("fallback", fallback.URL),
				Name:      "fallback",
				Target:    mustURL(fallback.URL),
				Weight:    1,
				Managed:   true,
				HTTP2Mode: proxyHTTP2ModeH2C,
			},
		},
		RetryPolicy: proxyBuildRetryPolicy(cfg),
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.StatusCode; got != http.StatusOK {
		t.Fatalf("status=%d want=%d", got, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q want=ok", string(body))
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("primaryHits=%d fallbackHits=%d want 1/1", primaryHits, fallbackHits)
	}
}

func TestDynamicProxyTransportRetriesAcrossMixedHTTP2Modes(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(h2c.NewHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		if r.ProtoMajor != 2 {
			t.Fatalf("primary proto major=%d want=2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}), &http2.Server{}))
	defer primary.Close()

	var fallbackHits int
	fallback := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackHits++
		if r.ProtoMajor != 2 {
			t.Fatalf("fallback proto major=%d want=2", r.ProtoMajor)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	fallback.EnableHTTP2 = true
	fallback.StartTLS()
	defer fallback.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "retry_attempts": 1,
  "retry_status_codes": [503],
  "tls_insecure_skip_verify": true,
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [503],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true, "http2_mode": "h2c_prior_knowledge" },
    { "name": "fallback", "url": %q, "weight": 1, "enabled": true, "http2_mode": "force_attempt" }
  ]
}`, primary.URL, fallback.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	transport, err := newDynamicProxyTransport(cfg, tracker)
	if err != nil {
		t.Fatalf("newDynamicProxyTransport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	decision := proxyRouteDecision{
		RewrittenHost: "proxy.local",
		RewrittenPath: "/demo",
		OrderedTargets: []proxyRouteTargetCandidate{
			{
				Key:          proxyBackendLookupKey("primary", primary.URL),
				Name:         "primary",
				Target:       mustURL(primary.URL),
				Weight:       1,
				Managed:      true,
				HTTP2Mode:    proxyHTTP2ModeH2C,
				TransportKey: proxyTransportKey(proxyConfiguredUpstreamTransportProfile(cfg, &cfg.Upstreams[0], cfg.Upstreams[0].HTTP2Mode)),
			},
			{
				Key:          proxyBackendLookupKey("fallback", fallback.URL),
				Name:         "fallback",
				Target:       mustURL(fallback.URL),
				Weight:       1,
				Managed:      true,
				HTTP2Mode:    proxyHTTP2ModeForceAttempt,
				TransportKey: proxyTransportKey(proxyConfiguredUpstreamTransportProfile(cfg, &cfg.Upstreams[1], cfg.Upstreams[1].HTTP2Mode)),
			},
		},
		RetryPolicy: proxyBuildRetryPolicy(cfg),
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.StatusCode; got != http.StatusOK {
		t.Fatalf("status=%d want=%d", got, http.StatusOK)
	}
	if string(body) != "ok" {
		t.Fatalf("body=%q want=ok", string(body))
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("primaryHits=%d fallbackHits=%d want 1/1", primaryHits, fallbackHits)
	}
}

func TestProxyRetryPolicyStatusCountsAsError(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8080", "weight": 1, "enabled": true }
  ],
  "retry_attempts": 1,
  "retry_status_codes": [429],
  "passive_health_enabled": true,
  "passive_unhealthy_status_codes": [404]
}`)

	policy := proxyBuildRetryPolicy(cfg)

	cases := []struct {
		name string
		code int
		want bool
	}{
		{name: "success", code: http.StatusOK, want: false},
		{name: "plain_4xx", code: http.StatusBadRequest, want: false},
		{name: "retry_status", code: http.StatusTooManyRequests, want: true},
		{name: "passive_only_status", code: http.StatusNotFound, want: true},
		{name: "server_error", code: http.StatusServiceUnavailable, want: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := policy.StatusCountsAsError(tc.code); got != tc.want {
				t.Fatalf("StatusCountsAsError(%d)=%v want=%v", tc.code, got, tc.want)
			}
		})
	}
}
