package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func transportMetricsTestLabel(name, rawURL string) string {
	return proxyTransportMetricsUpstreamLabel(name, mustURL(rawURL), true)
}

func transportMetricsTestDirectLabel(rawURL string) string {
	return proxyTransportMetricsUpstreamLabel(rawURL, mustURL(rawURL), false)
}

func findTransportMetricsSnapshotByLabel(snapshot proxyTransportMetricsSnapshot, upstream string) (proxyTransportUpstreamMetricsSnapshot, bool) {
	for _, candidate := range snapshot.Upstreams {
		if candidate.Upstream == upstream {
			return candidate, true
		}
	}
	return proxyTransportUpstreamMetricsSnapshot{}, false
}

func TestUpstreamHealthMonitorCircuitTransitionMetrics(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [503],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, upstream.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	key := proxyBackendLookupKey("primary", upstream.URL)

	tracker.RecordPassiveFailure(key, http.StatusServiceUnavailable, nil)

	tracker.mu.Lock()
	for _, backend := range tracker.backends {
		if backend != nil && backend.Key == key {
			backend.Healthy = true
			backend.CircuitReopenAt = time.Now().UTC().Add(-time.Second)
		}
	}
	tracker.mu.Unlock()

	if !tracker.AcquireTarget(key) {
		t.Fatal("AcquireTarget returned false after reopen window")
	}
	tracker.ReleaseTarget(key)
	tracker.RecordPassiveSuccess(key, http.StatusOK)

	snapshot := tracker.TransportMetricsSnapshot()
	primary, ok := findTransportMetricsSnapshotByLabel(snapshot, transportMetricsTestLabel("primary", upstream.URL))
	if !ok {
		t.Fatalf("missing primary metrics snapshot: %#v", snapshot.Upstreams)
	}
	if primary.PassiveFailuresStatusTotal != 1 {
		t.Fatalf("PassiveFailuresStatusTotal=%d want=1", primary.PassiveFailuresStatusTotal)
	}
	if primary.CircuitOpenTransitionsTotal != 1 {
		t.Fatalf("CircuitOpenTransitionsTotal=%d want=1", primary.CircuitOpenTransitionsTotal)
	}
	if primary.CircuitHalfOpenTransitionsTotal != 1 {
		t.Fatalf("CircuitHalfOpenTransitionsTotal=%d want=1", primary.CircuitHalfOpenTransitionsTotal)
	}
	if primary.CircuitClosedTransitionsTotal != 1 {
		t.Fatalf("CircuitClosedTransitionsTotal=%d want=1", primary.CircuitClosedTransitionsTotal)
	}
}

func TestMetricsAndStatusExposeUpstreamTransportSignals(t *testing.T) {
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
	req = req.WithContext(withProxyRouteDecision(req.Context(), proxyRouteDecision{
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
	}))

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
	if got := string(body); got != "ok" {
		t.Fatalf("body=%q want=ok", got)
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("primaryHits=%d fallbackHits=%d want 1/1", primaryHits, fallbackHits)
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = &proxyRuntime{
		cfg:          cfg,
		effectiveCfg: cfg,
		transport:    transport,
		health:       tracker,
	}
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	metricsRec := httptest.NewRecorder()
	metricsCtx, _ := gin.CreateTestContext(metricsRec)
	MetricsHandler(metricsCtx)
	metricsBody := metricsRec.Body.String()
	primaryLabel := transportMetricsTestLabel("primary", primary.URL)

	for _, needle := range []string{
		fmt.Sprintf(`tukuyomi_upstream_request_duration_seconds_count{upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_errors_total{kind="status",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_retries_total{reason="status",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_passive_failures_total{reason="status",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_circuit_transitions_total{state="open",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_circuit_state{state="open",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_inflight_requests{upstream=%q} 0`, primaryLabel),
	} {
		if !strings.Contains(metricsBody, needle) {
			t.Fatalf("missing metrics line %q in body:\n%s", needle, metricsBody)
		}
	}

	statusRec := httptest.NewRecorder()
	statusCtx, _ := gin.CreateTestContext(statusRec)
	StatusHandler(statusCtx)

	var status map[string]any
	if err := json.Unmarshal(statusRec.Body.Bytes(), &status); err != nil {
		t.Fatalf("json.Unmarshal status: %v", err)
	}
	if got := int(status["proxy_retry_attempts"].(float64)); got != 1 {
		t.Fatalf("proxy_retry_attempts=%d want=1", got)
	}
	if got := status["proxy_circuit_breaker_enabled"].(bool); !got {
		t.Fatalf("proxy_circuit_breaker_enabled=%v want=true", got)
	}
	backends, ok := status["upstream_health_backends"].([]any)
	if !ok || len(backends) != 2 {
		t.Fatalf("upstream_health_backends=%#v", status["upstream_health_backends"])
	}
	var primaryBackend map[string]any
	for _, raw := range backends {
		backend, ok := raw.(map[string]any)
		if ok && backend["name"] == "primary" {
			primaryBackend = backend
			break
		}
	}
	if primaryBackend == nil {
		t.Fatalf("missing primary backend status: %#v", backends)
	}
	if got := primaryBackend["circuit_state"]; got != "open" {
		t.Fatalf("primary circuit_state=%v want=open", got)
	}
	if got := primaryBackend["http2_mode"]; got != proxyHTTP2ModeDefault {
		t.Fatalf("primary http2_mode=%v want=%s", got, proxyHTTP2ModeDefault)
	}
	if got := int(primaryBackend["passive_failures"].(float64)); got != 1 {
		t.Fatalf("primary passive_failures=%d want=1", got)
	}
}

func TestPassiveFailuresIgnoreRetryOnlyStatuses(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		w.WriteHeader(http.StatusTooManyRequests)
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
  "retry_status_codes": [429],
  "passive_health_enabled": true,
  "passive_failure_threshold": 2,
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
	primaryKey := proxyBackendLookupKey("primary", primary.URL)
	tracker.mu.Lock()
	for _, backend := range tracker.backends {
		if backend != nil && backend.Key == primaryKey {
			backend.PassiveFailures = 1
			backend.Healthy = true
		}
	}
	tracker.mu.Unlock()

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), proxyRouteDecision{
		RewrittenHost: "proxy.local",
		RewrittenPath: "/demo",
		OrderedTargets: []proxyRouteTargetCandidate{
			{
				Key:     primaryKey,
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
	}))

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
	if got := string(body); got != "ok" {
		t.Fatalf("body=%q want=ok", got)
	}
	if primaryHits != 1 || fallbackHits != 1 {
		t.Fatalf("primaryHits=%d fallbackHits=%d want 1/1", primaryHits, fallbackHits)
	}

	transportSnapshot := tracker.TransportMetricsSnapshot()
	primaryMetrics, ok := findTransportMetricsSnapshotByLabel(transportSnapshot, transportMetricsTestLabel("primary", primary.URL))
	if !ok {
		t.Fatalf("missing primary transport metrics: %#v", transportSnapshot.Upstreams)
	}
	if primaryMetrics.RetriesStatusTotal != 1 {
		t.Fatalf("RetriesStatusTotal=%d want=1", primaryMetrics.RetriesStatusTotal)
	}
	if primaryMetrics.PassiveFailuresStatusTotal != 0 {
		t.Fatalf("PassiveFailuresStatusTotal=%d want=0", primaryMetrics.PassiveFailuresStatusTotal)
	}

	healthSnapshot := tracker.Snapshot()
	var primaryBackend upstreamBackendStatus
	for _, backend := range healthSnapshot.Backends {
		if backend.Name == "primary" {
			primaryBackend = backend
			break
		}
	}
	if primaryBackend.Name == "" {
		t.Fatalf("missing primary backend status: %#v", healthSnapshot.Backends)
	}
	if primaryBackend.PassiveFailures != 0 {
		t.Fatalf("PassiveFailures=%d want=0", primaryBackend.PassiveFailures)
	}
	if primaryBackend.CircuitState != "" {
		t.Fatalf("CircuitState=%q want empty", primaryBackend.CircuitState)
	}
	if !primaryBackend.Healthy {
		t.Fatalf("Healthy=%v want=true", primaryBackend.Healthy)
	}
}

func TestPassiveFailuresTrackPassiveUnhealthyStatusesWithoutRetry(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer primary.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "retry_attempts": 1,
  "retry_status_codes": [429],
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [503],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	transport, err := newDynamicProxyTransport(cfg, tracker)
	if err != nil {
		t.Fatalf("newDynamicProxyTransport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), proxyRouteDecision{
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
		},
		RetryPolicy: proxyBuildRetryPolicy(cfg),
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.StatusCode; got != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d", got, http.StatusServiceUnavailable)
	}
	if primaryHits != 1 {
		t.Fatalf("primaryHits=%d want=1", primaryHits)
	}

	transportSnapshot := tracker.TransportMetricsSnapshot()
	primaryMetrics, ok := findTransportMetricsSnapshotByLabel(transportSnapshot, transportMetricsTestLabel("primary", primary.URL))
	if !ok {
		t.Fatalf("missing primary transport metrics: %#v", transportSnapshot.Upstreams)
	}
	if primaryMetrics.RetriesStatusTotal != 0 {
		t.Fatalf("RetriesStatusTotal=%d want=0", primaryMetrics.RetriesStatusTotal)
	}
	if primaryMetrics.ErrorsStatusTotal != 1 {
		t.Fatalf("ErrorsStatusTotal=%d want=1", primaryMetrics.ErrorsStatusTotal)
	}
	if primaryMetrics.PassiveFailuresStatusTotal != 1 {
		t.Fatalf("PassiveFailuresStatusTotal=%d want=1", primaryMetrics.PassiveFailuresStatusTotal)
	}

	healthSnapshot := tracker.Snapshot()
	var primaryBackend upstreamBackendStatus
	for _, backend := range healthSnapshot.Backends {
		if backend.Name == "primary" {
			primaryBackend = backend
			break
		}
	}
	if primaryBackend.Name == "" {
		t.Fatalf("missing primary backend status: %#v", healthSnapshot.Backends)
	}
	if primaryBackend.PassiveFailures != 1 {
		t.Fatalf("PassiveFailures=%d want=1", primaryBackend.PassiveFailures)
	}
	if primaryBackend.CircuitState != "open" {
		t.Fatalf("CircuitState=%q want=open", primaryBackend.CircuitState)
	}
	if primaryBackend.Healthy {
		t.Fatalf("Healthy=%v want=false", primaryBackend.Healthy)
	}
}

func TestPassiveFailuresTrackPassiveUnhealthy4xxStatusMetricsWithoutRetry(t *testing.T) {
	var primaryHits int
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryHits++
		w.WriteHeader(http.StatusNotFound)
	}))
	defer primary.Close()

	cfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "retry_attempts": 1,
  "retry_status_codes": [503],
  "passive_health_enabled": true,
  "passive_failure_threshold": 1,
  "passive_unhealthy_status_codes": [404],
  "circuit_breaker_enabled": true,
  "circuit_breaker_open_sec": 30,
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL))

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	transport, err := newDynamicProxyTransport(cfg, tracker)
	if err != nil {
		t.Fatalf("newDynamicProxyTransport: %v", err)
	}

	req, err := http.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	if err != nil {
		t.Fatalf("http.NewRequest: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), proxyRouteDecision{
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
		},
		RetryPolicy: proxyBuildRetryPolicy(cfg),
	}))

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	_ = resp.Body.Close()

	if got := resp.StatusCode; got != http.StatusNotFound {
		t.Fatalf("status=%d want=%d", got, http.StatusNotFound)
	}
	if primaryHits != 1 {
		t.Fatalf("primaryHits=%d want=1", primaryHits)
	}

	transportSnapshot := tracker.TransportMetricsSnapshot()
	primaryMetrics, ok := findTransportMetricsSnapshotByLabel(transportSnapshot, transportMetricsTestLabel("primary", primary.URL))
	if !ok {
		t.Fatalf("missing primary transport metrics: %#v", transportSnapshot.Upstreams)
	}
	if primaryMetrics.RetriesStatusTotal != 0 {
		t.Fatalf("RetriesStatusTotal=%d want=0", primaryMetrics.RetriesStatusTotal)
	}
	if primaryMetrics.ErrorsStatusTotal != 1 {
		t.Fatalf("ErrorsStatusTotal=%d want=1", primaryMetrics.ErrorsStatusTotal)
	}
	if primaryMetrics.PassiveFailuresStatusTotal != 1 {
		t.Fatalf("PassiveFailuresStatusTotal=%d want=1", primaryMetrics.PassiveFailuresStatusTotal)
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = &proxyRuntime{
		cfg:          cfg,
		effectiveCfg: cfg,
		transport:    transport,
		health:       tracker,
	}
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	metricsRec := httptest.NewRecorder()
	metricsCtx, _ := gin.CreateTestContext(metricsRec)
	MetricsHandler(metricsCtx)
	metricsBody := metricsRec.Body.String()
	primaryLabel := transportMetricsTestLabel("primary", primary.URL)

	for _, needle := range []string{
		fmt.Sprintf(`tukuyomi_upstream_errors_total{kind="status",upstream=%q} 1`, primaryLabel),
		fmt.Sprintf(`tukuyomi_upstream_passive_failures_total{reason="status",upstream=%q} 1`, primaryLabel),
	} {
		if !strings.Contains(metricsBody, needle) {
			t.Fatalf("missing metrics line %q in body:\n%s", needle, metricsBody)
		}
	}
}

func TestUpstreamTransportMetricsPruneRemovedSeriesOnReload(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	replacement := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer replacement.Close()

	initialCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL))
	nextCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "replacement", "url": %q, "weight": 1, "enabled": true }
  ]
}`, replacement.URL))

	tracker := newUpstreamHealthMonitorForTest(t, initialCfg)
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 10*time.Millisecond)

	if err := tracker.Update(nextCfg); err != nil {
		t.Fatalf("tracker.Update: %v", err)
	}
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 15*time.Millisecond)
	tracker.metrics.RecordAttempt("replacement", mustURL(replacement.URL), true, 20*time.Millisecond)

	snapshot := tracker.TransportMetricsSnapshot()
	replacementLabel := transportMetricsTestLabel("replacement", replacement.URL)
	if len(snapshot.Upstreams) != 1 {
		t.Fatalf("snapshot.Upstreams=%#v want one active series", snapshot.Upstreams)
	}
	if got := snapshot.Upstreams[0].Upstream; got != replacementLabel {
		t.Fatalf("snapshot.Upstreams[0].Upstream=%q want %q", got, replacementLabel)
	}
	if got := snapshot.Upstreams[0].RequestsTotal; got != 1 {
		t.Fatalf("snapshot.Upstreams[0].RequestsTotal=%d want=1", got)
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = &proxyRuntime{
		cfg:          nextCfg,
		effectiveCfg: nextCfg,
		health:       tracker,
	}
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	MetricsHandler(ctx)
	body := rec.Body.String()

	if strings.Contains(body, fmt.Sprintf(`upstream=%q`, transportMetricsTestLabel("primary", primary.URL))) {
		t.Fatalf("metrics body still exports removed upstream labels:\n%s", body)
	}
	if !strings.Contains(body, fmt.Sprintf(`tukuyomi_upstream_request_duration_seconds_count{upstream=%q} 1`, replacementLabel)) {
		t.Fatalf("metrics body missing replacement transport series:\n%s", body)
	}
}

func TestUpstreamTransportMetricsPreserveSurvivingSeriesOnReload(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	secondary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer secondary.Close()

	replacement := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer replacement.Close()

	initialCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "secondary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL, secondary.URL))
	nextCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "replacement", "url": %q, "weight": 1, "enabled": true }
  ]
}`, primary.URL, replacement.URL))

	tracker := newUpstreamHealthMonitorForTest(t, initialCfg)
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 10*time.Millisecond)
	tracker.metrics.RecordAttempt("secondary", mustURL(secondary.URL), true, 20*time.Millisecond)

	if err := tracker.Update(nextCfg); err != nil {
		t.Fatalf("tracker.Update: %v", err)
	}
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 40*time.Millisecond)
	tracker.metrics.RecordAttempt("replacement", mustURL(replacement.URL), true, 50*time.Millisecond)

	snapshot := tracker.TransportMetricsSnapshot()
	if len(snapshot.Upstreams) != 2 {
		t.Fatalf("snapshot.Upstreams=%#v want surviving and replacement series", snapshot.Upstreams)
	}

	primaryLabel := transportMetricsTestLabel("primary", primary.URL)
	primaryMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, primaryLabel)
	if !ok {
		t.Fatalf("missing surviving primary metrics: %#v", snapshot.Upstreams)
	}
	if primaryMetrics.RequestsTotal != 2 {
		t.Fatalf("primary RequestsTotal=%d want=2 after reload", primaryMetrics.RequestsTotal)
	}
	if got := primaryMetrics.LatencyBucketCounts[1]; got != 1 {
		t.Fatalf("primary LatencyBucketCounts[1]=%d want=1 from pre-reload sample", got)
	}
	if got := primaryMetrics.LatencyBucketCounts[3]; got != 1 {
		t.Fatalf("primary LatencyBucketCounts[3]=%d want=1 from post-reload sample", got)
	}

	if _, ok := findTransportMetricsSnapshotByLabel(snapshot, transportMetricsTestLabel("secondary", secondary.URL)); ok {
		t.Fatalf("removed secondary metrics still present: %#v", snapshot.Upstreams)
	}

	replacementLabel := transportMetricsTestLabel("replacement", replacement.URL)
	replacementMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, replacementLabel)
	if !ok {
		t.Fatalf("missing replacement metrics: %#v", snapshot.Upstreams)
	}
	if replacementMetrics.RequestsTotal != 1 {
		t.Fatalf("replacement RequestsTotal=%d want=1", replacementMetrics.RequestsTotal)
	}
}

func TestUpstreamTransportMetricsResetSeriesOnBackendSwapReload(t *testing.T) {
	original := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer original.Close()

	replacement := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer replacement.Close()

	initialCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, original.URL))
	nextCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true }
  ]
}`, replacement.URL))

	tracker := newUpstreamHealthMonitorForTest(t, initialCfg)
	tracker.metrics.RecordAttempt("primary", mustURL(original.URL), true, 10*time.Millisecond)

	if err := tracker.Update(nextCfg); err != nil {
		t.Fatalf("tracker.Update: %v", err)
	}
	tracker.metrics.RecordAttempt("primary", mustURL(replacement.URL), true, 20*time.Millisecond)

	snapshot := tracker.TransportMetricsSnapshot()
	replacementLabel := transportMetricsTestLabel("primary", replacement.URL)
	if len(snapshot.Upstreams) != 1 {
		t.Fatalf("snapshot.Upstreams=%#v want one active series", snapshot.Upstreams)
	}
	if got := snapshot.Upstreams[0].Upstream; got != replacementLabel {
		t.Fatalf("snapshot.Upstreams[0].Upstream=%q want %q", got, replacementLabel)
	}
	if got := snapshot.Upstreams[0].RequestsTotal; got != 1 {
		t.Fatalf("snapshot.Upstreams[0].RequestsTotal=%d want=1 after backend swap", got)
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = &proxyRuntime{
		cfg:          nextCfg,
		effectiveCfg: nextCfg,
		health:       tracker,
	}
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	MetricsHandler(ctx)
	body := rec.Body.String()

	if !strings.Contains(body, fmt.Sprintf(`tukuyomi_upstream_request_duration_seconds_count{upstream=%q} 1`, replacementLabel)) {
		t.Fatalf("metrics body missing reset primary transport series:\n%s", body)
	}
}

func TestUpstreamTransportMetricsSyncRouteOnlyNamedTargets(t *testing.T) {
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer primary.Close()

	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer canary.Close()

	nextPrimary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer nextPrimary.Close()

	nextCanary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer nextCanary.Close()

	initialCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "canary", "url": %q, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "catchall",
      "action": {
        "upstream": "primary",
        "canary_upstream": "canary",
        "canary_weight_percent": 25
      }
    }
  ]
}`, primary.URL, canary.URL))
	nextCfg := mustValidateProxyRulesRaw(t, fmt.Sprintf(`{
  "upstreams": [
    { "name": "primary", "url": %q, "weight": 1, "enabled": true },
    { "name": "canary", "url": %q, "weight": 1, "enabled": true }
  ],
  "routes": [
    {
      "name": "catchall",
      "action": {
        "upstream": "primary",
        "canary_upstream": "canary",
        "canary_weight_percent": 25
      }
    }
  ]
}`, nextPrimary.URL, nextCanary.URL))

	tracker := newUpstreamHealthMonitorForTest(t, initialCfg)
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 10*time.Millisecond)
	tracker.metrics.RecordAttempt("canary", mustURL(canary.URL), true, 20*time.Millisecond)

	snapshot := tracker.TransportMetricsSnapshot()
	primaryLabel := transportMetricsTestLabel("primary", primary.URL)
	canaryLabel := transportMetricsTestLabel("canary", canary.URL)
	primaryMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, primaryLabel)
	if !ok {
		t.Fatalf("missing primary route-only metrics: %#v", snapshot.Upstreams)
	}
	if primaryMetrics.RequestsTotal != 1 {
		t.Fatalf("primary RequestsTotal=%d want=1", primaryMetrics.RequestsTotal)
	}
	canaryMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, canaryLabel)
	if !ok {
		t.Fatalf("missing canary route-only metrics: %#v", snapshot.Upstreams)
	}
	if canaryMetrics.RequestsTotal != 1 {
		t.Fatalf("canary RequestsTotal=%d want=1", canaryMetrics.RequestsTotal)
	}

	if err := tracker.Update(nextCfg); err != nil {
		t.Fatalf("tracker.Update: %v", err)
	}
	tracker.metrics.RecordAttempt("primary", mustURL(primary.URL), true, 30*time.Millisecond)
	tracker.metrics.RecordAttempt("canary", mustURL(canary.URL), true, 40*time.Millisecond)
	tracker.metrics.RecordAttempt("primary", mustURL(nextPrimary.URL), true, 50*time.Millisecond)
	tracker.metrics.RecordAttempt("canary", mustURL(nextCanary.URL), true, 60*time.Millisecond)

	snapshot = tracker.TransportMetricsSnapshot()
	if len(snapshot.Upstreams) != 2 {
		t.Fatalf("snapshot.Upstreams=%#v want two active route-only series", snapshot.Upstreams)
	}
	nextPrimaryLabel := transportMetricsTestLabel("primary", nextPrimary.URL)
	nextCanaryLabel := transportMetricsTestLabel("canary", nextCanary.URL)
	if _, ok := findTransportMetricsSnapshotByLabel(snapshot, primaryLabel); ok {
		t.Fatalf("stale primary route-only label still present: %#v", snapshot.Upstreams)
	}
	if _, ok := findTransportMetricsSnapshotByLabel(snapshot, canaryLabel); ok {
		t.Fatalf("stale canary route-only label still present: %#v", snapshot.Upstreams)
	}
	nextPrimaryMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, nextPrimaryLabel)
	if !ok {
		t.Fatalf("missing next primary route-only metrics: %#v", snapshot.Upstreams)
	}
	if nextPrimaryMetrics.RequestsTotal != 1 {
		t.Fatalf("next primary RequestsTotal=%d want=1", nextPrimaryMetrics.RequestsTotal)
	}
	nextCanaryMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, nextCanaryLabel)
	if !ok {
		t.Fatalf("missing next canary route-only metrics: %#v", snapshot.Upstreams)
	}
	if nextCanaryMetrics.RequestsTotal != 1 {
		t.Fatalf("next canary RequestsTotal=%d want=1", nextCanaryMetrics.RequestsTotal)
	}
}

func TestTransportMetricsKeepManagedLabelWhenNameMatchesURL(t *testing.T) {
	rawURL := "http://backend.internal/service"
	managedLabel := proxyTransportMetricsUpstreamLabel(rawURL, mustURL(rawURL), true)
	directLabel := proxyTransportMetricsUpstreamLabel(rawURL, mustURL(rawURL), false)

	if managedLabel != proxyBackendLookupKey(rawURL, rawURL) {
		t.Fatalf("managed label=%q want=%q", managedLabel, proxyBackendLookupKey(rawURL, rawURL))
	}
	if directLabel != rawURL {
		t.Fatalf("direct label=%q want=%q", directLabel, rawURL)
	}
	if managedLabel == directLabel {
		t.Fatalf("managed label collapsed to direct label %q", managedLabel)
	}
}

func TestMetricsExposeDistinctSeriesForDuplicateNameSameHostUpstreams(t *testing.T) {
	cfg := mustValidateProxyRulesRaw(t, `{
  "upstreams": [
    { "name": "shared", "url": "http://backend.internal/v1", "weight": 1, "enabled": true },
    { "name": "shared", "url": "http://backend.internal/v2", "weight": 1, "enabled": true }
  ]
}`)

	tracker := newUpstreamHealthMonitorForTest(t, cfg)
	firstLabel := transportMetricsTestLabel("shared", "http://backend.internal/v1")
	secondLabel := transportMetricsTestLabel("shared", "http://backend.internal/v2")

	tracker.metrics.RecordAttempt("shared", mustURL("http://backend.internal/v1"), true, 10*time.Millisecond)
	tracker.metrics.RecordAttempt("shared", mustURL("http://backend.internal/v2"), true, 20*time.Millisecond)

	snapshot := tracker.TransportMetricsSnapshot()
	if len(snapshot.Upstreams) != 2 {
		t.Fatalf("snapshot.Upstreams=%#v want two distinct series", snapshot.Upstreams)
	}
	firstMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, firstLabel)
	if !ok {
		t.Fatalf("missing first upstream metrics: %#v", snapshot.Upstreams)
	}
	secondMetrics, ok := findTransportMetricsSnapshotByLabel(snapshot, secondLabel)
	if !ok {
		t.Fatalf("missing second upstream metrics: %#v", snapshot.Upstreams)
	}
	if firstMetrics.RequestsTotal != 1 || secondMetrics.RequestsTotal != 1 {
		t.Fatalf("requests totals=(%d,%d) want 1/1", firstMetrics.RequestsTotal, secondMetrics.RequestsTotal)
	}

	proxyRuntimeMu.Lock()
	prev := proxyRt
	proxyRt = &proxyRuntime{
		cfg:          cfg,
		effectiveCfg: cfg,
		health:       tracker,
	}
	proxyRuntimeMu.Unlock()
	defer func() {
		proxyRuntimeMu.Lock()
		proxyRt = prev
		proxyRuntimeMu.Unlock()
	}()

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	MetricsHandler(ctx)
	body := rec.Body.String()

	for _, needle := range []string{
		fmt.Sprintf(`tukuyomi_upstream_request_duration_seconds_count{upstream=%q} 1`, firstLabel),
		fmt.Sprintf(`tukuyomi_upstream_request_duration_seconds_count{upstream=%q} 1`, secondLabel),
		fmt.Sprintf(`tukuyomi_upstream_inflight_requests{upstream=%q} 0`, firstLabel),
		fmt.Sprintf(`tukuyomi_upstream_inflight_requests{upstream=%q} 0`, secondLabel),
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("missing metrics line %q in body:\n%s", needle, body)
		}
	}
	if strings.Contains(body, `upstream="shared"`) {
		t.Fatalf("metrics body still exports collapsed duplicate-name label:\n%s", body)
	}
}
