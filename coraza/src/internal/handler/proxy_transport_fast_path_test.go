package handler

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type testRoundTripperFunc func(*http.Request) (*http.Response, error)

func (f testRoundTripperFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func TestOrderProxyRouteCandidatesSingleCandidateRejectsUnavailableManagedBackend(t *testing.T) {
	candidate := proxyRouteTargetCandidate{
		Key:     "missing",
		Name:    "primary",
		Target:  mustURL("http://backend.local"),
		Managed: true,
		Weight:  1,
	}
	health := &upstreamHealthMonitor{
		cfg:      normalizeProxyRulesConfig(ProxyRulesConfig{}),
		backends: nil,
	}

	if got := orderProxyRouteCandidates(httptest.NewRequest(http.MethodGet, "/", nil), []proxyRouteTargetCandidate{candidate}, proxyRouteTargetSelectionOptions{}, health); got != nil {
		t.Fatalf("orderProxyRouteCandidates()=%#v want nil", got)
	}
}

func TestDynamicProxyTransportSingleTargetFastPathUsesRewrittenRequest(t *testing.T) {
	target := mustURL("http://backend.local/base")
	candidate := proxyRouteTargetCandidate{
		Name:         "primary",
		Target:       target,
		Managed:      false,
		Weight:       1,
		TransportKey: "test",
	}
	classification := proxyRouteClassification{
		Source:           proxyRouteResolutionRoute,
		OriginalHost:     "proxy.local",
		RewrittenHost:    "backend.local",
		RewrittenPath:    "/demo",
		RewrittenRawPath: "",
		RewrittenQuery:   "q=1",
		RetryPolicy:      proxyRetryPolicy{},
	}
	selection := proxyRouteTransportSelection{
		SelectedUpstream:     "primary",
		SelectedTransportKey: "test",
		Target:               target,
		OrderedTargets:       []proxyRouteTargetCandidate{candidate},
		RewrittenHost:        "backend.local",
	}
	req := httptest.NewRequest(http.MethodGet, "http://backend.local/base/demo?q=1", nil)
	req.Host = "backend.local"
	req.Header.Set("Traceparent", "old")
	ctx := withProxyRouteClassification(req.Context(), classification)
	ctx = withProxyRouteTransportSelection(ctx, selection)
	req = req.WithContext(ctx)

	var gotReq *http.Request
	transport := &dynamicProxyTransport{
		transports: map[string]http.RoundTripper{
			"test": testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				gotReq = req
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			}),
		},
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	defer resp.Body.Close()
	if gotReq != req {
		t.Fatal("single-target fast path did not use the already rewritten request")
	}
	if got := req.Header.Get("Traceparent"); got != "old" {
		t.Fatalf("source traceparent=%q want old", got)
	}
}

func TestDynamicProxyTransportSingleTargetFastPathReleasesHealthOnBodyClose(t *testing.T) {
	target := mustURL("http://backend.local")
	candidate := proxyRouteTargetCandidate{
		Key:          "primary-key",
		Name:         "primary",
		Target:       target,
		Managed:      true,
		Weight:       1,
		TransportKey: "test",
	}
	classification := proxyRouteClassification{
		Source:        proxyRouteResolutionRoute,
		OriginalHost:  "proxy.local",
		RewrittenHost: "backend.local",
		RewrittenPath: "/demo",
		RetryPolicy:   proxyRetryPolicy{},
	}
	selection := proxyRouteTransportSelection{
		SelectedUpstream:     "primary",
		SelectedTransportKey: "test",
		Target:               target,
		HealthKey:            candidate.Key,
		OrderedTargets:       []proxyRouteTargetCandidate{candidate},
		RewrittenHost:        "backend.local",
	}
	req := httptest.NewRequest(http.MethodGet, "http://backend.local/demo", nil)
	req.Host = "backend.local"
	ctx := withProxyRouteClassification(req.Context(), classification)
	ctx = withProxyRouteTransportSelection(ctx, selection)
	req = req.WithContext(ctx)

	tracker := &upstreamHealthMonitor{
		cfg:     normalizeProxyRulesConfig(ProxyRulesConfig{}),
		metrics: newProxyTransportMetrics(),
		backends: []*proxyBackendState{{
			Key:        candidate.Key,
			Name:       candidate.Name,
			Target:     target,
			Enabled:    true,
			AdminState: upstreamAdminStateEnabled,
			Healthy:    true,
		}},
	}
	transport := &dynamicProxyTransport{
		tracker: tracker,
		transports: map[string]http.RoundTripper{
			"test": testRoundTripperFunc(func(req *http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader("ok")),
				}, nil
			}),
		},
	}

	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatalf("RoundTrip: %v", err)
	}
	if got := tracker.backends[0].InFlight; got != 1 {
		t.Fatalf("inflight before close=%d want 1", got)
	}
	if err := resp.Body.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if got := tracker.backends[0].InFlight; got != 0 {
		t.Fatalf("inflight after close=%d want 0", got)
	}
}
