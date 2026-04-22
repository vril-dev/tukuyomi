package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCloneProxyTransportRequestWithContextIsolatesHeaderMap(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/demo", nil)
	req.Header.Set("Traceparent", "old")
	req.Header.Set("X-Request", "one")
	ctx := context.WithValue(req.Context(), ctxKey("transport-clone-test"), "value")

	out := cloneProxyTransportRequestWithContext(req, ctx)
	if out == req {
		t.Fatal("transport request clone returned original request")
	}
	if out.Context() != ctx {
		t.Fatal("transport request clone did not attach requested context")
	}

	out.Header.Set("Traceparent", "new")
	out.Header.Set("X-Added", "yes")

	if got := req.Header.Get("Traceparent"); got != "old" {
		t.Fatalf("source traceparent=%q want old", got)
	}
	if got := req.Header.Get("X-Added"); got != "" {
		t.Fatalf("source X-Added=%q want empty", got)
	}
	if got := out.Header.Get("X-Request"); got != "one" {
		t.Fatalf("clone X-Request=%q want one", got)
	}
}

func TestCloneProxyRetryRequestDoesNotMutateSourceRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/original?keep=1", nil)
	req.Host = "proxy.local"
	req.Header.Set("Traceparent", "old")
	originalURL := req.URL.String()
	originalHost := req.Host

	classification := proxyRouteClassification{
		Source:         proxyRouteResolutionRoute,
		OriginalHost:   "proxy.local",
		RewrittenHost:  "backend.host",
		RewrittenPath:  "/rewritten",
		RewrittenQuery: "q=1",
	}
	candidate := proxyRouteTargetCandidate{
		Name:   "backend",
		Target: mustURL("http://backend.local/base?from=target"),
	}

	out, cancel, err := cloneProxyRetryRequest(req, req.Context(), classification, candidate, 0, proxyRetryPolicy{})
	if err != nil {
		t.Fatalf("cloneProxyRetryRequest: %v", err)
	}
	if cancel != nil {
		t.Fatal("cloneProxyRetryRequest returned unexpected cancel for no timeout policy")
	}
	if out == req {
		t.Fatal("retry request clone returned original request")
	}

	out.Header.Set("Traceparent", "new")
	out.URL.Path = "/mutated"

	if got := req.URL.String(); got != originalURL {
		t.Fatalf("source URL=%q want %q", got, originalURL)
	}
	if got := req.Host; got != originalHost {
		t.Fatalf("source Host=%q want %q", got, originalHost)
	}
	if got := req.Header.Get("Traceparent"); got != "old" {
		t.Fatalf("source traceparent=%q want old", got)
	}
	if got := out.URL.Scheme; got != "http" {
		t.Fatalf("retry URL scheme=%q want http", got)
	}
	if got := out.URL.Host; got != "backend.local" {
		t.Fatalf("retry URL host=%q want backend.local", got)
	}
	if got := out.Host; got != "backend.host" {
		t.Fatalf("retry Host=%q want backend.host", got)
	}
}
