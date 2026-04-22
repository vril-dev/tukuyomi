package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestEnsureProxyRequestIDSetsRequestAndResponseHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/ok", nil)
	rec := httptest.NewRecorder()
	ctx := newProxyServeContext(rec, req)

	reqID := ensureProxyRequestID(ctx)

	if reqID == "" {
		t.Fatal("generated request id is empty")
	}
	if got := ctx.Request.Header.Get("X-Request-ID"); got != reqID {
		t.Fatalf("request X-Request-ID=%q want %q", got, reqID)
	}
	if got := rec.Header().Get("X-Request-ID"); got != reqID {
		t.Fatalf("response X-Request-ID=%q want %q", got, reqID)
	}
}

func TestEnsureProxyRequestIDPreservesInboundRequestID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://proxy.local/ok", nil)
	req.Header.Set("X-Request-ID", "req-inbound")
	rec := httptest.NewRecorder()
	ctx := newProxyServeContext(rec, req)

	reqID := ensureProxyRequestID(ctx)

	if reqID != "req-inbound" {
		t.Fatalf("request id=%q want req-inbound", reqID)
	}
	if got := rec.Header().Get("X-Request-ID"); got != "req-inbound" {
		t.Fatalf("response X-Request-ID=%q want req-inbound", got)
	}
}
