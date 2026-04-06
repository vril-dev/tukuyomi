package handler

import (
	"context"
	"net/http"
	"net/url"
	"testing"

	"tukuyomi/internal/config"
)

func TestOnProxyResponseStripsInternalHeadersByDefault(t *testing.T) {
	restore := saveForwardingConfigForTest()
	defer restore()

	config.ForwardInternalResponseHeaders = false

	req, err := http.NewRequest(http.MethodGet, "http://example.test/app", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.URL, _ = url.Parse("http://example.test/app")
	ctx := context.WithValue(req.Context(), ctxKeyWafHit, true)
	ctx = context.WithValue(ctx, ctxKeyWafRule, "941100")
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"X-WAF-Hit": []string{"1"}, "X-WAF-RuleIDs": []string{"stale"}},
		Request:    req,
	}

	if err := onProxyResponse(res); err != nil {
		t.Fatalf("onProxyResponse: %v", err)
	}
	if got := res.Header.Get("X-WAF-Hit"); got != "" {
		t.Fatalf("X-WAF-Hit=%q want empty", got)
	}
	if got := res.Header.Get("X-WAF-RuleIDs"); got != "" {
		t.Fatalf("X-WAF-RuleIDs=%q want empty", got)
	}
}

func TestOnProxyResponseCanForwardInternalHeadersWhenEnabled(t *testing.T) {
	restore := saveForwardingConfigForTest()
	defer restore()

	config.ForwardInternalResponseHeaders = true

	req, err := http.NewRequest(http.MethodGet, "http://example.test/app", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.URL, _ = url.Parse("http://example.test/app")
	ctx := context.WithValue(req.Context(), ctxKeyWafHit, true)
	ctx = context.WithValue(ctx, ctxKeyWafRule, "941100")
	req = req.WithContext(ctx)

	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{},
		Request:    req,
	}

	if err := onProxyResponse(res); err != nil {
		t.Fatalf("onProxyResponse: %v", err)
	}
	if got := res.Header.Get("X-WAF-Hit"); got != "1" {
		t.Fatalf("X-WAF-Hit=%q want=%q", got, "1")
	}
	if got := res.Header.Get("X-WAF-RuleIDs"); got != "941100" {
		t.Fatalf("X-WAF-RuleIDs=%q want=%q", got, "941100")
	}
}
