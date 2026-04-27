package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestAnnotateWAFHitHonorsExposeWAFDebugHeaders(t *testing.T) {
	tests := []struct {
		name        string
		expose      bool
		wantHit     string
		wantRuleIDs string
	}{
		{
			name:        "default off",
			expose:      false,
			wantHit:     "",
			wantRuleIDs: "",
		},
		{
			name:        "explicit on",
			expose:      true,
			wantHit:     "1",
			wantRuleIDs: "900990,901100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := proxyRt
			proxyRt = &proxyRuntime{
				effectiveCfg: normalizeProxyRulesConfig(ProxyRulesConfig{
					ExposeWAFDebugHeaders: tt.expose,
				}),
			}
			defer func() {
				proxyRt = prev
			}()

			reqURL, err := url.Parse("http://proxy.local/app")
			if err != nil {
				t.Fatalf("url.Parse: %v", err)
			}
			req := (&http.Request{
				Method: http.MethodGet,
				URL:    reqURL,
				Header: make(http.Header),
			}).WithContext(context.WithValue(
				context.WithValue(context.WithValue(context.Background(), ctxKeyWafHit, true), ctxKeyWafRule, "900990,901100"),
				ctxKeyReqID,
				"req-test",
			))
			res := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
				Request:    req,
			}

			annotateWAFHit(res)

			if got := res.Header.Get("X-WAF-Hit"); got != tt.wantHit {
				t.Fatalf("X-WAF-Hit=%q want=%q", got, tt.wantHit)
			}
			if got := res.Header.Get("X-WAF-RuleIDs"); got != tt.wantRuleIDs {
				t.Fatalf("X-WAF-RuleIDs=%q want=%q", got, tt.wantRuleIDs)
			}
		})
	}
}

func TestWriteProxyCachedResponseHonorsExposeWAFDebugHeaders(t *testing.T) {
	tests := []struct {
		name        string
		expose      bool
		wantHit     string
		wantRuleIDs string
	}{
		{
			name:        "default off",
			expose:      false,
			wantHit:     "",
			wantRuleIDs: "",
		},
		{
			name:        "explicit on",
			expose:      true,
			wantHit:     "1",
			wantRuleIDs: "900990,901100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			prev := proxyRt
			proxyRt = &proxyRuntime{
				effectiveCfg: normalizeProxyRulesConfig(ProxyRulesConfig{
					ExposeWAFDebugHeaders: tt.expose,
				}),
			}
			defer func() {
				proxyRt = prev
			}()

			req := httptest.NewRequest(http.MethodGet, "http://proxy.local/app", nil).WithContext(
				context.WithValue(
					context.WithValue(context.WithValue(context.Background(), ctxKeyWafHit, true), ctxKeyWafRule, "900990,901100"),
					ctxKeyReqID,
					"req-test",
				),
			)
			rec := httptest.NewRecorder()
			entry := proxyResponseCacheEntry{
				Status: http.StatusOK,
				Header: http.Header{
					"Content-Type": []string{"text/plain"},
				},
			}

			if err := writeProxyCachedResponse(rec, req, entry, []byte("ok")); err != nil {
				t.Fatalf("writeProxyCachedResponse: %v", err)
			}

			if got := rec.Header().Get("X-WAF-Hit"); got != tt.wantHit {
				t.Fatalf("X-WAF-Hit=%q want=%q", got, tt.wantHit)
			}
			if got := rec.Header().Get("X-WAF-RuleIDs"); got != tt.wantRuleIDs {
				t.Fatalf("X-WAF-RuleIDs=%q want=%q", got, tt.wantRuleIDs)
			}
			if got := rec.Header().Get("X-Tukuyomi-Cache"); got != "HIT" {
				t.Fatalf("X-Tukuyomi-Cache=%q want=HIT", got)
			}
		})
	}
}

func TestServeProxyHonorsExposeWAFDebugHeaders(t *testing.T) {
	tests := []struct {
		name        string
		expose      bool
		wantHit     string
		wantRuleIDs string
	}{
		{
			name:        "default off",
			expose:      false,
			wantHit:     "",
			wantRuleIDs: "",
		},
		{
			name:        "explicit on",
			expose:      true,
			wantHit:     "1",
			wantRuleIDs: "900990,901100",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = w.Write([]byte("ok"))
			}))
			defer upstream.Close()

			tmp := t.TempDir()
			proxyPath := filepath.Join(tmp, "proxy.json")
			raw := `{
  "upstreams": [
    { "name": "primary", "url": "` + upstream.URL + `", "weight": 1, "enabled": true }
  ],
  "expose_waf_debug_headers": ` + map[bool]string{false: "false", true: "true"}[tt.expose] + `,
  "response_header_sanitize": {
    "mode": "auto"
  }
}`
			if err := os.WriteFile(proxyPath, []byte(raw), 0o644); err != nil {
				t.Fatalf("write proxy.json: %v", err)
			}
			if err := InitProxyRuntime(proxyPath, 2); err != nil {
				t.Fatalf("InitProxyRuntime: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://proxy.local/app", nil).WithContext(
				context.WithValue(
					context.WithValue(context.WithValue(context.Background(), ctxKeyWafHit, true), ctxKeyWafRule, "900990,901100"),
					ctxKeyReqID,
					"req-test",
				),
			)
			rec := httptest.NewRecorder()

			ServeProxy(rec, req)

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
			}
			if got := rec.Header().Get("X-WAF-Hit"); got != tt.wantHit {
				t.Fatalf("X-WAF-Hit=%q want=%q", got, tt.wantHit)
			}
			if got := rec.Header().Get("X-WAF-RuleIDs"); got != tt.wantRuleIDs {
				t.Fatalf("X-WAF-RuleIDs=%q want=%q", got, tt.wantRuleIDs)
			}
		})
	}
}
