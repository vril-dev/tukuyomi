package botdefensesignals

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"testing"
)

func TestEvaluateBrowserCookieSignals(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: "__bot_js", Value: url.QueryEscape(`{"wd":true,"lc":0,"sw":0,"sh":0}`)})
	score, signals := EvaluateBrowser(BrowserConfig{
		Enabled:            true,
		CookieName:         "__bot_js",
		ScoreThreshold:     2,
		RiskScorePerSignal: 3,
	}, req, false)
	if score != 9 {
		t.Fatalf("score=%d want=9 signals=%v", score, signals)
	}
	for _, want := range []string{"webdriver", "languages_missing", "screen_invalid"} {
		if !slices.Contains(signals, want) {
			t.Fatalf("signal %q missing from %v", want, signals)
		}
	}
}

func TestEvaluateBrowserMissingAfterChallenge(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	score, signals := EvaluateBrowser(BrowserConfig{
		Enabled:            true,
		CookieName:         "__bot_js",
		ScoreThreshold:     1,
		RiskScorePerSignal: 2,
	}, req, true)
	if score != 2 || len(signals) != 1 || signals[0] != "js_cookie_missing_after_challenge" {
		t.Fatalf("score=%d signals=%v", score, signals)
	}
}

func TestEvaluateDeviceAndHeaderAndTLS(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone) AppleWebKit/605.1.15 Mobile Safari/604.1")
	req.Header.Set("Accept", "text/html")
	req.TLS = &tls.ConnectionState{Version: tls.VersionTLS10}
	req.AddCookie(&http.Cookie{Name: "__bot_js", Value: url.QueryEscape(`{"wd":false,"lc":2,"sw":390,"sh":844,"tz":"","pf":"","hc":0,"mt":0}`)})

	deviceScore, deviceSignals := EvaluateDevice(DeviceConfig{
		Enabled:                    true,
		CookieName:                 "__bot_js",
		RequireTimeZone:            true,
		RequirePlatform:            true,
		RequireHardwareConcurrency: true,
		CheckMobileTouch:           true,
		ScoreThreshold:             2,
		RiskScorePerSignal:         2,
	}, req)
	if deviceScore != 8 || len(deviceSignals) != 4 {
		t.Fatalf("device score=%d signals=%v", deviceScore, deviceSignals)
	}

	headerScore, headerSignals := EvaluateHeaders(HeaderConfig{
		Enabled:                true,
		RequireAcceptLanguage:  true,
		RequireFetchMetadata:   true,
		RequireClientHints:     false,
		RequireUpgradeInsecure: true,
		ScoreThreshold:         2,
		RiskScorePerSignal:     2,
	}, req)
	if headerScore != 6 || len(headerSignals) != 3 {
		t.Fatalf("header score=%d signals=%v", headerScore, headerSignals)
	}

	tlsScore, tlsSignals := EvaluateTLS(TLSConfig{
		Enabled:            true,
		RequireSNI:         true,
		RequireALPN:        true,
		RequireModernTLS:   true,
		ScoreThreshold:     2,
		RiskScorePerSignal: 2,
	}, req)
	if tlsScore != 6 || len(tlsSignals) != 3 {
		t.Fatalf("tls score=%d signals=%v", tlsScore, tlsSignals)
	}
}

func TestCanInjectTelemetry(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 AppleWebKit/537.36")
	req.Header.Set("Accept", "text/html")
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": {"text/html; charset=utf-8"}},
		Body:       io.NopCloser(http.NoBody),
	}
	cfg := InjectionConfig{
		RuntimeEnabled:         true,
		DeviceSignalsEnabled:   true,
		InvisibleHTMLInjection: true,
		CookieName:             "__bot_js",
	}
	if !CanInjectTelemetry(cfg, req, res) {
		t.Fatal("expected telemetry injection to be allowed")
	}

	res.Header.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'")
	if CanInjectTelemetry(cfg, req, res) {
		t.Fatal("strict script-src should block inline telemetry injection")
	}
}
