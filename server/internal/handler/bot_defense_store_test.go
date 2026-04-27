package handler

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"tukuyomi/internal/botdefensestate"
	"tukuyomi/internal/bottelemetry"
)

func TestValidateBotDefenseRaw(t *testing.T) {
	raw := `{
  "enabled": true,
  "dry_run": true,
  "mode": "suspicious",
  "path_prefixes": ["api"],
  "exempt_cidrs": ["127.0.0.1/32"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__bot_ok",
  "challenge_secret": "test-secret-12345",
  "challenge_ttl_seconds": 1800,
  "challenge_status_code": 429,
  "behavioral_detection": {
    "enabled": true,
    "window_seconds": 30,
    "burst_threshold": 10,
    "path_fanout_threshold": 5,
    "ua_churn_threshold": 3,
    "missing_cookie_threshold": 4,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 3
  },
  "device_signals": {
    "enabled": true,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "tls_signals": {
    "enabled": true,
    "require_sni": true,
    "require_alpn": true,
    "require_modern_tls": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403
  },
  "challenge_failure_feedback": {
    "enabled": true,
    "reputation_feedback_seconds": 90
  },
  "path_policies": [
    {
      "name": "login",
      "path_prefixes": ["/login"],
      "dry_run": true
    }
  ]
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	if rt == nil || !rt.Raw.Enabled {
		t.Fatalf("runtime config should be enabled: %#v", rt)
	}
	if !rt.DryRun || !rt.Raw.DryRun {
		t.Fatalf("dry_run was not normalized: %#v %#v", rt.Raw, rt)
	}
	if rt.Raw.Mode != "suspicious" {
		t.Fatalf("mode=%q want=suspicious", rt.Raw.Mode)
	}
	if len(rt.Raw.PathPrefixes) != 1 || rt.Raw.PathPrefixes[0] != "/api" {
		t.Fatalf("path_prefixes=%v want=[/api]", rt.Raw.PathPrefixes)
	}
	if !rt.Raw.BehavioralDetection.Enabled || rt.Behavioral.WindowSeconds != 30 {
		t.Fatalf("behavioral detection was not normalized: %#v %#v", rt.Raw.BehavioralDetection, rt.Behavioral)
	}
	if !rt.Raw.BrowserSignals.Enabled || rt.BrowserSignals.JSCookieName != "__bot_js" || rt.BrowserSignals.RiskScorePerSignal != 3 {
		t.Fatalf("browser signals were not normalized: %#v %#v", rt.Raw.BrowserSignals, rt.BrowserSignals)
	}
	if !rt.Raw.DeviceSignals.Enabled || !rt.DeviceSignals.RequireTimeZone || rt.DeviceSignals.ScoreThreshold != 2 {
		t.Fatalf("device signals were not normalized: %#v %#v", rt.Raw.DeviceSignals, rt.DeviceSignals)
	}
	if !rt.Raw.HeaderSignals.Enabled || !rt.HeaderSignals.RequireAcceptLanguage || rt.HeaderSignals.ScoreThreshold != 2 {
		t.Fatalf("header signals were not normalized: %#v %#v", rt.Raw.HeaderSignals, rt.HeaderSignals)
	}
	if !rt.Raw.TLSSignals.Enabled || !rt.TLSSignals.RequireSNI || rt.TLSSignals.ScoreThreshold != 2 {
		t.Fatalf("tls signals were not normalized: %#v %#v", rt.Raw.TLSSignals, rt.TLSSignals)
	}
	if !rt.Raw.Quarantine.Enabled || rt.Quarantine.StrikesRequired != 2 || rt.Quarantine.StatusCode != 403 {
		t.Fatalf("quarantine was not normalized: %#v %#v", rt.Raw.Quarantine, rt.Quarantine)
	}
	if len(rt.Raw.PathPolicies) != 1 || rt.PathPolicies[0].DryRun == nil || !*rt.PathPolicies[0].DryRun {
		t.Fatalf("path policy dry_run was not normalized: %#v %#v", rt.Raw.PathPolicies, rt.PathPolicies)
	}
	if rt.Quarantine.ReputationFeedback != 0 {
		t.Fatalf("quarantine reputation feedback=%s want=0", rt.Quarantine.ReputationFeedback)
	}
	if !rt.Raw.ChallengeFailureFeedback.Enabled || rt.ChallengeFailureFeedback.ReputationFeedback != 90*time.Second {
		t.Fatalf("challenge failure feedback was not normalized: %#v %#v", rt.Raw.ChallengeFailureFeedback, rt.ChallengeFailureFeedback)
	}
}

func TestValidateBotDefenseRaw_InvalidCookieName(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "bad cookie",
  "challenge_ttl_seconds": 10,
  "challenge_status_code": 429
}`
	if _, err := ValidateBotDefenseRaw(raw); err == nil {
		t.Fatal("expected invalid cookie name error")
	}
}

func TestEvaluateBotDefense_ChallengeThenPass(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	botDefenseMu.Lock()
	prev := botDefenseRuntime
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	defer func() {
		botDefenseMu.Lock()
		botDefenseRuntime = prev
		botDefenseMu.Unlock()
	}()

	now := time.Unix(1_700_000_000, 0).UTC()

	req1 := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req1.Header.Set("User-Agent", "curl/8.0")
	d1 := EvaluateBotDefense(req1, "10.0.0.1", now)
	if d1.Allowed {
		t.Fatalf("first request should require challenge: %+v", d1)
	}
	if d1.Token == "" {
		t.Fatal("challenge token should not be empty")
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req2.Header.Set("User-Agent", "curl/8.0")
	req2.AddCookie(&http.Cookie{Name: d1.CookieName, Value: d1.Token})
	d2 := EvaluateBotDefense(req2, "10.0.0.1", now.Add(1*time.Second))
	if !d2.Allowed {
		t.Fatalf("request with valid challenge cookie should pass: %+v", d2)
	}
}

func TestEvaluateBotDefense_BehavioralSignalsChallenge(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "behavioral_detection": {
    "enabled": true,
    "window_seconds": 60,
    "burst_threshold": 10,
    "path_fanout_threshold": 3,
    "ua_churn_threshold": 2,
    "missing_cookie_threshold": 2,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseBehaviorState()

	now := time.Unix(1_700_001_000, 0).UTC()
	req1 := httptest.NewRequest(http.MethodGet, "http://example.test/a", nil)
	req1.Header.Set("User-Agent", "Mozilla/5.0")
	d1 := EvaluateBotDefense(req1, "10.0.0.2", now)
	if !d1.Allowed {
		t.Fatalf("first behavioral request should pass: %+v", d1)
	}

	req2 := httptest.NewRequest(http.MethodGet, "http://example.test/b", nil)
	req2.Header.Set("User-Agent", "ExampleBot/1.0")
	d2 := EvaluateBotDefense(req2, "10.0.0.2", now.Add(2*time.Second))
	if d2.Allowed {
		t.Fatalf("second request should challenge on behavior: %+v", d2)
	}
	if d2.RiskScore != 4 {
		t.Fatalf("risk score=%d want=4", d2.RiskScore)
	}
	if len(d2.Signals) != 2 {
		t.Fatalf("signals=%v want=2", d2.Signals)
	}
}

func TestEvaluateBotDefense_ValidChallengeWithoutBrowserTelemetryAddsRisk(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_500, 0).UTC()
	token := issueBotDefenseToken(rt, "10.0.0.4", "Mozilla/5.0", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})

	decision := EvaluateBotDefense(req, "10.0.0.4", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("request with valid challenge cookie should pass: %+v", decision)
	}
	if decision.RiskScore != 2 {
		t.Fatalf("risk score=%d want=2", decision.RiskScore)
	}
	if len(decision.Signals) != 1 || decision.Signals[0] != "js_cookie_missing_after_challenge" {
		t.Fatalf("signals=%v want=[js_cookie_missing_after_challenge]", decision.Signals)
	}
}

func TestEvaluateBotDefense_BrowserTelemetrySignalsAddRisk(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_700, 0).UTC()
	token := issueBotDefenseToken(rt, "10.0.0.5", "Mozilla/5.0", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})
	req.AddCookie(&http.Cookie{
		Name:  rt.BrowserSignals.JSCookieName,
		Value: `%7B%22wd%22%3Atrue%2C%22lc%22%3A0%2C%22sw%22%3A0%2C%22sh%22%3A0%7D`,
	})

	decision := EvaluateBotDefense(req, "10.0.0.5", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("request with valid challenge cookie should pass: %+v", decision)
	}
	if decision.RiskScore != 6 {
		t.Fatalf("risk score=%d want=6", decision.RiskScore)
	}
	if len(decision.Signals) != 3 {
		t.Fatalf("signals=%v want=3", decision.Signals)
	}
}

func TestEvaluateBotDefense_DeviceSignalsAddRisk(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  },
  "device_signals": {
    "enabled": true,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_700, 0).UTC()
	token := issueBotDefenseToken(rt, "10.0.0.6", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})
	req.AddCookie(&http.Cookie{
		Name:  rt.BrowserSignals.JSCookieName,
		Value: url.QueryEscape(`{"wd":false,"lc":2,"sw":390,"sh":844,"tz":"","pf":"","hc":0,"mt":0}`),
	})

	decision := EvaluateBotDefense(req, "10.0.0.6", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("request with valid challenge cookie should pass: %+v", decision)
	}
	if decision.RiskScore != 8 {
		t.Fatalf("risk score=%d want=8", decision.RiskScore)
	}
	if len(decision.Signals) != 4 {
		t.Fatalf("signals=%v want=4", decision.Signals)
	}
}

func TestEvaluateBotDefense_DeviceSignalsAllowConsistentMobileBrowser(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  },
  "device_signals": {
    "enabled": true,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_710, 0).UTC()
	token := issueBotDefenseToken(rt, "10.0.0.16", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})
	req.AddCookie(&http.Cookie{
		Name:  rt.BrowserSignals.JSCookieName,
		Value: url.QueryEscape(`{"wd":false,"lc":2,"sw":390,"sh":844,"tz":"Asia/Tokyo","pf":"iPhone","hc":6,"mt":5}`),
	})

	decision := EvaluateBotDefense(req, "10.0.0.16", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("consistent device telemetry should pass: %+v", decision)
	}
	if decision.RiskScore != 0 {
		t.Fatalf("risk score=%d want=0", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_DeviceSignalsWorkWithoutBrowserSignalsEnabled(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "device_signals": {
    "enabled": true,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	if rt.BrowserSignals.JSCookieName == "" {
		t.Fatal("device signals should provision a telemetry cookie name even when browser_signals is off")
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_720, 0).UTC()
	token := issueBotDefenseToken(rt, "10.0.0.17", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Version/17.0 Mobile/15E148 Safari/604.1")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})
	req.AddCookie(&http.Cookie{
		Name:  rt.BrowserSignals.JSCookieName,
		Value: url.QueryEscape(`{"wd":false,"lc":2,"sw":390,"sh":844,"tz":"","pf":"","hc":0,"mt":0}`),
	})

	decision := EvaluateBotDefense(req, "10.0.0.17", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("request with valid challenge cookie should pass: %+v", decision)
	}
	if decision.RiskScore != 8 {
		t.Fatalf("risk score=%d want=8", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_HeaderSignalsChallengeSpoofedBrowser(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_002_900, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	decision := EvaluateBotDefense(req, "10.0.0.6", now)
	if decision.Allowed {
		t.Fatalf("spoofed browser should challenge on header signals: %+v", decision)
	}
	if decision.RiskScore != 8 {
		t.Fatalf("risk score=%d want=8", decision.RiskScore)
	}
	if len(decision.Signals) != 4 {
		t.Fatalf("signals=%v want=4", decision.Signals)
	}
}

func TestEvaluateBotDefense_HeaderSignalsAllowConsistentBrowser(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_003_000, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-CH-UA", "\"Chromium\";v=\"123\", \"Not:A-Brand\";v=\"99\"")
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	decision := EvaluateBotDefense(req, "10.0.0.7", now)
	if !decision.Allowed {
		t.Fatalf("consistent browser should pass without extra risk: %+v", decision)
	}
	if decision.RiskScore != 0 {
		t.Fatalf("risk score=%d want=0", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_TLSSignalsChallengeLegacyBrowser(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "tls_signals": {
    "enabled": true,
    "require_sni": true,
    "require_alpn": true,
    "require_modern_tls": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_003_050, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS10,
		ServerName:         "",
		NegotiatedProtocol: "",
	}

	decision := EvaluateBotDefense(req, "10.0.0.9", now)
	if decision.Action != botDefenseActionChallenge {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionChallenge)
	}
	if decision.RiskScore != 6 {
		t.Fatalf("risk score=%d want=6", decision.RiskScore)
	}
	if len(decision.Signals) != 3 {
		t.Fatalf("signals=%v want=3", decision.Signals)
	}
}

func TestEvaluateBotDefense_TLSSignalsAllowModernBrowser(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "tls_signals": {
    "enabled": true,
    "require_sni": true,
    "require_alpn": true,
    "require_modern_tls": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_003_060, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.TLS = &tls.ConnectionState{
		Version:            tls.VersionTLS13,
		ServerName:         "example.test",
		NegotiatedProtocol: "h2",
	}

	decision := EvaluateBotDefense(req, "10.0.0.10", now)
	if !decision.Allowed {
		t.Fatalf("modern browser tls should pass: %+v", decision)
	}
	if decision.RiskScore != 0 {
		t.Fatalf("risk score=%d want=0", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_QuarantineAfterRepeatedHighRiskSignals(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_003_100, 0).UTC()
	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		return req
	}

	first := EvaluateBotDefense(makeReq(), "10.0.0.8", now)
	if first.Action != botDefenseActionChallenge {
		t.Fatalf("first request action=%q want=%q", first.Action, botDefenseActionChallenge)
	}
	second := EvaluateBotDefense(makeReq(), "10.0.0.8", now.Add(time.Second))
	if second.Action != botDefenseActionQuarantine {
		t.Fatalf("second request action=%q want=%q", second.Action, botDefenseActionQuarantine)
	}
	if second.Status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", second.Status, http.StatusForbidden)
	}
	third := EvaluateBotDefense(makeReq(), "10.0.0.8", now.Add(2*time.Second))
	if third.Action != botDefenseActionQuarantine {
		t.Fatalf("third request should remain quarantined: %+v", third)
	}
}

func TestEvaluateBotDefense_QuarantineAppliesIPReputationPenalty(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 1,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403,
    "reputation_feedback_seconds": 120
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreIPReputation := saveIPReputationStateForTest()
	defer restoreIPReputation()

	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	ipCfg := ipReputationConfig{
		Enabled:            true,
		BlockStatusCode:    http.StatusForbidden,
		RefreshIntervalSec: 60,
		RequestTimeoutSec:  5,
	}
	store, err := newIPReputationStore(ipCfg)
	if err != nil {
		t.Fatalf("newIPReputationStore() unexpected error: %v", err)
	}
	ipReputationMu.Lock()
	ipReputationRuntime = &runtimeIPReputationConfig{
		Raw: ipReputationFile{
			Default: ipCfg,
		},
		Default: runtimeIPReputationScope{
			Raw:   ipCfg,
			Store: store,
		},
		Hosts: map[string]runtimeIPReputationScope{},
	}
	ipReputationStoreRT = store
	ipReputationMu.Unlock()

	now := time.Now().UTC()
	clientIP := "203.0.113.50"
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	decision := EvaluateBotDefense(req, clientIP, now)
	if decision.Action != botDefenseActionQuarantine {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionQuarantine)
	}
	blocked, status := EvaluateIPReputation(clientIP)
	if !blocked {
		t.Fatal("expected quarantine to apply temporary ip reputation penalty")
	}
	if status != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", status, http.StatusForbidden)
	}
	snapshot := IPReputationStatus()
	if snapshot.DynamicPenaltyCount != 1 {
		t.Fatalf("dynamic penalty count=%d want=1", snapshot.DynamicPenaltyCount)
	}
}

func TestWriteBotDefenseChallenge_EmbedsBrowserTelemetryCookie(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("Accept", "text/html")

	WriteBotDefenseChallenge(rec, req, botDefenseDecision{
		Status:            http.StatusTooManyRequests,
		CookieName:        "__tukuyomi_bot_ok",
		BrowserCookieName: "__tukuyomi_bot_js",
		Token:             "token-value",
		TTLSeconds:        60,
	})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusTooManyRequests)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "__tukuyomi_bot_js") {
		t.Fatalf("challenge body should reference telemetry cookie: %s", body)
	}
	if !strings.Contains(body, "navigator.webdriver") {
		t.Fatalf("challenge body should collect browser telemetry: %s", body)
	}
}

func TestMaybeInjectBotDefenseTelemetryHTMLResponse(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "device_signals": {
    "enabled": true,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "invisible_html_injection": true,
    "invisible_max_body_bytes": 4096,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body := "<html><body><h1>Hello</h1></body></html>"
	res := &http.Response{
		StatusCode:    http.StatusOK,
		Header:        http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		Body:          io.NopCloser(strings.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
	}
	if err := maybeInjectBotDefenseTelemetry(res); err != nil {
		t.Fatalf("maybeInjectBotDefenseTelemetry() unexpected error: %v", err)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll(res.Body): %v", err)
	}
	out := string(got)
	if !strings.Contains(out, bottelemetry.ScriptMarker) {
		t.Fatalf("expected invisible telemetry marker in response body: %s", out)
	}
	if !strings.Contains(out, rt.BrowserSignals.JSCookieName) {
		t.Fatalf("expected telemetry cookie name in response body: %s", out)
	}
	if res.Header.Get("X-Tukuyomi-Bot-Telemetry") != "injected" {
		t.Fatalf("expected telemetry injection header, got %q", res.Header.Get("X-Tukuyomi-Bot-Telemetry"))
	}
}

func TestMaybeInjectBotDefenseTelemetrySkipsStrictCSP(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "device_signals": {
    "enabled": true,
    "invisible_html_injection": true,
    "invisible_max_body_bytes": 4096,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	body := "<html><body><h1>Hello</h1></body></html>"
	res := &http.Response{
		StatusCode: http.StatusOK,
		Header: http.Header{
			"Content-Type":            []string{"text/html; charset=utf-8"},
			"Content-Security-Policy": []string{"default-src 'self'; script-src 'self'"},
		},
		Body:          io.NopCloser(strings.NewReader(body)),
		Request:       req,
		ContentLength: int64(len(body)),
	}
	if err := maybeInjectBotDefenseTelemetry(res); err != nil {
		t.Fatalf("maybeInjectBotDefenseTelemetry() unexpected error: %v", err)
	}
	got, err := io.ReadAll(res.Body)
	if err != nil {
		t.Fatalf("ReadAll(res.Body): %v", err)
	}
	if string(got) != body {
		t.Fatalf("expected CSP-protected body to remain unchanged, got %s", string(got))
	}
	if res.Header.Get("X-Tukuyomi-Bot-Telemetry") != "" {
		t.Fatalf("expected no injection header, got %q", res.Header.Get("X-Tukuyomi-Bot-Telemetry"))
	}
}

func TestEvaluateBotDefense_ValidCookieStillCarriesBehaviorRisk(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "behavioral_detection": {
    "enabled": true,
    "window_seconds": 60,
    "burst_threshold": 10,
    "path_fanout_threshold": 10,
    "ua_churn_threshold": 10,
    "missing_cookie_threshold": 1,
    "score_threshold": 1,
    "risk_score_per_signal": 3
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseBehaviorState()

	now := time.Unix(1_700_002_000, 0).UTC()
	warmupReq := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	warmupReq.Header.Set("User-Agent", "Mozilla/5.0")
	warmupDecision := EvaluateBotDefense(warmupReq, "10.0.0.3", now)
	if warmupDecision.Allowed {
		t.Fatalf("warmup request should challenge without a cookie: %+v", warmupDecision)
	}
	token := issueBotDefenseToken(rt, "10.0.0.3", "Mozilla/5.0", now)
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: token})

	decision := EvaluateBotDefense(req, "10.0.0.3", now.Add(time.Second))
	if !decision.Allowed {
		t.Fatalf("request with valid cookie should still pass: %+v", decision)
	}
	if decision.RiskScore != 3 {
		t.Fatalf("risk score=%d want=3", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_PathPolicyOverridesModeAndRequiresTelemetry(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 3600,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  },
  "path_policies": [
    {
      "name": "login",
      "path_prefixes": ["/login"],
      "mode": "always",
      "telemetry_cookie_required": true
    }
  ]
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_004_000, 0).UTC()
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"
	req := httptest.NewRequest(http.MethodGet, "http://example.test/login", nil)
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.AddCookie(&http.Cookie{Name: rt.CookieName, Value: issueBotDefenseToken(rt, "10.0.0.18", userAgent, now)})

	decision := EvaluateBotDefense(req, "10.0.0.18", now.Add(time.Second))
	if decision.Action != botDefenseActionChallenge {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionChallenge)
	}
	if decision.Mode != botDefenseModeAlways {
		t.Fatalf("mode=%q want=%q", decision.Mode, botDefenseModeAlways)
	}
	if decision.FlowPolicy != "login" {
		t.Fatalf("flow policy=%q want=%q", decision.FlowPolicy, "login")
	}
	if !strings.Contains(strings.Join(decision.Signals, ","), "flow_telemetry_missing") {
		t.Fatalf("signals=%v want to contain flow_telemetry_missing", decision.Signals)
	}
}

func TestEvaluateBotDefense_PathPolicyScalesRiskAndSkipsQuarantine(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 1,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403
  },
  "path_policies": [
    {
      "name": "checkout",
      "path_prefixes": ["/checkout"],
      "risk_score_multiplier_percent": 200,
      "risk_score_offset": 1,
      "disable_quarantine": true
    }
  ]
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_004_100, 0).UTC()
	makeReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/checkout", nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html,application/xhtml+xml")
		return req
	}

	first := EvaluateBotDefense(makeReq(), "10.0.0.19", now)
	if first.Action != botDefenseActionChallenge {
		t.Fatalf("first action=%q want=%q", first.Action, botDefenseActionChallenge)
	}
	if first.RiskScore != 17 {
		t.Fatalf("risk score=%d want=17", first.RiskScore)
	}
	if first.FlowPolicy != "checkout" {
		t.Fatalf("flow policy=%q want=%q", first.FlowPolicy, "checkout")
	}

	second := EvaluateBotDefense(makeReq(), "10.0.0.19", now.Add(time.Second))
	if second.Action != botDefenseActionChallenge {
		t.Fatalf("second action=%q want=%q", second.Action, botDefenseActionChallenge)
	}
	if second.Status != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", second.Status, http.StatusTooManyRequests)
	}
	if second.RiskScore != 17 {
		t.Fatalf("second risk score=%d want=17", second.RiskScore)
	}
}

func TestEvaluateBotDefense_DryRunAllowsRequestButRetainsAction(t *testing.T) {
	raw := `{
  "enabled": true,
  "dry_run": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_004_200, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	decision := EvaluateBotDefense(req, "10.0.0.20", now)
	if !decision.Allowed {
		t.Fatalf("dry-run decision should allow request: %+v", decision)
	}
	if !decision.DryRun {
		t.Fatalf("dry_run=%v want=true", decision.DryRun)
	}
	if decision.Action != botDefenseActionChallenge {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionChallenge)
	}
	if decision.RiskScore != 8 {
		t.Fatalf("risk score=%d want=8", decision.RiskScore)
	}
}

func TestEvaluateBotDefense_PathPolicyDryRunOverridesEnforcement(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "path_policies": [
    {
      "name": "login",
      "path_prefixes": ["/login"],
      "dry_run": true
    }
  ]
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_004_300, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/login", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	decision := EvaluateBotDefense(req, "10.0.0.21", now)
	if !decision.Allowed {
		t.Fatalf("path-policy dry-run should allow request: %+v", decision)
	}
	if !decision.DryRun {
		t.Fatalf("dry_run=%v want=true", decision.DryRun)
	}
	if decision.FlowPolicy != "login" {
		t.Fatalf("flow policy=%q want=%q", decision.FlowPolicy, "login")
	}
	if decision.Action != botDefenseActionChallenge {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionChallenge)
	}
}

func TestEvaluateBotDefense_DryRunSkipsQuarantineEscalation(t *testing.T) {
	raw := `{
  "enabled": true,
  "dry_run": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 1,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403,
    "reputation_feedback_seconds": 120
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreIPReputation := saveIPReputationStateForTest()
	defer restoreIPReputation()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	ipCfg := ipReputationConfig{
		Enabled:            true,
		BlockStatusCode:    http.StatusForbidden,
		RefreshIntervalSec: 60,
		RequestTimeoutSec:  5,
	}
	store, err := newIPReputationStore(ipCfg)
	if err != nil {
		t.Fatalf("newIPReputationStore() unexpected error: %v", err)
	}
	ipReputationMu.Lock()
	ipReputationRuntime = &runtimeIPReputationConfig{
		Raw: ipReputationFile{
			Default: ipCfg,
		},
		Default: runtimeIPReputationScope{
			Raw:   ipCfg,
			Store: store,
		},
		Hosts: map[string]runtimeIPReputationScope{},
	}
	ipReputationStoreRT = store
	ipReputationMu.Unlock()

	now := time.Unix(1_700_004_350, 0).UTC()
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml")

	decision := EvaluateBotDefense(req, "10.0.0.22", now)
	if !decision.Allowed || !decision.DryRun {
		t.Fatalf("dry-run decision should allow request without enforcement: %+v", decision)
	}
	if decision.Action != botDefenseActionChallenge {
		t.Fatalf("action=%q want=%q", decision.Action, botDefenseActionChallenge)
	}
	if blocked, _, _ := botDefenseQuarantineStatus(rt, "10.0.0.22", now.Add(time.Second)); blocked {
		t.Fatal("dry-run should not create quarantine state")
	}
	if blocked, _ := EvaluateIPReputation("10.0.0.22"); blocked {
		t.Fatal("dry-run should not apply ip reputation penalty")
	}
}

func TestEvaluateBotDefense_UsesHostScopePrecedence(t *testing.T) {
	raw := `{
  "default": {
    "enabled": false,
    "mode": "suspicious",
    "path_prefixes": ["/"],
    "suspicious_user_agents": ["curl"],
    "challenge_secret": "test-bot-defense-secret-12345",
    "challenge_ttl_seconds": 300,
    "challenge_status_code": 429
  },
  "hosts": {
    "example.com": {
      "enabled": true,
      "mode": "always"
    },
    "example.com:8443": {
      "enabled": true,
      "mode": "suspicious"
    }
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	now := time.Unix(1_700_004_500, 0).UTC()

	reqPort := httptest.NewRequest(http.MethodGet, "https://example.com:8443/", nil)
	reqPort.Header.Set("User-Agent", "curl/8.0")
	decisionPort := EvaluateBotDefense(reqPort, "10.0.0.30", now)
	if decisionPort.Action != botDefenseActionChallenge {
		t.Fatalf("host:port request should challenge: %+v", decisionPort)
	}
	if decisionPort.HostScope != "example.com:8443" {
		t.Fatalf("host scope=%q want example.com:8443", decisionPort.HostScope)
	}

	reqHost := httptest.NewRequest(http.MethodGet, "http://example.com/", nil)
	reqHost.Header.Set("User-Agent", "Mozilla/5.0")
	decisionHost := EvaluateBotDefense(reqHost, "10.0.0.31", now.Add(time.Second))
	if decisionHost.Action != botDefenseActionChallenge {
		t.Fatalf("host request should use always-mode host scope: %+v", decisionHost)
	}
	if decisionHost.HostScope != "example.com" {
		t.Fatalf("host scope=%q want example.com", decisionHost.HostScope)
	}

	reqDefault := httptest.NewRequest(http.MethodGet, "http://other.example.com/", nil)
	reqDefault.Header.Set("User-Agent", "Mozilla/5.0")
	decisionDefault := EvaluateBotDefense(reqDefault, "10.0.0.32", now.Add(2*time.Second))
	if !decisionDefault.Allowed || decisionDefault.Action != "" {
		t.Fatalf("default-disabled request should pass: %+v", decisionDefault)
	}
}

func TestEvaluateBotDefense_BehavioralStateIsolatedByHostScope(t *testing.T) {
	raw := `{
  "default": {
    "enabled": true,
    "mode": "suspicious",
    "path_prefixes": ["/"],
    "suspicious_user_agents": ["curl"],
    "challenge_secret": "test-bot-defense-secret-12345",
    "challenge_ttl_seconds": 300,
    "challenge_status_code": 429,
    "behavioral_detection": {
      "enabled": true,
      "window_seconds": 60,
      "burst_threshold": 10,
      "path_fanout_threshold": 2,
      "ua_churn_threshold": 10,
      "missing_cookie_threshold": 2,
      "score_threshold": 1,
      "risk_score_per_signal": 2
    }
  },
  "hosts": {
    "one.example.com": {
      "enabled": true
    },
    "two.example.com": {
      "enabled": true
    }
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseBehaviorState()

	now := time.Unix(1_700_004_600, 0).UTC()
	reqOneA := httptest.NewRequest(http.MethodGet, "http://one.example.com/a", nil)
	reqOneA.Header.Set("User-Agent", "Mozilla/5.0")
	dOneA := EvaluateBotDefense(reqOneA, "10.0.0.33", now)
	if !dOneA.Allowed {
		t.Fatalf("first request in host scope should pass: %+v", dOneA)
	}

	reqOneB := httptest.NewRequest(http.MethodGet, "http://one.example.com/b", nil)
	reqOneB.Header.Set("User-Agent", "Mozilla/5.0")
	dOneB := EvaluateBotDefense(reqOneB, "10.0.0.33", now.Add(time.Second))
	if dOneB.Action != botDefenseActionChallenge {
		t.Fatalf("second request in first host scope should challenge: %+v", dOneB)
	}
	if dOneB.HostScope != "one.example.com" {
		t.Fatalf("host scope=%q want one.example.com", dOneB.HostScope)
	}

	reqTwoA := httptest.NewRequest(http.MethodGet, "http://two.example.com/a", nil)
	reqTwoA.Header.Set("User-Agent", "Mozilla/5.0")
	dTwoA := EvaluateBotDefense(reqTwoA, "10.0.0.33", now.Add(2*time.Second))
	if !dTwoA.Allowed || dTwoA.Action != "" {
		t.Fatalf("behavioral counters should not bleed into second host scope: %+v", dTwoA)
	}
}

func TestEvaluateBotDefense_QuarantineStrikesIsolatedByHostScope(t *testing.T) {
	raw := `{
  "default": {
    "enabled": true,
    "mode": "suspicious",
    "path_prefixes": ["/"],
    "challenge_secret": "test-bot-defense-secret-12345",
    "challenge_ttl_seconds": 300,
    "challenge_status_code": 429,
    "header_signals": {
      "enabled": true,
      "require_accept_language": true,
      "require_fetch_metadata": true,
      "require_client_hints": true,
      "require_upgrade_insecure_requests": true,
      "score_threshold": 2,
      "risk_score_per_signal": 2
    },
    "quarantine": {
      "enabled": true,
      "threshold": 8,
      "strikes_required": 2,
      "strike_window_seconds": 300,
      "ttl_seconds": 900,
      "status_code": 403
    }
  },
  "hosts": {
    "one.example.com": {
      "enabled": true
    },
    "two.example.com": {
      "enabled": true
    }
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseQuarantineState()

	now := time.Unix(1_700_004_700, 0).UTC()
	clientIP := "10.0.0.34"
	buildReq := func(rawURL string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, rawURL, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
		req.Header.Set("Accept", "text/html")
		return req
	}

	firstOne := EvaluateBotDefense(buildReq("http://one.example.com/"), clientIP, now)
	if firstOne.Action != botDefenseActionChallenge {
		t.Fatalf("first strike should challenge: %+v", firstOne)
	}

	firstTwo := EvaluateBotDefense(buildReq("http://two.example.com/"), clientIP, now.Add(time.Second))
	if firstTwo.Action != botDefenseActionChallenge {
		t.Fatalf("first strike in second host should challenge without inheriting strikes: %+v", firstTwo)
	}
	if blocked, _, _ := botDefenseQuarantineStatusForScope("two.example.com", selectBotDefenseRuntimeByScopeKey(rt, "two.example.com"), clientIP, now.Add(2*time.Second)); blocked {
		t.Fatal("second host should not be quarantined after one strike")
	}

	secondOne := EvaluateBotDefense(buildReq("http://one.example.com/"), clientIP, now.Add(2*time.Second))
	if secondOne.Action != botDefenseActionQuarantine {
		t.Fatalf("second strike in first host should quarantine: %+v", secondOne)
	}
	if secondOne.HostScope != "one.example.com" {
		t.Fatalf("host scope=%q want one.example.com", secondOne.HostScope)
	}
}

func TestImportPolicyJSONStorage_SeedsBotDefenseDBFromFile(t *testing.T) {
	restore := saveBotDefenseStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "bot-defense.json")
	raw := `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__bot_ok",
  "challenge_secret": "test-secret-12345",
  "challenge_ttl_seconds": 1800,
  "challenge_status_code": 429
}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write bot-defense file: %v", err)
	}
	if err := InitBotDefense(path); err != nil {
		t.Fatalf("init bot-defense: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := importPolicyJSONStorage(botDefenseConfigBlobKey, path, normalizeBotDefensePolicyRaw, "bot defense seed import"); err != nil {
		t.Fatalf("import bot-defense storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(botDefenseConfigBlobKey))
	if err != nil || !found {
		t.Fatalf("expected bot-defense normalized rows to be seeded found=%v err=%v", found, err)
	}
	rt, err := ValidateBotDefenseRaw(string(gotRaw))
	if err != nil {
		t.Fatalf("seeded normalized bot-defense invalid: %v", err)
	}
	if !rt.Raw.Enabled || rt.Raw.Mode != "suspicious" || len(rt.Raw.SuspiciousUserAgents) != 1 {
		t.Fatalf("seeded bot-defense mismatch: %+v", rt.Raw)
	}
	if _, _, found, err := store.GetConfigBlob(botDefenseConfigBlobKey); err != nil || found {
		t.Fatalf("legacy bot-defense blob found=%v err=%v", found, err)
	}
}

func TestSyncBotDefenseStorage_ImportsLegacyBlobAndAppliesRuntime(t *testing.T) {
	restore := saveBotDefenseStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "bot-defense.json")
	fileRaw := `{
  "enabled": false,
  "mode": "suspicious",
  "path_prefixes": ["/"]
}`
	if err := os.WriteFile(path, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write bot-defense file: %v", err)
	}
	if err := InitBotDefense(path); err != nil {
		t.Fatalf("init bot-defense: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	dbRaw := `{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/api"],
  "challenge_cookie_name": "__bot_ok",
  "challenge_secret": "test-secret-12345",
  "challenge_ttl_seconds": 1800,
  "challenge_status_code": 429
}`
	if err := store.UpsertConfigBlob(botDefenseConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncBotDefenseStorage(); err != nil {
		t.Fatalf("sync bot-defense storage: %v", err)
	}

	cfg := GetBotDefenseConfig()
	if !cfg.Enabled || cfg.Mode != "always" {
		t.Fatalf("runtime config mismatch: enabled=%v mode=%q", cfg.Enabled, cfg.Mode)
	}
	if _, _, found, err := store.GetConfigBlob(botDefenseConfigBlobKey); err != nil || found {
		t.Fatalf("legacy bot-defense blob found=%v err=%v", found, err)
	}
}

func saveBotDefenseStateForTest() func() {
	botDefenseMu.RLock()
	oldPath := botDefensePath
	oldRuntime := botDefenseRuntime
	botDefenseMu.RUnlock()
	oldBehaviorState := botdefensestate.SnapshotBehaviorStore()
	oldQuarantineState := botdefensestate.SnapshotQuarantineStore()
	botDefenseChallengeStateMu.Lock()
	oldChallengeState := make(map[string]botDefenseChallengePendingState, len(botDefenseChallengeStateByKey))
	for k, v := range botDefenseChallengeStateByKey {
		oldChallengeState[k] = v
	}
	oldChallengeSweep := botDefenseChallengeStateSweep
	botDefenseChallengeStateMu.Unlock()

	return func() {
		botDefenseMu.Lock()
		botDefensePath = oldPath
		botDefenseRuntime = oldRuntime
		botDefenseMu.Unlock()
		botdefensestate.RestoreBehaviorStore(oldBehaviorState)
		botdefensestate.RestoreQuarantineStore(oldQuarantineState)
		botDefenseChallengeStateMu.Lock()
		botDefenseChallengeStateByKey = oldChallengeState
		botDefenseChallengeStateSweep = oldChallengeSweep
		botDefenseChallengeStateMu.Unlock()
	}
}

func saveIPReputationStateForTest() func() {
	ipReputationMu.RLock()
	oldPath := ipReputationPath
	oldRuntime := ipReputationRuntime
	oldStore := ipReputationStoreRT
	ipReputationMu.RUnlock()

	return func() {
		if current := currentIPReputationRuntime(); current != nil && current != oldRuntime {
			closeRuntimeIPReputation(current)
		}
		ipReputationMu.Lock()
		ipReputationPath = oldPath
		ipReputationRuntime = oldRuntime
		ipReputationStoreRT = oldStore
		ipReputationMu.Unlock()
	}
}
