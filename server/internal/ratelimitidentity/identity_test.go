package ratelimitidentity

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseJWTSubjectValid(t *testing.T) {
	got := ParseJWTSubject("header.eyJzdWIiOiJ1c2VyLTEifQ.sig")
	if got != "user-1" {
		t.Fatalf("ParseJWTSubject()=%q want=%q", got, "user-1")
	}
}

func TestExtractJWTSubIgnoresOversizedAuthorizationToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", MaxJWTTokenBytes+1))
	if got := ExtractJWTSub(req, []string{"Authorization"}, nil); got != "" {
		t.Fatalf("ExtractJWTSub()=%q want empty", got)
	}
}

func TestExtractJWTSubIgnoresOversizedCookieToken(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "token", Value: strings.Repeat("a", MaxJWTTokenBytes+1)})
	if got := ExtractJWTSub(req, nil, []string{"token"}); got != "" {
		t.Fatalf("ExtractJWTSub()=%q want empty", got)
	}
}

func TestBuildKeyFallsBackToIPWhenJWTMissing(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", MaxJWTTokenBytes+1))
	identity := Extract(req, Config{JWTHeaderNames: []string{"Authorization"}})

	if got := BuildKey(KeyByJWTSub, "10.0.0.1", "JP", identity); got != "10.0.0.1" {
		t.Fatalf("jwt_sub fallback key=%q want ip", got)
	}
	if got := BuildKey(KeyByIPJWTSub, "10.0.0.1", "JP", identity); got != "10.0.0.1|10.0.0.1" {
		t.Fatalf("ip_jwt_sub fallback key=%q want ip|ip", got)
	}
}

func TestNormalizeAndApplyAdaptive(t *testing.T) {
	cfg := Config{AdaptiveEnabled: true}
	NormalizeConfig(&cfg)
	if cfg.AdaptiveScoreThreshold != DefaultAdaptiveScoreThreshold {
		t.Fatalf("threshold=%d", cfg.AdaptiveScoreThreshold)
	}
	policy, changed := ApplyAdaptive(cfg, Policy{Limit: 100, Burst: 20}, cfg.AdaptiveScoreThreshold+2)
	if !changed {
		t.Fatal("expected adaptive change")
	}
	if policy.Limit != 30 || policy.Burst != 6 {
		t.Fatalf("policy=%#v want limit=30 burst=6", policy)
	}
}
