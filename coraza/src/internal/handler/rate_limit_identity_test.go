package handler

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParseJWTSubject_Valid(t *testing.T) {
	got := parseJWTSubject("header.eyJzdWIiOiJ1c2VyLTEifQ.sig")
	if got != "user-1" {
		t.Fatalf("parseJWTSubject()=%q want=%q", got, "user-1")
	}
}

func TestExtractRateLimitJWTSub_IgnoresOversizedAuthorizationToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", maxRateLimitJWTTokenBytes+1))
	if got := extractRateLimitJWTSub(req, []string{"Authorization"}, nil); got != "" {
		t.Fatalf("extractRateLimitJWTSub()=%q want empty", got)
	}
}

func TestExtractRateLimitJWTSub_IgnoresOversizedCookieToken(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.AddCookie(mustCookie("token", strings.Repeat("a", maxRateLimitJWTTokenBytes+1)))
	if got := extractRateLimitJWTSub(req, nil, []string{"token"}); got != "" {
		t.Fatalf("extractRateLimitJWTSub()=%q want empty", got)
	}
}

func TestBuildRateLimitKey_FallsBackToIPWhenJWTMissing(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+strings.Repeat("a", maxRateLimitJWTTokenBytes+1))
	identity := extractRateLimitIdentity(req, rateLimitIdentityConfig{JWTHeaderNames: []string{"Authorization"}})

	if got := buildRateLimitKey(rateLimitKeyByJWTSub, "10.0.0.1", "JP", identity); got != "10.0.0.1" {
		t.Fatalf("jwt_sub fallback key=%q want ip", got)
	}
	if got := buildRateLimitKey(rateLimitKeyByIPJWTSub, "10.0.0.1", "JP", identity); got != "10.0.0.1|10.0.0.1" {
		t.Fatalf("ip_jwt_sub fallback key=%q want ip|ip", got)
	}
}
