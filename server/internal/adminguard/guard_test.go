package adminguard

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"tukuyomi/internal/config"
)

func TestAccessControlDefaultsBlankModeToAPIOnlyExternal(t *testing.T) {
	prevMode := config.AdminExternalMode
	prevCIDRs := append([]string(nil), config.AdminTrustedCIDRs...)
	prevForwarded := config.AdminTrustForwardedFor
	defer func() {
		config.AdminExternalMode = prevMode
		config.AdminTrustedCIDRs = prevCIDRs
		config.AdminTrustForwardedFor = prevForwarded
	}()

	config.AdminExternalMode = ""
	config.AdminTrustedCIDRs = []string{"127.0.0.1/32"}
	config.AdminTrustForwardedFor = false

	access, err := newAccessControl()
	if err != nil {
		t.Fatalf("newAccessControl: %v", err)
	}

	req := httptest.NewRequest("GET", "/tukuyomi-ui", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	if access.allowsEndpoint(req, endpointUI) {
		t.Fatal("expected external admin UI to be denied by default")
	}
	if !access.allowsEndpoint(req, endpointAPI) {
		t.Fatal("expected external admin API to remain allowed by default")
	}
}

func TestResolveClientIPUsesRemoteAddrWhenProxyProtocolAlreadyRewroteConnection(t *testing.T) {
	req := httptest.NewRequest("GET", "/tukuyomi-ui", nil)
	req.RemoteAddr = "198.51.100.10:45678"

	ip, ok := resolveClientIP(req, false, []netip.Prefix{})
	if !ok {
		t.Fatal("expected remote addr to parse")
	}
	if ip.String() != "198.51.100.10" {
		t.Fatalf("client ip=%s want=198.51.100.10", ip)
	}
}

func TestRateLimitSharesBucketAcrossAuthorizationValues(t *testing.T) {
	prevEnabled := config.AdminRateLimitEnabled
	prevRPS := config.AdminRateLimitRPS
	prevBurst := config.AdminRateLimitBurst
	prevStatus := config.AdminRateLimitStatusCode
	prevRetryAfter := config.AdminRateLimitRetryAfter
	defer func() {
		config.AdminRateLimitEnabled = prevEnabled
		config.AdminRateLimitRPS = prevRPS
		config.AdminRateLimitBurst = prevBurst
		config.AdminRateLimitStatusCode = prevStatus
		config.AdminRateLimitRetryAfter = prevRetryAfter
	}()
	config.AdminRateLimitEnabled = true
	config.AdminRateLimitRPS = 1
	config.AdminRateLimitBurst = 1
	config.AdminRateLimitStatusCode = 429
	config.AdminRateLimitRetryAfter = 1

	limiter := newRateLimiter()
	for i, authorization := range []string{"Bearer first", "Bearer second", ""} {
		req := httptest.NewRequest("POST", "/tukuyomi-api/auth/mfa/verify", nil)
		req.RemoteAddr = "203.0.113.10:12345"
		if authorization != "" {
			req.Header.Set("Authorization", authorization)
		}
		decision := limiter.Evaluate(req)
		if wantAllowed := i == 0; decision.Allowed != wantAllowed {
			t.Fatalf("request %d with Authorization %q allowed=%v want %v", i+1, authorization, decision.Allowed, wantAllowed)
		}
	}

	other := httptest.NewRequest("POST", "/tukuyomi-api/auth/mfa/verify", nil)
	other.RemoteAddr = "203.0.113.11:12345"
	if !limiter.Evaluate(other).Allowed {
		t.Fatal("another peer address should have its own bucket")
	}
}

func TestAccessControlForwardedForFromAppendingProxyCannotClaimTrustedCIDR(t *testing.T) {
	prevMode := config.AdminExternalMode
	prevCIDRs := append([]string(nil), config.AdminTrustedCIDRs...)
	prevForwarded := config.AdminTrustForwardedFor
	defer func() {
		config.AdminExternalMode = prevMode
		config.AdminTrustedCIDRs = prevCIDRs
		config.AdminTrustForwardedFor = prevForwarded
	}()
	config.AdminExternalMode = "api_only_external"
	config.AdminTrustedCIDRs = []string{"10.0.0.0/8"}
	config.AdminTrustForwardedFor = true

	access, err := newAccessControl()
	if err != nil {
		t.Fatalf("newAccessControl: %v", err)
	}
	for _, tc := range []struct {
		name    string
		headers map[string]string
		wantUI  bool
	}{
		{name: "spoofed leftmost entry", headers: map[string]string{"X-Forwarded-For": "10.0.0.5, 203.0.113.9"}},
		{name: "spoofed X-Real-IP is ignored", headers: map[string]string{"X-Forwarded-For": "203.0.113.9", "X-Real-IP": "10.0.0.6"}},
		{name: "internal client through the proxy", headers: map[string]string{"X-Forwarded-For": "10.0.0.5"}, wantUI: true},
	} {
		req := httptest.NewRequest("GET", "/tukuyomi-ui", nil)
		req.RemoteAddr = "10.0.0.2:4000"
		for name, value := range tc.headers {
			req.Header.Set(name, value)
		}
		if got := access.allowsEndpoint(req, endpointUI); got != tc.wantUI {
			t.Fatalf("%s: admin UI allowed=%v want %v", tc.name, got, tc.wantUI)
		}
	}
}
