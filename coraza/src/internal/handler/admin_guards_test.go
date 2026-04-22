package handler

import (
	"net/http/httptest"
	"net/netip"
	"testing"

	"tukuyomi/internal/config"
)

func TestAdminAccessControlDefaultsBlankModeToAPIOnlyExternal(t *testing.T) {
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

	access, err := newAdminAccessControl()
	if err != nil {
		t.Fatalf("newAdminAccessControl: %v", err)
	}

	req := httptest.NewRequest("GET", "/tukuyomi-ui", nil)
	req.RemoteAddr = "203.0.113.10:12345"
	if access.allowsEndpoint(req, adminEndpointUI) {
		t.Fatal("expected external admin UI to be denied by default")
	}
	if !access.allowsEndpoint(req, adminEndpointAPI) {
		t.Fatal("expected external admin API to remain allowed by default")
	}
}

func TestResolveAdminClientIPUsesRemoteAddrWhenProxyProtocolAlreadyRewroteConnection(t *testing.T) {
	req := httptest.NewRequest("GET", "/tukuyomi-ui", nil)
	req.RemoteAddr = "198.51.100.10:45678"

	ip, ok := resolveAdminClientIP(req, false, []netip.Prefix{})
	if !ok {
		t.Fatal("expected remote addr to parse")
	}
	if ip.String() != "198.51.100.10" {
		t.Fatalf("client ip=%s want=198.51.100.10", ip)
	}
}
