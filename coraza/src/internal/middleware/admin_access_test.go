package middleware

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestAdminAccess(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAccessConfig()
	defer restore()

	config.AdminTrustedCIDRs = []string{"127.0.0.1/32", "10.0.0.0/8"}
	config.AdminTrustedCIDRPrefixes = mustPrefixes(t, config.AdminTrustedCIDRs...)

	tests := []struct {
		name         string
		mode         string
		endpointKind string
		remoteAddr   string
		wantStatus   int
	}{
		{
			name:         "default mode blocks ui for external peer",
			mode:         "api_only_external",
			endpointKind: AdminEndpointUI,
			remoteAddr:   "198.51.100.24:1234",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "default mode allows api for external peer",
			mode:         "api_only_external",
			endpointKind: AdminEndpointAPI,
			remoteAddr:   "198.51.100.24:1234",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "trusted private peer can reach ui",
			mode:         "api_only_external",
			endpointKind: AdminEndpointUI,
			remoteAddr:   "10.20.30.40:1234",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "deny external blocks api for external peer",
			mode:         "deny_external",
			endpointKind: AdminEndpointAPI,
			remoteAddr:   "198.51.100.24:1234",
			wantStatus:   http.StatusForbidden,
		},
		{
			name:         "full external allows ui for external peer",
			mode:         "full_external",
			endpointKind: AdminEndpointUI,
			remoteAddr:   "198.51.100.24:1234",
			wantStatus:   http.StatusOK,
		},
		{
			name:         "custom trusted cidr allows front proxy ui",
			mode:         "deny_external",
			endpointKind: AdminEndpointUI,
			remoteAddr:   "203.0.113.14:1234",
			wantStatus:   http.StatusOK,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			config.AdminExternalMode = tc.mode
			if tc.name == "custom trusted cidr allows front proxy ui" {
				config.AdminTrustedCIDRs = []string{"203.0.113.0/24"}
				config.AdminTrustedCIDRPrefixes = mustPrefixes(t, config.AdminTrustedCIDRs...)
			} else {
				config.AdminTrustedCIDRs = []string{"127.0.0.1/32", "10.0.0.0/8"}
				config.AdminTrustedCIDRPrefixes = mustPrefixes(t, config.AdminTrustedCIDRs...)
			}

			r := gin.New()
			r.Use(AdminAccess(tc.endpointKind))
			r.GET("/admin", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/admin", nil)
			req.RemoteAddr = tc.remoteAddr
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)
			if w.Code != tc.wantStatus {
				t.Fatalf("status=%d want=%d body=%s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

func TestRemoteAddr(t *testing.T) {
	addr, ok := remoteAddr(&http.Request{RemoteAddr: "[2001:db8::1]:443"})
	if !ok {
		t.Fatal("expected ipv6 remote addr to parse")
	}
	if got := addr.String(); got != "2001:db8::1" {
		t.Fatalf("remoteAddr()=%q want=%q", got, "2001:db8::1")
	}
}

func saveAdminAccessConfig() func() {
	oldMode := config.AdminExternalMode
	oldCIDRs := append([]string(nil), config.AdminTrustedCIDRs...)
	oldPrefixes := append([]netip.Prefix(nil), config.AdminTrustedCIDRPrefixes...)
	return func() {
		config.AdminExternalMode = oldMode
		config.AdminTrustedCIDRs = oldCIDRs
		config.AdminTrustedCIDRPrefixes = oldPrefixes
	}
}

func mustPrefixes(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()
	out := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("ParsePrefix(%q): %v", cidr, err)
		}
		out = append(out, prefix)
	}
	return out
}
