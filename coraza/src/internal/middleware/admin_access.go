package middleware

import (
	"net"
	"net/http"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const (
	AdminEndpointAPI = "api"
	AdminEndpointUI  = "ui"
)

func AdminAccess(endpointKind string) gin.HandlerFunc {
	return func(c *gin.Context) {
		if adminRequestAllowed(c.Request, endpointKind) {
			c.Next()
			return
		}

		if endpointKind == AdminEndpointUI {
			c.AbortWithStatus(http.StatusForbidden)
			return
		}
		c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "forbidden"})
	}
}

func adminRequestAllowed(r *http.Request, endpointKind string) bool {
	if adminRequestFromTrustedPeer(r) {
		return true
	}

	switch strings.ToLower(strings.TrimSpace(config.AdminExternalMode)) {
	case "deny_external":
		return false
	case "full_external":
		return true
	case "", "api_only_external":
		return endpointKind == AdminEndpointAPI
	default:
		return endpointKind == AdminEndpointAPI
	}
}

func adminRequestFromTrustedPeer(r *http.Request) bool {
	addr, ok := remoteAddr(r)
	if !ok {
		return false
	}
	for _, prefix := range config.AdminTrustedCIDRPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func remoteAddr(r *http.Request) (netip.Addr, bool) {
	if r == nil {
		return netip.Addr{}, false
	}

	raw := strings.TrimSpace(r.RemoteAddr)
	if raw == "" {
		return netip.Addr{}, false
	}

	host := raw
	if parsedHost, _, err := net.SplitHostPort(raw); err == nil {
		host = parsedHost
	}
	host = strings.Trim(host, "[]")
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}
