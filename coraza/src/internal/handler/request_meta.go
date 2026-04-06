package handler

import (
	"net"
	"net/netip"
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func requestClientIP(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	return strings.TrimSpace(c.ClientIP())
}

func trustedForwardedHeaders(c *gin.Context) bool {
	if c == nil || c.Request == nil {
		return false
	}

	return remotePeerTrusted(c.Request.RemoteAddr)
}

func trustedRequestID(c *gin.Context) string {
	if !trustedForwardedHeaders(c) {
		return ""
	}

	return normalizeTrustedRequestID(c.GetHeader("X-Request-ID"))
}

func normalizeTrustedRequestID(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" || len(s) > 128 {
		return ""
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '-', r == '_', r == '.', r == ':':
		default:
			return ""
		}
	}

	return s
}

func remotePeerTrusted(remoteAddr string) bool {
	if len(config.TrustedProxyPrefixes) == 0 {
		return false
	}

	host := strings.TrimSpace(remoteAddr)
	if host == "" {
		return false
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	addr = addr.Unmap()

	for _, prefix := range config.TrustedProxyPrefixes {
		if prefix.Contains(addr) {
			return true
		}
	}

	return false
}
