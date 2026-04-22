package handler

import (
	"net"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

func requestClientIP(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return ""
	}

	if v := strings.TrimSpace(c.GetHeader("X-Real-IP")); v != "" {
		return v
	}
	if v := strings.TrimSpace(c.GetHeader("X-Forwarded-For")); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return v
	}

	return strings.TrimSpace(c.ClientIP())
}

func requestClientIPHTTP(req *http.Request) string {
	if req == nil {
		return ""
	}
	if v := strings.TrimSpace(req.Header.Get("X-Real-IP")); v != "" {
		return v
	}
	if v := strings.TrimSpace(req.Header.Get("X-Forwarded-For")); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return v
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(req.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(req.RemoteAddr)
}
