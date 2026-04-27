package requestmeta

import (
	"net"
	"net/http"
	"strings"
)

func ClientIPFromHeaders(realIP string, forwardedFor string, fallback string) string {
	if v := strings.TrimSpace(realIP); v != "" {
		return v
	}
	if v := strings.TrimSpace(forwardedFor); v != "" {
		if i := strings.Index(v, ","); i >= 0 {
			return strings.TrimSpace(v[:i])
		}
		return v
	}
	return strings.TrimSpace(fallback)
}

func ClientIPFromHTTP(req *http.Request) string {
	if req == nil {
		return ""
	}
	fallback := strings.TrimSpace(req.RemoteAddr)
	if host, _, err := net.SplitHostPort(fallback); err == nil {
		fallback = host
	}
	return ClientIPFromHeaders(req.Header.Get("X-Real-IP"), req.Header.Get("X-Forwarded-For"), fallback)
}
