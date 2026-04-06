package handler

import (
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestRequestClientIPUsesTrustedForwardedHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	if err := router.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}

	var got string
	router.GET("/", func(c *gin.Context) {
		got = requestClientIP(c)
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.1.2.3:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got != "198.51.100.10" {
		t.Fatalf("requestClientIP()=%q want=%q", got, "198.51.100.10")
	}
}

func TestRequestClientIPIgnoresForwardedHeadersFromUntrustedPeer(t *testing.T) {
	gin.SetMode(gin.TestMode)

	router := gin.New()
	if err := router.SetTrustedProxies([]string{"10.0.0.0/8"}); err != nil {
		t.Fatalf("SetTrustedProxies: %v", err)
	}

	var got string
	router.GET("/", func(c *gin.Context) {
		got = requestClientIP(c)
		c.Status(http.StatusNoContent)
	})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:23456"
	req.Header.Set("X-Forwarded-For", "198.51.100.10")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if got != "203.0.113.9" {
		t.Fatalf("requestClientIP()=%q want=%q", got, "203.0.113.9")
	}
}

func TestTrustedRequestIDRequiresTrustedPeer(t *testing.T) {
	restore := saveForwardingConfigForTest()
	defer restore()

	config.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	config.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.RemoteAddr = "10.1.2.3:12345"
	ctx.Request.Header.Set("X-Request-ID", "trace-123")
	if got := trustedRequestID(ctx); got != "trace-123" {
		t.Fatalf("trustedRequestID(trusted)=%q want=%q", got, "trace-123")
	}

	ctx.Request.RemoteAddr = "203.0.113.9:12345"
	if got := trustedRequestID(ctx); got != "" {
		t.Fatalf("trustedRequestID(untrusted)=%q want empty", got)
	}
}

func TestTrustedRequestIDRejectsUnsafeValues(t *testing.T) {
	restore := saveForwardingConfigForTest()
	defer restore()

	config.TrustedProxyCIDRs = []string{"10.0.0.0/8"}
	config.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	ctx, _ := gin.CreateTestContext(httptest.NewRecorder())
	ctx.Request = httptest.NewRequest(http.MethodGet, "/", nil)
	ctx.Request.RemoteAddr = "10.1.2.3:12345"
	ctx.Request.Header.Set("X-Request-ID", "bad value")
	if got := trustedRequestID(ctx); got != "" {
		t.Fatalf("trustedRequestID(unsafe)=%q want empty", got)
	}
}

func saveForwardingConfigForTest() func() {
	oldCIDRs := append([]string(nil), config.TrustedProxyCIDRs...)
	oldPrefixes := append([]netip.Prefix(nil), config.TrustedProxyPrefixes...)
	oldForward := config.ForwardInternalResponseHeaders

	return func() {
		config.TrustedProxyCIDRs = oldCIDRs
		config.TrustedProxyPrefixes = oldPrefixes
		config.ForwardInternalResponseHeaders = oldForward
	}
}
