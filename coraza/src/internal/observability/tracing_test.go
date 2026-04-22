package observability

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSetupTracingDisabledClearsEnabledFlag(t *testing.T) {
	tracingEnabled.Store(true)
	shutdown, err := SetupTracing(context.Background(), TracingConfig{Enabled: false})
	if err != nil {
		t.Fatalf("SetupTracing disabled: %v", err)
	}
	if shutdown == nil {
		t.Fatal("SetupTracing disabled returned nil shutdown")
	}
	if TracingEnabled() {
		t.Fatal("TracingEnabled()=true want false")
	}
}

func TestGinTracingMiddlewareNoopsWhenTracingDisabled(t *testing.T) {
	tracingEnabled.Store(false)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(GinTracingMiddleware())
	router.GET("/demo", func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want %d", rec.Code, http.StatusOK)
	}
	if got := rec.Header().Get("X-Trace-ID"); got != "" {
		t.Fatalf("X-Trace-ID=%q want empty", got)
	}
}
