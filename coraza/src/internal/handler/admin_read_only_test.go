package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestAdminReadOnlyMutationMiddlewareAllowsWhenDisabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminReadOnlyConfig()
	defer restore()
	config.AdminReadOnly = false

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/mutate", nil)

	called := false
	AdminReadOnlyMutationMiddleware()(c)
	if !c.IsAborted() {
		called = true
	}

	if !called {
		t.Fatal("middleware should allow request when read-only is disabled")
	}
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}
}

func TestAdminReadOnlyMutationMiddlewareBlocksWhenEnabled(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminReadOnlyConfig()
	defer restore()
	config.AdminReadOnly = true

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodPut, "/mutate", nil)

	AdminReadOnlyMutationMiddleware()(c)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), adminReadOnlyMessage) {
		t.Fatalf("body=%q missing message %q", rec.Body.String(), adminReadOnlyMessage)
	}
}

func saveAdminReadOnlyConfig() func() {
	old := config.AdminReadOnly
	return func() {
		config.AdminReadOnly = old
	}
}
