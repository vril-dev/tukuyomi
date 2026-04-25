package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

func TestAdminAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAuthConfig()
	defer restore()

	tests := []struct {
		name         string
		authDisabled bool
		resolver     AdminAuthResolver
		expectedCode int
	}{
		{
			name:         "auth disabled allows request",
			authDisabled: true,
			expectedCode: http.StatusOK,
		},
		{
			name:         "resolver principal accepted",
			authDisabled: false,
			resolver: func(*gin.Context) (AdminAuthResult, bool, error) {
				return AdminAuthResult{
					Principal: adminauth.Principal{
						UserID:   1,
						Username: "admin",
						Role:     adminauth.AdminRoleOwner,
						AuthKind: adminauth.AuthKindSession,
					},
					Mode:          string(adminauth.AuthKindSession),
					FallbackActor: "admin",
				}, true, nil
			},
			expectedCode: http.StatusOK,
		},
		{
			name:         "missing credential rejected",
			authDisabled: false,
			resolver: func(*gin.Context) (AdminAuthResult, bool, error) {
				return AdminAuthResult{}, false, nil
			},
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "resolver error rejected",
			authDisabled: false,
			resolver: func(*gin.Context) (AdminAuthResult, bool, error) {
				return AdminAuthResult{}, false, errors.New("invalid credential")
			},
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			config.APIAuthDisable = tc.authDisabled
			SetAdminAuthResolver(tc.resolver)
			t.Cleanup(func() {
				SetAdminAuthResolver(nil)
			})

			r := gin.New()
			r.Use(AdminAuth())
			r.GET("/protected", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Fatalf("status=%d want=%d", w.Code, tc.expectedCode)
			}
		})
	}
}

func TestAdminAuthSetsPrincipalContext(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAuthConfig()
	defer restore()

	config.APIAuthDisable = false
	SetAdminAuthResolver(func(*gin.Context) (AdminAuthResult, bool, error) {
		return AdminAuthResult{
			Principal: adminauth.Principal{
				UserID:       7,
				Username:     "operator",
				Role:         adminauth.AdminRoleOperator,
				AuthKind:     adminauth.AuthKindToken,
				CredentialID: "11",
				Scopes:       []string{"admin:read"},
			},
			Mode:          string(adminauth.AuthKindToken),
			FallbackActor: "operator",
		}, true, nil
	})
	defer SetAdminAuthResolver(nil)

	r := gin.New()
	r.Use(AdminAuth())
	r.GET("/protected", func(c *gin.Context) {
		principalValue, ok := c.Get("tukuyomi.admin_principal")
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "missing principal"})
			return
		}
		principal, ok := principalValue.(adminauth.Principal)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "invalid principal"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"actor":    c.GetString("tukuyomi.admin_actor"),
			"mode":     c.GetString("tukuyomi.admin_auth_mode"),
			"username": principal.Username,
		})
	})

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
	if got := w.Body.String(); got == "" || !containsAll(got, `"actor":"operator"`, `"mode":"token"`, `"username":"operator"`) {
		t.Fatalf("unexpected body=%s", got)
	}
}

func saveAuthConfig() func() {
	oldDisable := config.APIAuthDisable
	adminAuthResolverMu.RLock()
	oldResolver := adminAuthResolver
	adminAuthResolverMu.RUnlock()
	return func() {
		config.APIAuthDisable = oldDisable
		SetAdminAuthResolver(oldResolver)
	}
}

func containsAll(value string, needles ...string) bool {
	for _, needle := range needles {
		if !strings.Contains(value, needle) {
			return false
		}
	}
	return true
}
