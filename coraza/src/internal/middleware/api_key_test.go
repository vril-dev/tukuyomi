package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

func TestSecureKeyMatch(t *testing.T) {
	if !secureKeyMatch("abcdefghijklmnop", "abcdefghijklmnop") {
		t.Fatal("secureKeyMatch should return true for equal keys")
	}
	if secureKeyMatch("abcdefghijklmnop", "abcdefghijklmnoq") {
		t.Fatal("secureKeyMatch should return false for different keys")
	}
	if secureKeyMatch("", "abcdefghijklmnop") {
		t.Fatal("secureKeyMatch should return false for empty candidate key")
	}
	if secureKeyMatch("abcdefghijklmnop", "") {
		t.Fatal("secureKeyMatch should return false for empty expected key")
	}
}

func TestAPIKeyAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAuthConfig()
	defer restore()

	tests := []struct {
		name         string
		authDisabled bool
		primary      string
		secondary    string
		header       string
		expectedCode int
	}{
		{
			name:         "auth disabled allows request",
			authDisabled: true,
			primary:      "",
			secondary:    "",
			header:       "",
			expectedCode: http.StatusOK,
		},
		{
			name:         "primary key accepted",
			authDisabled: false,
			primary:      "primary-key-123456",
			secondary:    "secondary-key-1234",
			header:       "primary-key-123456",
			expectedCode: http.StatusOK,
		},
		{
			name:         "secondary key accepted",
			authDisabled: false,
			primary:      "primary-key-123456",
			secondary:    "secondary-key-1234",
			header:       "secondary-key-1234",
			expectedCode: http.StatusOK,
		},
		{
			name:         "invalid key rejected",
			authDisabled: false,
			primary:      "primary-key-123456",
			secondary:    "",
			header:       "wrong-key",
			expectedCode: http.StatusUnauthorized,
		},
		{
			name:         "no configured key rejected",
			authDisabled: false,
			primary:      "",
			secondary:    "",
			header:       "anything",
			expectedCode: http.StatusUnauthorized,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			config.APIAuthDisable = tc.authDisabled
			config.APIKeyPrimary = tc.primary
			config.APIKeySecondary = tc.secondary
			config.AdminSessionSecret = tc.primary
			config.AdminSessionTTL = time.Hour

			r := gin.New()
			r.Use(APIKeyAuth())
			r.GET("/protected", func(c *gin.Context) {
				c.Status(http.StatusOK)
			})

			req := httptest.NewRequest(http.MethodGet, "/protected", nil)
			if tc.header != "" {
				req.Header.Set("X-API-Key", tc.header)
			}
			w := httptest.NewRecorder()

			r.ServeHTTP(w, req)
			if w.Code != tc.expectedCode {
				t.Fatalf("status=%d want=%d", w.Code, tc.expectedCode)
			}
		})
	}
}

func TestAPIKeyAuthAcceptsValidSession(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAuthConfig()
	defer restore()

	config.APIAuthDisable = false
	config.APIKeyPrimary = "primary-key-123456"
	config.APIKeySecondary = ""
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour

	token, csrf, expiresAt, err := adminauth.Issue(config.AdminSessionSecret, time.Hour, time.Now().UTC())
	if err != nil {
		t.Fatalf("Issue() error = %v", err)
	}

	r := gin.New()
	r.Use(APIKeyAuth())
	r.POST("/protected", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodPost, "/protected", nil)
	req.Header.Set(adminauth.CSRFHeaderName, csrf)
	req.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: token, Expires: expiresAt})
	req.AddCookie(&http.Cookie{Name: adminauth.CSRFCookieName, Value: csrf, Expires: expiresAt})
	w := httptest.NewRecorder()

	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func saveAuthConfig() func() {
	oldDisable := config.APIAuthDisable
	oldPrimary := config.APIKeyPrimary
	oldSecondary := config.APIKeySecondary
	oldSecret := config.AdminSessionSecret
	oldTTL := config.AdminSessionTTL
	return func() {
		config.APIAuthDisable = oldDisable
		config.APIKeyPrimary = oldPrimary
		config.APIKeySecondary = oldSecondary
		config.AdminSessionSecret = oldSecret
		config.AdminSessionTTL = oldTTL
	}
}
