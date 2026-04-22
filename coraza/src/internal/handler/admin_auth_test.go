package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
)

func TestAdminAuthLoginSessionLogoutFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.APIKeyPrimary = "primary-key-123456"
	config.APIKeySecondary = ""
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = nil
	adminGuardMu.Unlock()

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{"api_key": config.APIKeyPrimary})
	loginReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	r.ServeHTTP(loginRes, loginReq)

	if loginRes.Code != http.StatusOK {
		t.Fatalf("login status=%d want=%d body=%s", loginRes.Code, http.StatusOK, loginRes.Body.String())
	}

	sessionCookie := findCookie(loginRes.Result().Cookies(), adminauth.SessionCookieName)
	csrfCookie := findCookie(loginRes.Result().Cookies(), adminauth.CSRFCookieName)
	if sessionCookie == nil || csrfCookie == nil {
		t.Fatalf("expected session and csrf cookies, got=%v", loginRes.Result().Cookies())
	}

	sessionReq := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	sessionReq.AddCookie(sessionCookie)
	sessionReq.AddCookie(csrfCookie)
	sessionRes := httptest.NewRecorder()
	r.ServeHTTP(sessionRes, sessionReq)
	if sessionRes.Code != http.StatusOK {
		t.Fatalf("session status=%d want=%d body=%s", sessionRes.Code, http.StatusOK, sessionRes.Body.String())
	}
	if !bytes.Contains(sessionRes.Body.Bytes(), []byte(`"authenticated":true`)) {
		t.Fatalf("expected authenticated session body, got=%s", sessionRes.Body.String())
	}

	logoutReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/logout", nil)
	logoutReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	logoutReq.AddCookie(sessionCookie)
	logoutReq.AddCookie(csrfCookie)
	logoutRes := httptest.NewRecorder()
	r.ServeHTTP(logoutRes, logoutReq)
	if logoutRes.Code != http.StatusOK {
		t.Fatalf("logout status=%d want=%d body=%s", logoutRes.Code, http.StatusOK, logoutRes.Body.String())
	}

	clearedSession := findCookie(logoutRes.Result().Cookies(), adminauth.SessionCookieName)
	if clearedSession == nil || clearedSession.MaxAge != -1 {
		t.Fatalf("expected cleared session cookie, got=%v", logoutRes.Result().Cookies())
	}
}

func TestAdminLoginRejectsInvalidKey(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.APIKeyPrimary = "primary-key-123456"
	config.APIKeySecondary = ""
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = nil
	adminGuardMu.Unlock()

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{"api_key": "wrong-key"})
	loginReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginRes := httptest.NewRecorder()
	r.ServeHTTP(loginRes, loginReq)

	if loginRes.Code != http.StatusUnauthorized {
		t.Fatalf("status=%d want=%d body=%s", loginRes.Code, http.StatusUnauthorized, loginRes.Body.String())
	}
}

func TestAdminLoginHonorsAdminAccessMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.APIKeyPrimary = "primary-key-123456"
	config.APIKeySecondary = ""
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour

	adminGuardMu.Lock()
	currentAdminAccess = &adminAccessControl{
		mode:              "deny_external",
		trustForwardedFor: false,
		trustedCIDRs:      []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")},
	}
	currentAdminRate = nil
	adminGuardMu.Unlock()

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{"api_key": config.APIKeyPrimary})
	loginReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/login", bytes.NewReader(loginBody))
	loginReq.Header.Set("Content-Type", "application/json")
	loginReq.RemoteAddr = "203.0.113.10:12345"
	loginRes := httptest.NewRecorder()
	r.ServeHTTP(loginRes, loginReq)

	if loginRes.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%s", loginRes.Code, http.StatusForbidden, loginRes.Body.String())
	}
}

func TestAdminLoginHonorsAdminRateLimitMiddleware(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.APIKeyPrimary = "primary-key-123456"
	config.APIKeySecondary = ""
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour

	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = &adminRateLimiter{
		enabled:           true,
		rps:               1,
		burst:             1,
		statusCode:        http.StatusTooManyRequests,
		retryAfterSeconds: 1,
		buckets:           map[string]*adminTokenBucket{},
	}
	adminGuardMu.Unlock()

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{"api_key": config.APIKeyPrimary})

	firstReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/login", bytes.NewReader(loginBody))
	firstReq.Header.Set("Content-Type", "application/json")
	firstReq.RemoteAddr = "127.0.0.1:12345"
	firstRes := httptest.NewRecorder()
	r.ServeHTTP(firstRes, firstReq)
	if firstRes.Code != http.StatusOK {
		t.Fatalf("first login status=%d want=%d body=%s", firstRes.Code, http.StatusOK, firstRes.Body.String())
	}

	secondReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/login", bytes.NewReader(loginBody))
	secondReq.Header.Set("Content-Type", "application/json")
	secondReq.RemoteAddr = "127.0.0.1:12345"
	secondRes := httptest.NewRecorder()
	r.ServeHTTP(secondRes, secondReq)
	if secondRes.Code != http.StatusTooManyRequests {
		t.Fatalf("second login status=%d want=%d body=%s", secondRes.Code, http.StatusTooManyRequests, secondRes.Body.String())
	}
}

func saveAdminAuthConfig() func() {
	oldBasePath := config.APIBasePath
	oldDisable := config.APIAuthDisable
	oldPrimary := config.APIKeyPrimary
	oldSecondary := config.APIKeySecondary
	oldSecret := config.AdminSessionSecret
	oldTTL := config.AdminSessionTTL
	oldAccess := currentAdminAccess
	oldRate := currentAdminRate
	return func() {
		config.APIBasePath = oldBasePath
		config.APIAuthDisable = oldDisable
		config.APIKeyPrimary = oldPrimary
		config.APIKeySecondary = oldSecondary
		config.AdminSessionSecret = oldSecret
		config.AdminSessionTTL = oldTTL
		adminGuardMu.Lock()
		currentAdminAccess = oldAccess
		currentAdminRate = oldRate
		adminGuardMu.Unlock()
	}
}

func findCookie(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}
