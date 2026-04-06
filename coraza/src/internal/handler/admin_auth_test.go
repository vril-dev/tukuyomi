package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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

func saveAdminAuthConfig() func() {
	oldBasePath := config.APIBasePath
	oldDisable := config.APIAuthDisable
	oldPrimary := config.APIKeyPrimary
	oldSecondary := config.APIKeySecondary
	oldSecret := config.AdminSessionSecret
	oldTTL := config.AdminSessionTTL
	return func() {
		config.APIBasePath = oldBasePath
		config.APIAuthDisable = oldDisable
		config.APIKeyPrimary = oldPrimary
		config.APIKeySecondary = oldSecondary
		config.AdminSessionSecret = oldSecret
		config.AdminSessionTTL = oldTTL
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
