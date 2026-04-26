package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
	"tukuyomi/internal/middleware"
)

func TestAdminLoginRejectsLegacyAPIKeyPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{"api_key": "old-shared-key"})
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
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	config.AdminExternalMode = "deny_external"
	config.AdminTrustedCIDRs = []string{"127.0.0.1/32"}
	config.AdminTrustForwardedFor = false
	config.AdminRateLimitEnabled = false
	initAdminGuardsForTest(t)

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "password",
	})
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
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	config.AdminExternalMode = "full_external"
	config.AdminRateLimitEnabled = true
	config.AdminRateLimitRPS = 1
	config.AdminRateLimitBurst = 1
	config.AdminRateLimitStatusCode = http.StatusTooManyRequests
	config.AdminRateLimitRetryAfter = 1
	initAdminGuardsForTest(t)

	r := gin.New()
	RegisterAdminAuthRoutes(r)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.createAdminUser("admin", "", adminauth.AdminRoleOwner, passwordHash, false, time.Now().UTC()); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "correct horse battery staple",
	})

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

func TestAdminAuthDBPasswordSessionFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.createAdminUser("admin", "admin@example.test", adminauth.AdminRoleOwner, passwordHash, true, time.Now().UTC()); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	r := gin.New()
	RegisterAdminAuthRoutes(r)
	protected := r.Group(config.APIBasePath, middleware.AdminAuth())
	protected.POST("/protected", func(c *gin.Context) {
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
			"mode":     c.GetString("tukuyomi.admin_auth_mode"),
			"username": principal.Username,
			"role":     principal.Role,
		})
	})

	loginBody, _ := json.Marshal(map[string]string{
		"username": "admin",
		"password": "correct horse battery staple",
	})
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
		t.Fatalf("expected db session and csrf cookies, got=%v", loginRes.Result().Cookies())
	}
	if !bytes.Contains(loginRes.Body.Bytes(), []byte(`"username":"admin"`)) {
		t.Fatalf("expected username in login body, got=%s", loginRes.Body.String())
	}
	if !bytes.Contains(loginRes.Body.Bytes(), []byte(`"must_change_password":true`)) {
		t.Fatalf("expected must_change_password in login body, got=%s", loginRes.Body.String())
	}

	sessionReq := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	sessionReq.AddCookie(sessionCookie)
	sessionReq.AddCookie(csrfCookie)
	sessionRes := httptest.NewRecorder()
	r.ServeHTTP(sessionRes, sessionReq)
	if sessionRes.Code != http.StatusOK {
		t.Fatalf("session status=%d want=%d body=%s", sessionRes.Code, http.StatusOK, sessionRes.Body.String())
	}
	if !bytes.Contains(sessionRes.Body.Bytes(), []byte(`"username":"admin"`)) {
		t.Fatalf("expected username in session body, got=%s", sessionRes.Body.String())
	}
	if !bytes.Contains(sessionRes.Body.Bytes(), []byte(`"must_change_password":true`)) {
		t.Fatalf("expected must_change_password in session body, got=%s", sessionRes.Body.String())
	}

	protectedReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/protected", nil)
	protectedReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	protectedReq.AddCookie(sessionCookie)
	protectedReq.AddCookie(csrfCookie)
	protectedRes := httptest.NewRecorder()
	r.ServeHTTP(protectedRes, protectedReq)
	if protectedRes.Code != http.StatusOK {
		t.Fatalf("protected status=%d want=%d body=%s", protectedRes.Code, http.StatusOK, protectedRes.Body.String())
	}
	if !bytes.Contains(protectedRes.Body.Bytes(), []byte(`"mode":"session"`)) {
		t.Fatalf("expected session mode, got=%s", protectedRes.Body.String())
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

	afterLogoutReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/protected", nil)
	afterLogoutReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	afterLogoutReq.AddCookie(sessionCookie)
	afterLogoutReq.AddCookie(csrfCookie)
	afterLogoutRes := httptest.NewRecorder()
	r.ServeHTTP(afterLogoutRes, afterLogoutReq)
	if afterLogoutRes.Code != http.StatusUnauthorized {
		t.Fatalf("after logout status=%d want=%d body=%s", afterLogoutRes.Code, http.StatusUnauthorized, afterLogoutRes.Body.String())
	}
}

func TestAdminAuthDBPersonalAccessTokenFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("unused-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := store.createAdminUser("automation", "", adminauth.AdminRoleOperator, passwordHash, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	pat, _, err := store.createAdminPersonalAccessToken(user.UserID, "ci", []string{"admin:read"}, nil, config.AdminSessionSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	r := gin.New()
	protected := r.Group(config.APIBasePath, middleware.AdminAuth())
	protected.GET("/protected", func(c *gin.Context) {
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
			"mode":     c.GetString("tukuyomi.admin_auth_mode"),
			"username": principal.Username,
			"role":     principal.Role,
			"scopes":   principal.Scopes,
		})
	})

	req := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/protected", nil)
	req.Header.Set("Authorization", "Bearer "+pat.Token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", res.Code, http.StatusOK, res.Body.String())
	}
	if !bytes.Contains(res.Body.Bytes(), []byte(`"mode":"token"`)) {
		t.Fatalf("expected token mode, got=%s", res.Body.String())
	}
	if !bytes.Contains(res.Body.Bytes(), []byte(`"username":"automation"`)) {
		t.Fatalf("expected automation username, got=%s", res.Body.String())
	}
}

func TestAdminAuthManagementAccountAndPasswordFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.createAdminUser("admin", "admin@example.test", adminauth.AdminRoleOwner, passwordHash, false, time.Now().UTC()); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	r := gin.New()
	registerAdminAuthManagementRoutesForTest(r)
	sessionCookie, csrfCookie := loginAdminForTest(t, r, "admin", "correct horse battery staple")

	accountReq := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/account", nil)
	accountReq.AddCookie(sessionCookie)
	accountReq.AddCookie(csrfCookie)
	accountRes := httptest.NewRecorder()
	r.ServeHTTP(accountRes, accountReq)
	if accountRes.Code != http.StatusOK {
		t.Fatalf("account status=%d want=%d body=%s", accountRes.Code, http.StatusOK, accountRes.Body.String())
	}
	if !bytes.Contains(accountRes.Body.Bytes(), []byte(`"email":"admin@example.test"`)) {
		t.Fatalf("expected account email, got=%s", accountRes.Body.String())
	}

	wrongUpdateBody, _ := json.Marshal(map[string]string{
		"username":         "admin2",
		"email":            "admin2@example.test",
		"current_password": "wrong password",
	})
	wrongUpdateReq := httptest.NewRequest(http.MethodPut, config.APIBasePath+"/auth/account", bytes.NewReader(wrongUpdateBody))
	wrongUpdateReq.Header.Set("Content-Type", "application/json")
	wrongUpdateReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	wrongUpdateReq.AddCookie(sessionCookie)
	wrongUpdateReq.AddCookie(csrfCookie)
	wrongUpdateRes := httptest.NewRecorder()
	r.ServeHTTP(wrongUpdateRes, wrongUpdateReq)
	if wrongUpdateRes.Code != http.StatusForbidden {
		t.Fatalf("wrong update status=%d want=%d body=%s", wrongUpdateRes.Code, http.StatusForbidden, wrongUpdateRes.Body.String())
	}

	updateBody, _ := json.Marshal(map[string]string{
		"username":         "admin2",
		"email":            "admin2@example.test",
		"current_password": "correct horse battery staple",
	})
	updateReq := httptest.NewRequest(http.MethodPut, config.APIBasePath+"/auth/account", bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	updateReq.AddCookie(sessionCookie)
	updateReq.AddCookie(csrfCookie)
	updateRes := httptest.NewRecorder()
	r.ServeHTTP(updateRes, updateReq)
	if updateRes.Code != http.StatusOK {
		t.Fatalf("update status=%d want=%d body=%s", updateRes.Code, http.StatusOK, updateRes.Body.String())
	}
	if !bytes.Contains(updateRes.Body.Bytes(), []byte(`"username":"admin2"`)) {
		t.Fatalf("expected updated username, got=%s", updateRes.Body.String())
	}

	passwordBody, _ := json.Marshal(map[string]string{
		"current_password": "correct horse battery staple",
		"new_password":     "new secure password",
	})
	passwordReq := httptest.NewRequest(http.MethodPut, config.APIBasePath+"/auth/password", bytes.NewReader(passwordBody))
	passwordReq.Header.Set("Content-Type", "application/json")
	passwordReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	passwordReq.AddCookie(sessionCookie)
	passwordReq.AddCookie(csrfCookie)
	passwordRes := httptest.NewRecorder()
	r.ServeHTTP(passwordRes, passwordReq)
	if passwordRes.Code != http.StatusOK {
		t.Fatalf("password status=%d want=%d body=%s", passwordRes.Code, http.StatusOK, passwordRes.Body.String())
	}
	if !bytes.Contains(passwordRes.Body.Bytes(), []byte(`"reauth_required":true`)) {
		t.Fatalf("expected reauth_required, got=%s", passwordRes.Body.String())
	}

	oldSessionReq := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/session", nil)
	oldSessionReq.AddCookie(sessionCookie)
	oldSessionReq.AddCookie(csrfCookie)
	oldSessionRes := httptest.NewRecorder()
	r.ServeHTTP(oldSessionRes, oldSessionReq)
	if oldSessionRes.Code != http.StatusOK {
		t.Fatalf("old session status=%d want=%d body=%s", oldSessionRes.Code, http.StatusOK, oldSessionRes.Body.String())
	}
	if !bytes.Contains(oldSessionRes.Body.Bytes(), []byte(`"authenticated":false`)) {
		t.Fatalf("old session should be invalid, got=%s", oldSessionRes.Body.String())
	}

	loginAdminForTest(t, r, "admin2", "new secure password")
}

func TestAdminAuthManagementAPITokenFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.createAdminUser("admin", "admin@example.test", adminauth.AdminRoleOwner, passwordHash, false, time.Now().UTC()); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	r := gin.New()
	registerAdminAuthManagementRoutesForTest(r)
	protected := r.Group(config.APIBasePath, middleware.AdminAuth())
	protected.POST("/protected", func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	sessionCookie, csrfCookie := loginAdminForTest(t, r, "admin", "correct horse battery staple")

	createBody, _ := json.Marshal(map[string]any{
		"label":            "deploy",
		"scopes":           []string{"admin:write"},
		"current_password": "correct horse battery staple",
	})
	createReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/api-tokens", bytes.NewReader(createBody))
	createReq.Header.Set("Content-Type", "application/json")
	createReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	createReq.AddCookie(sessionCookie)
	createReq.AddCookie(csrfCookie)
	createRes := httptest.NewRecorder()
	r.ServeHTTP(createRes, createReq)
	if createRes.Code != http.StatusCreated {
		t.Fatalf("create token status=%d want=%d body=%s", createRes.Code, http.StatusCreated, createRes.Body.String())
	}
	var created adminAPITokenCreateResponse
	if err := json.Unmarshal(createRes.Body.Bytes(), &created); err != nil {
		t.Fatalf("decode created token: %v", err)
	}
	if !strings.HasPrefix(created.Token, adminauth.PersonalAccessTokenPrefix) {
		t.Fatalf("token prefix mismatch: %q", created.Token)
	}
	if created.Record.TokenID <= 0 || !created.Record.Active {
		t.Fatalf("created record=%+v", created.Record)
	}

	listReq := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/api-tokens", nil)
	listReq.AddCookie(sessionCookie)
	listReq.AddCookie(csrfCookie)
	listRes := httptest.NewRecorder()
	r.ServeHTTP(listRes, listReq)
	if listRes.Code != http.StatusOK {
		t.Fatalf("list token status=%d want=%d body=%s", listRes.Code, http.StatusOK, listRes.Body.String())
	}
	if bytes.Contains(listRes.Body.Bytes(), []byte(created.Token)) {
		t.Fatalf("list response leaked token secret: %s", listRes.Body.String())
	}

	tokenReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/protected", nil)
	tokenReq.Header.Set("Authorization", "Bearer "+created.Token)
	tokenRes := httptest.NewRecorder()
	r.ServeHTTP(tokenRes, tokenReq)
	if tokenRes.Code != http.StatusOK {
		t.Fatalf("token protected status=%d want=%d body=%s", tokenRes.Code, http.StatusOK, tokenRes.Body.String())
	}

	revokeReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/auth/api-tokens/"+strconv.FormatInt(created.Record.TokenID, 10)+"/revoke", nil)
	revokeReq.Header.Set(adminauth.CSRFHeaderName, csrfCookie.Value)
	revokeReq.AddCookie(sessionCookie)
	revokeReq.AddCookie(csrfCookie)
	revokeRes := httptest.NewRecorder()
	r.ServeHTTP(revokeRes, revokeReq)
	if revokeRes.Code != http.StatusOK {
		t.Fatalf("revoke token status=%d want=%d body=%s", revokeRes.Code, http.StatusOK, revokeRes.Body.String())
	}

	revokedTokenReq := httptest.NewRequest(http.MethodPost, config.APIBasePath+"/protected", nil)
	revokedTokenReq.Header.Set("Authorization", "Bearer "+created.Token)
	revokedTokenRes := httptest.NewRecorder()
	r.ServeHTTP(revokedTokenRes, revokedTokenReq)
	if revokedTokenRes.Code != http.StatusUnauthorized {
		t.Fatalf("revoked token status=%d want=%d body=%s", revokedTokenRes.Code, http.StatusUnauthorized, revokedTokenRes.Body.String())
	}
}

func TestAdminAuthManagementRejectsTokenAuth(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.APIBasePath = "/tukuyomi-api"
	config.APIAuthDisable = false
	config.AdminSessionSecret = "session-secret-123456"
	config.AdminSessionTTL = time.Hour
	allowAdminGuardsForTest(t)

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("unused-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	user, err := store.createAdminUser("automation", "", adminauth.AdminRoleOperator, passwordHash, false, time.Now().UTC())
	if err != nil {
		t.Fatalf("create admin user: %v", err)
	}
	pat, _, err := store.createAdminPersonalAccessToken(user.UserID, "ci", []string{"admin:write"}, nil, config.AdminSessionSecret, time.Now().UTC())
	if err != nil {
		t.Fatalf("create token: %v", err)
	}

	r := gin.New()
	registerAdminAuthManagementRoutesForTest(r)

	req := httptest.NewRequest(http.MethodGet, config.APIBasePath+"/auth/account", nil)
	req.Header.Set("Authorization", "Bearer "+pat.Token)
	res := httptest.NewRecorder()
	r.ServeHTTP(res, req)
	if res.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%s", res.Code, http.StatusForbidden, res.Body.String())
	}
}

func TestEnsureAdminBootstrapOwnerFromEnvCreatesOnlyWhenEmpty(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveAdminAuthConfig()
	defer restore()

	config.AdminSessionSecret = "session-secret-123456"
	store := initConfigDBStoreForTest(t)
	t.Setenv(AdminBootstrapUsernameEnv, "owner")
	t.Setenv(AdminBootstrapEmailEnv, "owner@example.test")
	t.Setenv(AdminBootstrapPasswordEnv, "correct horse battery staple")

	created, err := EnsureAdminBootstrapOwnerFromEnv()
	if err != nil {
		t.Fatalf("bootstrap owner: %v", err)
	}
	if !created {
		t.Fatalf("created=false want true")
	}

	principal, ok, err := store.authenticateAdminPassword("owner", "correct horse battery staple", time.Now().UTC())
	if err != nil {
		t.Fatalf("authenticate bootstrap owner: %v", err)
	}
	if !ok {
		t.Fatalf("authenticate bootstrap owner ok=false want true")
	}
	if principal.Role != adminauth.AdminRoleOwner {
		t.Fatalf("role=%q want owner", principal.Role)
	}

	created, err = EnsureAdminBootstrapOwnerFromEnv()
	if err != nil {
		t.Fatalf("second bootstrap owner: %v", err)
	}
	if created {
		t.Fatalf("second bootstrap created=true want false")
	}
	count, err := store.countAdminUsers()
	if err != nil {
		t.Fatalf("count admin users: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin user count=%d want 1", count)
	}
}

func TestImportAdminUsersSeedStorageCreatesInitialOwner(t *testing.T) {
	gin.SetMode(gin.TestMode)

	store := initConfigDBStoreForTest(t)
	seedDir := t.TempDir()
	seedRaw := []byte(`{
  "users": [
    {
      "username": "seed-admin",
      "email": "seed-admin@example.test",
      "role": "owner",
      "password": "correct horse battery staple",
      "must_change_password": true
    }
  ]
}`)
	if err := os.WriteFile(filepath.Join(seedDir, startupAdminUsersSeedName), seedRaw, 0o600); err != nil {
		t.Fatalf("write admin user seed: %v", err)
	}
	t.Setenv(startupSeedConfDirEnv, seedDir)

	if err := importAdminUsersSeedStorage(); err != nil {
		t.Fatalf("import admin user seed: %v", err)
	}
	count, err := store.countAdminUsers()
	if err != nil {
		t.Fatalf("count admin users: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin user count=%d want 1", count)
	}
	principal, ok, err := store.authenticateAdminPassword("seed-admin", "correct horse battery staple", time.Now().UTC())
	if err != nil {
		t.Fatalf("authenticate seed admin: %v", err)
	}
	if !ok {
		t.Fatalf("authenticate seed admin ok=false want true")
	}
	if principal.Role != adminauth.AdminRoleOwner {
		t.Fatalf("seed admin role=%q want owner", principal.Role)
	}
	if !principal.MustChangePassword {
		t.Fatalf("seed admin must_change_password=false want true")
	}

	if err := importAdminUsersSeedStorage(); err != nil {
		t.Fatalf("second import admin user seed: %v", err)
	}
	count, err = store.countAdminUsers()
	if err != nil {
		t.Fatalf("count admin users after second import: %v", err)
	}
	if count != 1 {
		t.Fatalf("admin user count after second import=%d want 1", count)
	}
}

func TestPrepareAdminUsersSeedRejectsPasswordChangeDisabled(t *testing.T) {
	raw := []byte(`{
  "users": [
    {
      "username": "seed-admin",
      "role": "owner",
      "password": "correct horse battery staple",
      "must_change_password": false
    }
  ]
}`)
	if _, err := prepareAdminUsersSeed(raw); err == nil || !strings.Contains(err.Error(), "must_change_password") {
		t.Fatalf("prepareAdminUsersSeed err=%v want must_change_password rejection", err)
	}
}

func registerAdminAuthManagementRoutesForTest(r *gin.Engine) {
	RegisterAdminAuthRoutes(r)
	api := r.Group(config.APIBasePath, middleware.AdminAuth())
	api.GET("/auth/account", GetAdminAccount)
	api.PUT("/auth/account", PutAdminAccount)
	api.PUT("/auth/password", PutAdminPassword)
	api.GET("/auth/api-tokens", GetAdminAPITokens)
	api.POST("/auth/api-tokens", PostAdminAPIToken)
	api.POST("/auth/api-tokens/:token_id/revoke", PostAdminAPITokenRevoke)
}

func loginAdminForTest(t *testing.T, r *gin.Engine, identifier string, password string) (*http.Cookie, *http.Cookie) {
	t.Helper()
	loginBody, _ := json.Marshal(map[string]string{
		"identifier": identifier,
		"password":   password,
	})
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
	return sessionCookie, csrfCookie
}

func saveAdminAuthConfig() func() {
	oldBasePath := config.APIBasePath
	oldDisable := config.APIAuthDisable
	oldSecret := config.AdminSessionSecret
	oldTTL := config.AdminSessionTTL
	oldExternalMode := config.AdminExternalMode
	oldTrustedCIDRs := append([]string(nil), config.AdminTrustedCIDRs...)
	oldTrustForwardedFor := config.AdminTrustForwardedFor
	oldRateLimitEnabled := config.AdminRateLimitEnabled
	oldRateLimitRPS := config.AdminRateLimitRPS
	oldRateLimitBurst := config.AdminRateLimitBurst
	oldRateLimitStatusCode := config.AdminRateLimitStatusCode
	oldRateLimitRetryAfter := config.AdminRateLimitRetryAfter
	return func() {
		config.APIBasePath = oldBasePath
		config.APIAuthDisable = oldDisable
		config.AdminSessionSecret = oldSecret
		config.AdminSessionTTL = oldTTL
		config.AdminExternalMode = oldExternalMode
		config.AdminTrustedCIDRs = oldTrustedCIDRs
		config.AdminTrustForwardedFor = oldTrustForwardedFor
		config.AdminRateLimitEnabled = oldRateLimitEnabled
		config.AdminRateLimitRPS = oldRateLimitRPS
		config.AdminRateLimitBurst = oldRateLimitBurst
		config.AdminRateLimitStatusCode = oldRateLimitStatusCode
		config.AdminRateLimitRetryAfter = oldRateLimitRetryAfter
		_ = InitAdminGuards()
	}
}

func allowAdminGuardsForTest(t *testing.T) {
	t.Helper()
	config.AdminExternalMode = "full_external"
	config.AdminTrustedCIDRs = nil
	config.AdminTrustForwardedFor = false
	config.AdminRateLimitEnabled = false
	initAdminGuardsForTest(t)
}

func initAdminGuardsForTest(t *testing.T) {
	t.Helper()
	if err := InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
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
