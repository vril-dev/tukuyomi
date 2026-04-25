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
	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = nil
	adminGuardMu.Unlock()

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
	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = nil
	adminGuardMu.Unlock()

	store := initConfigDBStoreForTest(t)
	passwordHash, err := adminauth.HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := store.createAdminUser("admin", "admin@example.test", adminauth.AdminRoleOwner, passwordHash, false, time.Now().UTC()); err != nil {
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
	adminGuardMu.Lock()
	currentAdminAccess = nil
	currentAdminRate = nil
	adminGuardMu.Unlock()

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

func saveAdminAuthConfig() func() {
	oldBasePath := config.APIBasePath
	oldDisable := config.APIAuthDisable
	oldSecret := config.AdminSessionSecret
	oldTTL := config.AdminSessionTTL
	oldAccess := currentAdminAccess
	oldRate := currentAdminRate
	return func() {
		config.APIBasePath = oldBasePath
		config.APIAuthDisable = oldDisable
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
