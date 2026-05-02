package center

import (
	"bytes"
	"context"
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/runtimeartifactbundle"
)

func TestRuntimeConfigFromEnvDefaults(t *testing.T) {
	t.Setenv(ListenAddrEnv, "")
	t.Setenv(APIBasePathEnv, "")
	t.Setenv(UIBasePathEnv, "")
	t.Setenv(TLSEnabledEnv, "")

	cfg, err := RuntimeConfigFromEnv()
	if err != nil {
		t.Fatalf("RuntimeConfigFromEnv: %v", err)
	}
	if cfg.ListenAddr != DefaultListenAddr {
		t.Fatalf("listen=%q want %q", cfg.ListenAddr, DefaultListenAddr)
	}
	if cfg.APIBasePath != DefaultAPIBasePath {
		t.Fatalf("api=%q want %q", cfg.APIBasePath, DefaultAPIBasePath)
	}
	if cfg.UIBasePath != DefaultUIBasePath {
		t.Fatalf("ui=%q want %q", cfg.UIBasePath, DefaultUIBasePath)
	}
	if cfg.TLSEnabled {
		t.Fatal("tls should default off")
	}
}

func TestRuntimeConfigFromEnvAcceptsManualTLS(t *testing.T) {
	certFile, keyFile := writeCenterTLSFilesForTest(t)
	t.Setenv(TLSEnabledEnv, "true")
	t.Setenv(TLSCertFileEnv, certFile)
	t.Setenv(TLSKeyFileEnv, keyFile)
	t.Setenv(TLSMinVersionEnv, "tls1.3")

	cfg, err := RuntimeConfigFromEnv()
	if err != nil {
		t.Fatalf("RuntimeConfigFromEnv: %v", err)
	}
	if !cfg.TLSEnabled || cfg.TLSCertFile != certFile || cfg.TLSKeyFile != keyFile || cfg.TLSMinVersion != "tls1.3" {
		t.Fatalf("unexpected TLS config: %+v", cfg)
	}
}

func TestRuntimeConfigFromEnvRejectsTLSWithoutPair(t *testing.T) {
	t.Setenv(TLSEnabledEnv, "true")
	t.Setenv(TLSCertFileEnv, "")
	t.Setenv(TLSKeyFileEnv, "")

	if _, err := RuntimeConfigFromEnv(); err == nil {
		t.Fatal("expected missing TLS pair to be rejected")
	}
}

func TestRuntimeConfigFromEnvRejectsInvalidTLSMinVersion(t *testing.T) {
	t.Setenv(TLSEnabledEnv, "false")
	t.Setenv(TLSMinVersionEnv, "ssl3")

	if _, err := RuntimeConfigFromEnv(); err == nil {
		t.Fatal("expected invalid TLS minimum version to be rejected")
	}
}

func TestRuntimeConfigFromEnvRejectsUnsafeBasePath(t *testing.T) {
	t.Setenv(ListenAddrEnv, "")
	t.Setenv(APIBasePathEnv, "/center-api/../bad")
	t.Setenv(UIBasePathEnv, "")

	if _, err := RuntimeConfigFromEnv(); err == nil {
		t.Fatal("expected unsafe api base path to be rejected")
	}
}

func TestCenterLoginFlowUsesIsolatedAdminCookies(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	created, err := handler.EnsureAdminBootstrapOwnerFromEnv()
	if err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	}
	if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	sessionBefore := performRequest(engine, http.MethodGet, "/center-api/auth/session", "", nil)
	if sessionBefore.Code != http.StatusOK {
		t.Fatalf("session before code=%d body=%s", sessionBefore.Code, sessionBefore.Body.String())
	}
	if authenticatedBool(t, sessionBefore.Body.Bytes()) {
		t.Fatal("session before login is authenticated")
	}

	loginBody := `{"identifier":"center-admin","password":"center-admin-password"}`
	login := performRequest(engine, http.MethodPost, "/center-api/auth/login", loginBody, map[string]string{
		"Content-Type": "application/json",
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("login did not issue cookies")
	}
	cookieNames := adminauth.CenterCookieNames()
	centerSessionCookie := cookieByNameForTest(cookies, cookieNames.Session)
	centerCSRFCookie := cookieByNameForTest(cookies, cookieNames.CSRF)
	if centerSessionCookie == nil || centerCSRFCookie == nil {
		t.Fatalf("login did not issue center cookies %q/%q: %v", cookieNames.Session, cookieNames.CSRF, cookies)
	}
	if cookieByNameForTest(cookies, adminauth.SessionCookieName) != nil || cookieByNameForTest(cookies, adminauth.CSRFCookieName) != nil {
		t.Fatalf("center login must not issue gateway admin cookies: %v", cookies)
	}
	if !strings.Contains(login.Body.String(), `"session_cookie":"`+cookieNames.Session+`"`) || !strings.Contains(login.Body.String(), `"csrf_cookie_name":"`+cookieNames.CSRF+`"`) {
		t.Fatalf("login response does not report center cookie names: %s", login.Body.String())
	}

	wrongCookieReq := httptest.NewRequest(http.MethodGet, "/center-api/auth/session", nil)
	wrongCookieReq.AddCookie(&http.Cookie{Name: adminauth.SessionCookieName, Value: centerSessionCookie.Value})
	wrongCookieSession := httptest.NewRecorder()
	engine.ServeHTTP(wrongCookieSession, wrongCookieReq)
	if wrongCookieSession.Code != http.StatusOK {
		t.Fatalf("wrong-cookie session code=%d body=%s", wrongCookieSession.Code, wrongCookieSession.Body.String())
	}
	if authenticatedBool(t, wrongCookieSession.Body.Bytes()) {
		t.Fatal("center accepted gateway admin cookie name")
	}

	req := httptest.NewRequest(http.MethodGet, "/center-api/auth/session", nil)
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	sessionAfter := httptest.NewRecorder()
	engine.ServeHTTP(sessionAfter, req)
	if sessionAfter.Code != http.StatusOK {
		t.Fatalf("session after code=%d body=%s", sessionAfter.Code, sessionAfter.Body.String())
	}
	if !authenticatedBool(t, sessionAfter.Body.Bytes()) {
		t.Fatal("session after login is not authenticated")
	}

	ui := performRequest(engine, http.MethodGet, "/center-ui", "", nil)
	if ui.Code != http.StatusOK {
		t.Fatalf("ui code=%d body=%s", ui.Code, ui.Body.String())
	}
	if !strings.Contains(ui.Body.String(), "Tukuyomi Center") {
		t.Fatal("center ui response does not contain product title")
	}
}

func TestCenterAuthIgnoresGlobalAuthDisable(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	} else if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}
	config.APIAuthDisable = true

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	session := performRequest(engine, http.MethodGet, "/center-api/auth/session", "", nil)
	if session.Code != http.StatusOK {
		t.Fatalf("session code=%d body=%s", session.Code, session.Body.String())
	}
	if authenticatedBool(t, session.Body.Bytes()) || strings.Contains(session.Body.String(), `"mode":"disabled"`) {
		t.Fatalf("center auth should remain required when global auth disable is true: %s", session.Body.String())
	}

	protected := performRequest(engine, http.MethodGet, "/center-api/settings", "", nil)
	if protected.Code != http.StatusUnauthorized {
		t.Fatalf("protected code=%d body=%s", protected.Code, protected.Body.String())
	}

	login := performRequest(engine, http.MethodPost, "/center-api/auth/login", `{"identifier":"center-admin","password":"center-admin-password"}`, map[string]string{
		"Content-Type": "application/json",
	})
	if login.Code != http.StatusOK || !strings.Contains(login.Body.String(), `"mode":"session"`) {
		t.Fatalf("login code=%d body=%s", login.Code, login.Body.String())
	}
}

func TestBootstrapApprovedDeviceCreatesApprovedDeviceAndRejectsTrustChange(t *testing.T) {
	restore := configureCenterAuthTest(t)
	defer restore()
	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	fixture := signedEnrollmentFixtureForTest(t, "gateway-a", "default", "nonce-bootstrap-a", time.Now().UTC())
	publicPEMBytes, err := base64.StdEncoding.DecodeString(fixture.Request.PublicKeyPEMB64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	rec, err := BootstrapApprovedDevice(context.Background(), BootstrapApprovedDeviceInput{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyPEM:               string(publicPEMBytes),
		PublicKeyFingerprintSHA256: fixture.Request.PublicKeyFingerprintSHA256,
	})
	if err != nil {
		t.Fatalf("BootstrapApprovedDevice: %v", err)
	}
	if rec.DeviceID != "gateway-a" || rec.Status != DeviceStatusApproved || rec.PublicKeyFingerprintSHA256 != fixture.Request.PublicKeyFingerprintSHA256 {
		t.Fatalf("unexpected device record: %+v", rec)
	}
	enrollments, err := ListEnrollments(context.Background(), EnrollmentStatusApproved, 10)
	if err != nil {
		t.Fatalf("ListEnrollments: %v", err)
	}
	if len(enrollments) != 1 || enrollments[0].DeviceID != "gateway-a" || enrollments[0].Status != EnrollmentStatusApproved {
		t.Fatalf("unexpected approved enrollments: %+v", enrollments)
	}

	again, err := BootstrapApprovedDevice(context.Background(), BootstrapApprovedDeviceInput{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyPEM:               string(publicPEMBytes),
		PublicKeyFingerprintSHA256: fixture.Request.PublicKeyFingerprintSHA256,
	})
	if err != nil {
		t.Fatalf("BootstrapApprovedDevice idempotent: %v", err)
	}
	if again.ApprovedEnrollmentID != rec.ApprovedEnrollmentID {
		t.Fatalf("approved enrollment changed: %d != %d", again.ApprovedEnrollmentID, rec.ApprovedEnrollmentID)
	}

	other := signedEnrollmentFixtureForTest(t, "gateway-a", "default", "nonce-bootstrap-b", time.Now().UTC())
	otherPEM, err := base64.StdEncoding.DecodeString(other.Request.PublicKeyPEMB64)
	if err != nil {
		t.Fatalf("decode other public key: %v", err)
	}
	_, err = BootstrapApprovedDevice(context.Background(), BootstrapApprovedDeviceInput{
		DeviceID:                   other.Request.DeviceID,
		KeyID:                      other.Request.KeyID,
		PublicKeyPEM:               string(otherPEM),
		PublicKeyFingerprintSHA256: other.Request.PublicKeyFingerprintSHA256,
	})
	if err == nil || !strings.Contains(err.Error(), "different trust material") {
		t.Fatalf("expected trust conflict, got %v", err)
	}
}

func TestCenterSettingsEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()
	old := struct {
		dbDriver        string
		dbRetentionDays int
		fileRetention   time.Duration
		adminReadOnly   bool
	}{
		dbDriver:        config.DBDriver,
		dbRetentionDays: config.DBRetentionDays,
		fileRetention:   config.FileRetention,
		adminReadOnly:   config.AdminReadOnly,
	}
	defer func() {
		config.DBDriver = old.dbDriver
		config.DBRetentionDays = old.dbRetentionDays
		config.FileRetention = old.fileRetention
		config.AdminReadOnly = old.adminReadOnly
	}()
	config.DBDriver = "sqlite"
	config.DBRetentionDays = 45
	config.FileRetention = 14 * 24 * time.Hour
	config.AdminReadOnly = false

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 45); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	} else if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	engine, err := NewEngine(RuntimeConfig{
		ListenAddr:  "127.0.0.1:19092",
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cookies, csrfCookie := loginCenterForTest(t, engine)
	settings := performRequestWithCookies(engine, http.MethodGet, "/center-api/settings", "", nil, cookies)
	if settings.Code != http.StatusOK {
		t.Fatalf("settings code=%d body=%s", settings.Code, settings.Body.String())
	}
	var payload centerSettingsPayload
	if err := json.Unmarshal(settings.Body.Bytes(), &payload); err != nil {
		t.Fatalf("unmarshal settings: %v", err)
	}
	if payload.Runtime.Mode != "center" || payload.Runtime.ListenAddr != "127.0.0.1:19092" || payload.Runtime.APIBasePath != "/center-api" || payload.Runtime.UIBasePath != "/center-ui" {
		t.Fatalf("runtime settings mismatch: %+v", payload.Runtime)
	}
	if payload.Storage.DBDriver != "sqlite" || payload.Storage.DBRetentionDays != 45 || payload.Storage.FileRetentionDays != 14 {
		t.Fatalf("storage settings mismatch: %+v", payload.Storage)
	}
	if payload.Access.ReadOnly {
		t.Fatalf("access settings mismatch: %+v", payload.Access)
	}
	if payload.Config.EnrollmentTokenDefaultMaxUses != EnrollmentTokenDefaultMaxUses ||
		payload.Config.EnrollmentTokenDefaultTTLSeconds != 0 ||
		payload.Config.AdminSessionTTLSeconds != 3600 {
		t.Fatalf("config settings mismatch: %+v", payload.Config)
	}
	if payload.Config.ListenAddr != "127.0.0.1:19092" || payload.Config.APIBasePath != "/center-api" || payload.Config.UIBasePath != "/center-ui" ||
		payload.Config.TLSMode != centerSettingsTLSModeOff || payload.Config.TLSMinVersion != "tls1.2" || payload.RestartRequired {
		t.Fatalf("listener settings mismatch: restart=%v config=%+v", payload.RestartRequired, payload.Config)
	}
	update := performRequestWithCookies(
		engine,
		http.MethodPut,
		"/center-api/settings",
		`{"config":{"enrollment_token_default_max_uses":3,"enrollment_token_default_ttl_seconds":86400,"admin_session_ttl_seconds":7200}}`,
		map[string]string{
			"If-Match":               payload.ETag,
			"Content-Type":           "application/json",
			adminauth.CSRFHeaderName: csrfCookie.Value,
		},
		cookies,
	)
	if update.Code != http.StatusOK {
		t.Fatalf("update settings code=%d body=%s", update.Code, update.Body.String())
	}
	var updated centerSettingsPayload
	if err := json.Unmarshal(update.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal updated settings: %v", err)
	}
	if updated.Config.EnrollmentTokenDefaultMaxUses != 3 ||
		updated.Config.EnrollmentTokenDefaultTTLSeconds != 86400 ||
		updated.Config.AdminSessionTTLSeconds != 7200 ||
		config.AdminSessionTTL != 2*time.Hour {
		t.Fatalf("updated config mismatch: %+v", updated.Config)
	}
	if updated.RestartRequired {
		t.Fatalf("token-only settings update should not require restart: %+v", updated)
	}
	token, _, err := CreateEnrollmentToken(context.Background(), EnrollmentTokenCreate{CreatedBy: "test"})
	if err != nil {
		t.Fatalf("CreateEnrollmentToken: %v", err)
	}
	if token.MaxUses != 3 || token.ExpiresAtUnix <= time.Now().UTC().Unix() {
		t.Fatalf("token did not use settings defaults: %+v", token)
	}

	listenerUpdate := performRequestWithCookies(
		engine,
		http.MethodPut,
		"/center-api/settings",
		`{"config":{"enrollment_token_default_max_uses":3,"enrollment_token_default_ttl_seconds":86400,"admin_session_ttl_seconds":7200,"listen_addr":"127.0.0.1:19192","api_base_path":"/center-api","ui_base_path":"/center-ui","tls_mode":"off","tls_min_version":"tls1.3"}}`,
		map[string]string{
			"If-Match":               updated.ETag,
			"Content-Type":           "application/json",
			adminauth.CSRFHeaderName: csrfCookie.Value,
		},
		cookies,
	)
	if listenerUpdate.Code != http.StatusOK {
		t.Fatalf("listener settings code=%d body=%s", listenerUpdate.Code, listenerUpdate.Body.String())
	}
	var listenerUpdated centerSettingsPayload
	if err := json.Unmarshal(listenerUpdate.Body.Bytes(), &listenerUpdated); err != nil {
		t.Fatalf("unmarshal listener settings: %v", err)
	}
	if !listenerUpdated.RestartRequired || listenerUpdated.Config.ListenAddr != "127.0.0.1:19192" || listenerUpdated.Config.TLSMinVersion != "tls1.3" {
		t.Fatalf("listener update should require restart: %+v", listenerUpdated)
	}

	badTLS := performRequestWithCookies(
		engine,
		http.MethodPut,
		"/center-api/settings",
		`{"config":{"tls_mode":"manual"}}`,
		map[string]string{
			"If-Match":               listenerUpdated.ETag,
			"Content-Type":           "application/json",
			adminauth.CSRFHeaderName: csrfCookie.Value,
		},
		cookies,
	)
	if badTLS.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad tls settings code=%d body=%s", badTLS.Code, badTLS.Body.String())
	}

	badTLSVersion := performRequestWithCookies(
		engine,
		http.MethodPut,
		"/center-api/settings",
		`{"config":{"tls_mode":"off","tls_min_version":"ssl3"}}`,
		map[string]string{
			"If-Match":               listenerUpdated.ETag,
			"Content-Type":           "application/json",
			adminauth.CSRFHeaderName: csrfCookie.Value,
		},
		cookies,
	)
	if badTLSVersion.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad tls min version code=%d body=%s", badTLSVersion.Code, badTLSVersion.Body.String())
	}

	badSessionTTL := performRequestWithCookies(
		engine,
		http.MethodPut,
		"/center-api/settings",
		`{"config":{"admin_session_ttl_seconds":299}}`,
		map[string]string{
			"If-Match":               listenerUpdated.ETag,
			"Content-Type":           "application/json",
			adminauth.CSRFHeaderName: csrfCookie.Value,
		},
		cookies,
	)
	if badSessionTTL.Code != http.StatusUnprocessableEntity {
		t.Fatalf("bad session ttl code=%d body=%s", badSessionTTL.Code, badSessionTTL.Body.String())
	}
}

func TestCenterRuntimeBuildStoresArtifactAndAssignsDevice(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()
	restoreBuilder := replaceRuntimeBuildRunnerForTest(fakeRuntimeBuildRunner{})
	defer restoreBuilder()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if _, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}
	insertRuntimeBuildDeviceForTest(t)

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}
	cookies, csrfCookie := loginCenterForTest(t, engine)

	capabilities := performRequestWithCookies(engine, http.MethodGet, "/center-api/runtime-builder/capabilities", "", nil, cookies)
	if capabilities.Code != http.StatusOK ||
		!strings.Contains(capabilities.Body.String(), `"php_fpm_supported":true`) ||
		!strings.Contains(capabilities.Body.String(), `"psgi_supported":true`) {
		t.Fatalf("capabilities code=%d body=%s", capabilities.Code, capabilities.Body.String())
	}
	var capabilityView RuntimeBuilderCapabilities
	if err := json.Unmarshal(capabilities.Body.Bytes(), &capabilityView); err != nil {
		t.Fatalf("decode runtime builder capabilities: %v", err)
	}
	psgiSupported := map[string]bool{}
	for _, runtime := range capabilityView.Runtimes {
		if runtime.RuntimeFamily == RuntimeFamilyPSGI && runtime.Supported {
			psgiSupported[runtime.RuntimeID] = true
		}
	}
	for _, runtimeID := range []string{"perl536", "perl538", "perl540"} {
		if !psgiSupported[runtimeID] {
			t.Fatalf("capabilities missing supported PSGI runtime %s: %+v", runtimeID, capabilityView.Runtimes)
		}
	}
	start := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/build-device-1/runtime-builds",
		`{"runtime_family":"php-fpm","runtime_id":"php83","assign":true,"reason":"test build"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if start.Code != http.StatusAccepted {
		t.Fatalf("start runtime build code=%d body=%s", start.Code, start.Body.String())
	}
	var startResp runtimeBuildJobResponseForTest
	if err := json.Unmarshal(start.Body.Bytes(), &startResp); err != nil {
		t.Fatalf("decode start runtime build: %v", err)
	}
	if startResp.Job.JobID == "" {
		t.Fatalf("start response missing job: %+v", startResp)
	}
	listStarted := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/build-device-1/runtime-builds", "", nil, cookies)
	if listStarted.Code != http.StatusOK {
		t.Fatalf("list runtime builds code=%d body=%s", listStarted.Code, listStarted.Body.String())
	}
	var listStartedResp runtimeBuildJobsResponseForTest
	if err := json.Unmarshal(listStarted.Body.Bytes(), &listStartedResp); err != nil {
		t.Fatalf("decode runtime build list: %v", err)
	}
	if !runtimeBuildJobListContains(listStartedResp.Jobs, startResp.Job.JobID) {
		t.Fatalf("runtime build list missing started job %q: %+v", startResp.Job.JobID, listStartedResp.Jobs)
	}

	var job RuntimeBuildJob
	for i := 0; i < 50; i++ {
		status := performRequestWithCookies(engine, http.MethodGet, "/center-api/runtime-builds/"+startResp.Job.JobID, "", nil, cookies)
		if status.Code != http.StatusOK {
			t.Fatalf("runtime build status code=%d body=%s", status.Code, status.Body.String())
		}
		var statusResp runtimeBuildJobResponseForTest
		if err := json.Unmarshal(status.Body.Bytes(), &statusResp); err != nil {
			t.Fatalf("decode runtime build status: %v", err)
		}
		job = statusResp.Job
		if job.Status == RuntimeBuildStatusSucceeded || job.Status == RuntimeBuildStatusFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if job.Status != RuntimeBuildStatusSucceeded || job.Artifact == nil || job.Assignment == nil {
		t.Fatalf("runtime build job=%+v, want succeeded artifact and assignment", job)
	}
	if job.Artifact.RuntimeFamily != RuntimeFamilyPHPFPM || job.Artifact.RuntimeID != "php83" {
		t.Fatalf("artifact identity unexpected: %+v", job.Artifact)
	}
	if job.Assignment.DesiredArtifactRevision != job.Artifact.ArtifactRevision || job.Assignment.DesiredState != RuntimeAssignmentDesiredInstalled {
		t.Fatalf("assignment unexpected: %+v artifact=%+v", job.Assignment, job.Artifact)
	}

	startPSGI := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/build-device-1/runtime-builds",
		`{"runtime_family":"psgi","runtime_id":"perl540","assign":true,"reason":"test psgi build"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if startPSGI.Code != http.StatusAccepted {
		t.Fatalf("start PSGI runtime build code=%d body=%s", startPSGI.Code, startPSGI.Body.String())
	}
	var startPSGIResp runtimeBuildJobResponseForTest
	if err := json.Unmarshal(startPSGI.Body.Bytes(), &startPSGIResp); err != nil {
		t.Fatalf("decode start PSGI runtime build: %v", err)
	}
	var psgiJob RuntimeBuildJob
	for i := 0; i < 50; i++ {
		status := performRequestWithCookies(engine, http.MethodGet, "/center-api/runtime-builds/"+startPSGIResp.Job.JobID, "", nil, cookies)
		if status.Code != http.StatusOK {
			t.Fatalf("PSGI runtime build status code=%d body=%s", status.Code, status.Body.String())
		}
		var statusResp runtimeBuildJobResponseForTest
		if err := json.Unmarshal(status.Body.Bytes(), &statusResp); err != nil {
			t.Fatalf("decode PSGI runtime build status: %v", err)
		}
		psgiJob = statusResp.Job
		if psgiJob.Status == RuntimeBuildStatusSucceeded || psgiJob.Status == RuntimeBuildStatusFailed {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if psgiJob.Status != RuntimeBuildStatusSucceeded || psgiJob.Artifact == nil || psgiJob.Assignment == nil {
		t.Fatalf("PSGI runtime build job=%+v, want succeeded artifact and assignment", psgiJob)
	}
	if psgiJob.Artifact.RuntimeFamily != RuntimeFamilyPSGI || psgiJob.Artifact.RuntimeID != "perl540" {
		t.Fatalf("PSGI artifact identity unexpected: %+v", psgiJob.Artifact)
	}
	listCompleted := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/build-device-1/runtime-builds", "", nil, cookies)
	if listCompleted.Code != http.StatusOK {
		t.Fatalf("list completed runtime builds code=%d body=%s", listCompleted.Code, listCompleted.Body.String())
	}
	var listCompletedResp runtimeBuildJobsResponseForTest
	if err := json.Unmarshal(listCompleted.Body.Bytes(), &listCompletedResp); err != nil {
		t.Fatalf("decode completed runtime build list: %v", err)
	}
	if !runtimeBuildJobListContains(listCompletedResp.Jobs, job.JobID) || !runtimeBuildJobListContains(listCompletedResp.Jobs, psgiJob.JobID) {
		t.Fatalf("runtime build list missing completed jobs %q/%q: %+v", job.JobID, psgiJob.JobID, listCompletedResp.Jobs)
	}

	deployment := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/build-device-1/runtime-deployment", "", nil, cookies)
	if deployment.Code != http.StatusOK {
		t.Fatalf("runtime deployment code=%d body=%s", deployment.Code, deployment.Body.String())
	}
	if !strings.Contains(deployment.Body.String(), `"artifact_revision":"`+job.Artifact.ArtifactRevision+`"`) ||
		!strings.Contains(deployment.Body.String(), `"artifact_revision":"`+psgiJob.Artifact.ArtifactRevision+`"`) ||
		!strings.Contains(deployment.Body.String(), `"desired_state":"installed"`) {
		t.Fatalf("runtime deployment missing built artifact assignment: %s", deployment.Body.String())
	}
}

func TestStoreRuntimeArtifactBundleIsIdempotentForSameRevision(t *testing.T) {
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	first, err := runtimeArtifactBundleForStoreTest(time.Unix(1000, 0).UTC())
	if err != nil {
		t.Fatalf("build first artifact: %v", err)
	}
	second, err := runtimeArtifactBundleForStoreTest(time.Unix(2000, 123456789).UTC())
	if err != nil {
		t.Fatalf("build second artifact: %v", err)
	}
	if first.Revision != second.Revision {
		t.Fatalf("revision changed for same runtime content: first=%s second=%s", first.Revision, second.Revision)
	}
	if first.ArtifactHash == second.ArtifactHash {
		t.Fatal("test setup expected generated_at to change archive hash")
	}

	storedFirst, err := StoreRuntimeArtifactBundle(context.Background(), first.Compressed, "test")
	if err != nil {
		t.Fatalf("store first artifact: %v", err)
	}
	storedSecond, err := StoreRuntimeArtifactBundle(context.Background(), second.Compressed, "test")
	if err != nil {
		t.Fatalf("store duplicate artifact: %v", err)
	}
	if storedSecond.ArtifactRevision != storedFirst.ArtifactRevision ||
		storedSecond.ArtifactHash != storedFirst.ArtifactHash {
		t.Fatalf("duplicate artifact did not return existing record: first=%+v second=%+v", storedFirst, storedSecond)
	}
}

func TestCenterDeviceEnrollmentApprovalFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	} else if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cookies, csrfCookie := loginCenterForTest(t, engine)
	expiredTokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"expired","expires_at_unix":1}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if expiredTokenResp.Code != http.StatusBadRequest {
		t.Fatalf("expired token code=%d body=%s", expiredTokenResp.Code, expiredTokenResp.Body.String())
	}

	defaultTokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"default max uses"}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if defaultTokenResp.Code != http.StatusCreated {
		t.Fatalf("create default token code=%d body=%s", defaultTokenResp.Code, defaultTokenResp.Body.String())
	}
	var defaultToken struct {
		Record EnrollmentTokenRecord `json:"record"`
	}
	if err := json.Unmarshal(defaultTokenResp.Body.Bytes(), &defaultToken); err != nil {
		t.Fatalf("decode default token response: %v body=%s", err, defaultTokenResp.Body.String())
	}
	if defaultToken.Record.MaxUses != EnrollmentTokenDefaultMaxUses {
		t.Fatalf("default token max uses=%d want=%d", defaultToken.Record.MaxUses, EnrollmentTokenDefaultMaxUses)
	}

	tokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"factory batch","max_uses":5}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if tokenResp.Code != http.StatusCreated {
		t.Fatalf("create token code=%d body=%s", tokenResp.Code, tokenResp.Body.String())
	}
	var createdToken struct {
		Token  string                `json:"token"`
		Record EnrollmentTokenRecord `json:"record"`
	}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &createdToken); err != nil {
		t.Fatalf("decode token response: %v body=%s", err, tokenResp.Body.String())
	}
	if createdToken.Token == "" || createdToken.Record.TokenID <= 0 || createdToken.Record.UseCount != 0 {
		t.Fatalf("unexpected created token: %+v", createdToken)
	}

	revokedTokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"revoked","max_uses":1}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revokedTokenResp.Code != http.StatusCreated {
		t.Fatalf("create revoked token code=%d body=%s", revokedTokenResp.Code, revokedTokenResp.Body.String())
	}
	var revokedToken struct {
		Token  string                `json:"token"`
		Record EnrollmentTokenRecord `json:"record"`
	}
	if err := json.Unmarshal(revokedTokenResp.Body.Bytes(), &revokedToken); err != nil {
		t.Fatalf("decode revoked token response: %v body=%s", err, revokedTokenResp.Body.String())
	}
	revoke := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens/"+strconv.FormatInt(revokedToken.Record.TokenID, 10)+"/revoke", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke token code=%d body=%s", revoke.Code, revoke.Body.String())
	}

	rejectedEnrollment := signedEnrollmentForTest(t, "edge-device-revoked", "key-1", "nonce-revoked", time.Now().UTC())
	rejectedEnrollmentBody, err := json.Marshal(rejectedEnrollment)
	if err != nil {
		t.Fatalf("marshal rejected enrollment: %v", err)
	}
	revokedEnroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(rejectedEnrollmentBody), map[string]string{
		"Content-Type":       "application/json",
		"X-Enrollment-Token": revokedToken.Token,
	})
	if revokedEnroll.Code != http.StatusForbidden {
		t.Fatalf("revoked enroll code=%d body=%s", revokedEnroll.Code, revokedEnroll.Body.String())
	}

	pendingTokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"pending revoked","max_uses":1}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if pendingTokenResp.Code != http.StatusCreated {
		t.Fatalf("create pending token code=%d body=%s", pendingTokenResp.Code, pendingTokenResp.Body.String())
	}
	var pendingToken struct {
		Token  string                `json:"token"`
		Record EnrollmentTokenRecord `json:"record"`
	}
	if err := json.Unmarshal(pendingTokenResp.Body.Bytes(), &pendingToken); err != nil {
		t.Fatalf("decode pending token response: %v body=%s", err, pendingTokenResp.Body.String())
	}
	pendingRevokedFixture := signedEnrollmentFixtureForTest(t, "edge-device-pending-revoked", "key-1", "nonce-pending-revoked", time.Now().UTC())
	pendingRevokedBody, err := json.Marshal(pendingRevokedFixture.Request)
	if err != nil {
		t.Fatalf("marshal pending revoked enrollment: %v", err)
	}
	pendingRevokedEnroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(pendingRevokedBody), map[string]string{
		"Content-Type":       "application/json",
		"X-Enrollment-Token": pendingToken.Token,
	})
	if pendingRevokedEnroll.Code != http.StatusAccepted {
		t.Fatalf("pending revoked enroll code=%d body=%s", pendingRevokedEnroll.Code, pendingRevokedEnroll.Body.String())
	}
	revokePendingToken := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens/"+strconv.FormatInt(pendingToken.Record.TokenID, 10)+"/revoke", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revokePendingToken.Code != http.StatusOK {
		t.Fatalf("revoke pending token code=%d body=%s", revokePendingToken.Code, revokePendingToken.Body.String())
	}
	rejectedStatusReq := signedDeviceStatusForTest(t, pendingRevokedFixture, "nonce-status-rejected", time.Now().UTC())
	rejectedStatusBody, err := json.Marshal(rejectedStatusReq)
	if err != nil {
		t.Fatalf("marshal rejected status: %v", err)
	}
	rejectedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(rejectedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if rejectedStatus.Code != http.StatusOK {
		t.Fatalf("rejected status code=%d body=%s", rejectedStatus.Code, rejectedStatus.Body.String())
	}
	if !strings.Contains(rejectedStatus.Body.String(), `"status":"rejected"`) {
		t.Fatalf("rejected status body=%s", rejectedStatus.Body.String())
	}

	enrollmentFixture := signedEnrollmentFixtureForTest(t, "edge-device-1", "key-1", "nonce-12345678", time.Now().UTC())
	enrollmentBody, err := json.Marshal(enrollmentFixture.Request)
	if err != nil {
		t.Fatalf("marshal enrollment: %v", err)
	}
	missingTokenEnroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(enrollmentBody), map[string]string{
		"Content-Type": "application/json",
	})
	if missingTokenEnroll.Code != http.StatusUnauthorized {
		t.Fatalf("missing token enroll code=%d body=%s", missingTokenEnroll.Code, missingTokenEnroll.Body.String())
	}
	enroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(enrollmentBody), map[string]string{
		"Content-Type":       "application/json",
		"X-Enrollment-Token": createdToken.Token,
	})
	if enroll.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", enroll.Code, enroll.Body.String())
	}
	var enrollResp struct {
		Status       string `json:"status"`
		EnrollmentID int64  `json:"enrollment_id"`
	}
	if err := json.Unmarshal(enroll.Body.Bytes(), &enrollResp); err != nil {
		t.Fatalf("decode enroll response: %v body=%s", err, enroll.Body.String())
	}
	if enrollResp.Status != EnrollmentStatusPending || enrollResp.EnrollmentID <= 0 {
		t.Fatalf("unexpected enroll response: %+v", enrollResp)
	}

	replay := performRequest(engine, http.MethodPost, "/v1/enroll", string(enrollmentBody), map[string]string{
		"Content-Type":       "application/json",
		"X-Enrollment-Token": createdToken.Token,
	})
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay code=%d body=%s", replay.Code, replay.Body.String())
	}

	pendingStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-pending", time.Now().UTC())
	pendingStatusBody, err := json.Marshal(pendingStatusReq)
	if err != nil {
		t.Fatalf("marshal pending status: %v", err)
	}
	pendingStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(pendingStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if pendingStatus.Code != http.StatusOK {
		t.Fatalf("pending status code=%d body=%s", pendingStatus.Code, pendingStatus.Body.String())
	}
	if !strings.Contains(pendingStatus.Body.String(), `"status":"pending"`) {
		t.Fatalf("pending status body=%s", pendingStatus.Body.String())
	}

	tokens := performRequestWithCookies(engine, http.MethodGet, "/center-api/enrollment-tokens", "", nil, cookies)
	if tokens.Code != http.StatusOK {
		t.Fatalf("list tokens code=%d body=%s", tokens.Code, tokens.Body.String())
	}
	if !strings.Contains(tokens.Body.String(), `"use_count":1`) || !strings.Contains(tokens.Body.String(), `"status":"revoked"`) {
		t.Fatalf("token list missing use/revoke state: %s", tokens.Body.String())
	}

	before := performRequestWithCookies(engine, http.MethodGet, "/center-api/status", "", nil, cookies)
	if before.Code != http.StatusOK {
		t.Fatalf("status before code=%d body=%s", before.Code, before.Body.String())
	}
	countsBefore := decodeCenterStatusForTest(t, before.Body.Bytes())
	if countsBefore.PendingEnrollments != 1 || countsBefore.ApprovedDevices != 0 || countsBefore.TotalDevices != 0 {
		t.Fatalf("unexpected counts before approve: %+v", countsBefore)
	}

	list := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/enrollments?status=pending", "", nil, cookies)
	if list.Code != http.StatusOK {
		t.Fatalf("list code=%d body=%s", list.Code, list.Body.String())
	}
	if !strings.Contains(list.Body.String(), "edge-device-1") {
		t.Fatalf("pending list missing device: %s", list.Body.String())
	}
	if !strings.Contains(list.Body.String(), `"enrollment_token_id":`+strconv.FormatInt(createdToken.Record.TokenID, 10)) {
		t.Fatalf("pending list missing linked enrollment token id: %s", list.Body.String())
	}

	approve := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/enrollments/"+strconv.FormatInt(enrollResp.EnrollmentID, 10)+"/approve",
		"",
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve code=%d body=%s", approve.Code, approve.Body.String())
	}

	legacyPlatformStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-platform-compat", time.Now().UTC())
	legacyPlatformStatusReq.RuntimeDeploymentSupported = false
	legacyPlatformStatusReq.RuntimeInventory = nil
	legacyPlatformStatusReq.BodyHash = platformDeviceStatusBodyHash(legacyPlatformStatusReq)
	legacyPlatformStatusReq.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(enrollmentFixture.PrivateKey, []byte(signedEnvelopeMessage(legacyPlatformStatusReq.DeviceID, legacyPlatformStatusReq.KeyID, legacyPlatformStatusReq.Timestamp, legacyPlatformStatusReq.Nonce, legacyPlatformStatusReq.BodyHash))))
	legacyPlatformStatusBody, err := json.Marshal(legacyPlatformStatusReq)
	if err != nil {
		t.Fatalf("marshal legacy platform status: %v", err)
	}
	legacyPlatformStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(legacyPlatformStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if legacyPlatformStatus.Code != http.StatusOK {
		t.Fatalf("legacy platform status code=%d body=%s", legacyPlatformStatus.Code, legacyPlatformStatus.Body.String())
	}

	approvedStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-approved", time.Now().UTC())
	approvedStatusBody, err := json.Marshal(approvedStatusReq)
	if err != nil {
		t.Fatalf("marshal approved status: %v", err)
	}
	approvedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(approvedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if approvedStatus.Code != http.StatusOK {
		t.Fatalf("approved status code=%d body=%s", approvedStatus.Code, approvedStatus.Body.String())
	}
	if !strings.Contains(approvedStatus.Body.String(), `"status":"approved"`) {
		t.Fatalf("approved status body=%s", approvedStatus.Body.String())
	}

	runtimeArtifact, err := runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   runtimeartifactbundle.RuntimeFamilyPHPFPM,
		RuntimeID:       "php83",
		DisplayName:     "PHP 8.3",
		DetectedVersion: "8.3.30",
		Target: runtimeartifactbundle.TargetKey{
			OS:            "linux",
			Arch:          "amd64",
			KernelVersion: "6.8.0-test",
			DistroID:      "ubuntu",
			DistroIDLike:  "debian",
			DistroVersion: "24.04",
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "ubuntu-24.04-amd64",
		GeneratedAt:    time.Unix(1000, 0).UTC(),
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"php83","display_name":"PHP 8.3","detected_version":"8.3.30","source":"bundled"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["core","date"]`)},
			{ArchivePath: "php-fpm", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "php", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/local/sbin/php-fpm", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-fpm-binary")},
			{ArchivePath: "rootfs/usr/bin/php", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
		},
	})
	if err != nil {
		t.Fatalf("build runtime artifact: %v", err)
	}
	artifactRevision := runtimeArtifact.Revision
	importRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/runtime-artifacts/import",
		`{"artifact_b64":"`+base64.StdEncoding.EncodeToString(runtimeArtifact.Compressed)+`"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if importRuntime.Code != http.StatusCreated {
		t.Fatalf("import runtime artifact code=%d body=%s", importRuntime.Code, importRuntime.Body.String())
	}
	if !strings.Contains(importRuntime.Body.String(), `"artifact_revision":"`+artifactRevision+`"`) ||
		!strings.Contains(importRuntime.Body.String(), `"storage_state":"stored"`) {
		t.Fatalf("runtime artifact import response unexpected: %s", importRuntime.Body.String())
	}
	runtimeDeployment := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/runtime-deployment", "", nil, cookies)
	if runtimeDeployment.Code != http.StatusOK {
		t.Fatalf("runtime deployment code=%d body=%s", runtimeDeployment.Code, runtimeDeployment.Body.String())
	}
	if !strings.Contains(runtimeDeployment.Body.String(), `"artifact_revision":"`+artifactRevision+`"`) ||
		!strings.Contains(runtimeDeployment.Body.String(), `"storage_state":"stored"`) {
		t.Fatalf("runtime deployment missing compatible artifact: %s", runtimeDeployment.Body.String())
	}
	assignRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments",
		`{"runtime_family":"php-fpm","runtime_id":"php83","artifact_revision":"`+artifactRevision+`","reason":"test assignment"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if assignRuntime.Code != http.StatusOK {
		t.Fatalf("assign runtime code=%d body=%s", assignRuntime.Code, assignRuntime.Body.String())
	}
	if !strings.Contains(assignRuntime.Body.String(), `"desired_artifact_revision":"`+artifactRevision+`"`) {
		t.Fatalf("assign runtime response missing revision: %s", assignRuntime.Body.String())
	}
	assignedStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-assigned", time.Now().UTC())
	assignedStatusBody, err := json.Marshal(assignedStatusReq)
	if err != nil {
		t.Fatalf("marshal assigned status: %v", err)
	}
	assignedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(assignedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if assignedStatus.Code != http.StatusOK {
		t.Fatalf("assigned status code=%d body=%s", assignedStatus.Code, assignedStatus.Body.String())
	}
	if !strings.Contains(assignedStatus.Body.String(), `"runtime_assignments"`) ||
		!strings.Contains(assignedStatus.Body.String(), `"artifact_revision":"`+artifactRevision+`"`) {
		t.Fatalf("assigned status missing runtime assignment: %s", assignedStatus.Body.String())
	}
	dispatchedDeployment := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/runtime-deployment", "", nil, cookies)
	if dispatchedDeployment.Code != http.StatusOK {
		t.Fatalf("dispatched deployment code=%d body=%s", dispatchedDeployment.Code, dispatchedDeployment.Body.String())
	}
	var dispatchedView RuntimeDeploymentView
	if err := json.Unmarshal(dispatchedDeployment.Body.Bytes(), &dispatchedView); err != nil {
		t.Fatalf("decode dispatched deployment: %v body=%s", err, dispatchedDeployment.Body.String())
	}
	if len(dispatchedView.Assignments) != 0 {
		t.Fatalf("dispatched assignment must be hidden from pending queue: %+v", dispatchedView.Assignments)
	}
	clearDispatched := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments/clear",
		`{"runtime_family":"php-fpm","runtime_id":"php83"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if clearDispatched.Code != http.StatusConflict {
		t.Fatalf("clear dispatched runtime code=%d body=%s", clearDispatched.Code, clearDispatched.Body.String())
	}
	downloadRuntimeReq := signedRuntimeArtifactDownloadForTest(t, enrollmentFixture, "nonce-runtime-download", time.Now().UTC(), runtimeArtifact)
	downloadRuntimeBody, err := json.Marshal(downloadRuntimeReq)
	if err != nil {
		t.Fatalf("marshal runtime download: %v", err)
	}
	downloadRuntime := performRequest(
		engine,
		http.MethodPost,
		"/v1/runtime-artifact-download",
		string(downloadRuntimeBody),
		map[string]string{"Content-Type": "application/json"},
	)
	if downloadRuntime.Code != http.StatusOK {
		t.Fatalf("download runtime code=%d body=%s", downloadRuntime.Code, downloadRuntime.Body.String())
	}
	if !bytes.Equal(downloadRuntime.Body.Bytes(), runtimeArtifact.Compressed) {
		t.Fatalf("download runtime body mismatch")
	}
	if downloadRuntime.Header().Get("X-Tukuyomi-Runtime-Artifact-Revision") != artifactRevision ||
		downloadRuntime.Header().Get("X-Tukuyomi-Runtime-Artifact-Hash") != runtimeArtifact.ArtifactHash ||
		!strings.Contains(downloadRuntime.Header().Get("Content-Disposition"), "php83-"+artifactRevision[:12]+".tar.gz") {
		t.Fatalf("download runtime headers unexpected: %v", downloadRuntime.Header())
	}
	psgiRuntimeArtifact, err := psgiRuntimeArtifactBundleForStoreTest("perl540", time.Unix(1000, 0).UTC())
	if err != nil {
		t.Fatalf("build psgi runtime artifact: %v", err)
	}
	importPSGIRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/runtime-artifacts/import",
		`{"artifact_b64":"`+base64.StdEncoding.EncodeToString(psgiRuntimeArtifact.Compressed)+`"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if importPSGIRuntime.Code != http.StatusCreated {
		t.Fatalf("import psgi runtime artifact code=%d body=%s", importPSGIRuntime.Code, importPSGIRuntime.Body.String())
	}
	assignPSGIRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments",
		`{"runtime_family":"psgi","runtime_id":"perl540","artifact_revision":"`+psgiRuntimeArtifact.Revision+`","reason":"test psgi assignment"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if assignPSGIRuntime.Code != http.StatusOK {
		t.Fatalf("assign psgi runtime code=%d body=%s", assignPSGIRuntime.Code, assignPSGIRuntime.Body.String())
	}
	downloadPSGIRuntimeReq := signedRuntimeArtifactDownloadForTest(t, enrollmentFixture, "nonce-runtime-download-psgi", time.Now().UTC(), psgiRuntimeArtifact)
	downloadPSGIRuntimeBody, err := json.Marshal(downloadPSGIRuntimeReq)
	if err != nil {
		t.Fatalf("marshal psgi runtime download: %v", err)
	}
	downloadPSGIRuntime := performRequest(
		engine,
		http.MethodPost,
		"/v1/runtime-artifact-download",
		string(downloadPSGIRuntimeBody),
		map[string]string{"Content-Type": "application/json"},
	)
	if downloadPSGIRuntime.Code != http.StatusOK {
		t.Fatalf("download psgi runtime code=%d body=%s", downloadPSGIRuntime.Code, downloadPSGIRuntime.Body.String())
	}
	if downloadPSGIRuntime.Header().Get("X-Tukuyomi-Runtime-Family") != RuntimeFamilyPSGI ||
		downloadPSGIRuntime.Header().Get("X-Tukuyomi-Runtime-ID") != "perl540" {
		t.Fatalf("download psgi runtime headers unexpected: %v", downloadPSGIRuntime.Header())
	}
	installedStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-installed", time.Now().UTC())
	installedStatusReq.RuntimeInventory[0].Source = "center"
	installedStatusReq.RuntimeInventory[0].ArtifactRevision = artifactRevision
	installedStatusReq.RuntimeInventory[0].ArtifactHash = runtimeArtifact.ArtifactHash
	installedStatusReq.RuntimeInventory[0].ApplyState = "installed"
	installedStatusReq.RuntimeInventory = append(installedStatusReq.RuntimeInventory, DeviceRuntimeSummary{
		RuntimeFamily:    "psgi",
		RuntimeID:        "perl540",
		DisplayName:      "Perl 5.40",
		DetectedVersion:  "v5.40.0",
		Source:           "center",
		Available:        true,
		ModuleCount:      157,
		UsageReported:    true,
		ArtifactRevision: psgiRuntimeArtifact.Revision,
		ArtifactHash:     psgiRuntimeArtifact.ArtifactHash,
		ApplyState:       "installed",
	})
	resignDeviceStatusForTest(t, enrollmentFixture, &installedStatusReq)
	installedStatusBody, err := json.Marshal(installedStatusReq)
	if err != nil {
		t.Fatalf("marshal installed status: %v", err)
	}
	installedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(installedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if installedStatus.Code != http.StatusOK {
		t.Fatalf("installed status code=%d body=%s", installedStatus.Code, installedStatus.Body.String())
	}
	if strings.Contains(installedStatus.Body.String(), `"runtime_assignments"`) {
		t.Fatalf("installed status should not return completed assignment: %s", installedStatus.Body.String())
	}
	removeRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments/remove",
		`{"runtime_family":"php-fpm","runtime_id":"php83","reason":"test removal"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if removeRuntime.Code != http.StatusOK {
		t.Fatalf("remove runtime code=%d body=%s", removeRuntime.Code, removeRuntime.Body.String())
	}
	if !strings.Contains(removeRuntime.Body.String(), `"desired_state":"removed"`) {
		t.Fatalf("remove runtime response missing removed state: %s", removeRuntime.Body.String())
	}
	removalStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-removal", time.Now().UTC())
	removalStatusBody, err := json.Marshal(removalStatusReq)
	if err != nil {
		t.Fatalf("marshal removal status: %v", err)
	}
	removalStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(removalStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if removalStatus.Code != http.StatusOK {
		t.Fatalf("removal status code=%d body=%s", removalStatus.Code, removalStatus.Body.String())
	}
	if !strings.Contains(removalStatus.Body.String(), `"desired_state":"removed"`) {
		t.Fatalf("removal status missing runtime removal assignment: %s", removalStatus.Body.String())
	}
	removePSGI := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments/remove",
		`{"runtime_family":"psgi","runtime_id":"perl538","reason":"test psgi removal"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if removePSGI.Code != http.StatusOK {
		t.Fatalf("remove psgi code=%d body=%s", removePSGI.Code, removePSGI.Body.String())
	}
	if !strings.Contains(removePSGI.Body.String(), `"runtime_family":"psgi"`) || !strings.Contains(removePSGI.Body.String(), `"desired_state":"removed"`) {
		t.Fatalf("remove psgi response unexpected: %s", removePSGI.Body.String())
	}
	virtualRemovedReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-virtual-removed", time.Now().UTC())
	virtualRemovedReq.RuntimeInventory = []DeviceRuntimeSummary{
		{
			RuntimeFamily: "php-fpm",
			RuntimeID:     "php83",
			Source:        "center",
			Available:     false,
			UsageReported: true,
			ApplyState:    "removed",
		},
		{
			RuntimeFamily: "psgi",
			RuntimeID:     "perl538",
			Source:        "center",
			Available:     false,
			UsageReported: true,
			ApplyState:    "removed",
		},
	}
	virtualRemovedReq.BodyHash = deviceStatusBodyHash(virtualRemovedReq)
	virtualRemovedReq.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(enrollmentFixture.PrivateKey, []byte(signedEnvelopeMessage(virtualRemovedReq.DeviceID, virtualRemovedReq.KeyID, virtualRemovedReq.Timestamp, virtualRemovedReq.Nonce, virtualRemovedReq.BodyHash))))
	virtualRemovedBody, err := json.Marshal(virtualRemovedReq)
	if err != nil {
		t.Fatalf("marshal virtual removed status: %v", err)
	}
	virtualRemovedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(virtualRemovedBody), map[string]string{
		"Content-Type": "application/json",
	})
	if virtualRemovedStatus.Code != http.StatusOK {
		t.Fatalf("virtual removed status code=%d body=%s", virtualRemovedStatus.Code, virtualRemovedStatus.Body.String())
	}
	virtualRemovedDeployment := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/runtime-deployment", "", nil, cookies)
	if virtualRemovedDeployment.Code != http.StatusOK {
		t.Fatalf("virtual removed deployment code=%d body=%s", virtualRemovedDeployment.Code, virtualRemovedDeployment.Body.String())
	}
	var virtualRemovedView RuntimeDeploymentView
	if err := json.Unmarshal(virtualRemovedDeployment.Body.Bytes(), &virtualRemovedView); err != nil {
		t.Fatalf("decode virtual removed deployment: %v body=%s", err, virtualRemovedDeployment.Body.String())
	}
	if len(virtualRemovedView.Assignments) != 0 {
		t.Fatalf("completed removal assignments must leave pending queue: %+v", virtualRemovedView.Assignments)
	}
	for _, runtime := range virtualRemovedView.Device.RuntimeInventory {
		if runtime.RuntimeFamily == "psgi" && runtime.RuntimeID == "perl538" {
			t.Fatalf("virtual removed runtime must not remain in runtime inventory: %+v", runtime)
		}
	}
	removedStatusByRuntime := map[string]bool{}
	for _, status := range virtualRemovedView.ApplyStatus {
		if status.ApplyState == "removed" {
			removedStatusByRuntime[status.RuntimeFamily+":"+status.RuntimeID] = true
		}
	}
	if !removedStatusByRuntime["php-fpm:php83"] || !removedStatusByRuntime["psgi:perl538"] {
		t.Fatalf("virtual removed status did not update apply status: %+v", virtualRemovedView.ApplyStatus)
	}
	reassignRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments",
		`{"runtime_family":"php-fpm","runtime_id":"php83","artifact_revision":"`+artifactRevision+`","reason":"test clear before dispatch"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if reassignRuntime.Code != http.StatusOK {
		t.Fatalf("reassign runtime code=%d body=%s", reassignRuntime.Code, reassignRuntime.Body.String())
	}
	clearRuntime := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/edge-device-1/runtime-assignments/clear",
		`{"runtime_family":"php-fpm","runtime_id":"php83"}`,
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if clearRuntime.Code != http.StatusOK {
		t.Fatalf("clear runtime code=%d body=%s", clearRuntime.Code, clearRuntime.Body.String())
	}
	if !strings.Contains(clearRuntime.Body.String(), `"cleared":true`) {
		t.Fatalf("clear runtime response unexpected: %s", clearRuntime.Body.String())
	}
	downloadClearedReq := signedRuntimeArtifactDownloadForTest(t, enrollmentFixture, "nonce-runtime-download-cleared", time.Now().UTC(), runtimeArtifact)
	downloadClearedBody, err := json.Marshal(downloadClearedReq)
	if err != nil {
		t.Fatalf("marshal cleared runtime download: %v", err)
	}
	downloadCleared := performRequest(
		engine,
		http.MethodPost,
		"/v1/runtime-artifact-download",
		string(downloadClearedBody),
		map[string]string{"Content-Type": "application/json"},
	)
	if downloadCleared.Code != http.StatusNotFound {
		t.Fatalf("download cleared runtime code=%d body=%s", downloadCleared.Code, downloadCleared.Body.String())
	}
	restoredStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-restored", time.Now().UTC())
	restoredStatusBody, err := json.Marshal(restoredStatusReq)
	if err != nil {
		t.Fatalf("marshal restored status: %v", err)
	}
	restoredStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(restoredStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if restoredStatus.Code != http.StatusOK {
		t.Fatalf("restored status code=%d body=%s", restoredStatus.Code, restoredStatus.Body.String())
	}

	configRevision := strings.Repeat("a", 64)
	configSnapshotReq := signedDeviceConfigSnapshotForTest(t, enrollmentFixture, "nonce-config-approved", time.Now().UTC(), configRevision, []byte(`{"schema_version":1,"domains":{"proxy":{"etag":"test","raw":{"routes":[]}}}}`))
	configSnapshotBody, err := json.Marshal(configSnapshotReq)
	if err != nil {
		t.Fatalf("marshal config snapshot: %v", err)
	}
	configSnapshot := performRequest(engine, http.MethodPost, "/v1/device-config-snapshot", string(configSnapshotBody), map[string]string{
		"Content-Type": "application/json",
	})
	if configSnapshot.Code != http.StatusOK {
		t.Fatalf("config snapshot code=%d body=%s", configSnapshot.Code, configSnapshot.Body.String())
	}
	if !strings.Contains(configSnapshot.Body.String(), `"config_revision":"`+configRevision+`"`) {
		t.Fatalf("config snapshot response missing revision: %s", configSnapshot.Body.String())
	}

	after := performRequestWithCookies(engine, http.MethodGet, "/center-api/status", "", nil, cookies)
	if after.Code != http.StatusOK {
		t.Fatalf("status after code=%d body=%s", after.Code, after.Body.String())
	}
	countsAfter := decodeCenterStatusForTest(t, after.Body.Bytes())
	if countsAfter.PendingEnrollments != 0 || countsAfter.ApprovedDevices != 1 || countsAfter.TotalDevices != 1 {
		t.Fatalf("unexpected counts after approve: %+v", countsAfter)
	}

	devices := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices", "", nil, cookies)
	if devices.Code != http.StatusOK {
		t.Fatalf("devices code=%d body=%s", devices.Code, devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"status":"approved"`) {
		t.Fatalf("approved device missing: %s", devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"enrollment_token_id":`+strconv.FormatInt(createdToken.Record.TokenID, 10)) {
		t.Fatalf("approved device missing linked enrollment token id: %s", devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"runtime_role":"gateway"`) ||
		!strings.Contains(devices.Body.String(), `"build_version":"v1.2.0-test"`) ||
		!strings.Contains(devices.Body.String(), `"go_version":"go1.26.2-test"`) {
		t.Fatalf("approved device missing runtime inventory: %s", devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"os":"linux"`) ||
		!strings.Contains(devices.Body.String(), `"arch":"amd64"`) ||
		!strings.Contains(devices.Body.String(), `"distro_id":"ubuntu"`) ||
		!strings.Contains(devices.Body.String(), `"distro_version":"24.04"`) {
		t.Fatalf("approved device missing platform inventory: %s", devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"runtime_deployment_supported":true`) ||
		!strings.Contains(devices.Body.String(), `"runtime_family":"php-fpm"`) ||
		!strings.Contains(devices.Body.String(), `"runtime_id":"php83"`) ||
		!strings.Contains(devices.Body.String(), `"module_count":42`) {
		t.Fatalf("approved device missing runtime summary: %s", devices.Body.String())
	}
	if !strings.Contains(devices.Body.String(), `"config_snapshot_revision":"`+configRevision+`"`) ||
		!strings.Contains(devices.Body.String(), `"config_snapshot_bytes":`) {
		t.Fatalf("approved device missing config snapshot metadata: %s", devices.Body.String())
	}
	download := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/config-snapshot", "", nil, cookies)
	if download.Code != http.StatusOK {
		t.Fatalf("config snapshot download code=%d body=%s", download.Code, download.Body.String())
	}
	if !strings.Contains(download.Body.String(), `"schema_version":1`) || !strings.Contains(download.Header().Get("Content-Disposition"), "edge-device-1-config-aaaaaaaaaaaa.json") {
		t.Fatalf("config snapshot download unexpected: disposition=%q body=%s", download.Header().Get("Content-Disposition"), download.Body.String())
	}

	configRevision2 := strings.Repeat("b", 64)
	configSnapshotReq2 := signedDeviceConfigSnapshotForTest(t, enrollmentFixture, "nonce-config-approved-2", time.Now().UTC(), configRevision2, []byte(`{"schema_version":2,"domains":{"proxy":{"etag":"test-2","raw":{"routes":[{"name":"r2"}]}}}}`))
	configSnapshotBody2, err := json.Marshal(configSnapshotReq2)
	if err != nil {
		t.Fatalf("marshal second config snapshot: %v", err)
	}
	configSnapshot2 := performRequest(engine, http.MethodPost, "/v1/device-config-snapshot", string(configSnapshotBody2), map[string]string{
		"Content-Type": "application/json",
	})
	if configSnapshot2.Code != http.StatusOK {
		t.Fatalf("second config snapshot code=%d body=%s", configSnapshot2.Code, configSnapshot2.Body.String())
	}
	history := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/config-snapshots?limit=1&offset=0", "", nil, cookies)
	if history.Code != http.StatusOK {
		t.Fatalf("config snapshot history code=%d body=%s", history.Code, history.Body.String())
	}
	var historyResp DeviceConfigSnapshotListResult
	if err := json.Unmarshal(history.Body.Bytes(), &historyResp); err != nil {
		t.Fatalf("decode config snapshot history: %v body=%s", err, history.Body.String())
	}
	if historyResp.Limit != 1 || historyResp.Offset != 0 || historyResp.NextOffset != 1 || len(historyResp.Snapshots) != 1 {
		t.Fatalf("unexpected config snapshot history paging: %+v", historyResp)
	}
	if historyResp.Snapshots[0].Revision != configRevision2 || len(historyResp.Snapshots[0].PayloadJSON) != 0 {
		t.Fatalf("config snapshot history should expose latest metadata only: %+v", historyResp.Snapshots[0])
	}
	if strings.Contains(history.Body.String(), "schema_version") || strings.Contains(history.Body.String(), "routes") {
		t.Fatalf("config snapshot history leaked payload: %s", history.Body.String())
	}
	clampedHistory := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/config-snapshots?limit=1000", "", nil, cookies)
	if clampedHistory.Code != http.StatusOK {
		t.Fatalf("clamped config snapshot history code=%d body=%s", clampedHistory.Code, clampedHistory.Body.String())
	}
	if !strings.Contains(clampedHistory.Body.String(), `"limit":6`) {
		t.Fatalf("config snapshot history did not clamp limit: %s", clampedHistory.Body.String())
	}
	revisionDownload := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/config-snapshots/"+configRevision+"?download=1", "", nil, cookies)
	if revisionDownload.Code != http.StatusOK {
		t.Fatalf("config snapshot revision download code=%d body=%s", revisionDownload.Code, revisionDownload.Body.String())
	}
	if !strings.Contains(revisionDownload.Body.String(), `"schema_version":1`) || !strings.Contains(revisionDownload.Header().Get("Content-Disposition"), "edge-device-1-config-aaaaaaaaaaaa.json") {
		t.Fatalf("config snapshot revision download unexpected: disposition=%q body=%s", revisionDownload.Header().Get("Content-Disposition"), revisionDownload.Body.String())
	}
	invalidRevision := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/edge-device-1/config-snapshots/not-a-revision", "", nil, cookies)
	if invalidRevision.Code != http.StatusBadRequest {
		t.Fatalf("invalid revision code=%d body=%s", invalidRevision.Code, invalidRevision.Body.String())
	}

	ruleBundle, err := edgeartifactbundle.BuildBundle([]edgeartifactbundle.RuleFile{
		{Path: "rules/tukuyomi.conf", Kind: "base", ETag: "rule-1", Body: []byte("SecRuleEngine On\n")},
		{Path: "rules/crs/REQUEST-901.conf", Kind: "crs_asset", ETag: "rule-2", Disabled: true, Body: []byte("SecRule ARGS \"@rx test\" \"id:901\"\n")},
	}, time.Now().UTC())
	if err != nil {
		t.Fatalf("build rule artifact bundle: %v", err)
	}
	ruleReq := signedRuleArtifactBundleForTest(t, enrollmentFixture, "nonce-rule-artifact", time.Now().UTC(), ruleBundle)
	ruleBody, err := json.Marshal(ruleReq)
	if err != nil {
		t.Fatalf("marshal rule artifact bundle: %v", err)
	}
	ruleUpload := performRequest(engine, http.MethodPost, "/v1/rule-artifact-bundle", string(ruleBody), map[string]string{
		"Content-Type": "application/json",
	})
	if ruleUpload.Code != http.StatusOK {
		t.Fatalf("rule artifact upload code=%d body=%s", ruleUpload.Code, ruleUpload.Body.String())
	}
	if !strings.Contains(ruleUpload.Body.String(), `"status":"stored"`) || !strings.Contains(ruleUpload.Body.String(), `"bundle_revision":"`+ruleBundle.Revision+`"`) {
		t.Fatalf("rule artifact upload response unexpected: %s", ruleUpload.Body.String())
	}
	ruleUploadDuplicate := performRequest(engine, http.MethodPost, "/v1/rule-artifact-bundle", string(ruleBody), map[string]string{
		"Content-Type": "application/json",
	})
	if ruleUploadDuplicate.Code != http.StatusOK {
		t.Fatalf("duplicate rule artifact upload code=%d body=%s", ruleUploadDuplicate.Code, ruleUploadDuplicate.Body.String())
	}
	if !strings.Contains(ruleUploadDuplicate.Body.String(), `"status":"duplicate"`) {
		t.Fatalf("duplicate rule artifact response unexpected: %s", ruleUploadDuplicate.Body.String())
	}
	var ruleFileCount int
	if err := withCenterDB(context.Background(), func(db *sql.DB, driver string) error {
		return db.QueryRow(`SELECT COUNT(*) FROM center_rule_artifact_files WHERE device_id = `+placeholder(driver, 1)+` AND bundle_revision = `+placeholder(driver, 2), "edge-device-1", ruleBundle.Revision).Scan(&ruleFileCount)
	}); err != nil {
		t.Fatalf("count rule artifact files: %v", err)
	}
	if ruleFileCount != 2 {
		t.Fatalf("rule artifact file count=%d want 2", ruleFileCount)
	}
	malformedRuleReq := signedRuleArtifactBytesForTest(t, enrollmentFixture, "nonce-rule-artifact-bad", time.Now().UTC(), strings.Repeat("c", 64), []byte("not-gzip"))
	malformedRuleBody, err := json.Marshal(malformedRuleReq)
	if err != nil {
		t.Fatalf("marshal malformed rule artifact bundle: %v", err)
	}
	malformedRuleUpload := performRequest(engine, http.MethodPost, "/v1/rule-artifact-bundle", string(malformedRuleBody), map[string]string{
		"Content-Type": "application/json",
	})
	if malformedRuleUpload.Code != http.StatusUnprocessableEntity {
		t.Fatalf("malformed rule artifact upload code=%d body=%s", malformedRuleUpload.Code, malformedRuleUpload.Body.String())
	}

	revokeApprovedToken := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens/"+strconv.FormatInt(createdToken.Record.TokenID, 10)+"/revoke", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revokeApprovedToken.Code != http.StatusOK {
		t.Fatalf("revoke approved token code=%d body=%s", revokeApprovedToken.Code, revokeApprovedToken.Body.String())
	}

	revokedStatusReq := signedDeviceStatusForTest(t, enrollmentFixture, "nonce-status-revoked", time.Now().UTC())
	revokedStatusBody, err := json.Marshal(revokedStatusReq)
	if err != nil {
		t.Fatalf("marshal revoked status: %v", err)
	}
	revokedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(revokedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if revokedStatus.Code != http.StatusOK {
		t.Fatalf("revoked status code=%d body=%s", revokedStatus.Code, revokedStatus.Body.String())
	}
	if !strings.Contains(revokedStatus.Body.String(), `"status":"revoked"`) {
		t.Fatalf("revoked status body=%s", revokedStatus.Body.String())
	}

	afterRevoke := performRequestWithCookies(engine, http.MethodGet, "/center-api/status", "", nil, cookies)
	if afterRevoke.Code != http.StatusOK {
		t.Fatalf("status after revoke code=%d body=%s", afterRevoke.Code, afterRevoke.Body.String())
	}
	countsAfterRevoke := decodeCenterStatusForTest(t, afterRevoke.Body.Bytes())
	if countsAfterRevoke.PendingEnrollments != 0 || countsAfterRevoke.ApprovedDevices != 0 || countsAfterRevoke.TotalDevices != 1 {
		t.Fatalf("unexpected counts after revoke: %+v", countsAfterRevoke)
	}

	devicesAfterRevoke := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices", "", nil, cookies)
	if devicesAfterRevoke.Code != http.StatusOK {
		t.Fatalf("devices after revoke code=%d body=%s", devicesAfterRevoke.Code, devicesAfterRevoke.Body.String())
	}
	if !strings.Contains(devicesAfterRevoke.Body.String(), `"status":"revoked"`) ||
		!strings.Contains(devicesAfterRevoke.Body.String(), `"enrollment_token_status":"revoked"`) ||
		!strings.Contains(devicesAfterRevoke.Body.String(), `"enrollment_token_prefix":"`) {
		t.Fatalf("revoked device missing token revoke state: %s", devicesAfterRevoke.Body.String())
	}
}

func TestCenterDeviceRevokeApprovalFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	} else if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cookies, csrfCookie := loginCenterForTest(t, engine)
	tokenResp := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens", `{"label":"factory revoke","max_uses":3}`, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if tokenResp.Code != http.StatusCreated {
		t.Fatalf("create token code=%d body=%s", tokenResp.Code, tokenResp.Body.String())
	}
	var createdToken struct {
		Token  string                `json:"token"`
		Record EnrollmentTokenRecord `json:"record"`
	}
	if err := json.Unmarshal(tokenResp.Body.Bytes(), &createdToken); err != nil {
		t.Fatalf("decode token response: %v body=%s", err, tokenResp.Body.String())
	}

	fixture := signedEnrollmentFixtureForTest(t, "edge-device-revoke-action", "key-1", "nonce-revoke-action", time.Now().UTC())
	enrollmentBody, err := json.Marshal(fixture.Request)
	if err != nil {
		t.Fatalf("marshal enrollment: %v", err)
	}
	enroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(enrollmentBody), map[string]string{
		"Content-Type":       "application/json",
		"X-Enrollment-Token": createdToken.Token,
	})
	if enroll.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", enroll.Code, enroll.Body.String())
	}
	var enrollResp struct {
		EnrollmentID int64 `json:"enrollment_id"`
	}
	if err := json.Unmarshal(enroll.Body.Bytes(), &enrollResp); err != nil {
		t.Fatalf("decode enroll response: %v body=%s", err, enroll.Body.String())
	}

	approve := performRequestWithCookies(
		engine,
		http.MethodPost,
		"/center-api/devices/enrollments/"+strconv.FormatInt(enrollResp.EnrollmentID, 10)+"/approve",
		"",
		map[string]string{adminauth.CSRFHeaderName: csrfCookie.Value},
		cookies,
	)
	if approve.Code != http.StatusOK {
		t.Fatalf("approve code=%d body=%s", approve.Code, approve.Body.String())
	}

	archiveApproved := performRequestWithCookies(engine, http.MethodPost, "/center-api/devices/edge-device-revoke-action/archive", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if archiveApproved.Code != http.StatusConflict {
		t.Fatalf("archive approved device code=%d body=%s", archiveApproved.Code, archiveApproved.Body.String())
	}

	revoke := performRequestWithCookies(engine, http.MethodPost, "/center-api/devices/edge-device-revoke-action/revoke", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revoke.Code != http.StatusOK {
		t.Fatalf("revoke device code=%d body=%s", revoke.Code, revoke.Body.String())
	}
	if !strings.Contains(revoke.Body.String(), `"status":"revoked"`) ||
		!strings.Contains(revoke.Body.String(), `"revoked_by":"center-admin"`) {
		t.Fatalf("revoke response missing revoked state: %s", revoke.Body.String())
	}

	statusReq := signedDeviceStatusForTest(t, fixture, "nonce-status-revoked-action", time.Now().UTC())
	statusBody, err := json.Marshal(statusReq)
	if err != nil {
		t.Fatalf("marshal status: %v", err)
	}
	status := performRequest(engine, http.MethodPost, "/v1/device-status", string(statusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if status.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", status.Code, status.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"status":"revoked"`) {
		t.Fatalf("status body missing revoked state: %s", status.Body.String())
	}

	archive := performRequestWithCookies(engine, http.MethodPost, "/center-api/devices/edge-device-revoke-action/archive", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if archive.Code != http.StatusOK {
		t.Fatalf("archive device code=%d body=%s", archive.Code, archive.Body.String())
	}
	if !strings.Contains(archive.Body.String(), `"status":"archived"`) ||
		!strings.Contains(archive.Body.String(), `"archived_by":"center-admin"`) {
		t.Fatalf("archive response missing archived state: %s", archive.Body.String())
	}

	archivedStatusReq := signedDeviceStatusForTest(t, fixture, "nonce-status-archived-action", time.Now().UTC())
	archivedStatusBody, err := json.Marshal(archivedStatusReq)
	if err != nil {
		t.Fatalf("marshal archived status: %v", err)
	}
	archivedStatus := performRequest(engine, http.MethodPost, "/v1/device-status", string(archivedStatusBody), map[string]string{
		"Content-Type": "application/json",
	})
	if archivedStatus.Code != http.StatusOK {
		t.Fatalf("archived status code=%d body=%s", archivedStatus.Code, archivedStatus.Body.String())
	}
	if !strings.Contains(archivedStatus.Body.String(), `"status":"archived"`) {
		t.Fatalf("archived status body missing archived state: %s", archivedStatus.Body.String())
	}

	pending := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices/enrollments?status=pending", "", nil, cookies)
	if pending.Code != http.StatusOK {
		t.Fatalf("pending list code=%d body=%s", pending.Code, pending.Body.String())
	}
	if strings.Contains(pending.Body.String(), "edge-device-revoke-action") {
		t.Fatalf("revoked registered device was moved back to pending approvals: %s", pending.Body.String())
	}

	defaultDevices := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices", "", nil, cookies)
	if defaultDevices.Code != http.StatusOK {
		t.Fatalf("default devices code=%d body=%s", defaultDevices.Code, defaultDevices.Body.String())
	}
	if strings.Contains(defaultDevices.Body.String(), "edge-device-revoke-action") {
		t.Fatalf("archived device remained in default registered list: %s", defaultDevices.Body.String())
	}

	archivedDevices := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices?include_archived=1", "", nil, cookies)
	if archivedDevices.Code != http.StatusOK {
		t.Fatalf("archived devices code=%d body=%s", archivedDevices.Code, archivedDevices.Body.String())
	}
	if !strings.Contains(archivedDevices.Body.String(), `"status":"archived"`) ||
		!strings.Contains(archivedDevices.Body.String(), `"archived_by":"center-admin"`) {
		t.Fatalf("archived device missing from include_archived list: %s", archivedDevices.Body.String())
	}

	revokeToken := performRequestWithCookies(engine, http.MethodPost, "/center-api/enrollment-tokens/"+strconv.FormatInt(createdToken.Record.TokenID, 10)+"/revoke", "", map[string]string{
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if revokeToken.Code != http.StatusOK {
		t.Fatalf("revoke token after archive code=%d body=%s", revokeToken.Code, revokeToken.Body.String())
	}
	archivedDevicesAfterTokenRevoke := performRequestWithCookies(engine, http.MethodGet, "/center-api/devices?include_archived=1", "", nil, cookies)
	if archivedDevicesAfterTokenRevoke.Code != http.StatusOK {
		t.Fatalf("archived devices after token revoke code=%d body=%s", archivedDevicesAfterTokenRevoke.Code, archivedDevicesAfterTokenRevoke.Body.String())
	}
	if !strings.Contains(archivedDevicesAfterTokenRevoke.Body.String(), `"status":"archived"`) ||
		!strings.Contains(archivedDevicesAfterTokenRevoke.Body.String(), `"enrollment_token_status":"revoked"`) {
		t.Fatalf("token revoke changed archived device state unexpectedly: %s", archivedDevicesAfterTokenRevoke.Body.String())
	}

	countsResp := performRequestWithCookies(engine, http.MethodGet, "/center-api/status", "", nil, cookies)
	if countsResp.Code != http.StatusOK {
		t.Fatalf("status counts code=%d body=%s", countsResp.Code, countsResp.Body.String())
	}
	counts := decodeCenterStatusForTest(t, countsResp.Body.Bytes())
	if counts.TotalDevices != 0 || counts.ApprovedDevices != 0 || counts.PendingEnrollments != 0 {
		t.Fatalf("unexpected counts after device revoke: %+v", counts)
	}
}

func TestCenterAccountManagementFlow(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	defer restore()

	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer handler.InitLogsStatsStore(false, "", 0)

	t.Setenv(handler.AdminBootstrapUsernameEnv, "center-admin")
	t.Setenv(handler.AdminBootstrapPasswordEnv, "center-admin-password")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		t.Fatalf("EnsureAdminBootstrapOwnerFromEnv: %v", err)
	} else if !created {
		t.Fatal("bootstrap admin was not created")
	}
	if err := handler.InitAdminGuards(); err != nil {
		t.Fatalf("InitAdminGuards: %v", err)
	}

	engine, err := NewEngine(RuntimeConfig{
		APIBasePath: "/center-api",
		UIBasePath:  "/center-ui",
	})
	if err != nil {
		t.Fatalf("NewEngine: %v", err)
	}

	cookies, csrfCookie := loginCenterForTest(t, engine)
	account := performRequestWithCookies(engine, http.MethodGet, "/center-api/auth/account", "", nil, cookies)
	if account.Code != http.StatusOK {
		t.Fatalf("account code=%d body=%s", account.Code, account.Body.String())
	}
	if !strings.Contains(account.Body.String(), `"username":"center-admin"`) {
		t.Fatalf("account body missing username: %s", account.Body.String())
	}

	updateBody := `{"username":"center-admin2","email":"center-admin@example.test","current_password":"center-admin-password"}`
	update := performRequestWithCookies(engine, http.MethodPut, "/center-api/auth/account", updateBody, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if update.Code != http.StatusOK {
		t.Fatalf("update account code=%d body=%s", update.Code, update.Body.String())
	}
	if !strings.Contains(update.Body.String(), `"username":"center-admin2"`) || !strings.Contains(update.Body.String(), `"email":"center-admin@example.test"`) {
		t.Fatalf("updated account body missing identity: %s", update.Body.String())
	}

	passwordBody := `{"current_password":"center-admin-password","new_password":"new center password"}`
	password := performRequestWithCookies(engine, http.MethodPut, "/center-api/auth/password", passwordBody, map[string]string{
		"Content-Type":           "application/json",
		adminauth.CSRFHeaderName: csrfCookie.Value,
	}, cookies)
	if password.Code != http.StatusOK {
		t.Fatalf("password code=%d body=%s", password.Code, password.Body.String())
	}
	if !strings.Contains(password.Body.String(), `"reauth_required":true`) {
		t.Fatalf("password response missing reauth_required: %s", password.Body.String())
	}

	oldSession := performRequestWithCookies(engine, http.MethodGet, "/center-api/auth/session", "", nil, cookies)
	if oldSession.Code != http.StatusOK {
		t.Fatalf("old session code=%d body=%s", oldSession.Code, oldSession.Body.String())
	}
	if authenticatedBool(t, oldSession.Body.Bytes()) {
		t.Fatal("old session remained authenticated after password change")
	}

	loginCenterWithCredentialsForTest(t, engine, "center-admin2", "new center password")
}

func configureCenterAuthTest(t *testing.T) func() {
	t.Helper()
	old := struct {
		dbPath                 string
		adminSessionSecret     string
		adminSessionTTL        time.Duration
		apiAuthDisable         bool
		adminExternalMode      string
		adminTrustedCIDRs      []string
		adminTrustForwardedFor bool
		requestLogEnabled      bool
	}{
		dbPath:                 config.DBPath,
		adminSessionSecret:     config.AdminSessionSecret,
		adminSessionTTL:        config.AdminSessionTTL,
		apiAuthDisable:         config.APIAuthDisable,
		adminExternalMode:      config.AdminExternalMode,
		adminTrustedCIDRs:      append([]string(nil), config.AdminTrustedCIDRs...),
		adminTrustForwardedFor: config.AdminTrustForwardedFor,
		requestLogEnabled:      config.RequestLogEnabled,
	}
	config.DBPath = filepath.Join(t.TempDir(), "center-test.db")
	config.AdminSessionSecret = "center-test-session-secret-123456789"
	config.AdminSessionTTL = time.Hour
	config.APIAuthDisable = false
	config.AdminExternalMode = "full_external"
	config.AdminTrustedCIDRs = []string{"127.0.0.1/32", "::1/128"}
	config.AdminTrustForwardedFor = false
	config.RequestLogEnabled = false
	return func() {
		config.DBPath = old.dbPath
		config.AdminSessionSecret = old.adminSessionSecret
		config.AdminSessionTTL = old.adminSessionTTL
		config.APIAuthDisable = old.apiAuthDisable
		config.AdminExternalMode = old.adminExternalMode
		config.AdminTrustedCIDRs = old.adminTrustedCIDRs
		config.AdminTrustForwardedFor = old.adminTrustForwardedFor
		config.RequestLogEnabled = old.requestLogEnabled
	}
}

func performRequest(engine http.Handler, method, target, body string, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

func performRequestWithCookies(engine http.Handler, method, target, body string, headers map[string]string, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	for _, cookie := range cookies {
		req.AddCookie(cookie)
	}
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)
	return rec
}

type runtimeBuildJobResponseForTest struct {
	Job RuntimeBuildJob `json:"job"`
}

type runtimeBuildJobsResponseForTest struct {
	Jobs []RuntimeBuildJob `json:"jobs"`
}

func runtimeBuildJobListContains(jobs []RuntimeBuildJob, jobID string) bool {
	for _, job := range jobs {
		if job.JobID == jobID {
			return true
		}
	}
	return false
}

func runtimeArtifactBundleForStoreTest(generatedAt time.Time) (runtimeartifactbundle.Build, error) {
	return runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   runtimeartifactbundle.RuntimeFamilyPHPFPM,
		RuntimeID:       "php83",
		DisplayName:     "PHP 8.3",
		DetectedVersion: "8.3.30",
		Target: runtimeartifactbundle.TargetKey{
			OS:            "linux",
			Arch:          "amd64",
			KernelVersion: "6.8.0-test",
			DistroID:      "ubuntu",
			DistroIDLike:  "debian",
			DistroVersion: "24.04",
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "ubuntu-24.04-amd64",
		GeneratedAt:    generatedAt,
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"php83","display_name":"PHP 8.3","detected_version":"8.3.30","binary_path":"data/php-fpm/binaries/php83/php-fpm","cli_binary_path":"data/php-fpm/binaries/php83/php","source":"bundled"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["core","date"]`)},
			{ArchivePath: "php-fpm", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "php", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/local/sbin/php-fpm", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-fpm-binary")},
			{ArchivePath: "rootfs/usr/bin/php", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
		},
	})
}

func psgiRuntimeArtifactBundleForStoreTest(runtimeID string, generatedAt time.Time) (runtimeartifactbundle.Build, error) {
	displayName, detectedVersion := fakePSGIRuntimeBuildVersion(runtimeID)
	return runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   runtimeartifactbundle.RuntimeFamilyPSGI,
		RuntimeID:       runtimeID,
		DisplayName:     displayName,
		DetectedVersion: detectedVersion,
		Target: runtimeartifactbundle.TargetKey{
			OS:            "linux",
			Arch:          "amd64",
			KernelVersion: "6.8.0-test",
			DistroID:      "ubuntu",
			DistroIDLike:  "debian",
			DistroVersion: "24.04",
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "ubuntu-24.04-amd64",
		GeneratedAt:    generatedAt,
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"` + runtimeID + `","display_name":"` + displayName + `","detected_version":"` + detectedVersion + `","perl_path":"data/psgi/binaries/` + runtimeID + `/perl","starman_path":"data/psgi/binaries/` + runtimeID + `/starman","source":"bundled"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["plack","starman"]`)},
			{ArchivePath: "perl", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "starman", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/bin/perl", FileKind: "rootfs", Mode: 0o755, Body: []byte("perl-binary")},
			{ArchivePath: "rootfs/usr/bin/starman", FileKind: "rootfs", Mode: 0o755, Body: []byte("starman-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
		},
	})
}

type fakeRuntimeBuildRunner struct{}

func (fakeRuntimeBuildRunner) Capabilities(context.Context) RuntimeBuilderCapabilities {
	return RuntimeBuilderCapabilities{
		Available:       true,
		DockerAvailable: true,
		PHPFPMSupported: true,
		PSGISupported:   true,
		Runtimes: []RuntimeBuildRuntimeState{
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php83", Supported: true},
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php84", Supported: true},
			{RuntimeFamily: RuntimeFamilyPHPFPM, RuntimeID: "php85", Supported: true},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl536", Supported: true},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl538", Supported: true},
			{RuntimeFamily: RuntimeFamilyPSGI, RuntimeID: "perl540", Supported: true},
		},
	}
}

func (fakeRuntimeBuildRunner) Build(_ context.Context, req centerRuntimeBuildExecution) (runtimeartifactbundle.Build, string, error) {
	if req.RuntimeFamily == RuntimeFamilyPSGI {
		displayName, detectedVersion := fakePSGIRuntimeBuildVersion(req.RuntimeID)
		built, err := runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
			RuntimeFamily:   req.RuntimeFamily,
			RuntimeID:       req.RuntimeID,
			DisplayName:     displayName,
			DetectedVersion: detectedVersion,
			Target: runtimeartifactbundle.TargetKey{
				OS:            req.Target.OS,
				Arch:          req.Target.Arch,
				KernelVersion: req.Target.KernelVersion,
				DistroID:      req.Target.DistroID,
				DistroIDLike:  req.Target.DistroIDLike,
				DistroVersion: req.Target.DistroVersion,
			},
			BuilderVersion: "test-builder",
			BuilderProfile: "test-profile",
			GeneratedAt:    time.Unix(1000, 0).UTC(),
			Files: []runtimeartifactbundle.File{
				{
					ArchivePath: "runtime.json",
					FileKind:    "metadata",
					Mode:        0o644,
					Body:        []byte(`{"runtime_id":"` + req.RuntimeID + `","display_name":"` + displayName + `","detected_version":"` + detectedVersion + `","perl_path":"data/psgi/binaries/` + req.RuntimeID + `/perl","starman_path":"data/psgi/binaries/` + req.RuntimeID + `/starman","source":"bundled"}`),
				},
				{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["plack","starman"]`)},
				{ArchivePath: "perl", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
				{ArchivePath: "starman", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
				{ArchivePath: "rootfs/usr/bin/perl", FileKind: "rootfs", Mode: 0o755, Body: []byte("perl-binary")},
				{ArchivePath: "rootfs/usr/bin/starman", FileKind: "rootfs", Mode: 0o755, Body: []byte("starman-binary")},
				{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
			},
		})
		return built, "fake psgi build complete", err
	}
	built, err := runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   req.RuntimeFamily,
		RuntimeID:       req.RuntimeID,
		DisplayName:     "PHP 8.3",
		DetectedVersion: "8.3.30",
		Target: runtimeartifactbundle.TargetKey{
			OS:            req.Target.OS,
			Arch:          req.Target.Arch,
			KernelVersion: req.Target.KernelVersion,
			DistroID:      req.Target.DistroID,
			DistroIDLike:  req.Target.DistroIDLike,
			DistroVersion: req.Target.DistroVersion,
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "test-profile",
		GeneratedAt:    time.Unix(1000, 0).UTC(),
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"` + req.RuntimeID + `","display_name":"PHP 8.3","detected_version":"8.3.30","binary_path":"data/php-fpm/binaries/php83/php-fpm","cli_binary_path":"data/php-fpm/binaries/php83/php","source":"bundled"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["core","date"]`)},
			{ArchivePath: "php-fpm", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "php", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/local/sbin/php-fpm", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-fpm-binary")},
			{ArchivePath: "rootfs/usr/bin/php", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
		},
	})
	return built, "fake build complete", err
}

func fakePSGIRuntimeBuildVersion(runtimeID string) (string, string) {
	switch runtimeID {
	case "perl536":
		return "Perl 5.36", "v5.36.0"
	case "perl540":
		return "Perl 5.40", "v5.40.0"
	default:
		return "Perl 5.38", "v5.38.5"
	}
}

func replaceRuntimeBuildRunnerForTest(next centerRuntimeBuildRunner) func() {
	runtimeBuildMu.Lock()
	oldRunner := runtimeBuildRunner
	oldJobs := runtimeBuildJobs
	oldLocks := runtimeBuildLocks
	runtimeBuildRunner = next
	runtimeBuildJobs = map[string]RuntimeBuildJob{}
	runtimeBuildLocks = map[string]string{}
	runtimeBuildMu.Unlock()
	return func() {
		runtimeBuildMu.Lock()
		runtimeBuildRunner = oldRunner
		runtimeBuildJobs = oldJobs
		runtimeBuildLocks = oldLocks
		runtimeBuildMu.Unlock()
	}
}

func insertRuntimeBuildDeviceForTest(t *testing.T) {
	t.Helper()
	now := time.Now().UTC().Unix()
	if err := withCenterDB(context.Background(), func(db *sql.DB, driver string) error {
		_, err := db.ExecContext(context.Background(), `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
     approved_at_unix, approved_by, created_at_unix, updated_at_unix, last_seen_at_unix,
     runtime_role, build_version, go_version, os, arch, kernel_version,
     distro_id, distro_id_like, distro_version, runtime_deployment_supported)
VALUES
    (`+placeholders(driver, 20, 1)+`)`,
			"build-device-1",
			"default",
			"test-public-key",
			strings.Repeat("b", 64),
			DeviceStatusApproved,
			now,
			"test",
			now,
			now,
			now,
			"gateway",
			"test-build",
			"go-test",
			"linux",
			goruntime.GOARCH,
			"6.8.0-test",
			"ubuntu",
			"debian",
			"24.04",
			1,
		)
		return err
	}); err != nil {
		t.Fatalf("insert runtime build device: %v", err)
	}
}

func loginCenterForTest(t *testing.T, engine http.Handler) ([]*http.Cookie, *http.Cookie) {
	t.Helper()
	return loginCenterWithCredentialsForTest(t, engine, "center-admin", "center-admin-password")
}

func loginCenterWithCredentialsForTest(t *testing.T, engine http.Handler, identifier string, password string) ([]*http.Cookie, *http.Cookie) {
	t.Helper()
	loginPayload, err := json.Marshal(map[string]string{
		"identifier": identifier,
		"password":   password,
	})
	if err != nil {
		t.Fatalf("marshal login payload: %v", err)
	}
	login := performRequest(engine, http.MethodPost, "/center-api/auth/login", string(loginPayload), map[string]string{
		"Content-Type": "application/json",
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	csrfCookie := cookieByNameForTest(cookies, adminauth.CenterCookieNames().CSRF)
	if csrfCookie == nil {
		t.Fatalf("login did not issue csrf cookie: %v", cookies)
	}
	return cookies, csrfCookie
}

func cookieByNameForTest(cookies []*http.Cookie, name string) *http.Cookie {
	for _, cookie := range cookies {
		if cookie.Name == name {
			return cookie
		}
	}
	return nil
}

type signedEnrollmentFixture struct {
	Request     EnrollmentRequest
	PrivateKey  ed25519.PrivateKey
	Fingerprint string
}

func signedEnrollmentForTest(t *testing.T, deviceID, keyID, nonce string, ts time.Time) EnrollmentRequest {
	return signedEnrollmentFixtureForTest(t, deviceID, keyID, nonce, ts).Request
}

func signedEnrollmentFixtureForTest(t *testing.T, deviceID, keyID, nonce string, ts time.Time) signedEnrollmentFixture {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	publicKeyDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
	if len(publicKeyPEM) == 0 {
		t.Fatal("public key pem is empty")
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	req := EnrollmentRequest{
		DeviceID:                   deviceID,
		KeyID:                      keyID,
		PublicKeyPEMB64:            base64.StdEncoding.EncodeToString(publicKeyPEM),
		PublicKeyFingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
	}
	req.BodyHash = enrollmentBodyHash(req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(privateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
	return signedEnrollmentFixture{
		Request:     req,
		PrivateKey:  privateKey,
		Fingerprint: req.PublicKeyFingerprintSHA256,
	}
}

func signedDeviceStatusForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string, ts time.Time) DeviceStatusRequest {
	t.Helper()
	req := DeviceStatusRequest{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyFingerprintSHA256: fixture.Fingerprint,
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
		RuntimeRole:                "gateway",
		BuildVersion:               "v1.2.0-test",
		GoVersion:                  "go1.26.2-test",
		OS:                         "linux",
		Arch:                       "amd64",
		KernelVersion:              "6.8.0-test",
		DistroID:                   "ubuntu",
		DistroIDLike:               "debian",
		DistroVersion:              "24.04",
		RuntimeDeploymentSupported: true,
		RuntimeInventory: []DeviceRuntimeSummary{
			{
				RuntimeFamily:   "php-fpm",
				RuntimeID:       "php83",
				DisplayName:     "PHP 8.3",
				DetectedVersion: "8.3.30",
				Source:          "bundled",
				Available:       true,
				ModuleCount:     42,
				UsageReported:   true,
			},
			{
				RuntimeFamily:   "psgi",
				RuntimeID:       "perl538",
				DisplayName:     "Perl 5.38",
				DetectedVersion: "v5.38.5",
				Source:          "bundled",
				Available:       true,
				ModuleCount:     157,
				UsageReported:   true,
			},
		},
	}
	req.BodyHash = deviceStatusBodyHash(req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
	return req
}

func resignDeviceStatusForTest(t *testing.T, fixture signedEnrollmentFixture, req *DeviceStatusRequest) {
	t.Helper()
	req.BodyHash = deviceStatusBodyHash(*req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
}

func signedDeviceConfigSnapshotForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string, ts time.Time, revision string, payload []byte) DeviceConfigSnapshotRequest {
	t.Helper()
	sum := sha256.Sum256(payload)
	req := DeviceConfigSnapshotRequest{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyFingerprintSHA256: fixture.Fingerprint,
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
		ConfigRevision:             revision,
		PayloadHash:                hex.EncodeToString(sum[:]),
		Snapshot:                   append(json.RawMessage(nil), payload...),
	}
	req.BodyHash = deviceConfigSnapshotBodyHash(req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
	return req
}

func signedRuleArtifactBundleForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string, ts time.Time, bundle edgeartifactbundle.Build) RuleArtifactBundleRequest {
	t.Helper()
	return signedRuleArtifactBytesForTest(t, fixture, nonce, ts, bundle.Revision, bundle.Compressed)
}

func signedRuleArtifactBytesForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string, ts time.Time, revision string, bundle []byte) RuleArtifactBundleRequest {
	t.Helper()
	sum := sha256.Sum256(bundle)
	req := RuleArtifactBundleRequest{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyFingerprintSHA256: fixture.Fingerprint,
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
		BundleRevision:             revision,
		BundleHash:                 hex.EncodeToString(sum[:]),
		CompressedSize:             int64(len(bundle)),
		UncompressedSize:           1,
		FileCount:                  1,
		BundleB64:                  base64.StdEncoding.EncodeToString(bundle),
	}
	if parsed, err := edgeartifactbundle.Parse(bundle); err == nil {
		req.UncompressedSize = parsed.UncompressedSize
		req.FileCount = parsed.FileCount
	}
	req.BodyHash = ruleArtifactBundleBodyHash(req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
	return req
}

func signedRuntimeArtifactDownloadForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string, ts time.Time, bundle runtimeartifactbundle.Build) RuntimeArtifactDownloadRequest {
	t.Helper()
	req := RuntimeArtifactDownloadRequest{
		DeviceID:                   fixture.Request.DeviceID,
		KeyID:                      fixture.Request.KeyID,
		PublicKeyFingerprintSHA256: fixture.Fingerprint,
		Timestamp:                  ts.UTC().Format(time.RFC3339Nano),
		Nonce:                      nonce,
		RuntimeFamily:              bundle.Manifest.RuntimeFamily,
		RuntimeID:                  bundle.Manifest.RuntimeID,
		ArtifactRevision:           bundle.Revision,
		ArtifactHash:               bundle.ArtifactHash,
	}
	req.BodyHash = runtimeArtifactDownloadBodyHash(req)
	req.SignatureB64 = base64.StdEncoding.EncodeToString(ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash))))
	return req
}

func decodeCenterStatusForTest(t *testing.T, raw []byte) DeviceCounts {
	t.Helper()
	var payload DeviceCounts
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode center status: %v body=%s", err, string(raw))
	}
	return payload
}

func authenticatedBool(t *testing.T, raw []byte) bool {
	t.Helper()
	var payload struct {
		Authenticated bool `json:"authenticated"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatalf("decode session: %v body=%s", err, string(raw))
	}
	return payload.Authenticated
}

func writeCenterTLSFilesForTest(t *testing.T) (string, string) {
	t.Helper()
	publicKey, privateKey, err := ed25519.GenerateKey(cryptorand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     []string{"localhost"},
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, tmpl, tmpl, publicKey, privateKey)
	if err != nil {
		t.Fatalf("CreateCertificate: %v", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	dir := t.TempDir()
	certFile := filepath.Join(dir, "center.crt")
	keyFile := filepath.Join(dir, "center.key")
	if err := os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), 0o600); err != nil {
		t.Fatalf("write cert: %v", err)
	}
	if err := os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}), 0o600); err != nil {
		t.Fatalf("write key: %v", err)
	}
	return certFile, keyFile
}
