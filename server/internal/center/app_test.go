package center

import (
	"crypto/ed25519"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestRuntimeConfigFromEnvDefaults(t *testing.T) {
	t.Setenv(ListenAddrEnv, "")
	t.Setenv(APIBasePathEnv, "")
	t.Setenv(UIBasePathEnv, "")

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
}

func TestRuntimeConfigFromEnvRejectsUnsafeBasePath(t *testing.T) {
	t.Setenv(ListenAddrEnv, "")
	t.Setenv(APIBasePathEnv, "/center-api/../bad")
	t.Setenv(UIBasePathEnv, "")

	if _, err := RuntimeConfigFromEnv(); err == nil {
		t.Fatal("expected unsafe api base path to be rejected")
	}
}

func TestCenterLoginFlowUsesSharedAdminAuth(t *testing.T) {
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
	if !strings.Contains(ui.Body.String(), "TUKUYOMI Center") {
		t.Fatal("center ui response does not contain product title")
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

	enrollment := signedEnrollmentForTest(t, "edge-device-1", "key-1", "nonce-12345678", time.Now().UTC())
	enrollmentBody, err := json.Marshal(enrollment)
	if err != nil {
		t.Fatalf("marshal enrollment: %v", err)
	}
	enroll := performRequest(engine, http.MethodPost, "/v1/enroll", string(enrollmentBody), map[string]string{
		"Content-Type":  "application/json",
		"X-License-Key": "license-test-key",
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
		"Content-Type": "application/json",
	})
	if replay.Code != http.StatusConflict {
		t.Fatalf("replay code=%d body=%s", replay.Code, replay.Body.String())
	}

	cookies, csrfCookie := loginCenterForTest(t, engine)
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

func loginCenterForTest(t *testing.T, engine http.Handler) ([]*http.Cookie, *http.Cookie) {
	t.Helper()
	loginBody := `{"identifier":"center-admin","password":"center-admin-password"}`
	login := performRequest(engine, http.MethodPost, "/center-api/auth/login", loginBody, map[string]string{
		"Content-Type": "application/json",
	})
	if login.Code != http.StatusOK {
		t.Fatalf("login code=%d body=%s", login.Code, login.Body.String())
	}
	cookies := login.Result().Cookies()
	csrfCookie := cookieByNameForTest(cookies, adminauth.CSRFCookieName)
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

func signedEnrollmentForTest(t *testing.T, deviceID, keyID, nonce string, ts time.Time) EnrollmentRequest {
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
