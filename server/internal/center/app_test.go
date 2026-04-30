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
	if !strings.Contains(devices.Body.String(), `"runtime_role":"gateway"`) ||
		!strings.Contains(devices.Body.String(), `"build_version":"v1.2.0-test"`) ||
		!strings.Contains(devices.Body.String(), `"go_version":"go1.26.2-test"`) {
		t.Fatalf("approved device missing runtime inventory: %s", devices.Body.String())
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
	}
	req.BodyHash = deviceStatusBodyHash(req)
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
