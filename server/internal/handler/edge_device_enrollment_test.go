package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestPostEdgeDeviceEnrollmentCreatesIdentityAndSendsSignedRequest(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	centerCalls := 0
	statusCalls := 0
	snapshotCalls := 0
	centerDeviceStatus := "approved"
	var capturedPublicKey ed25519.PublicKey
	var capturedFingerprint string
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			centerCalls++
			expectedToken := "tky_enroll_test"
			if centerCalls == 2 {
				expectedToken = "tky_enroll_replace"
			}
			if got := r.Header.Get("X-Enrollment-Token"); got != expectedToken {
				t.Fatalf("token=%q want %q", got, expectedToken)
			}
			var req edgeDeviceEnrollmentWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode enrollment: %v", err)
			}
			if req.DeviceID != "edge-device-1" || req.KeyID != "default" {
				t.Fatalf("unexpected identity in enrollment: %+v", req)
			}
			nextPublicKey := verifySignedEdgeEnrollmentForTest(t, req)
			if centerCalls == 1 {
				capturedPublicKey = nextPublicKey
				capturedFingerprint = req.PublicKeyFingerprintSHA256
			} else if req.PublicKeyFingerprintSHA256 != capturedFingerprint {
				t.Fatalf("replacement enrollment rotated device key fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, capturedFingerprint)
			}
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case "/v1/device-status":
			statusCalls++
			var req edgeDeviceStatusWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode status: %v", err)
			}
			verifySignedEdgeStatusForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"` + centerDeviceStatus + `","device_id":"edge-device-1","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/device-config-snapshot":
			snapshotCalls++
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000001}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.GET("/edge/device-auth", GetEdgeDeviceAuthStatus)
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)
	router.POST("/edge/device-auth/refresh", PostEdgeDeviceStatusRefresh)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-1","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}
	if centerCalls != 1 {
		t.Fatalf("centerCalls=%d want 1", centerCalls)
	}
	if !strings.Contains(rec.Body.String(), `"identity_configured":true`) || !strings.Contains(rec.Body.String(), `"enrollment_status":"pending"`) {
		t.Fatalf("unexpected enrollment response: %s", rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"proxy_locked":true`) {
		t.Fatalf("pending enrollment should lock proxy: %s", rec.Body.String())
	}
	pendingDuplicate := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_pending_duplicate","device_id":"edge-device-1","key_id":"default"}`
	pendingDuplicateRec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", pendingDuplicate)
	if pendingDuplicateRec.Code != http.StatusConflict {
		t.Fatalf("pending duplicate code=%d body=%s", pendingDuplicateRec.Code, pendingDuplicateRec.Body.String())
	}
	if centerCalls != 1 {
		t.Fatalf("pending duplicate should not call center, centerCalls=%d", centerCalls)
	}

	status := performEdgeDeviceRequest(router, http.MethodGet, "/edge/device-auth", "")
	if status.Code != http.StatusOK {
		t.Fatalf("status code=%d body=%s", status.Code, status.Body.String())
	}
	if !strings.Contains(status.Body.String(), `"device_id":"edge-device-1"`) || !strings.Contains(status.Body.String(), `"center_url":`+quoteJSON(center.URL)) {
		t.Fatalf("status missing identity: %s", status.Body.String())
	}
	if gate := currentEdgeProxyGateState(); !gate.Locked || gate.Reason != edgeProxyLockReasonNotApproved {
		t.Fatalf("pending identity gate=%+v", gate)
	}

	refresh := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/refresh", `{}`)
	if refresh.Code != http.StatusOK {
		t.Fatalf("refresh code=%d body=%s", refresh.Code, refresh.Body.String())
	}
	if statusCalls != 1 {
		t.Fatalf("statusCalls=%d want 1", statusCalls)
	}
	if !strings.Contains(refresh.Body.String(), `"enrollment_status":"approved"`) ||
		!strings.Contains(refresh.Body.String(), `"center_product_id":"product-a"`) ||
		!strings.Contains(refresh.Body.String(), `"config_snapshot_revision":"`) ||
		!strings.Contains(refresh.Body.String(), `"proxy_locked":false`) {
		t.Fatalf("unexpected refresh response: %s", refresh.Body.String())
	}
	if snapshotCalls != 1 {
		t.Fatalf("snapshotCalls=%d want 1", snapshotCalls)
	}
	if gate := currentEdgeProxyGateState(); gate.Locked {
		t.Fatalf("approved identity should unlock proxy, gate=%+v", gate)
	}

	mismatch := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"other-device"}`
	mismatchRec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", mismatch)
	if mismatchRec.Code != http.StatusConflict {
		t.Fatalf("mismatch code=%d body=%s", mismatchRec.Code, mismatchRec.Body.String())
	}
	if centerCalls != 1 {
		t.Fatalf("identity mismatch should not call center, centerCalls=%d", centerCalls)
	}
	approvedDuplicate := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_approved_duplicate","device_id":"edge-device-1","key_id":"default"}`
	approvedDuplicateRec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", approvedDuplicate)
	if approvedDuplicateRec.Code != http.StatusConflict {
		t.Fatalf("approved duplicate code=%d body=%s", approvedDuplicateRec.Code, approvedDuplicateRec.Body.String())
	}
	if centerCalls != 1 {
		t.Fatalf("approved duplicate should not call center, centerCalls=%d", centerCalls)
	}

	centerDeviceStatus = "revoked"
	revokedRefresh := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/refresh", `{}`)
	if revokedRefresh.Code != http.StatusOK {
		t.Fatalf("revoked refresh code=%d body=%s", revokedRefresh.Code, revokedRefresh.Body.String())
	}
	if !strings.Contains(revokedRefresh.Body.String(), `"enrollment_status":"revoked"`) ||
		!strings.Contains(revokedRefresh.Body.String(), `"proxy_locked":true`) {
		t.Fatalf("unexpected revoked refresh response: %s", revokedRefresh.Body.String())
	}
	if gate := currentEdgeProxyGateState(); !gate.Locked || gate.Reason != edgeProxyLockReasonNotApproved {
		t.Fatalf("revoked identity should lock proxy, gate=%+v", gate)
	}

	replacement := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_replace"}`
	replacementRec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", replacement)
	if replacementRec.Code != http.StatusAccepted {
		t.Fatalf("replacement enroll code=%d body=%s", replacementRec.Code, replacementRec.Body.String())
	}
	if centerCalls != 2 {
		t.Fatalf("replacement enrollment did not call center, centerCalls=%d", centerCalls)
	}
	if !strings.Contains(replacementRec.Body.String(), `"device_id":"edge-device-1"`) ||
		!strings.Contains(replacementRec.Body.String(), `"enrollment_status":"pending"`) ||
		!strings.Contains(replacementRec.Body.String(), `"proxy_locked":true`) {
		t.Fatalf("unexpected replacement enrollment response: %s", replacementRec.Body.String())
	}

	centerDeviceStatus = "approved"
	reapprovedRefresh := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/refresh", `{}`)
	if reapprovedRefresh.Code != http.StatusOK {
		t.Fatalf("reapproved refresh code=%d body=%s", reapprovedRefresh.Code, reapprovedRefresh.Body.String())
	}
	if !strings.Contains(reapprovedRefresh.Body.String(), `"enrollment_status":"approved"`) ||
		!strings.Contains(reapprovedRefresh.Body.String(), `"proxy_locked":false`) {
		t.Fatalf("unexpected reapproved refresh response: %s", reapprovedRefresh.Body.String())
	}
}

func TestEdgeDeviceStatusAutoRefreshUpdatesCachedApproval(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-auto-refresh.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	statusCalls := 0
	snapshotCalls := 0
	var capturedPublicKey ed25519.PublicKey
	var capturedFingerprint string
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			var req edgeDeviceEnrollmentWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode enrollment: %v", err)
			}
			capturedPublicKey = verifySignedEdgeEnrollmentForTest(t, req)
			capturedFingerprint = req.PublicKeyFingerprintSHA256
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case "/v1/device-status":
			statusCalls++
			var req edgeDeviceStatusWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode status: %v", err)
			}
			verifySignedEdgeStatusForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-device-1","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/device-config-snapshot":
			snapshotCalls++
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000001}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-1","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	status, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background())
	if err != nil {
		t.Fatalf("autoRefreshEdgeDeviceCenterStatus: %v", err)
	}
	if !attempted {
		t.Fatal("auto refresh should attempt after enrollment")
	}
	if statusCalls != 1 {
		t.Fatalf("statusCalls=%d want 1", statusCalls)
	}
	if status.EnrollmentStatus != edgeEnrollmentStatusApproved || status.ProxyLocked {
		t.Fatalf("unexpected auto refresh status: %+v", status)
	}
	if snapshotCalls != 1 || status.ConfigSnapshotRevision == "" {
		t.Fatalf("config snapshot not pushed, calls=%d status=%+v", snapshotCalls, status)
	}
	if gate := currentEdgeProxyGateState(); gate.Locked {
		t.Fatalf("approved identity should unlock proxy, gate=%+v", gate)
	}
}

func TestEdgeDeviceStatusRefreshLoopWakesAfterEnrollment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-loop-refresh.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)
	defer func() {
		edgeDeviceStatusRefreshTriggerMu.Lock()
		edgeDeviceStatusRefreshTrigger = nil
		edgeDeviceStatusRefreshTriggerMu.Unlock()
	}()

	statusSeen := make(chan struct{}, 1)
	snapshotSeen := make(chan struct{}, 1)
	var capturedPublicKey ed25519.PublicKey
	var capturedFingerprint string
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/enroll":
			var req edgeDeviceEnrollmentWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode enrollment: %v", err)
			}
			capturedPublicKey = verifySignedEdgeEnrollmentForTest(t, req)
			capturedFingerprint = req.PublicKeyFingerprintSHA256
			w.WriteHeader(http.StatusAccepted)
			_, _ = w.Write([]byte(`{"status":"pending"}`))
		case "/v1/device-status":
			var req edgeDeviceStatusWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode status: %v", err)
			}
			verifySignedEdgeStatusForTest(t, req, capturedPublicKey, capturedFingerprint)
			select {
			case statusSeen <- struct{}{}:
			default:
			}
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-device-1","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/device-config-snapshot":
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			select {
			case snapshotSeen <- struct{}{}:
			default:
			}
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000001}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	StartEdgeDeviceStatusRefreshLoop(time.Hour)

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)
	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-1","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	select {
	case <-statusSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("status refresh loop was not woken after enrollment")
	}
	select {
	case <-snapshotSeen:
	case <-time.After(2 * time.Second):
		t.Fatal("config snapshot was not pushed after approval")
	}
	deadline := time.After(2 * time.Second)
	for {
		if gate := currentEdgeProxyGateState(); !gate.Locked {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("approved identity should unlock proxy after wake, gate=%+v", currentEdgeProxyGateState())
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func TestPostEdgeDeviceEnrollmentRequiresEnabledRuntime(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(false, false)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-disabled.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", `{"center_url":"http://127.0.0.1:9092","enrollment_token":"token"}`)
	if rec.Code != http.StatusConflict {
		t.Fatalf("disabled code=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPostEdgeDeviceEnrollmentRejectsInvalidBoundaryInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-invalid.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	cases := []struct {
		name string
		body string
		want int
	}{
		{
			name: "trailing JSON",
			body: `{"center_url":"http://127.0.0.1","enrollment_token":"token"} {}`,
			want: http.StatusBadRequest,
		},
		{
			name: "token too long",
			body: `{"center_url":"http://127.0.0.1","enrollment_token":"` + strings.Repeat("x", edgeEnrollmentTokenMaxBytes+1) + `"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "unexpected center path",
			body: `{"center_url":"http://127.0.0.1/center-api","enrollment_token":"token"}`,
			want: http.StatusBadRequest,
		},
		{
			name: "center credentials",
			body: `{"center_url":"http://user:pass@127.0.0.1","enrollment_token":"token"}`,
			want: http.StatusBadRequest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", tc.body)
			if rec.Code != tc.want {
				t.Fatalf("code=%d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
		})
	}
}

func performEdgeDeviceRequest(router http.Handler, method string, path string, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func verifySignedEdgeEnrollmentForTest(t *testing.T, req edgeDeviceEnrollmentWireRequest) ed25519.PublicKey {
	t.Helper()
	if req.BodyHash != edgeEnrollmentBodyHash(req) {
		t.Fatalf("body_hash mismatch")
	}
	pemBytes, err := base64.StdEncoding.DecodeString(req.PublicKeyPEMB64)
	if err != nil {
		t.Fatalf("public key b64: %v", err)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		t.Fatalf("invalid public key PEM")
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not Ed25519")
	}
	sum := sha256.Sum256(block.Bytes)
	if hex.EncodeToString(sum[:]) != req.PublicKeyFingerprintSHA256 {
		t.Fatalf("fingerprint mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("signature verification failed")
	}
	return pub
}

func verifySignedEdgeStatusForTest(t *testing.T, req edgeDeviceStatusWireRequest, pub ed25519.PublicKey, fingerprint string) {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key was not captured")
	}
	if req.BodyHash != edgeDeviceStatusBodyHash(req) {
		t.Fatalf("status body_hash mismatch")
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		t.Fatalf("fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, fingerprint)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("status signature verification failed")
	}
}

func verifySignedEdgeConfigSnapshotForTest(t *testing.T, req edgeDeviceConfigSnapshotWireRequest, pub ed25519.PublicKey, fingerprint string) {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key was not captured")
	}
	if req.BodyHash != edgeDeviceConfigSnapshotBodyHash(req) {
		t.Fatalf("config snapshot body_hash mismatch")
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		t.Fatalf("fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, fingerprint)
	}
	if !json.Valid(req.Snapshot) {
		t.Fatalf("config snapshot is not valid JSON")
	}
	sum := sha256.Sum256(req.Snapshot)
	if hex.EncodeToString(sum[:]) != req.PayloadHash {
		t.Fatalf("config snapshot payload_hash mismatch")
	}
	if req.ConfigRevision == "" {
		t.Fatalf("config snapshot revision is empty")
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("config snapshot signature verification failed")
	}
}

func setEdgeRuntimeForTest(enabled bool, deviceAuthEnabled bool) func() {
	oldEdgeEnabled := config.EdgeEnabled
	oldDeviceAuthEnabled := config.EdgeDeviceAuthEnabled
	oldRequireDeviceApproval := config.EdgeRequireDeviceApproval
	config.EdgeEnabled = enabled
	config.EdgeDeviceAuthEnabled = deviceAuthEnabled
	config.EdgeRequireDeviceApproval = enabled
	return func() {
		config.EdgeEnabled = oldEdgeEnabled
		config.EdgeDeviceAuthEnabled = oldDeviceAuthEnabled
		config.EdgeRequireDeviceApproval = oldRequireDeviceApproval
	}
}

func quoteJSON(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
