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
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/runtimeartifactbundle"
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
	restoreConfig := saveConfigFilePathForTest(t, writeSettingsConfigFixture(t))
	defer restoreConfig()
	oldAllowInsecureDefaults := config.AllowInsecureDefaults
	oldRemoteSSHCenterSigningKey := config.RemoteSSHGatewayCenterSigningPublicKey
	config.AllowInsecureDefaults = true
	config.RemoteSSHGatewayCenterSigningPublicKey = ""
	defer func() {
		config.AllowInsecureDefaults = oldAllowInsecureDefaults
		config.RemoteSSHGatewayCenterSigningPublicKey = oldRemoteSSHCenterSigningKey
	}()

	centerCalls := 0
	statusCalls := 0
	snapshotCalls := 0
	signingKeyCalls := 0
	centerDeviceStatus := "approved"
	centerSigningPublicKey := "ed25519:" + base64.StdEncoding.EncodeToString(bytesOfLengthForTest(ed25519.PublicKeySize, 0x21))
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
		case "/v1/remote-ssh/signing-key":
			signingKeyCalls++
			_, _ = w.Write([]byte(`{"public_key":` + quoteJSON(centerSigningPublicKey) + `,"algorithm":"ed25519"}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.GET("/edge/device-auth", GetEdgeDeviceAuthStatus)
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)
	router.POST("/edge/device-auth/refresh", PostEdgeDeviceStatusRefresh)
	router.POST("/edge/device-auth/remote-ssh/signing-key/refresh", PostEdgeRemoteSSHSigningKeyRefresh)

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
	_, _, importedCfg, err := loadAppConfigStorage(false)
	if err != nil {
		t.Fatalf("load app config after center signing key import: %v", err)
	}
	if importedCfg.RemoteSSH.Gateway.CenterSigningPublicKey != centerSigningPublicKey {
		t.Fatalf("imported center signing key=%q want %q", importedCfg.RemoteSSH.Gateway.CenterSigningPublicKey, centerSigningPublicKey)
	}
	if config.RemoteSSHGatewayCenterSigningPublicKey != centerSigningPublicKey {
		t.Fatalf("runtime center signing key=%q want %q", config.RemoteSSHGatewayCenterSigningPublicKey, centerSigningPublicKey)
	}
	if signingKeyCalls != 1 {
		t.Fatalf("signingKeyCalls=%d want 1", signingKeyCalls)
	}
	rotatedCenterSigningPublicKey := "ed25519:" + base64.StdEncoding.EncodeToString(bytesOfLengthForTest(ed25519.PublicKeySize, 0x22))
	centerSigningPublicKey = rotatedCenterSigningPublicKey
	missingConfirm := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/remote-ssh/signing-key/refresh", `{}`)
	if missingConfirm.Code != http.StatusPreconditionRequired {
		t.Fatalf("missing confirm signing key refresh code=%d body=%s", missingConfirm.Code, missingConfirm.Body.String())
	}
	explicitRefresh := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/remote-ssh/signing-key/refresh", `{"confirm":true}`)
	if explicitRefresh.Code != http.StatusOK {
		t.Fatalf("explicit signing key refresh code=%d body=%s", explicitRefresh.Code, explicitRefresh.Body.String())
	}
	if !strings.Contains(explicitRefresh.Body.String(), quoteJSON(rotatedCenterSigningPublicKey)) {
		t.Fatalf("explicit signing key refresh did not return rotated key: %s", explicitRefresh.Body.String())
	}
	_, _, refreshedCfg, err := loadAppConfigStorage(false)
	if err != nil {
		t.Fatalf("load app config after explicit signing key refresh: %v", err)
	}
	if refreshedCfg.RemoteSSH.Gateway.CenterSigningPublicKey != rotatedCenterSigningPublicKey {
		t.Fatalf("refreshed center signing key=%q want %q", refreshedCfg.RemoteSSH.Gateway.CenterSigningPublicKey, rotatedCenterSigningPublicKey)
	}
	if config.RemoteSSHGatewayCenterSigningPublicKey != rotatedCenterSigningPublicKey {
		t.Fatalf("runtime refreshed center signing key=%q want %q", config.RemoteSSHGatewayCenterSigningPublicKey, rotatedCenterSigningPublicKey)
	}
	if signingKeyCalls != 2 {
		t.Fatalf("signingKeyCalls=%d want 2", signingKeyCalls)
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

func TestBootstrapCenterProtectedGatewayEnablesEdgeAndApprovesIdentity(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "gateway.db")
	configPath := filepath.Join(tmp, "config.json")
	raw := `{
  "edge": {
    "enabled": false,
    "device_auth": {
      "enabled": false,
      "status_refresh_interval_sec": 0
    }
  },
  "storage": {
    "db_driver": "sqlite",
    "db_path": "db/tukuyomi.db",
    "db_dsn": ""
  }
}`
	if err := os.WriteFile(configPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	restoreConfig := saveConfigFilePathForTest(t, configPath)
	defer restoreConfig()
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	if _, err := store.writeProxyConfigVersion("", ProxyRulesConfig{}, configVersionSourceImport, "", "test proxy seed", 0); err != nil {
		t.Fatalf("write proxy seed: %v", err)
	}
	seedBypass, err := bypassconf.MarshalJSON(bypassconf.File{Default: bypassconf.Scope{Entries: []bypassconf.Entry{
		{Path: "/center-api/"},
		{Path: "/center-manage-api/"},
		{Path: "/center-ui/"},
		{Path: "/healthz"},
	}}})
	if err != nil {
		t.Fatalf("marshal bypass seed: %v", err)
	}
	if _, err := store.writePolicyJSONConfigVersion("", mustPolicyJSONSpec(bypassConfigBlobKey), seedBypass, configVersionSourceImport, "", "test bypass seed", 0); err != nil {
		t.Fatalf("write bypass seed: %v", err)
	}

	first, err := BootstrapCenterProtectedGateway(context.Background(), CenterProtectedGatewayBootstrapOptions{
		CenterURL:             "http://127.0.0.1:9092",
		GatewayAPIBasePath:    "/center-api",
		CenterAPIBasePath:     "/center-manage-api",
		CenterUIBasePath:      "/center-ui",
		DeviceID:              "gateway-a",
		CenterTLSCABundleFile: "conf/center-ca.pem",
		CenterTLSServerName:   "center.example.local",
	})
	if err != nil {
		t.Fatalf("BootstrapCenterProtectedGateway prepare: %v", err)
	}
	if !first.AppConfigUpdated {
		t.Fatal("expected bootstrap to update app_config")
	}
	if first.DeviceID != "gateway-a" || first.KeyID != "default" {
		t.Fatalf("unexpected identity: %+v", first)
	}
	if !strings.Contains(first.PublicKeyPEM, "BEGIN PUBLIC KEY") {
		t.Fatalf("public key PEM missing header: %q", first.PublicKeyPEM)
	}
	if first.EnrollmentStatus != edgeEnrollmentStatusLocal {
		t.Fatalf("status=%q want local", first.EnrollmentStatus)
	}

	_, _, cfg, err := loadAppConfigStorage(false)
	if err != nil {
		t.Fatalf("load app config: %v", err)
	}
	if !cfg.Edge.Enabled || !cfg.Edge.DeviceAuth.Enabled {
		t.Fatalf("edge config was not enabled: %+v", cfg.Edge)
	}
	if cfg.Edge.DeviceAuth.StatusRefreshIntervalSec != config.DefaultEdgeDeviceStatusRefreshSec {
		t.Fatalf("poll interval=%d want %d", cfg.Edge.DeviceAuth.StatusRefreshIntervalSec, config.DefaultEdgeDeviceStatusRefreshSec)
	}
	if cfg.RemoteSSH.Gateway.CenterTLSCABundleFile != "conf/center-ca.pem" || cfg.RemoteSSH.Gateway.CenterTLSServerName != "center.example.local" {
		t.Fatalf("center tls trust settings were not bootstrapped: %+v", cfg.RemoteSSH.Gateway)
	}
	proxyCfg, _, found, err := store.loadActiveProxyConfig()
	if err != nil {
		t.Fatalf("load proxy config: %v", err)
	}
	if !found {
		t.Fatal("proxy config was not seeded")
	}
	if len(proxyCfg.Upstreams) != 1 || proxyCfg.Upstreams[0].Name != "center" || proxyCfg.Upstreams[0].URL != "http://127.0.0.1:9092" {
		t.Fatalf("center upstream was not bootstrapped: %+v", proxyCfg.Upstreams)
	}
	if len(proxyCfg.Routes) != 2 || proxyCfg.Routes[0].Name != "center-api" || proxyCfg.Routes[1].Name != "center-ui" {
		t.Fatalf("center routes were not bootstrapped: %+v", proxyCfg.Routes)
	}
	if proxyCfg.Routes[0].Match.Path == nil || proxyCfg.Routes[0].Match.Path.Value != "/center-api" {
		t.Fatalf("center api route match mismatch: %+v", proxyCfg.Routes[0])
	}
	if proxyCfg.Routes[0].Action.PathRewrite == nil || proxyCfg.Routes[0].Action.PathRewrite.Prefix != "/center-manage-api" {
		t.Fatalf("center api route rewrite mismatch: %+v", proxyCfg.Routes[0].Action)
	}
	bypassRaw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(bypassConfigBlobKey))
	if err != nil {
		t.Fatalf("load bypass config: %v", err)
	}
	if !found {
		t.Fatal("bypass config was not preserved")
	}
	parsedBypass, err := bypassconf.Parse(string(bypassRaw))
	if err != nil {
		t.Fatalf("parse bypass config: %v raw=%s", err, string(bypassRaw))
	}
	for _, entry := range parsedBypass.Default.Entries {
		if strings.TrimRight(entry.Path, "/") == "/center-api" || strings.TrimRight(entry.Path, "/") == "/center-manage-api" || strings.TrimRight(entry.Path, "/") == "/center-ui" {
			t.Fatalf("center route leaked into WAF bypass: %s", string(bypassRaw))
		}
	}
	if !strings.Contains(string(bypassRaw), `"/healthz"`) {
		t.Fatalf("unrelated bypass entry was not preserved: %s", string(bypassRaw))
	}

	second, err := BootstrapCenterProtectedGateway(context.Background(), CenterProtectedGatewayBootstrapOptions{
		CenterURL:          "http://127.0.0.1:9092",
		GatewayAPIBasePath: "/center-api",
		CenterAPIBasePath:  "/center-manage-api",
		CenterUIBasePath:   "/center-ui",
		DeviceID:           "gateway-a",
		MarkApproved:       true,
	})
	if err != nil {
		t.Fatalf("BootstrapCenterProtectedGateway approve: %v", err)
	}
	if second.AppConfigUpdated {
		t.Fatal("second bootstrap should be idempotent for app_config")
	}
	if second.PublicKeyFingerprintSHA256 != first.PublicKeyFingerprintSHA256 {
		t.Fatalf("fingerprint rotated: %q != %q", second.PublicKeyFingerprintSHA256, first.PublicKeyFingerprintSHA256)
	}
	if second.EnrollmentStatus != edgeEnrollmentStatusApproved {
		t.Fatalf("status=%q want approved", second.EnrollmentStatus)
	}
	status, err := currentEdgeDeviceAuthStatus()
	if err != nil {
		t.Fatalf("currentEdgeDeviceAuthStatus: %v", err)
	}
	if status.EnrollmentStatus != edgeEnrollmentStatusApproved || status.CenterURL != "http://127.0.0.1:9092" {
		t.Fatalf("unexpected current status: %+v", status)
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

func TestApplyEdgeRuntimeRemovalDeletesUnusedManagedPHPBundle(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	t.Chdir(tmp)
	inventoryPath := filepath.Join("data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{})
	rootDir := phpRuntimeRootDirFromInventoryPath(inventoryPath)
	bundleDir := filepath.Join(rootDir, "binaries", "php83")
	runtimeDir := filepath.Join(rootDir, "runtime", "php83")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "php-fpm.conf"), []byte("[global]\n"), 0o600); err != nil {
		t.Fatalf("write runtime config: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	applyEdgeRuntimeRemoval(edgeRuntimeDeviceAssignment{
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php83",
		DesiredState:  "removed",
	})

	if _, err := os.Stat(bundleDir); !os.IsNotExist(err) {
		t.Fatalf("bundle dir stat err=%v, want not exist", err)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir stat err=%v, want not exist", err)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("php-fpm", "php83")]
	if status.ApplyState != "removed" || status.ApplyError != "" {
		t.Fatalf("apply status=%+v, want removed without error", status)
	}
	summary := currentEdgeRuntimeInventorySummary()
	if len(summary) != 1 || summary[0].RuntimeFamily != "php-fpm" || summary[0].RuntimeID != "php83" || summary[0].ApplyState != "removed" {
		t.Fatalf("summary=%+v, want virtual removed runtime", summary)
	}
}

func TestApplyEdgeRuntimeRemovalBlocksReferencedPHPRuntime(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	t.Chdir(tmp)
	inventoryPath := filepath.Join("data", "php-fpm", "inventory.json")
	vhostPath := filepath.Join(tmp, "data", "php-fpm", "vhosts.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{"vhosts":[{"name":"app","mode":"php-fpm","hostname":"127.0.0.1","listen_port":19083,"document_root":"data/vhosts/app/public","runtime_id":"php83","generated_target":"app-php"}]}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{})
	bundleDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", "php83")
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	applyEdgeRuntimeRemoval(edgeRuntimeDeviceAssignment{
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php83",
		DesiredState:  "removed",
	})

	if _, err := os.Stat(bundleDir); err != nil {
		t.Fatalf("bundle dir should remain: %v", err)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("php-fpm", "php83")]
	if status.ApplyState != "blocked" || !strings.Contains(status.ApplyError, "app-php") {
		t.Fatalf("apply status=%+v, want blocked with generated target", status)
	}
}

func TestApplyEdgeRuntimeInstallDownloadsAndInstallsPHPArtifact(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	t.Chdir(tmp)
	inventoryPath := filepath.Join("data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	artifact := buildGatewayRuntimeArtifactForTest(t, "php83")
	identity := newEdgeDeviceIdentityForTest(t)
	publicKey := publicKeyFromEdgeIdentityForTest(t, identity)
	downloadCalls := 0
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime-artifact-download" {
			t.Fatalf("unexpected path=%q", r.URL.Path)
		}
		downloadCalls++
		var req edgeRuntimeArtifactDownloadWireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode download request: %v", err)
		}
		verifySignedEdgeRuntimeArtifactDownloadForTest(t, req, publicKey, identity.PublicKeyFingerprintSHA256)
		if req.ArtifactRevision != artifact.Revision || req.ArtifactHash != artifact.ArtifactHash {
			t.Fatalf("download request artifact=%s/%s want %s/%s", req.ArtifactRevision, req.ArtifactHash, artifact.Revision, artifact.ArtifactHash)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(artifact.Compressed)
	}))
	defer center.Close()
	identity.CenterURL = center.URL

	applyEdgePHPRuntimeInstall(context.Background(), identity, assignmentForRuntimeArtifactForTest(artifact), "php83")

	if downloadCalls != 1 {
		t.Fatalf("downloadCalls=%d want 1", downloadCalls)
	}
	bundleDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", "php83")
	for _, name := range []string{"php-fpm", "php", "modules.json", "runtime.json", "rootfs/usr/local/sbin/php-fpm", "rootfs/usr/bin/php", "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"} {
		if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("installed file %s missing: %v", name, err)
		}
	}
	rawManifest, err := os.ReadFile(filepath.Join(bundleDir, "runtime.json"))
	if err != nil {
		t.Fatalf("read installed runtime manifest: %v", err)
	}
	var manifest phpRuntimeArtifactManifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("decode installed runtime manifest: %v", err)
	}
	if manifest.BinaryPath != "data/php-fpm/binaries/php83/php-fpm" || manifest.CLIBinaryPath != "data/php-fpm/binaries/php83/php" {
		t.Fatalf("installed manifest paths=%q/%q, want relative data paths", manifest.BinaryPath, manifest.CLIBinaryPath)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("php-fpm", "php83")]
	if status.ApplyState != "installed" || status.ArtifactRevision != artifact.Revision || status.ArtifactHash != artifact.ArtifactHash {
		t.Fatalf("apply status=%+v, want installed artifact", status)
	}
	summary := currentEdgeRuntimeInventorySummary()
	if len(summary) != 1 || summary[0].RuntimeID != "php83" || summary[0].Source != "center" ||
		summary[0].ArtifactRevision != artifact.Revision || summary[0].ArtifactHash != artifact.ArtifactHash ||
		summary[0].ApplyState != "installed" {
		t.Fatalf("summary=%+v, want installed center runtime", summary)
	}
}

func TestApplyEdgeRuntimeInstallDownloadsAndInstallsPSGIArtifact(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	t.Chdir(tmp)
	inventoryPath := filepath.Join("data", "psgi", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPSGIRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := InitPSGIRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPSGIRuntimeInventoryRuntime: %v", err)
	}

	artifact := buildGatewayPSGIRuntimeArtifactForTest(t, "perl538")
	identity := newEdgeDeviceIdentityForTest(t)
	publicKey := publicKeyFromEdgeIdentityForTest(t, identity)
	downloadCalls := 0
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/runtime-artifact-download" {
			t.Fatalf("unexpected path=%q", r.URL.Path)
		}
		downloadCalls++
		var req edgeRuntimeArtifactDownloadWireRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode download request: %v", err)
		}
		verifySignedEdgeRuntimeArtifactDownloadForTest(t, req, publicKey, identity.PublicKeyFingerprintSHA256)
		if req.ArtifactRevision != artifact.Revision || req.ArtifactHash != artifact.ArtifactHash {
			t.Fatalf("download request artifact=%s/%s want %s/%s", req.ArtifactRevision, req.ArtifactHash, artifact.Revision, artifact.ArtifactHash)
		}
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = w.Write(artifact.Compressed)
	}))
	defer center.Close()
	identity.CenterURL = center.URL

	applyEdgePSGIRuntimeInstall(context.Background(), identity, assignmentForRuntimeArtifactForTest(artifact), "perl538")

	if downloadCalls != 1 {
		t.Fatalf("downloadCalls=%d want 1", downloadCalls)
	}
	bundleDir := filepath.Join(psgiRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", "perl538")
	for _, name := range []string{"perl", "starman", "modules.json", "runtime.json", "rootfs/usr/bin/perl", "rootfs/usr/bin/starman", "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2"} {
		if _, err := os.Stat(filepath.Join(bundleDir, filepath.FromSlash(name))); err != nil {
			t.Fatalf("installed file %s missing: %v", name, err)
		}
	}
	rawManifest, err := os.ReadFile(filepath.Join(bundleDir, "runtime.json"))
	if err != nil {
		t.Fatalf("read installed runtime manifest: %v", err)
	}
	var manifest psgiRuntimeArtifactManifest
	if err := json.Unmarshal(rawManifest, &manifest); err != nil {
		t.Fatalf("decode installed runtime manifest: %v", err)
	}
	if manifest.PerlPath != "data/psgi/binaries/perl538/perl" || manifest.StarmanPath != "data/psgi/binaries/perl538/starman" {
		t.Fatalf("installed manifest paths=%q/%q, want relative data paths", manifest.PerlPath, manifest.StarmanPath)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("psgi", "perl538")]
	if status.ApplyState != "installed" || status.ArtifactRevision != artifact.Revision || status.ArtifactHash != artifact.ArtifactHash {
		t.Fatalf("apply status=%+v, want installed artifact", status)
	}
	var found bool
	for _, item := range currentEdgeRuntimeInventorySummary() {
		if item.RuntimeFamily != "psgi" || item.RuntimeID != "perl538" {
			continue
		}
		found = true
		if item.Source != "center" || item.ArtifactRevision != artifact.Revision ||
			item.ArtifactHash != artifact.ArtifactHash || item.ApplyState != "installed" {
			t.Fatalf("summary item=%+v, want installed center PSGI runtime", item)
		}
	}
	if !found {
		t.Fatalf("summary missing installed PSGI runtime: %+v", currentEdgeRuntimeInventorySummary())
	}
}

func TestApplyEdgeRuntimeInstallRejectsHashMismatch(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	artifact := buildGatewayRuntimeArtifactForTest(t, "php83")
	identity := newEdgeDeviceIdentityForTest(t)
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(artifact.Compressed)
	}))
	defer center.Close()
	identity.CenterURL = center.URL
	assignment := assignmentForRuntimeArtifactForTest(artifact)
	assignment.ArtifactHash = strings.Repeat("a", 64)

	applyEdgePHPRuntimeInstall(context.Background(), identity, assignment, "php83")

	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("php-fpm", "php83")]
	if status.ApplyState != "failed" || !strings.Contains(status.ApplyError, "hash mismatch") {
		t.Fatalf("apply status=%+v, want failed hash mismatch", status)
	}
	bundleDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", "php83")
	if _, err := os.Stat(bundleDir); !os.IsNotExist(err) {
		t.Fatalf("bundle dir stat err=%v, want not exist", err)
	}
}

func TestInstallEdgePHPRuntimeArtifactRejectsTargetMismatch(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	artifact := buildGatewayRuntimeArtifactForTest(t, "php83")
	artifact.Manifest.Target.DistroVersion = artifact.Manifest.Target.DistroVersion + "-mismatch"
	if edgeRuntimeArtifactTargetMatchesGateway(artifact.Manifest.Target) {
		t.Fatal("test target should not match gateway platform")
	}
	if err := installEdgePHPRuntimeArtifact(artifact.Compressed, runtimeartifactbundle.Parsed{
		Manifest:         artifact.Manifest,
		Files:            nil,
		Revision:         artifact.Revision,
		ArtifactHash:     artifact.ArtifactHash,
		CompressedSize:   artifact.CompressedSize,
		UncompressedSize: artifact.UncompressedSize,
		FileCount:        artifact.FileCount,
	}, assignmentForRuntimeArtifactForTest(artifact)); err == nil {
		t.Fatal("install should reject mismatched target before extraction")
	}
}

func TestApplyEdgeRuntimeRemovalDeletesUnusedManagedPSGIBundle(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "psgi", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPSGIRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	writeTestPSGIRuntimeArtifact(t, inventoryPath, "perl538")
	rootDir := psgiRuntimeRootDirFromInventoryPath(inventoryPath)
	bundleDir := filepath.Join(rootDir, "binaries", "perl538")
	runtimeDir := filepath.Join(rootDir, "runtime", "perl538")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "process.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatalf("write runtime manifest: %v", err)
	}
	if err := InitPSGIRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPSGIRuntimeInventoryRuntime: %v", err)
	}

	applyEdgeRuntimeRemoval(edgeRuntimeDeviceAssignment{
		RuntimeFamily: "psgi",
		RuntimeID:     "perl538",
		DesiredState:  "removed",
	})

	if _, err := os.Stat(bundleDir); !os.IsNotExist(err) {
		t.Fatalf("bundle dir stat err=%v, want not exist", err)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir stat err=%v, want not exist", err)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("psgi", "perl538")]
	if status.ApplyState != "removed" || status.ApplyError != "" {
		t.Fatalf("apply status=%+v, want removed without error", status)
	}
	var found bool
	for _, item := range currentEdgeRuntimeInventorySummary() {
		if item.RuntimeFamily == "psgi" && item.RuntimeID == "perl538" {
			found = true
			if item.ApplyState != "removed" {
				t.Fatalf("summary item=%+v, want removed", item)
			}
		}
	}
	if !found {
		t.Fatalf("summary missing virtual PSGI removal: %+v", currentEdgeRuntimeInventorySummary())
	}
	pruneCompletedEdgeRuntimeApplyStatuses(nil)
	for _, item := range currentEdgeRuntimeInventorySummary() {
		if item.RuntimeFamily == "psgi" && item.RuntimeID == "perl538" {
			t.Fatalf("removed virtual runtime should be pruned after Center stops sending assignment: %+v", item)
		}
	}
}

func TestPruneCompletedEdgeRuntimeApplyStatusesKeepsDesiredRemoval(t *testing.T) {
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	setEdgeRuntimeApplyStatus(edgeRuntimeApplyStatus{
		RuntimeFamily: "psgi",
		RuntimeID:     "perl538",
		ApplyState:    "removed",
	})
	pruneCompletedEdgeRuntimeApplyStatuses([]edgeRuntimeDeviceAssignment{
		{
			RuntimeFamily: "psgi",
			RuntimeID:     "perl538",
			DesiredState:  "removed",
		},
	})
	if _, ok := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("psgi", "perl538")]; !ok {
		t.Fatal("removed status should remain while Center still sends the removal assignment")
	}

	pruneCompletedEdgeRuntimeApplyStatuses(nil)
	if _, ok := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("psgi", "perl538")]; ok {
		t.Fatal("removed status should be pruned after Center stops sending the removal assignment")
	}
}

func TestApplyEdgeRuntimeRemovalBlocksReferencedPSGIRuntime(t *testing.T) {
	restoreRuntime := resetPHPFoundationRuntimesForTest(t)
	defer restoreRuntime()
	restoreAssignments := resetEdgeRuntimeAssignmentStateForTest(t)
	defer restoreAssignments()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "psgi", "inventory.json")
	vhostPath := filepath.Join(tmp, "data", "psgi", "vhosts.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir config dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPSGIRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{"vhosts":[{"name":"mt-site","mode":"psgi","hostname":"127.0.0.1","listen_port":19538,"document_root":"data/mt/mt-static","runtime_id":"perl538","app_root":"data/mt/MT","psgi_file":"mt.psgi","generated_target":"mt-psgi"}]}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPSGIRuntimeArtifact(t, inventoryPath, "perl538")
	bundleDir := filepath.Join(psgiRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", "perl538")
	if err := InitPSGIRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPSGIRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	applyEdgeRuntimeRemoval(edgeRuntimeDeviceAssignment{
		RuntimeFamily: "psgi",
		RuntimeID:     "perl538",
		DesiredState:  "removed",
	})

	if _, err := os.Stat(bundleDir); err != nil {
		t.Fatalf("bundle dir should remain: %v", err)
	}
	status := edgeRuntimeApplyStatusSnapshot()[edgeRuntimeAssignmentKey("psgi", "perl538")]
	if status.ApplyState != "blocked" || !strings.Contains(status.ApplyError, "mt-psgi") {
		t.Fatalf("apply status=%+v, want blocked with generated target", status)
	}
}

func TestEdgeDeviceStatusAutoRefreshUploadsRuleArtifactOncePerRevision(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-rule-artifact.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: "rules/tukuyomi.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-1"},
		{Path: "rules/crs/REQUEST-901-INITIALIZATION.conf", Kind: wafRuleAssetKindCRSAsset, Raw: []byte("SecRule ARGS \"@rx test\" \"id:901000,phase:1,pass\"\n"), ETag: "rule-etag-2", Disabled: true},
	}, configVersionSourceImport, "test", "test rule artifact upload", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion: %v", err)
	}

	statusCalls := 0
	snapshotCalls := 0
	artifactCalls := 0
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
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-device-rule","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/rule-artifact-bundle":
			artifactCalls++
			var req edgeRuleArtifactBundleWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode rule artifact: %v", err)
			}
			parsed := verifySignedEdgeRuleArtifactBundleForTest(t, req, capturedPublicKey, capturedFingerprint)
			if parsed.FileCount != 2 || parsed.Files[0].Path != "rules/crs/REQUEST-901-INITIALIZATION.conf" || parsed.Files[0].Disabled ||
				parsed.Files[1].Path != "rules/tukuyomi.conf" || string(parsed.Files[1].Body) != "SecRuleEngine On\n" {
				t.Fatalf("unexpected parsed rule artifact: %+v", parsed)
			}
			_, _ = w.Write([]byte(`{"status":"stored","bundle_revision":` + quoteJSON(req.BundleRevision) + `,"received_at_unix":1700000001}`))
		case "/v1/device-config-snapshot":
			snapshotCalls++
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			if !strings.Contains(string(req.Snapshot), `"bundle_revision"`) {
				t.Fatalf("config snapshot does not reference rule artifact bundle: %s", string(req.Snapshot))
			}
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000002}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-rule","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	status, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background())
	if err != nil {
		t.Fatalf("first autoRefreshEdgeDeviceCenterStatus: %v", err)
	}
	if !attempted {
		t.Fatal("first auto refresh should attempt")
	}
	if artifactCalls != 1 || snapshotCalls != 1 || status.RuleArtifactRevision == "" || status.ConfigSnapshotRevision == "" {
		t.Fatalf("first refresh did not upload artifact and snapshot: artifact=%d snapshot=%d status=%+v", artifactCalls, snapshotCalls, status)
	}

	status, attempted, err = autoRefreshEdgeDeviceCenterStatus(context.Background())
	if err != nil {
		t.Fatalf("second autoRefreshEdgeDeviceCenterStatus: %v", err)
	}
	if !attempted {
		t.Fatal("second auto refresh should attempt")
	}
	if statusCalls != 2 {
		t.Fatalf("statusCalls=%d want 2", statusCalls)
	}
	if artifactCalls != 1 || snapshotCalls != 1 {
		t.Fatalf("unchanged revision should not reupload: artifact=%d snapshot=%d status=%+v", artifactCalls, snapshotCalls, status)
	}
}

func TestApplyEdgeWAFRuleArtifactBundleWritesDBAndReloads(t *testing.T) {
	restoreRules := saveRulesFileConfigForTest()
	defer restoreRules()

	tmp := t.TempDir()
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", tmp)
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false

	dbPath := filepath.Join(tmp, "edge-waf-apply.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 32); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-current"},
	}, configVersionSourceImport, "test", "test WAF apply seed", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion seed: %v", err)
	}

	next, err := edgeartifactbundle.BuildBundle([]edgeartifactbundle.RuleFile{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Body: []byte("SecRuleEngine DetectionOnly\n"), ETag: "rule-etag-next"},
	}, time.Unix(2000, 0).UTC())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	parsed, err := edgeartifactbundle.Parse(next.Compressed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if err := applyEdgeWAFRuleArtifactBundle(parsed); err != nil {
		t.Fatalf("applyEdgeWAFRuleArtifactBundle: %v", err)
	}

	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("loadActiveWAFRuleAssets found=%v err=%v", found, err)
	}
	got, ok := wafRuleAssetMap(assets)[config.DefaultBaseRuleAssetPath]
	if !ok {
		t.Fatalf("missing applied rule asset: %+v", assets)
	}
	if string(got.Raw) != "SecRuleEngine DetectionOnly\n" || got.ETag != "rule-etag-next" {
		t.Fatalf("applied asset mismatch: %+v", got)
	}
	currentRevision, err := currentEdgeWAFRuleBundleRevision()
	if err != nil {
		t.Fatalf("currentEdgeWAFRuleBundleRevision: %v", err)
	}
	if currentRevision != parsed.Revision {
		t.Fatalf("current revision=%s want=%s", currentRevision, parsed.Revision)
	}
}

func TestApplyEdgeWAFRuleAssignmentBlocksStaleBase(t *testing.T) {
	restoreRules := saveRulesFileConfigForTest()
	defer restoreRules()
	restoreWAFState := resetEdgeWAFRuleAssignmentStateForTest(t)
	defer restoreWAFState()

	tmp := t.TempDir()
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", tmp)
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false

	dbPath := filepath.Join(tmp, "edge-waf-stale.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 32); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-current"},
	}, configVersionSourceImport, "test", "test WAF stale seed", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion seed: %v", err)
	}
	currentRevision, err := currentEdgeWAFRuleBundleRevision()
	if err != nil {
		t.Fatalf("currentEdgeWAFRuleBundleRevision: %v", err)
	}

	applyEdgeWAFRuleAssignment(context.Background(), &edgeDeviceIdentityRecord{CenterURL: "http://127.0.0.1"}, &edgeWAFRuleDeviceAssignment{
		BundleRevision:     strings.Repeat("a", 64),
		BaseBundleRevision: strings.Repeat("b", 64),
		CompressedSize:     1,
		UncompressedSize:   1,
		FileCount:          1,
	})

	status := edgeWAFRuleApplyStatusSnapshot()
	if status == nil {
		t.Fatal("expected WAF apply status")
	}
	if status.ApplyState != "blocked" || status.LocalBundleRevision != currentRevision || !strings.Contains(status.ApplyError, "changed after assignment") {
		t.Fatalf("WAF apply status=%+v, want stale-base blocked with current revision %s", status, currentRevision)
	}
}

func TestEdgeDeviceStatusAutoRefreshAppliesWAFRuleAssignment(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()
	restoreRules := saveRulesFileConfigForTest()
	defer restoreRules()
	restoreWAFState := resetEdgeWAFRuleAssignmentStateForTest(t)
	defer restoreWAFState()

	tmp := t.TempDir()
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", tmp)
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false

	dbPath := filepath.Join(tmp, "edge-waf-polling.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 32); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-current"},
	}, configVersionSourceImport, "test", "test WAF polling seed", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion seed: %v", err)
	}
	baseRevision, err := currentEdgeWAFRuleBundleRevision()
	if err != nil {
		t.Fatalf("currentEdgeWAFRuleBundleRevision: %v", err)
	}
	next, err := edgeartifactbundle.BuildBundle([]edgeartifactbundle.RuleFile{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Body: []byte("SecRuleEngine DetectionOnly\n"), ETag: "rule-etag-next"},
	}, time.Unix(0, 0).UTC())
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}

	statusCalls := 0
	downloadCalls := 0
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
			if statusCalls == 2 {
				if req.WAFRuleApplyStatus == nil || req.WAFRuleApplyStatus.ApplyState != "applied" || req.WAFRuleApplyStatus.LocalBundleRevision != next.Revision {
					t.Fatalf("second status missing WAF applied report: %+v", req.WAFRuleApplyStatus)
				}
			}
			if statusCalls == 1 {
				_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-waf-device","key_id":"default","product_id":"product-a","checked_at_unix":1700000000,"waf_rule_assignment":{"bundle_revision":` +
					quoteJSON(next.Revision) + `,"base_bundle_revision":` + quoteJSON(baseRevision) + `,"compressed_size":` + strconv.FormatInt(next.CompressedSize, 10) +
					`,"uncompressed_size":` + strconv.FormatInt(next.UncompressedSize, 10) + `,"file_count":` + strconv.Itoa(next.FileCount) + `,"assigned_at_unix":1700000000}}`))
				return
			}
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-waf-device","key_id":"default","product_id":"product-a","checked_at_unix":1700000001}`))
		case "/v1/waf-rule-artifact-download":
			downloadCalls++
			var req edgeWAFRuleArtifactDownloadWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode WAF artifact download: %v", err)
			}
			verifySignedEdgeWAFRuleArtifactDownloadForTest(t, req, capturedPublicKey, capturedFingerprint)
			if req.BundleRevision != next.Revision {
				t.Fatalf("download revision=%s want=%s", req.BundleRevision, next.Revision)
			}
			w.Header().Set("Content-Type", "application/gzip")
			_, _ = w.Write(next.Compressed)
		case "/v1/device-config-snapshot":
			snapshotCalls++
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			if !strings.Contains(string(req.Snapshot), next.Revision) {
				t.Fatalf("config snapshot does not reference applied WAF bundle: %s", string(req.Snapshot))
			}
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000002}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-waf-device","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	if _, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background()); err != nil || !attempted {
		t.Fatalf("first autoRefreshEdgeDeviceCenterStatus attempted=%v err=%v", attempted, err)
	}
	if downloadCalls != 1 || snapshotCalls != 1 {
		t.Fatalf("first refresh download=%d snapshot=%d want 1 each", downloadCalls, snapshotCalls)
	}
	status := edgeWAFRuleApplyStatusSnapshot()
	if status == nil || status.ApplyState != "applied" || status.LocalBundleRevision != next.Revision {
		t.Fatalf("WAF apply status after first refresh=%+v", status)
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("loadActiveWAFRuleAssets found=%v err=%v", found, err)
	}
	got, ok := wafRuleAssetMap(assets)[config.DefaultBaseRuleAssetPath]
	if !ok || string(got.Raw) != "SecRuleEngine DetectionOnly\n" {
		t.Fatalf("applied WAF asset mismatch ok=%v asset=%+v assets=%+v", ok, got, assets)
	}

	if _, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background()); err != nil || !attempted {
		t.Fatalf("second autoRefreshEdgeDeviceCenterStatus attempted=%v err=%v", attempted, err)
	}
	if statusCalls != 2 {
		t.Fatalf("statusCalls=%d want 2", statusCalls)
	}
	if status := edgeWAFRuleApplyStatusSnapshot(); status != nil {
		t.Fatalf("terminal WAF status should be pruned after report: %+v", status)
	}
}

func TestEdgeDeviceStatusRefreshSerializesConcurrentArtifactUploads(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-rule-artifact-concurrent.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: "rules/tukuyomi.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-1"},
	}, configVersionSourceImport, "test", "test concurrent rule artifact upload", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion: %v", err)
	}

	var statusCalls int32
	var snapshotCalls int32
	var artifactCalls int32
	artifactStarted := make(chan struct{})
	releaseArtifact := make(chan struct{})
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
			atomic.AddInt32(&statusCalls, 1)
			var req edgeDeviceStatusWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode status: %v", err)
			}
			verifySignedEdgeStatusForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-device-rule","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/rule-artifact-bundle":
			if atomic.AddInt32(&artifactCalls, 1) == 1 {
				close(artifactStarted)
				<-releaseArtifact
			}
			var req edgeRuleArtifactBundleWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode rule artifact: %v", err)
			}
			parsed := verifySignedEdgeRuleArtifactBundleForTest(t, req, capturedPublicKey, capturedFingerprint)
			if parsed.FileCount != 1 {
				t.Fatalf("file_count=%d want 1", parsed.FileCount)
			}
			_, _ = w.Write([]byte(`{"status":"stored","bundle_revision":` + quoteJSON(req.BundleRevision) + `,"received_at_unix":1700000001}`))
		case "/v1/device-config-snapshot":
			atomic.AddInt32(&snapshotCalls, 1)
			var req edgeDeviceConfigSnapshotWireRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode config snapshot: %v", err)
			}
			verifySignedEdgeConfigSnapshotForTest(t, req, capturedPublicKey, capturedFingerprint)
			_, _ = w.Write([]byte(`{"status":"stored","config_revision":` + quoteJSON(req.ConfigRevision) + `,"received_at_unix":1700000002}`))
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-rule","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	refreshDone := make(chan error, 2)
	runRefresh := func() {
		status, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background())
		if err != nil {
			refreshDone <- err
			return
		}
		if !attempted {
			refreshDone <- errors.New("refresh was not attempted")
			return
		}
		if status.EnrollmentStatus != edgeEnrollmentStatusApproved {
			refreshDone <- fmt.Errorf("status=%s want approved", status.EnrollmentStatus)
			return
		}
		refreshDone <- nil
	}
	go runRefresh()
	select {
	case <-artifactStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("first refresh did not start artifact upload")
	}
	go runRefresh()
	time.Sleep(50 * time.Millisecond)
	if got := atomic.LoadInt32(&statusCalls); got != 1 {
		t.Fatalf("concurrent refresh should wait for the active refresh, statusCalls=%d", got)
	}
	if got := atomic.LoadInt32(&artifactCalls); got != 1 {
		t.Fatalf("concurrent refresh duplicated artifact upload, artifactCalls=%d", got)
	}
	close(releaseArtifact)
	for i := 0; i < 2; i++ {
		select {
		case err := <-refreshDone:
			if err != nil {
				t.Fatalf("refresh %d: %v", i+1, err)
			}
		case <-time.After(2 * time.Second):
			t.Fatalf("refresh %d did not finish", i+1)
		}
	}
	if got := atomic.LoadInt32(&artifactCalls); got != 1 {
		t.Fatalf("artifactCalls=%d want 1", got)
	}
	if got := atomic.LoadInt32(&snapshotCalls); got != 1 {
		t.Fatalf("snapshotCalls=%d want 1", got)
	}
}

func TestEdgeDeviceStatusRefreshSkipsConfigSnapshotWhenRuleArtifactFails(t *testing.T) {
	gin.SetMode(gin.TestMode)
	restoreEdgeRuntime := setEdgeRuntimeForTest(true, true)
	defer restoreEdgeRuntime()

	dbPath := filepath.Join(t.TempDir(), "edge-device-rule-artifact-failure.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer InitLogsStatsStore(false, "", 0)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("store is nil")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: "rules/tukuyomi.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n"), ETag: "rule-etag-1"},
	}, configVersionSourceImport, "test", "test failed rule artifact upload", 0); err != nil {
		t.Fatalf("writeWAFRuleAssetsVersion: %v", err)
	}

	var snapshotCalls int32
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
			_, _ = w.Write([]byte(`{"status":"approved","device_id":"edge-device-rule","key_id":"default","product_id":"product-a","checked_at_unix":1700000000}`))
		case "/v1/rule-artifact-bundle":
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"error":"rule artifact store unavailable"}`))
		case "/v1/device-config-snapshot":
			atomic.AddInt32(&snapshotCalls, 1)
			w.WriteHeader(http.StatusInternalServerError)
		default:
			t.Fatalf("path=%q", r.URL.Path)
		}
	}))
	defer center.Close()

	router := gin.New()
	router.POST("/edge/device-auth/enroll", PostEdgeDeviceEnrollment)

	body := `{"center_url":` + quoteJSON(center.URL) + `,"enrollment_token":"tky_enroll_test","device_id":"edge-device-rule","key_id":"default"}`
	rec := performEdgeDeviceRequest(router, http.MethodPost, "/edge/device-auth/enroll", body)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("enroll code=%d body=%s", rec.Code, rec.Body.String())
	}

	status, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background())
	if err != nil {
		t.Fatalf("autoRefreshEdgeDeviceCenterStatus: %v", err)
	}
	if !attempted {
		t.Fatal("refresh should attempt")
	}
	if status.RuleArtifactError == "" {
		t.Fatalf("rule artifact failure was not recorded: %+v", status)
	}
	if status.ConfigSnapshotRevision != "" || atomic.LoadInt32(&snapshotCalls) != 0 {
		t.Fatalf("config snapshot should wait for accepted rule artifact: snapshotCalls=%d status=%+v", snapshotCalls, status)
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

func TestEdgeProxyRuleAssignmentBaseMatchesSameContentGeneration(t *testing.T) {
	if !edgeProxyRuleAssignmentBaseMatches(
		"proxy:23:2a652ffdf1c197900c218af0ee3001e096c95f",
		"proxy:21:2a652ffdf1c197900c218af0ee3001e096c95f",
	) {
		t.Fatal("same proxy content hash across generations should match")
	}
	if edgeProxyRuleAssignmentBaseMatches(
		"proxy:23:2a652ffdf1c197900c218af0ee3001e096c95f",
		"proxy:21:different",
	) {
		t.Fatal("different proxy content hash should not match")
	}
	if edgeProxyRuleAssignmentBaseMatches("", "proxy:21:2a652ffdf1c197900c218af0ee3001e096c95f") {
		t.Fatal("empty current etag should not match")
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

func verifySignedEdgeRuleArtifactBundleForTest(t *testing.T, req edgeRuleArtifactBundleWireRequest, pub ed25519.PublicKey, fingerprint string) edgeartifactbundle.Parsed {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key was not captured")
	}
	if req.BodyHash != edgeRuleArtifactBundleBodyHash(req) {
		t.Fatalf("rule artifact body_hash mismatch")
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		t.Fatalf("fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, fingerprint)
	}
	bundle, err := base64.StdEncoding.DecodeString(req.BundleB64)
	if err != nil {
		t.Fatalf("rule artifact bundle b64: %v", err)
	}
	sum := sha256.Sum256(bundle)
	if hex.EncodeToString(sum[:]) != req.BundleHash {
		t.Fatalf("rule artifact bundle_hash mismatch")
	}
	parsed, err := edgeartifactbundle.Parse(bundle)
	if err != nil {
		t.Fatalf("parse rule artifact bundle: %v", err)
	}
	if parsed.Revision != req.BundleRevision {
		t.Fatalf("rule artifact revision=%q want %q", parsed.Revision, req.BundleRevision)
	}
	if parsed.BundleHash != req.BundleHash {
		t.Fatalf("parsed bundle_hash=%q want %q", parsed.BundleHash, req.BundleHash)
	}
	if parsed.CompressedSize != req.CompressedSize {
		t.Fatalf("compressed_size=%d want %d", parsed.CompressedSize, req.CompressedSize)
	}
	if parsed.UncompressedSize != req.UncompressedSize {
		t.Fatalf("uncompressed_size=%d want %d", parsed.UncompressedSize, req.UncompressedSize)
	}
	if parsed.FileCount != req.FileCount {
		t.Fatalf("file_count=%d want %d", parsed.FileCount, req.FileCount)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("rule artifact signature verification failed")
	}
	return parsed
}

func verifySignedEdgeRuntimeArtifactDownloadForTest(t *testing.T, req edgeRuntimeArtifactDownloadWireRequest, pub ed25519.PublicKey, fingerprint string) {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key was not captured")
	}
	if req.BodyHash != edgeRuntimeArtifactDownloadBodyHash(req) {
		t.Fatalf("runtime artifact download body_hash mismatch")
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		t.Fatalf("fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, fingerprint)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("runtime artifact download signature verification failed")
	}
}

func verifySignedEdgeWAFRuleArtifactDownloadForTest(t *testing.T, req edgeWAFRuleArtifactDownloadWireRequest, pub ed25519.PublicKey, fingerprint string) {
	t.Helper()
	if len(pub) != ed25519.PublicKeySize {
		t.Fatalf("public key was not captured")
	}
	if req.BodyHash != edgeWAFRuleArtifactDownloadBodyHash(req) {
		t.Fatalf("WAF rule artifact download body_hash mismatch")
	}
	if req.PublicKeyFingerprintSHA256 != fingerprint {
		t.Fatalf("fingerprint=%q want %q", req.PublicKeyFingerprintSHA256, fingerprint)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil {
		t.Fatalf("signature b64: %v", err)
	}
	if !ed25519.Verify(pub, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		t.Fatalf("WAF rule artifact download signature verification failed")
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

func resetEdgeRuntimeAssignmentStateForTest(t *testing.T) func() {
	t.Helper()

	edgeRuntimeAssignmentMu.Lock()
	prevActive := edgeRuntimeAssignmentActive
	edgeRuntimeAssignmentActive = map[string]struct{}{}
	edgeRuntimeAssignmentMu.Unlock()

	edgeRuntimeApplyStatusMu.Lock()
	prevStatuses := edgeRuntimeApplyStatuses
	edgeRuntimeApplyStatuses = map[string]edgeRuntimeApplyStatus{}
	edgeRuntimeApplyStatusMu.Unlock()

	return func() {
		edgeRuntimeAssignmentMu.Lock()
		edgeRuntimeAssignmentActive = prevActive
		edgeRuntimeAssignmentMu.Unlock()

		edgeRuntimeApplyStatusMu.Lock()
		edgeRuntimeApplyStatuses = prevStatuses
		edgeRuntimeApplyStatusMu.Unlock()
	}
}

func resetEdgeWAFRuleAssignmentStateForTest(t *testing.T) func() {
	t.Helper()

	edgeWAFRuleAssignmentMu.Lock()
	prevActive := edgeWAFRuleAssignmentActive
	edgeWAFRuleAssignmentActive = false
	edgeWAFRuleAssignmentMu.Unlock()

	edgeWAFRuleApplyStatusMu.Lock()
	prevStatus := edgeWAFRuleApplyStatusCurrent
	edgeWAFRuleApplyStatusCurrent = nil
	edgeWAFRuleApplyStatusMu.Unlock()

	return func() {
		edgeWAFRuleAssignmentMu.Lock()
		edgeWAFRuleAssignmentActive = prevActive
		edgeWAFRuleAssignmentMu.Unlock()

		edgeWAFRuleApplyStatusMu.Lock()
		edgeWAFRuleApplyStatusCurrent = prevStatus
		edgeWAFRuleApplyStatusMu.Unlock()
	}
}

func newEdgeDeviceIdentityForTest(t *testing.T) edgeDeviceIdentityRecord {
	t.Helper()
	identity, err := newEdgeDeviceIdentity("edge-runtime-install", "default")
	if err != nil {
		t.Fatalf("newEdgeDeviceIdentity: %v", err)
	}
	return identity
}

func publicKeyFromEdgeIdentityForTest(t *testing.T, identity edgeDeviceIdentityRecord) ed25519.PublicKey {
	t.Helper()
	_, publicDER, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		t.Fatalf("parseEdgeDevicePrivateKey: %v", err)
	}
	publicAny, err := x509.ParsePKIXPublicKey(publicDER)
	if err != nil {
		t.Fatalf("parse public key: %v", err)
	}
	publicKey, ok := publicAny.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("public key is not Ed25519")
	}
	return publicKey
}

func buildGatewayRuntimeArtifactForTest(t *testing.T, runtimeID string) runtimeartifactbundle.Build {
	t.Helper()
	platform := currentEdgeGatewayPlatformMetadata()
	if platform.OS != "linux" || platform.Arch == "" || platform.DistroID == "" || platform.DistroVersion == "" {
		t.Skipf("runtime artifact install test requires linux platform metadata, got %+v", platform)
	}
	build, err := runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   runtimeartifactbundle.RuntimeFamilyPHPFPM,
		RuntimeID:       runtimeID,
		DisplayName:     defaultDisplayNameForRuntimeID(runtimeID),
		DetectedVersion: "8.3.30",
		Target: runtimeartifactbundle.TargetKey{
			OS:            platform.OS,
			Arch:          platform.Arch,
			KernelVersion: platform.KernelVersion,
			DistroID:      platform.DistroID,
			DistroIDLike:  platform.DistroIDLike,
			DistroVersion: platform.DistroVersion,
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "test-profile",
		GeneratedAt:    time.Unix(1000, 0).UTC(),
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"` + runtimeID + `","display_name":"` + defaultDisplayNameForRuntimeID(runtimeID) + `","detected_version":"8.3.30","binary_path":"data/php-fpm/binaries/` + runtimeID + `/php-fpm","cli_binary_path":"data/php-fpm/binaries/` + runtimeID + `/php","source":"center"}`),
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
	return build
}

func buildGatewayPSGIRuntimeArtifactForTest(t *testing.T, runtimeID string) runtimeartifactbundle.Build {
	t.Helper()
	platform := currentEdgeGatewayPlatformMetadata()
	if platform.OS != "linux" || platform.Arch == "" || platform.DistroID == "" || platform.DistroVersion == "" {
		t.Skipf("runtime artifact install test requires linux platform metadata, got %+v", platform)
	}
	build, err := runtimeartifactbundle.BuildBundle(runtimeartifactbundle.BuildInput{
		RuntimeFamily:   runtimeartifactbundle.RuntimeFamilyPSGI,
		RuntimeID:       runtimeID,
		DisplayName:     defaultDisplayNameForPSGIRuntimeID(runtimeID),
		DetectedVersion: "v5.38.5",
		Target: runtimeartifactbundle.TargetKey{
			OS:            platform.OS,
			Arch:          platform.Arch,
			KernelVersion: platform.KernelVersion,
			DistroID:      platform.DistroID,
			DistroIDLike:  platform.DistroIDLike,
			DistroVersion: platform.DistroVersion,
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "test-profile",
		GeneratedAt:    time.Unix(1000, 0).UTC(),
		Files: []runtimeartifactbundle.File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"` + runtimeID + `","display_name":"` + defaultDisplayNameForPSGIRuntimeID(runtimeID) + `","detected_version":"v5.38.5","perl_path":"data/psgi/binaries/` + runtimeID + `/perl","starman_path":"data/psgi/binaries/` + runtimeID + `/starman","source":"center"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["plack","starman"]`)},
			{ArchivePath: "perl", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "starman", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/bin/perl", FileKind: "rootfs", Mode: 0o755, Body: []byte("perl-binary")},
			{ArchivePath: "rootfs/usr/bin/starman", FileKind: "rootfs", Mode: 0o755, Body: []byte("starman-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
		},
	})
	if err != nil {
		t.Fatalf("build PSGI runtime artifact: %v", err)
	}
	return build
}

func assignmentForRuntimeArtifactForTest(artifact runtimeartifactbundle.Build) edgeRuntimeDeviceAssignment {
	return edgeRuntimeDeviceAssignment{
		RuntimeFamily:    artifact.Manifest.RuntimeFamily,
		RuntimeID:        artifact.Manifest.RuntimeID,
		ArtifactRevision: artifact.Revision,
		ArtifactHash:     artifact.ArtifactHash,
		CompressedSize:   artifact.CompressedSize,
		UncompressedSize: artifact.UncompressedSize,
		FileCount:        artifact.FileCount,
		DetectedVersion:  artifact.Manifest.DetectedVersion,
		DesiredState:     "installed",
		AssignedAtUnix:   time.Now().UTC().Unix(),
	}
}

func writeTestPSGIRuntimeArtifact(t *testing.T, inventoryPath string, runtimeID string) {
	t.Helper()

	runtimeDir := filepath.Join(psgiRuntimeRootDirFromInventoryPath(inventoryPath), "binaries", runtimeID)
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir psgi runtime dir: %v", err)
	}
	for _, name := range []string{"perl", "starman"} {
		if err := os.WriteFile(filepath.Join(runtimeDir, name), []byte("#!/bin/sh\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	modulesRaw, err := json.Marshal([]string{"plack", "starman"})
	if err != nil {
		t.Fatalf("marshal psgi modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "modules.json"), append(modulesRaw, '\n'), 0o600); err != nil {
		t.Fatalf("write modules.json: %v", err)
	}
	manifest := psgiRuntimeArtifactManifest{
		RuntimeID:       runtimeID,
		DisplayName:     defaultDisplayNameForPSGIRuntimeID(runtimeID),
		DetectedVersion: "v5.38.5",
		PerlPath:        filepath.ToSlash(filepath.Join(runtimeDir, "perl")),
		StarmanPath:     filepath.ToSlash(filepath.Join(runtimeDir, "starman")),
		Source:          "bundled",
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		t.Fatalf("marshal psgi manifest: %v", err)
	}
	if err := os.WriteFile(filepath.Join(runtimeDir, "runtime.json"), append(manifestRaw, '\n'), 0o600); err != nil {
		t.Fatalf("write runtime.json: %v", err)
	}
}

func quoteJSON(value string) string {
	raw, _ := json.Marshal(value)
	return string(raw)
}
