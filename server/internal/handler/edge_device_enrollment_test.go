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
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
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

func TestApplyEdgeRuntimeRemovalDeletesUnusedManagedPHPBundle(t *testing.T) {
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
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
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
