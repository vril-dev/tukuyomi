package handler

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	goruntime "runtime"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/edgeconfigsnapshot"
)

const (
	edgeDeviceIdentityID        = int64(1)
	edgeEnrollmentTokenMaxBytes = 256
	edgeEnrollmentHTTPTimeout   = 10 * time.Second
)

const (
	edgeEnrollmentStatusApproved     = "approved"
	edgeEnrollmentStatusArchived     = "archived"
	edgeEnrollmentStatusFailed       = "failed"
	edgeEnrollmentStatusLocal        = "local"
	edgeEnrollmentStatusPending      = "pending"
	edgeEnrollmentStatusProductShift = "product_changed"
	edgeEnrollmentStatusRevoked      = "revoked"
	edgeEnrollmentStatusUnconfigured = "unconfigured"

	edgeProxyLockReasonAuthDisabled    = "device_auth_disabled"
	edgeProxyLockReasonIdentityMissing = "identity_unconfigured"
	edgeProxyLockReasonNotApproved     = "device_not_approved"
	edgeProxyLockReasonStoreError      = "store_error"
	edgeProxyLockReasonStoreMissing    = "store_unavailable"
)

var (
	edgeDeviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	edgeKeyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

	errEdgeDeviceIdentityNotFound = errors.New("edge device identity not found")

	edgeDeviceStatusRefreshTriggerMu sync.RWMutex
	edgeDeviceStatusRefreshTrigger   chan struct{}
	edgeDeviceCenterRefreshMu        sync.Mutex

	edgeRuleArtifactUploadMu       sync.Mutex
	edgeRuleArtifactUploadRevision string
)

type edgeDeviceIdentityRecord struct {
	DeviceID                   string
	KeyID                      string
	PrivateKeyPEM              string
	PublicKeyFingerprintSHA256 string
	EnrollmentStatus           string
	CenterURL                  string
	CenterProductID            string
	CenterStatusCheckedAtUnix  int64
	CenterStatusError          string
	ConfigSnapshotRevision     string
	ConfigSnapshotPushedAtUnix int64
	ConfigSnapshotError        string
	RuleArtifactRevision       string
	RuleArtifactPushedAtUnix   int64
	RuleArtifactError          string
	LastEnrollmentAtUnix       int64
	LastEnrollmentError        string
	CreatedAtUnix              int64
	UpdatedAtUnix              int64
}

type edgeDeviceAuthStatusResponse struct {
	StoreAvailable             bool   `json:"store_available"`
	EdgeEnabled                bool   `json:"edge_enabled"`
	DeviceAuthEnabled          bool   `json:"device_auth_enabled"`
	RequireDeviceApproval      bool   `json:"require_device_approval"`
	ProxyLocked                bool   `json:"proxy_locked"`
	ProxyLockReason            string `json:"proxy_lock_reason"`
	IdentityConfigured         bool   `json:"identity_configured"`
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	EnrollmentStatus           string `json:"enrollment_status"`
	CenterURL                  string `json:"center_url"`
	CenterProductID            string `json:"center_product_id"`
	CenterStatusCheckedAtUnix  int64  `json:"center_status_checked_at_unix"`
	CenterStatusError          string `json:"center_status_error"`
	ConfigSnapshotRevision     string `json:"config_snapshot_revision"`
	ConfigSnapshotPushedAtUnix int64  `json:"config_snapshot_pushed_at_unix"`
	ConfigSnapshotError        string `json:"config_snapshot_error"`
	RuleArtifactRevision       string `json:"rule_artifact_revision"`
	RuleArtifactPushedAtUnix   int64  `json:"rule_artifact_pushed_at_unix"`
	RuleArtifactError          string `json:"rule_artifact_error"`
	LastEnrollmentAtUnix       int64  `json:"last_enrollment_at_unix"`
	LastEnrollmentError        string `json:"last_enrollment_error"`
}

type edgeDeviceEnrollmentRequest struct {
	CenterURL       string `json:"center_url"`
	EnrollmentToken string `json:"enrollment_token"`
	DeviceID        string `json:"device_id"`
	KeyID           string `json:"key_id"`
}

type edgeDeviceEnrollmentWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyPEMB64            string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type edgeDeviceStatusWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	RuntimeRole                string `json:"runtime_role,omitempty"`
	BuildVersion               string `json:"build_version,omitempty"`
	GoVersion                  string `json:"go_version,omitempty"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type edgeDeviceConfigSnapshotWireRequest struct {
	DeviceID                   string          `json:"device_id"`
	KeyID                      string          `json:"key_id"`
	PublicKeyFingerprintSHA256 string          `json:"public_key_fingerprint_sha256"`
	Timestamp                  string          `json:"timestamp"`
	Nonce                      string          `json:"nonce"`
	ConfigRevision             string          `json:"config_revision"`
	PayloadHash                string          `json:"payload_hash"`
	BodyHash                   string          `json:"body_hash"`
	SignatureB64               string          `json:"signature_b64"`
	Snapshot                   json.RawMessage `json:"snapshot"`
}

type edgeRuleArtifactBundleWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BundleRevision             string `json:"bundle_revision"`
	BundleHash                 string `json:"bundle_hash"`
	CompressedSize             int64  `json:"compressed_size"`
	UncompressedSize           int64  `json:"uncompressed_size"`
	FileCount                  int    `json:"file_count"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
	BundleB64                  string `json:"bundle_b64"`
}

type edgeDeviceCenterStatusResponse struct {
	Status        string `json:"status"`
	DeviceID      string `json:"device_id"`
	KeyID         string `json:"key_id"`
	ProductID     string `json:"product_id"`
	CheckedAtUnix int64  `json:"checked_at_unix"`
}

type edgeDeviceConfigSnapshotResponse struct {
	Status         string `json:"status"`
	ConfigRevision string `json:"config_revision"`
	ReceivedAtUnix int64  `json:"received_at_unix"`
}

type edgeRuleArtifactBundleResponse struct {
	Status         string `json:"status"`
	BundleRevision string `json:"bundle_revision"`
	ReceivedAtUnix int64  `json:"received_at_unix"`
}

type edgeProxyGateState struct {
	Locked bool
	Reason string
}

func GetEdgeDeviceAuthStatus(c *gin.Context) {
	status, err := currentEdgeDeviceAuthStatus()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load edge device identity"})
		return
	}
	c.JSON(http.StatusOK, status)
}

func PostEdgeDeviceStatusRefresh(c *gin.Context) {
	status, err := refreshEdgeDeviceCenterStatus(c.Request.Context())
	if err != nil {
		respondEdgeDeviceEnrollmentError(c, err)
		return
	}
	c.JSON(http.StatusOK, status)
}

func PostEdgeDeviceEnrollment(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 8*1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req edgeDeviceEnrollmentRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid enrollment request"})
		return
	}

	status, err := enrollEdgeDevice(c.Request.Context(), req)
	if err != nil {
		respondEdgeDeviceEnrollmentError(c, err)
		return
	}
	c.JSON(http.StatusAccepted, status)
}

func StartEdgeDeviceStatusRefreshLoop(interval time.Duration) {
	if interval <= 0 || !config.EdgeEnabled || !config.EdgeDeviceAuthEnabled {
		return
	}
	trigger := make(chan struct{}, 1)
	edgeDeviceStatusRefreshTriggerMu.Lock()
	edgeDeviceStatusRefreshTrigger = trigger
	edgeDeviceStatusRefreshTriggerMu.Unlock()
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		log.Printf("[EDGE][DEVICE] center status refresh loop enabled interval=%s", interval)
		lastError := ""
		lastStatus := ""
		refresh := func() {
			status, attempted, err := autoRefreshEdgeDeviceCenterStatus(context.Background())
			if !attempted {
				return
			}
			if err != nil {
				msg := strings.TrimSpace(err.Error())
				if msg != "" && msg != lastError {
					log.Printf("[EDGE][DEVICE][WARN] center status refresh failed: %s", msg)
					lastError = msg
				}
				return
			}
			lastError = ""
			if status.EnrollmentStatus != "" && status.EnrollmentStatus != lastStatus {
				log.Printf("[EDGE][DEVICE] center status=%s proxy_locked=%t", status.EnrollmentStatus, status.ProxyLocked)
				lastStatus = status.EnrollmentStatus
			}
		}
		refresh()
		for {
			select {
			case <-ticker.C:
				refresh()
			case <-trigger:
				refresh()
			}
		}
	}()
}

func TriggerEdgeDeviceStatusRefresh() {
	edgeDeviceStatusRefreshTriggerMu.RLock()
	trigger := edgeDeviceStatusRefreshTrigger
	edgeDeviceStatusRefreshTriggerMu.RUnlock()
	if trigger == nil {
		return
	}
	select {
	case trigger <- struct{}{}:
	default:
	}
}

func currentEdgeDeviceAuthStatus() (edgeDeviceAuthStatusResponse, error) {
	status := edgeDeviceAuthStatusResponse{
		StoreAvailable:        getLogsStatsStore() != nil,
		EdgeEnabled:           config.EdgeEnabled,
		DeviceAuthEnabled:     config.EdgeDeviceAuthEnabled,
		RequireDeviceApproval: config.EdgeRequireDeviceApproval,
		EnrollmentStatus:      edgeEnrollmentStatusUnconfigured,
	}
	store := getLogsStatsStore()
	if store == nil {
		applyEdgeProxyGateStatus(&status)
		return status, nil
	}
	rec, found, err := loadEdgeDeviceIdentity(store)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	if !found {
		applyEdgeProxyGateStatus(&status)
		return status, nil
	}
	status.IdentityConfigured = true
	status.DeviceID = rec.DeviceID
	status.KeyID = rec.KeyID
	status.PublicKeyFingerprintSHA256 = rec.PublicKeyFingerprintSHA256
	status.EnrollmentStatus = rec.EnrollmentStatus
	status.CenterURL = rec.CenterURL
	status.CenterProductID = rec.CenterProductID
	status.CenterStatusCheckedAtUnix = rec.CenterStatusCheckedAtUnix
	status.CenterStatusError = rec.CenterStatusError
	status.ConfigSnapshotRevision = rec.ConfigSnapshotRevision
	status.ConfigSnapshotPushedAtUnix = rec.ConfigSnapshotPushedAtUnix
	status.ConfigSnapshotError = rec.ConfigSnapshotError
	status.RuleArtifactRevision = rec.RuleArtifactRevision
	status.RuleArtifactPushedAtUnix = rec.RuleArtifactPushedAtUnix
	status.RuleArtifactError = rec.RuleArtifactError
	status.LastEnrollmentAtUnix = rec.LastEnrollmentAtUnix
	status.LastEnrollmentError = rec.LastEnrollmentError
	applyEdgeProxyGateStatus(&status)
	return status, nil
}

func enrollEdgeDevice(ctx context.Context, req edgeDeviceEnrollmentRequest) (edgeDeviceAuthStatusResponse, error) {
	if !config.EdgeEnabled || !config.EdgeDeviceAuthEnabled {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusConflict, message: "edge device authentication is not enabled in the running process"}
	}
	store := getLogsStatsStore()
	if store == nil {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusServiceUnavailable, message: "runtime DB store is not initialized"}
	}
	centerBaseURL, enrollURL, err := normalizeCenterEnrollmentURL(req.CenterURL)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadRequest, message: err.Error()}
	}
	token := strings.TrimSpace(req.EnrollmentToken)
	if token == "" {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadRequest, message: "enrollment token is required"}
	}
	if len(token) > edgeEnrollmentTokenMaxBytes {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadRequest, message: "enrollment token is too long"}
	}

	identity, err := prepareEdgeDeviceIdentity(store, req)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	if !edgeCanRequestEnrollment(identity.EnrollmentStatus) {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusConflict, message: edgeEnrollmentBlockedMessage(identity.EnrollmentStatus)}
	}

	wireReq, err := signedEdgeDeviceEnrollmentRequest(identity)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	centerStatus, centerBody, err := sendEdgeDeviceEnrollment(ctx, enrollURL, token, wireReq)
	now := time.Now().UTC().Unix()
	identity.CenterURL = centerBaseURL
	identity.LastEnrollmentAtUnix = now
	identity.UpdatedAtUnix = now
	if err != nil {
		identity.EnrollmentStatus = edgeEnrollmentStatusFailed
		identity.LastEnrollmentError = clampEdgeText(err.Error(), 4096)
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: err.Error()}
	}
	if centerStatus < 200 || centerStatus >= 300 {
		message := centerEnrollmentErrorMessage(centerStatus, centerBody)
		identity.EnrollmentStatus = edgeEnrollmentStatusFailed
		identity.LastEnrollmentError = clampEdgeText(message, 4096)
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: message}
	}
	identity.EnrollmentStatus = edgeEnrollmentStatusPending
	identity.LastEnrollmentError = ""
	identity.CenterStatusError = ""
	if err := upsertEdgeDeviceIdentity(store, identity); err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	TriggerEdgeDeviceStatusRefresh()
	return edgeDeviceStatusFromIdentity(identity), nil
}

func refreshEdgeDeviceCenterStatus(ctx context.Context) (edgeDeviceAuthStatusResponse, error) {
	edgeDeviceCenterRefreshMu.Lock()
	defer edgeDeviceCenterRefreshMu.Unlock()

	if !config.EdgeEnabled || !config.EdgeDeviceAuthEnabled {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusConflict, message: "edge device authentication is not enabled in the running process"}
	}
	store := getLogsStatsStore()
	if store == nil {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusServiceUnavailable, message: "runtime DB store is not initialized"}
	}
	identity, found, err := loadEdgeDeviceIdentity(store)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	if !found {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusConflict, message: "local device identity is not configured"}
	}
	if strings.TrimSpace(identity.CenterURL) == "" {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusConflict, message: "center URL is not configured"}
	}
	statusURL, err := centerDeviceStatusURL(identity.CenterURL)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadRequest, message: err.Error()}
	}
	wireReq, err := signedEdgeDeviceStatusRequest(identity)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	centerHTTPStatus, centerBody, err := sendEdgeDeviceStatus(ctx, statusURL, wireReq)
	now := time.Now().UTC().Unix()
	identity.UpdatedAtUnix = now
	identity.CenterStatusCheckedAtUnix = now
	if err != nil {
		identity.CenterStatusError = clampEdgeText(err.Error(), 4096)
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: err.Error()}
	}
	if centerHTTPStatus < 200 || centerHTTPStatus >= 300 {
		message := centerEnrollmentErrorMessage(centerHTTPStatus, centerBody)
		identity.CenterStatusError = clampEdgeText(message, 4096)
		if centerHTTPStatus == http.StatusNotFound {
			identity.EnrollmentStatus = edgeEnrollmentStatusUnconfigured
		} else if centerHTTPStatus >= 400 && centerHTTPStatus < 500 {
			identity.EnrollmentStatus = edgeEnrollmentStatusFailed
		}
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: message}
	}
	var payload edgeDeviceCenterStatusResponse
	if err := json.Unmarshal(centerBody, &payload); err != nil {
		identity.CenterStatusError = "center status response is invalid JSON"
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: "center status response is invalid JSON"}
	}
	nextStatus := normalizeEdgeStatus(payload.Status)
	if nextStatus == "" {
		identity.CenterStatusError = "center status response is missing status"
		if updateErr := upsertEdgeDeviceIdentity(store, identity); updateErr != nil {
			return edgeDeviceAuthStatusResponse{}, updateErr
		}
		return edgeDeviceAuthStatusResponse{}, edgeEnrollmentError{status: http.StatusBadGateway, message: "center status response is missing status"}
	}
	identity.EnrollmentStatus = nextStatus
	identity.CenterProductID = clampEdgeText(payload.ProductID, 191)
	identity.CenterStatusError = ""
	if identity.EnrollmentStatus == edgeEnrollmentStatusApproved {
		if pushEdgeRuleArtifactBundleIfChanged(ctx, &identity) {
			pushEdgeConfigSnapshotIfChanged(ctx, &identity)
		}
	}
	if err := upsertEdgeDeviceIdentity(store, identity); err != nil {
		return edgeDeviceAuthStatusResponse{}, err
	}
	return edgeDeviceStatusFromIdentity(identity), nil
}

func autoRefreshEdgeDeviceCenterStatus(ctx context.Context) (edgeDeviceAuthStatusResponse, bool, error) {
	if !config.EdgeEnabled || !config.EdgeDeviceAuthEnabled {
		return edgeDeviceAuthStatusResponse{}, false, nil
	}
	store := getLogsStatsStore()
	if store == nil {
		return edgeDeviceAuthStatusResponse{}, false, nil
	}
	identity, found, err := loadEdgeDeviceIdentity(store)
	if err != nil {
		return edgeDeviceAuthStatusResponse{}, true, err
	}
	if !found || strings.TrimSpace(identity.CenterURL) == "" {
		return edgeDeviceAuthStatusResponse{}, false, nil
	}
	status, err := refreshEdgeDeviceCenterStatus(ctx)
	return status, true, err
}

func prepareEdgeDeviceIdentity(store *wafEventStore, req edgeDeviceEnrollmentRequest) (edgeDeviceIdentityRecord, error) {
	store.mu.Lock()
	defer store.mu.Unlock()

	identity, found, err := loadEdgeDeviceIdentityUnlocked(store)
	if err != nil {
		return edgeDeviceIdentityRecord{}, err
	}
	if found {
		if err := verifyRequestedEdgeIdentity(identity, req.DeviceID, req.KeyID); err != nil {
			return edgeDeviceIdentityRecord{}, edgeEnrollmentError{status: http.StatusConflict, message: err.Error()}
		}
		return identity, nil
	}

	identity, err = newEdgeDeviceIdentity(req.DeviceID, req.KeyID)
	if err != nil {
		return edgeDeviceIdentityRecord{}, edgeEnrollmentError{status: http.StatusBadRequest, message: err.Error()}
	}
	if err := upsertEdgeDeviceIdentityUnlocked(store, identity); err != nil {
		return edgeDeviceIdentityRecord{}, err
	}
	return identity, nil
}

type edgeEnrollmentError struct {
	status  int
	message string
}

func (e edgeEnrollmentError) Error() string {
	return e.message
}

func respondEdgeDeviceEnrollmentError(c *gin.Context, err error) {
	var enrollmentErr edgeEnrollmentError
	if errors.As(err, &enrollmentErr) {
		c.JSON(enrollmentErr.status, gin.H{"error": enrollmentErr.message})
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to request device enrollment"})
}

func normalizeCenterEnrollmentURL(raw string) (string, string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return "", "", fmt.Errorf("center URL is required")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", "", fmt.Errorf("center URL must be absolute")
	}
	if u.User != nil {
		return "", "", fmt.Errorf("center URL must not include credentials")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", "", fmt.Errorf("center URL scheme must be http or https")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return "", "", fmt.Errorf("center URL must not include query or fragment")
	}
	path := strings.TrimRight(u.EscapedPath(), "/")
	if path != "" && path != "/v1/enroll" {
		return "", "", fmt.Errorf("center URL path must be empty or /v1/enroll")
	}
	base := &url.URL{Scheme: u.Scheme, Host: u.Host}
	enroll := *base
	enroll.Path = "/v1/enroll"
	return base.String(), enroll.String(), nil
}

func centerDeviceStatusURL(centerBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(centerBaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is not configured")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("center URL scheme must be http or https")
	}
	u.Path = "/v1/device-status"
	u.RawPath = ""
	return u.String(), nil
}

func centerDeviceConfigSnapshotURL(centerBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(centerBaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is not configured")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("center URL scheme must be http or https")
	}
	u.Path = "/v1/device-config-snapshot"
	u.RawPath = ""
	return u.String(), nil
}

func centerRuleArtifactBundleURL(centerBaseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(centerBaseURL))
	if err != nil || u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("center URL is not configured")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("center URL is invalid")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return "", fmt.Errorf("center URL scheme must be http or https")
	}
	u.Path = "/v1/rule-artifact-bundle"
	u.RawPath = ""
	return u.String(), nil
}

type edgeConfigSnapshotRuleAsset struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	ETag      string `json:"etag"`
	Disabled  bool   `json:"disabled"`
	SizeBytes int    `json:"size_bytes"`
}

func buildEdgeRuleArtifactBundle() (edgeartifactbundle.Build, bool, error) {
	store := getLogsStatsStore()
	if store == nil {
		return edgeartifactbundle.Build{}, false, fmt.Errorf("config DB store is not initialized")
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found || len(assets) == 0 {
		return edgeartifactbundle.Build{}, found, err
	}
	files := make([]edgeartifactbundle.RuleFile, 0, len(assets))
	for _, asset := range assets {
		files = append(files, edgeartifactbundle.RuleFile{
			Path:     asset.Path,
			Kind:     asset.Kind,
			ETag:     asset.ETag,
			Disabled: asset.Disabled,
			Body:     asset.Raw,
		})
	}
	bundle, err := edgeartifactbundle.BuildBundle(files, time.Now().UTC())
	if err != nil {
		return edgeartifactbundle.Build{}, true, err
	}
	return bundle, true, nil
}

func buildEdgeConfigSnapshot(identity edgeDeviceIdentityRecord) (edgeconfigsnapshot.Build, error) {
	builder := edgeconfigsnapshot.New(identity.DeviceID, identity.KeyID, buildinfo.Version, goruntime.Version())
	addGatewayConfigSnapshotDomains(builder, identity.RuleArtifactRevision)
	return builder.Build()
}

func addGatewayConfigSnapshotDomains(builder *edgeconfigsnapshot.Builder, ruleArtifactRevision string) {
	if builder == nil {
		return
	}

	if raw, etag, _, err := loadAppConfigStorage(false); err == nil {
		redacted, paths, redactErr := edgeconfigsnapshot.RedactAppConfigRaw(raw)
		if redactErr != nil {
			builder.AddDomainError(appConfigDomain, redactErr)
		} else {
			builder.AddRedactedPaths(paths...)
			builder.AddRawDomain(appConfigDomain, etag, redacted)
		}
	} else {
		builder.AddDomainError(appConfigDomain, err)
	}

	proxyRaw, proxyETag, proxyCfg, _, _ := ProxyRulesSnapshot()
	if strings.TrimSpace(proxyRaw) == "" {
		proxyRaw = mustJSON(normalizeProxyRulesConfig(proxyCfg))
	}
	builder.AddRawDomain(proxyConfigDomain, proxyETag, []byte(proxyRaw))

	siteRaw, siteETag, _, _, _ := SiteConfigSnapshot()
	builder.AddRawDomain(siteConfigDomain, siteETag, []byte(siteRaw))

	vhostRaw, vhostETag, _, _ := VhostConfigSnapshot()
	builder.AddRawDomain(vhostConfigDomain, vhostETag, []byte(vhostRaw))

	phpRaw, phpETag, _, _ := PHPRuntimeInventorySnapshot()
	builder.AddRawDomain(phpRuntimeInventoryConfigDomain, phpETag, []byte(phpRaw))

	psgiRaw, psgiETag, _, _ := PSGIRuntimeInventorySnapshot()
	builder.AddRawDomain(psgiRuntimeInventoryConfigDomain, psgiETag, []byte(psgiRaw))

	taskRaw, taskETag, _, _, _ := ScheduledTaskConfigSnapshot()
	builder.AddRawDomain(scheduledTaskConfigDomain, taskETag, []byte(taskRaw))

	cacheRaw, cacheETag, cacheCfg, _ := ResponseCacheSnapshot()
	if strings.TrimSpace(cacheRaw) == "" {
		cacheRaw = mustJSON(cacheCfg)
	}
	builder.AddRawDomain(responseCacheConfigBlobKey, cacheETag, []byte(cacheRaw))

	if raw, etag, _, err := snapshotUpstreamRuntimeFile(proxyCfg); err == nil {
		builder.AddRawDomain(upstreamRuntimeConfigDomain, etag, []byte(raw))
	} else {
		builder.AddDomainError(upstreamRuntimeConfigDomain, err)
	}

	store := getLogsStatsStore()
	if store == nil {
		builder.AddWarning("config DB store is not initialized")
		return
	}
	for _, spec := range []policyJSONConfigSpec{
		{Domain: cacheConfigBlobKey},
		{Domain: bypassConfigBlobKey},
		{Domain: countryBlockConfigBlobKey},
		{Domain: rateLimitConfigBlobKey},
		{Domain: botDefenseConfigBlobKey},
		{Domain: semanticConfigBlobKey},
		{Domain: notificationConfigBlobKey},
		{Domain: ipReputationConfigBlobKey},
	} {
		raw, rec, found, err := store.loadActivePolicyJSONConfig(spec)
		if err != nil {
			builder.AddDomainError(spec.Domain, err)
			continue
		}
		if found {
			builder.AddRawDomain(spec.Domain, rec.ETag, raw)
		}
	}
	if names, rec, found, err := store.loadActiveCRSDisabledConfig(); err != nil {
		builder.AddDomainError(crsDisabledConfigDomain, err)
	} else if found {
		builder.AddValueDomain(crsDisabledConfigDomain, rec.ETag, map[string]any{"disabled_rules": names})
	}
	if rules, rec, found, err := store.loadActiveManagedOverrideRules(); err != nil {
		builder.AddDomainError(overrideRulesConfigDomain, err)
	} else if found {
		out := make([]map[string]any, 0, len(rules))
		for _, rule := range rules {
			out = append(out, map[string]any{
				"name": rule.Name,
				"etag": rule.ETag,
				"raw":  string(rule.Raw),
			})
		}
		builder.AddValueDomain(overrideRulesConfigDomain, rec.ETag, out)
	}
	if assets, rec, found, err := store.loadActiveWAFRuleAssets(); err != nil {
		builder.AddDomainError(wafRuleAssetsConfigDomain, err)
	} else if found {
		out := make([]edgeConfigSnapshotRuleAsset, 0, len(assets))
		for _, asset := range assets {
			out = append(out, edgeConfigSnapshotRuleAsset{
				Path:      asset.Path,
				Kind:      asset.Kind,
				ETag:      asset.ETag,
				Disabled:  asset.Disabled,
				SizeBytes: len(asset.Raw),
			})
		}
		builder.AddValueDomain(wafRuleAssetsConfigDomain, rec.ETag, map[string]any{
			"bundle_revision": strings.TrimSpace(ruleArtifactRevision),
			"assets":          out,
		})
	}
}

func loadEdgeDeviceIdentity(store *wafEventStore) (edgeDeviceIdentityRecord, bool, error) {
	if store == nil {
		return edgeDeviceIdentityRecord{}, false, nil
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return loadEdgeDeviceIdentityUnlocked(store)
}

func loadEdgeDeviceIdentityUnlocked(store *wafEventStore) (edgeDeviceIdentityRecord, bool, error) {
	var rec edgeDeviceIdentityRecord
	err := store.queryRow(`
SELECT device_id, key_id, private_key_pem, public_key_fingerprint_sha256, enrollment_status,
       center_url, center_product_id, center_status_checked_at_unix, center_status_error,
       config_snapshot_revision, config_snapshot_pushed_at_unix, config_snapshot_error,
       rule_artifact_revision, rule_artifact_pushed_at_unix, rule_artifact_error,
       last_enrollment_at_unix, last_enrollment_error, created_at_unix, updated_at_unix
  FROM edge_device_identities
 WHERE identity_id = ?`, edgeDeviceIdentityID).Scan(
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PrivateKeyPEM,
		&rec.PublicKeyFingerprintSHA256,
		&rec.EnrollmentStatus,
		&rec.CenterURL,
		&rec.CenterProductID,
		&rec.CenterStatusCheckedAtUnix,
		&rec.CenterStatusError,
		&rec.ConfigSnapshotRevision,
		&rec.ConfigSnapshotPushedAtUnix,
		&rec.ConfigSnapshotError,
		&rec.RuleArtifactRevision,
		&rec.RuleArtifactPushedAtUnix,
		&rec.RuleArtifactError,
		&rec.LastEnrollmentAtUnix,
		&rec.LastEnrollmentError,
		&rec.CreatedAtUnix,
		&rec.UpdatedAtUnix,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return edgeDeviceIdentityRecord{}, false, nil
	}
	if err != nil {
		return edgeDeviceIdentityRecord{}, false, err
	}
	return rec, true, nil
}

func upsertEdgeDeviceIdentity(store *wafEventStore, rec edgeDeviceIdentityRecord) error {
	if store == nil {
		return errEdgeDeviceIdentityNotFound
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	return upsertEdgeDeviceIdentityUnlocked(store, rec)
}

func upsertEdgeDeviceIdentityUnlocked(store *wafEventStore, rec edgeDeviceIdentityRecord) error {
	if store == nil {
		return errEdgeDeviceIdentityNotFound
	}
	if rec.CreatedAtUnix <= 0 {
		rec.CreatedAtUnix = time.Now().UTC().Unix()
	}
	if rec.UpdatedAtUnix <= 0 {
		rec.UpdatedAtUnix = rec.CreatedAtUnix
	}
	if rec.EnrollmentStatus == "" {
		rec.EnrollmentStatus = edgeEnrollmentStatusLocal
	}
	result, err := store.exec(`
UPDATE edge_device_identities
   SET device_id = ?,
       key_id = ?,
       private_key_pem = ?,
       public_key_fingerprint_sha256 = ?,
       enrollment_status = ?,
       center_url = ?,
       center_product_id = ?,
       center_status_checked_at_unix = ?,
       center_status_error = ?,
       config_snapshot_revision = ?,
       config_snapshot_pushed_at_unix = ?,
       config_snapshot_error = ?,
       rule_artifact_revision = ?,
       rule_artifact_pushed_at_unix = ?,
       rule_artifact_error = ?,
       last_enrollment_at_unix = ?,
       last_enrollment_error = ?,
       updated_at_unix = ?
 WHERE identity_id = ?`,
		rec.DeviceID,
		rec.KeyID,
		rec.PrivateKeyPEM,
		rec.PublicKeyFingerprintSHA256,
		rec.EnrollmentStatus,
		rec.CenterURL,
		rec.CenterProductID,
		rec.CenterStatusCheckedAtUnix,
		rec.CenterStatusError,
		rec.ConfigSnapshotRevision,
		rec.ConfigSnapshotPushedAtUnix,
		rec.ConfigSnapshotError,
		rec.RuleArtifactRevision,
		rec.RuleArtifactPushedAtUnix,
		rec.RuleArtifactError,
		rec.LastEnrollmentAtUnix,
		rec.LastEnrollmentError,
		rec.UpdatedAtUnix,
		edgeDeviceIdentityID,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err == nil && affected > 0 {
		return nil
	}
	_, err = store.exec(`
INSERT INTO edge_device_identities
    (identity_id, device_id, key_id, private_key_pem, public_key_fingerprint_sha256,
     enrollment_status, center_url, center_product_id, center_status_checked_at_unix, center_status_error,
     config_snapshot_revision, config_snapshot_pushed_at_unix, config_snapshot_error,
     rule_artifact_revision, rule_artifact_pushed_at_unix, rule_artifact_error,
     last_enrollment_at_unix, last_enrollment_error,
     created_at_unix, updated_at_unix)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		edgeDeviceIdentityID,
		rec.DeviceID,
		rec.KeyID,
		rec.PrivateKeyPEM,
		rec.PublicKeyFingerprintSHA256,
		rec.EnrollmentStatus,
		rec.CenterURL,
		rec.CenterProductID,
		rec.CenterStatusCheckedAtUnix,
		rec.CenterStatusError,
		rec.ConfigSnapshotRevision,
		rec.ConfigSnapshotPushedAtUnix,
		rec.ConfigSnapshotError,
		rec.RuleArtifactRevision,
		rec.RuleArtifactPushedAtUnix,
		rec.RuleArtifactError,
		rec.LastEnrollmentAtUnix,
		rec.LastEnrollmentError,
		rec.CreatedAtUnix,
		rec.UpdatedAtUnix,
	)
	return err
}

func newEdgeDeviceIdentity(requestedDeviceID string, requestedKeyID string) (edgeDeviceIdentityRecord, error) {
	deviceID := strings.TrimSpace(requestedDeviceID)
	if deviceID == "" {
		var err error
		deviceID, err = randomEdgeIdentifier("tky")
		if err != nil {
			return edgeDeviceIdentityRecord{}, err
		}
	}
	keyID := strings.TrimSpace(requestedKeyID)
	if keyID == "" {
		keyID = "default"
	}
	if !edgeDeviceIDPattern.MatchString(deviceID) {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("invalid device_id")
	}
	if !edgeKeyIDPattern.MatchString(keyID) {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("invalid key_id")
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("generate device key: %w", err)
	}
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("marshal device private key: %w", err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("marshal device public key: %w", err)
	}
	sum := sha256.Sum256(publicDER)
	now := time.Now().UTC().Unix()
	return edgeDeviceIdentityRecord{
		DeviceID:                   deviceID,
		KeyID:                      keyID,
		PrivateKeyPEM:              string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER})),
		PublicKeyFingerprintSHA256: hex.EncodeToString(sum[:]),
		EnrollmentStatus:           "local",
		CreatedAtUnix:              now,
		UpdatedAtUnix:              now,
	}, nil
}

func verifyRequestedEdgeIdentity(identity edgeDeviceIdentityRecord, requestedDeviceID string, requestedKeyID string) error {
	deviceID := strings.TrimSpace(requestedDeviceID)
	if deviceID != "" && deviceID != identity.DeviceID {
		return fmt.Errorf("local device identity already exists with a different device_id")
	}
	keyID := strings.TrimSpace(requestedKeyID)
	if keyID != "" && keyID != identity.KeyID {
		return fmt.Errorf("local device identity already exists with a different key_id")
	}
	return nil
}

func edgeCanRequestEnrollment(status string) bool {
	switch normalizeEdgeStatus(status) {
	case "", edgeEnrollmentStatusArchived, edgeEnrollmentStatusFailed, edgeEnrollmentStatusLocal, edgeEnrollmentStatusProductShift, edgeEnrollmentStatusRevoked, edgeEnrollmentStatusUnconfigured:
		return true
	default:
		return false
	}
}

func edgeEnrollmentBlockedMessage(status string) string {
	switch normalizeEdgeStatus(status) {
	case edgeEnrollmentStatusApproved:
		return "device is already approved by Center"
	case edgeEnrollmentStatusPending:
		return "device enrollment is already pending in Center"
	default:
		return "device enrollment cannot be requested from the current status"
	}
}

func signedEdgeDeviceEnrollmentRequest(identity edgeDeviceIdentityRecord) (edgeDeviceEnrollmentWireRequest, error) {
	privateKey, publicKeyDER, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeDeviceEnrollmentWireRequest{}, err
	}
	publicPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKeyDER})
	publicPEMB64 := base64.StdEncoding.EncodeToString(publicPEM)
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeDeviceEnrollmentWireRequest{}, err
	}
	req := edgeDeviceEnrollmentWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyPEMB64:            publicPEMB64,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
	}
	req.BodyHash = edgeEnrollmentBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func signedEdgeDeviceStatusRequest(identity edgeDeviceIdentityRecord) (edgeDeviceStatusWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeDeviceStatusWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeDeviceStatusWireRequest{}, err
	}
	req := edgeDeviceStatusWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		RuntimeRole:                "gateway",
		BuildVersion:               clampEdgeText(buildinfo.Version, 128),
		GoVersion:                  clampEdgeText(goruntime.Version(), 64),
	}
	req.BodyHash = edgeDeviceStatusBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func signedEdgeDeviceConfigSnapshotRequest(identity edgeDeviceIdentityRecord, snapshot edgeconfigsnapshot.Build) (edgeDeviceConfigSnapshotWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeDeviceConfigSnapshotWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeDeviceConfigSnapshotWireRequest{}, err
	}
	req := edgeDeviceConfigSnapshotWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		ConfigRevision:             snapshot.Revision,
		PayloadHash:                snapshot.PayloadHash,
		Snapshot:                   append(json.RawMessage(nil), snapshot.PayloadRaw...),
	}
	req.BodyHash = edgeDeviceConfigSnapshotBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func signedEdgeRuleArtifactBundleRequest(identity edgeDeviceIdentityRecord, bundle edgeartifactbundle.Build) (edgeRuleArtifactBundleWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeRuleArtifactBundleWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeRuleArtifactBundleWireRequest{}, err
	}
	req := edgeRuleArtifactBundleWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		BundleRevision:             bundle.Revision,
		BundleHash:                 bundle.BundleHash,
		CompressedSize:             bundle.CompressedSize,
		UncompressedSize:           bundle.UncompressedSize,
		FileCount:                  bundle.FileCount,
		BundleB64:                  base64.StdEncoding.EncodeToString(bundle.Compressed),
	}
	req.BodyHash = edgeRuleArtifactBundleBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func parseEdgeDevicePrivateKey(raw string) (ed25519.PrivateKey, []byte, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "PRIVATE KEY" || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, fmt.Errorf("invalid local device private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("parse local device private key: %w", err)
	}
	privateKey, ok := key.(ed25519.PrivateKey)
	if !ok || len(privateKey) != ed25519.PrivateKeySize {
		return nil, nil, fmt.Errorf("local device private key must be Ed25519")
	}
	publicKey, ok := privateKey.Public().(ed25519.PublicKey)
	if !ok || len(publicKey) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("local device public key must be Ed25519")
	}
	publicDER, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal local device public key: %w", err)
	}
	return privateKey, publicDER, nil
}

func sendEdgeDeviceEnrollment(ctx context.Context, enrollURL string, token string, wireReq edgeDeviceEnrollmentWireRequest) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, enrollURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Enrollment-Token", token)
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	return res.StatusCode, resBody, nil
}

func sendEdgeDeviceStatus(ctx context.Context, statusURL string, wireReq edgeDeviceStatusWireRequest) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, statusURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	return res.StatusCode, resBody, nil
}

func sendEdgeDeviceConfigSnapshot(ctx context.Context, snapshotURL string, wireReq edgeDeviceConfigSnapshotWireRequest) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, snapshotURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	return res.StatusCode, resBody, nil
}

func sendEdgeRuleArtifactBundle(ctx context.Context, bundleURL string, wireReq edgeRuleArtifactBundleWireRequest) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, bundleURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, 8*1024))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	return res.StatusCode, resBody, nil
}

func pushEdgeRuleArtifactBundleIfChanged(ctx context.Context, identity *edgeDeviceIdentityRecord) bool {
	if identity == nil {
		return true
	}
	bundle, found, err := buildEdgeRuleArtifactBundle()
	if err != nil {
		identity.RuleArtifactError = clampEdgeText(err.Error(), 2048)
		return false
	}
	if !found {
		identity.RuleArtifactError = ""
		return true
	}
	if bundle.Revision == strings.TrimSpace(identity.RuleArtifactRevision) {
		identity.RuleArtifactError = ""
		return true
	}
	if !beginEdgeRuleArtifactUpload(bundle.Revision) {
		return false
	}
	defer finishEdgeRuleArtifactUpload(bundle.Revision)

	bundleURL, err := centerRuleArtifactBundleURL(identity.CenterURL)
	if err != nil {
		identity.RuleArtifactError = clampEdgeText(err.Error(), 2048)
		return false
	}
	wireReq, err := signedEdgeRuleArtifactBundleRequest(*identity, bundle)
	if err != nil {
		identity.RuleArtifactError = clampEdgeText(err.Error(), 2048)
		return false
	}
	centerHTTPStatus, centerBody, err := sendEdgeRuleArtifactBundle(ctx, bundleURL, wireReq)
	if err != nil {
		identity.RuleArtifactError = clampEdgeText(err.Error(), 2048)
		return false
	}
	if centerHTTPStatus < 200 || centerHTTPStatus >= 300 {
		identity.RuleArtifactError = clampEdgeText(centerEnrollmentErrorMessage(centerHTTPStatus, centerBody), 2048)
		return false
	}
	var payload edgeRuleArtifactBundleResponse
	if err := json.Unmarshal(centerBody, &payload); err != nil {
		identity.RuleArtifactError = "center rule artifact response is invalid JSON"
		return false
	}
	if payload.BundleRevision != bundle.Revision {
		identity.RuleArtifactError = "center rule artifact response revision mismatch"
		return false
	}
	identity.RuleArtifactRevision = bundle.Revision
	identity.RuleArtifactPushedAtUnix = time.Now().UTC().Unix()
	if payload.ReceivedAtUnix > 0 {
		identity.RuleArtifactPushedAtUnix = payload.ReceivedAtUnix
	}
	identity.RuleArtifactError = ""
	return true
}

func beginEdgeRuleArtifactUpload(revision string) bool {
	revision = strings.TrimSpace(revision)
	if revision == "" {
		return false
	}
	edgeRuleArtifactUploadMu.Lock()
	defer edgeRuleArtifactUploadMu.Unlock()
	if edgeRuleArtifactUploadRevision != "" {
		return false
	}
	edgeRuleArtifactUploadRevision = revision
	return true
}

func finishEdgeRuleArtifactUpload(revision string) {
	revision = strings.TrimSpace(revision)
	edgeRuleArtifactUploadMu.Lock()
	defer edgeRuleArtifactUploadMu.Unlock()
	if edgeRuleArtifactUploadRevision == revision {
		edgeRuleArtifactUploadRevision = ""
	}
}

func pushEdgeConfigSnapshotIfChanged(ctx context.Context, identity *edgeDeviceIdentityRecord) {
	if identity == nil {
		return
	}
	snapshot, err := buildEdgeConfigSnapshot(*identity)
	if err != nil {
		identity.ConfigSnapshotError = clampEdgeText(err.Error(), 2048)
		return
	}
	if snapshot.Revision == strings.TrimSpace(identity.ConfigSnapshotRevision) {
		identity.ConfigSnapshotError = ""
		return
	}
	snapshotURL, err := centerDeviceConfigSnapshotURL(identity.CenterURL)
	if err != nil {
		identity.ConfigSnapshotError = clampEdgeText(err.Error(), 2048)
		return
	}
	wireReq, err := signedEdgeDeviceConfigSnapshotRequest(*identity, snapshot)
	if err != nil {
		identity.ConfigSnapshotError = clampEdgeText(err.Error(), 2048)
		return
	}
	centerHTTPStatus, centerBody, err := sendEdgeDeviceConfigSnapshot(ctx, snapshotURL, wireReq)
	if err != nil {
		identity.ConfigSnapshotError = clampEdgeText(err.Error(), 2048)
		return
	}
	if centerHTTPStatus < 200 || centerHTTPStatus >= 300 {
		identity.ConfigSnapshotError = clampEdgeText(centerEnrollmentErrorMessage(centerHTTPStatus, centerBody), 2048)
		return
	}
	var payload edgeDeviceConfigSnapshotResponse
	if err := json.Unmarshal(centerBody, &payload); err != nil {
		identity.ConfigSnapshotError = "center config snapshot response is invalid JSON"
		return
	}
	if payload.ConfigRevision != snapshot.Revision {
		identity.ConfigSnapshotError = "center config snapshot response revision mismatch"
		return
	}
	identity.ConfigSnapshotRevision = snapshot.Revision
	identity.ConfigSnapshotPushedAtUnix = time.Now().UTC().Unix()
	if payload.ReceivedAtUnix > 0 {
		identity.ConfigSnapshotPushedAtUnix = payload.ReceivedAtUnix
	}
	identity.ConfigSnapshotError = ""
}

func centerEnrollmentErrorMessage(status int, body []byte) string {
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if strings.TrimSpace(payload.Error) != "" {
			return fmt.Sprintf("center enrollment failed: HTTP %d: %s", status, strings.TrimSpace(payload.Error))
		}
		if strings.TrimSpace(payload.Message) != "" {
			return fmt.Sprintf("center enrollment failed: HTTP %d: %s", status, strings.TrimSpace(payload.Message))
		}
	}
	text := strings.TrimSpace(string(body))
	if text != "" {
		return fmt.Sprintf("center enrollment failed: HTTP %d: %s", status, clampEdgeText(text, 512))
	}
	return fmt.Sprintf("center enrollment failed: HTTP %d", status)
}

func edgeDeviceStatusFromIdentity(identity edgeDeviceIdentityRecord) edgeDeviceAuthStatusResponse {
	status := edgeDeviceAuthStatusResponse{
		StoreAvailable:             true,
		EdgeEnabled:                config.EdgeEnabled,
		DeviceAuthEnabled:          config.EdgeDeviceAuthEnabled,
		RequireDeviceApproval:      config.EdgeRequireDeviceApproval,
		IdentityConfigured:         true,
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		EnrollmentStatus:           identity.EnrollmentStatus,
		CenterURL:                  identity.CenterURL,
		CenterProductID:            identity.CenterProductID,
		CenterStatusCheckedAtUnix:  identity.CenterStatusCheckedAtUnix,
		CenterStatusError:          identity.CenterStatusError,
		ConfigSnapshotRevision:     identity.ConfigSnapshotRevision,
		ConfigSnapshotPushedAtUnix: identity.ConfigSnapshotPushedAtUnix,
		ConfigSnapshotError:        identity.ConfigSnapshotError,
		RuleArtifactRevision:       identity.RuleArtifactRevision,
		RuleArtifactPushedAtUnix:   identity.RuleArtifactPushedAtUnix,
		RuleArtifactError:          identity.RuleArtifactError,
		LastEnrollmentAtUnix:       identity.LastEnrollmentAtUnix,
		LastEnrollmentError:        identity.LastEnrollmentError,
	}
	applyEdgeProxyGateStatus(&status)
	return status
}

func edgeEnrollmentBodyHash(req edgeDeviceEnrollmentWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyPEMB64 + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce,
	))
	return hex.EncodeToString(sum[:])
}

func edgeDeviceStatusBodyHash(req edgeDeviceStatusWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.RuntimeRole + "\n" +
			req.BuildVersion + "\n" +
			req.GoVersion,
	))
	return hex.EncodeToString(sum[:])
}

func edgeDeviceConfigSnapshotBodyHash(req edgeDeviceConfigSnapshotWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.ConfigRevision + "\n" +
			req.PayloadHash,
	))
	return hex.EncodeToString(sum[:])
}

func edgeRuleArtifactBundleBodyHash(req edgeRuleArtifactBundleWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.BundleRevision + "\n" +
			req.BundleHash + "\n" +
			fmt.Sprintf("%d", req.CompressedSize) + "\n" +
			fmt.Sprintf("%d", req.UncompressedSize) + "\n" +
			fmt.Sprintf("%d", req.FileCount),
	))
	return hex.EncodeToString(sum[:])
}

func edgeEnrollmentSignedMessage(deviceID, keyID, timestamp, nonce, bodyHash string) string {
	return deviceID + "\n" + keyID + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash
}

func randomEdgeIdentifier(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + "-" + hex.EncodeToString(raw[:]), nil
}

func applyEdgeProxyGateStatus(status *edgeDeviceAuthStatusResponse) {
	if status == nil {
		return
	}
	status.RequireDeviceApproval = config.EdgeRequireDeviceApproval
	gate := edgeProxyGateFromStatus(*status)
	status.ProxyLocked = gate.Locked
	status.ProxyLockReason = gate.Reason
}

func currentEdgeProxyGateState() edgeProxyGateState {
	status, err := currentEdgeDeviceAuthStatus()
	if err != nil {
		return edgeProxyGateState{Locked: true, Reason: edgeProxyLockReasonStoreError}
	}
	return edgeProxyGateFromStatus(status)
}

func edgeProxyGateFromStatus(status edgeDeviceAuthStatusResponse) edgeProxyGateState {
	if !config.EdgeEnabled || !config.EdgeRequireDeviceApproval {
		return edgeProxyGateState{}
	}
	if !config.EdgeDeviceAuthEnabled {
		return edgeProxyGateState{Locked: true, Reason: edgeProxyLockReasonAuthDisabled}
	}
	if !status.StoreAvailable {
		return edgeProxyGateState{Locked: true, Reason: edgeProxyLockReasonStoreMissing}
	}
	if !status.IdentityConfigured {
		return edgeProxyGateState{Locked: true, Reason: edgeProxyLockReasonIdentityMissing}
	}
	if status.EnrollmentStatus != edgeEnrollmentStatusApproved {
		return edgeProxyGateState{Locked: true, Reason: edgeProxyLockReasonNotApproved}
	}
	return edgeProxyGateState{}
}

func normalizeEdgeStatus(raw string) string {
	status := strings.ToLower(strings.TrimSpace(raw))
	if status == "" || len(status) > 64 {
		return ""
	}
	for _, r := range status {
		if (r < 'a' || r > 'z') && r != '_' && (r < '0' || r > '9') {
			return ""
		}
	}
	return status
}

func clampEdgeText(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if limit <= 0 || len(raw) <= limit {
		return raw
	}
	return raw[:limit]
}
