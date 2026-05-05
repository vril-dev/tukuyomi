package handler

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
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
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/user"
	"path"
	"path/filepath"
	"regexp"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/creack/pty"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/centertls"
	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/edgeconfigsnapshot"
	"tukuyomi/internal/remotestream"
	"tukuyomi/internal/runtimeartifactbundle"
	"tukuyomi/internal/waf"
)

const (
	edgeDeviceIdentityID        = int64(1)
	edgeEnrollmentTokenMaxBytes = 256
	edgeEnrollmentHTTPTimeout   = 10 * time.Second
	edgeRuntimeArtifactTimeout  = 10 * time.Minute
	edgeProxyRuleBundleMaxBytes = edgeconfigsnapshot.MaxBytes
	edgeWAFRuleArtifactMaxBytes = edgeartifactbundle.MaxCompressedBytes
)

const (
	centerProtectedBootstrapActor        = "system:center-protected-bootstrap"
	centerProtectedUpstreamName          = "center"
	centerProtectedDefaultGatewayAPIPath = "/center-api"
	centerProtectedDefaultCenterAPIPath  = "/center-api"
	centerProtectedDefaultCenterUIPath   = "/center-ui"
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

	errEdgeDeviceIdentityNotFound               = errors.New("edge device identity not found")
	errEdgeRemoteSSHCenterSigningKeyUnavailable = errors.New("center remote ssh signing key unavailable")

	edgeDeviceStatusRefreshTriggerMu sync.RWMutex
	edgeDeviceStatusRefreshTrigger   chan struct{}
	edgeDeviceCenterRefreshMu        sync.Mutex

	edgeRuleArtifactUploadMu       sync.Mutex
	edgeRuleArtifactUploadRevision string

	edgeRuntimeAssignmentMu         sync.Mutex
	edgeRuntimeAssignmentActive     = map[string]struct{}{}
	edgeRuntimeApplyStatusMu        sync.RWMutex
	edgeRuntimeApplyStatuses        = map[string]edgeRuntimeApplyStatus{}
	edgeProxyRuleAssignmentMu       sync.Mutex
	edgeProxyRuleAssignmentActive   bool
	edgeProxyRuleApplyStatusMu      sync.RWMutex
	edgeProxyRuleApplyStatusCurrent *edgeProxyRuleApplyStatus
	edgeWAFRuleAssignmentMu         sync.Mutex
	edgeWAFRuleAssignmentActive     bool
	edgeWAFRuleApplyStatusMu        sync.RWMutex
	edgeWAFRuleApplyStatusCurrent   *edgeWAFRuleApplyStatus
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

type edgeRemoteSSHSigningKeyRefreshRequest struct {
	Confirm bool `json:"confirm"`
}

type CenterProtectedGatewayBootstrapOptions struct {
	CenterURL                string
	GatewayAPIBasePath       string
	CenterAPIBasePath        string
	CenterUIBasePath         string
	DeviceID                 string
	KeyID                    string
	CenterTLSCABundleFile    string
	CenterTLSServerName      string
	StatusRefreshIntervalSec int
	MarkApproved             bool
}

type centerProtectedGatewayRouteConfig struct {
	GatewayAPIBasePath string
	CenterAPIBasePath  string
	CenterUIBasePath   string
}

type CenterProtectedGatewayBootstrapResult struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyPEM               string `json:"public_key_pem"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	CenterURL                  string `json:"center_url"`
	EnrollmentStatus           string `json:"enrollment_status"`
	AppConfigUpdated           bool   `json:"app_config_updated"`
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
	DeviceID                   string                     `json:"device_id"`
	KeyID                      string                     `json:"key_id"`
	PublicKeyFingerprintSHA256 string                     `json:"public_key_fingerprint_sha256"`
	Timestamp                  string                     `json:"timestamp"`
	Nonce                      string                     `json:"nonce"`
	RuntimeRole                string                     `json:"runtime_role,omitempty"`
	BuildVersion               string                     `json:"build_version,omitempty"`
	GoVersion                  string                     `json:"go_version,omitempty"`
	OS                         string                     `json:"os,omitempty"`
	Arch                       string                     `json:"arch,omitempty"`
	KernelVersion              string                     `json:"kernel_version,omitempty"`
	DistroID                   string                     `json:"distro_id,omitempty"`
	DistroIDLike               string                     `json:"distro_id_like,omitempty"`
	DistroVersion              string                     `json:"distro_version,omitempty"`
	RuntimeDeploymentSupported bool                       `json:"runtime_deployment_supported,omitempty"`
	RuntimeInventory           []edgeDeviceRuntimeSummary `json:"runtime_inventory,omitempty"`
	ProxyRuleApplyStatus       *edgeProxyRuleApplyStatus  `json:"proxy_rule_apply_status,omitempty"`
	WAFRuleApplyStatus         *edgeWAFRuleApplyStatus    `json:"waf_rule_apply_status,omitempty"`
	BodyHash                   string                     `json:"body_hash"`
	SignatureB64               string                     `json:"signature_b64"`
}

type edgeDeviceRuntimeSummary struct {
	RuntimeFamily       string   `json:"runtime_family"`
	RuntimeID           string   `json:"runtime_id"`
	DisplayName         string   `json:"display_name,omitempty"`
	DetectedVersion     string   `json:"detected_version,omitempty"`
	Source              string   `json:"source,omitempty"`
	Available           bool     `json:"available"`
	AvailabilityMessage string   `json:"availability_message,omitempty"`
	ModuleCount         int      `json:"module_count"`
	UsageReported       bool     `json:"usage_reported"`
	AppCount            int      `json:"app_count"`
	GeneratedTargets    []string `json:"generated_targets,omitempty"`
	ProcessRunning      bool     `json:"process_running"`
	ArtifactRevision    string   `json:"artifact_revision,omitempty"`
	ArtifactHash        string   `json:"artifact_hash,omitempty"`
	ApplyState          string   `json:"apply_state,omitempty"`
	ApplyError          string   `json:"apply_error,omitempty"`
}

type edgeGatewayPlatformMetadata struct {
	OS            string
	Arch          string
	KernelVersion string
	DistroID      string
	DistroIDLike  string
	DistroVersion string
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

type edgeRuntimeArtifactDownloadWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	RuntimeFamily              string `json:"runtime_family"`
	RuntimeID                  string `json:"runtime_id"`
	ArtifactRevision           string `json:"artifact_revision"`
	ArtifactHash               string `json:"artifact_hash"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type edgeProxyRulesBundleDownloadWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BundleRevision             string `json:"bundle_revision"`
	PayloadHash                string `json:"payload_hash"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type edgeWAFRuleArtifactDownloadWireRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BundleRevision             string `json:"bundle_revision"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type edgeDeviceCenterStatusResponse struct {
	Status                       string                         `json:"status"`
	DeviceID                     string                         `json:"device_id"`
	KeyID                        string                         `json:"key_id"`
	ProductID                    string                         `json:"product_id"`
	CheckedAtUnix                int64                          `json:"checked_at_unix"`
	RuleArtifactUploadRequired   bool                           `json:"rule_artifact_upload_required,omitempty"`
	ConfigSnapshotUploadRequired bool                           `json:"config_snapshot_upload_required,omitempty"`
	RuntimeAssignments           []edgeRuntimeDeviceAssignment  `json:"runtime_assignments,omitempty"`
	ProxyRuleAssignment          *edgeProxyRuleDeviceAssignment `json:"proxy_rule_assignment,omitempty"`
	WAFRuleAssignment            *edgeWAFRuleDeviceAssignment   `json:"waf_rule_assignment,omitempty"`
	RemoteSSHSession             *edgeRemoteSSHDeviceSession    `json:"remote_ssh_session,omitempty"`
}

type edgeRemoteSSHCenterSigningKeyResponse struct {
	PublicKey string `json:"public_key"`
	Algorithm string `json:"algorithm"`
}

type edgeRuntimeDeviceAssignment struct {
	RuntimeFamily    string `json:"runtime_family"`
	RuntimeID        string `json:"runtime_id"`
	ArtifactRevision string `json:"artifact_revision,omitempty"`
	ArtifactHash     string `json:"artifact_hash,omitempty"`
	CompressedSize   int64  `json:"compressed_size,omitempty"`
	UncompressedSize int64  `json:"uncompressed_size,omitempty"`
	FileCount        int    `json:"file_count,omitempty"`
	DetectedVersion  string `json:"detected_version,omitempty"`
	DesiredState     string `json:"desired_state"`
	AssignedAtUnix   int64  `json:"assigned_at_unix"`
}

type edgeRuntimeApplyStatus struct {
	RuntimeFamily    string
	RuntimeID        string
	ArtifactRevision string
	ArtifactHash     string
	ApplyState       string
	ApplyError       string
}

type edgeProxyRuleDeviceAssignment struct {
	BundleRevision  string `json:"bundle_revision"`
	PayloadHash     string `json:"payload_hash"`
	PayloadETag     string `json:"payload_etag"`
	SourceProxyETag string `json:"source_proxy_etag"`
	SizeBytes       int64  `json:"size_bytes"`
	AssignedAtUnix  int64  `json:"assigned_at_unix"`
}

type edgeProxyRuleApplyStatus struct {
	DesiredBundleRevision string `json:"desired_bundle_revision,omitempty"`
	LocalProxyETag        string `json:"local_proxy_etag,omitempty"`
	ApplyState            string `json:"apply_state,omitempty"`
	ApplyError            string `json:"apply_error,omitempty"`
}

type edgeWAFRuleDeviceAssignment struct {
	BundleRevision     string `json:"bundle_revision"`
	BaseBundleRevision string `json:"base_bundle_revision"`
	CompressedSize     int64  `json:"compressed_size"`
	UncompressedSize   int64  `json:"uncompressed_size"`
	FileCount          int    `json:"file_count"`
	AssignedAtUnix     int64  `json:"assigned_at_unix"`
}

type edgeWAFRuleApplyStatus struct {
	DesiredBundleRevision string `json:"desired_bundle_revision,omitempty"`
	LocalBundleRevision   string `json:"local_bundle_revision,omitempty"`
	ApplyState            string `json:"apply_state,omitempty"`
	ApplyError            string `json:"apply_error,omitempty"`
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

func PostEdgeRemoteSSHSigningKeyRefresh(c *gin.Context) {
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1024)
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var req edgeRemoteSSHSigningKeyRefreshRequest
	if err := decoder.Decode(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote ssh signing key refresh request"})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid remote ssh signing key refresh request"})
		return
	}
	if !req.Confirm {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "confirm is required"})
		return
	}
	identity, err := approvedEdgeDeviceIdentityForRemoteSSHCenterSigningKey()
	if err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": err.Error()})
		return
	}
	key, err := persistRemoteSSHGatewayCenterSigningKeyFromApprovedCenter(c.Request.Context(), identity, true)
	if err != nil {
		switch {
		case errors.Is(err, errEdgeRemoteSSHCenterSigningKeyUnavailable):
			c.JSON(http.StatusConflict, gin.H{"error": "center remote ssh signing key is unavailable"})
		default:
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to refresh remote ssh signing key"})
		}
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"center_signing_public_key": key,
		"algorithm":                 "ed25519",
	})
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
		message := centerHTTPErrorMessage("center status refresh failed", centerHTTPStatus, centerBody)
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
		importRemoteSSHGatewayCenterSigningKeyFromApprovedCenter(ctx, identity)
		applyEdgeProxyRuleAssignment(ctx, identity, payload.ProxyRuleAssignment)
		pruneCompletedEdgeProxyRuleApplyStatus(payload.ProxyRuleAssignment)
		applyEdgeWAFRuleAssignment(ctx, &identity, payload.WAFRuleAssignment)
		pruneCompletedEdgeWAFRuleApplyStatus(payload.WAFRuleAssignment)
		applyEdgeRuntimeAssignments(ctx, identity, payload.RuntimeAssignments)
		pruneCompletedEdgeRuntimeApplyStatuses(payload.RuntimeAssignments)
		applyEdgeRemoteSSHSession(ctx, identity, payload.RemoteSSHSession)
		if pushEdgeRuleArtifactBundle(ctx, &identity, payload.RuleArtifactUploadRequired) {
			pushEdgeConfigSnapshot(ctx, &identity, payload.ConfigSnapshotUploadRequired)
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

func BootstrapCenterProtectedGateway(ctx context.Context, opts CenterProtectedGatewayBootstrapOptions) (CenterProtectedGatewayBootstrapResult, error) {
	_ = ctx
	centerURL, _, err := normalizeCenterEnrollmentURL(opts.CenterURL)
	if err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}
	routeCfg, err := normalizeCenterProtectedGatewayRouteConfig(opts)
	if err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}
	if opts.StatusRefreshIntervalSec < 0 || opts.StatusRefreshIntervalSec > config.MaxEdgeDeviceStatusRefreshSec {
		return CenterProtectedGatewayBootstrapResult{}, fmt.Errorf("status refresh interval must be between 0 and %d", config.MaxEdgeDeviceStatusRefreshSec)
	}
	store := getLogsStatsStore()
	if store == nil {
		return CenterProtectedGatewayBootstrapResult{}, fmt.Errorf("db store is not initialized")
	}

	appUpdated, err := bootstrapCenterProtectedGatewayAppConfig(opts.StatusRefreshIntervalSec, opts.CenterTLSCABundleFile, opts.CenterTLSServerName)
	if err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}
	if err := bootstrapCenterProtectedGatewayRouting(store, centerURL, routeCfg); err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}

	identity, err := prepareEdgeDeviceIdentity(store, edgeDeviceEnrollmentRequest{
		DeviceID: opts.DeviceID,
		KeyID:    opts.KeyID,
	})
	if err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}
	if opts.MarkApproved && !edgeCanMarkBootstrapApproved(identity.EnrollmentStatus) {
		return CenterProtectedGatewayBootstrapResult{}, fmt.Errorf("local device identity status %q cannot be auto-approved", identity.EnrollmentStatus)
	}

	publicPEM, err := edgeDevicePublicKeyPEM(identity)
	if err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}

	now := time.Now().UTC().Unix()
	identity.CenterURL = centerURL
	identity.CenterStatusError = ""
	identity.UpdatedAtUnix = now
	if opts.MarkApproved {
		identity.EnrollmentStatus = edgeEnrollmentStatusApproved
		identity.LastEnrollmentError = ""
	}
	if err := upsertEdgeDeviceIdentity(store, identity); err != nil {
		return CenterProtectedGatewayBootstrapResult{}, err
	}

	return CenterProtectedGatewayBootstrapResult{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyPEM:               publicPEM,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		CenterURL:                  centerURL,
		EnrollmentStatus:           identity.EnrollmentStatus,
		AppConfigUpdated:           appUpdated,
	}, nil
}

func bootstrapCenterProtectedGatewayAppConfig(statusRefreshIntervalSec int, centerTLSCABundleFile string, centerTLSServerName string) (bool, error) {
	_, etag, cfg, err := loadAppConfigStorage(true)
	if err != nil {
		return false, err
	}
	changed := false
	centerTLSCABundleFile = strings.TrimSpace(centerTLSCABundleFile)
	centerTLSServerName = strings.TrimSpace(centerTLSServerName)
	if !cfg.Edge.Enabled {
		cfg.Edge.Enabled = true
		changed = true
	}
	if !cfg.Edge.DeviceAuth.Enabled {
		cfg.Edge.DeviceAuth.Enabled = true
		changed = true
	}
	if statusRefreshIntervalSec > 0 && cfg.Edge.DeviceAuth.StatusRefreshIntervalSec != statusRefreshIntervalSec {
		cfg.Edge.DeviceAuth.StatusRefreshIntervalSec = statusRefreshIntervalSec
		changed = true
	} else if cfg.Edge.DeviceAuth.StatusRefreshIntervalSec == 0 {
		cfg.Edge.DeviceAuth.StatusRefreshIntervalSec = config.DefaultEdgeDeviceStatusRefreshSec
		changed = true
	}
	if centerTLSCABundleFile != "" && cfg.RemoteSSH.Gateway.CenterTLSCABundleFile != centerTLSCABundleFile {
		cfg.RemoteSSH.Gateway.CenterTLSCABundleFile = centerTLSCABundleFile
		changed = true
	}
	if centerTLSServerName != "" && cfg.RemoteSSH.Gateway.CenterTLSServerName != centerTLSServerName {
		cfg.RemoteSSH.Gateway.CenterTLSServerName = centerTLSServerName
		changed = true
	}
	if !changed {
		return false, nil
	}
	if _, err := persistSettingsAppConfig(cfg, etag); err != nil {
		return false, err
	}
	return true, nil
}

func bootstrapCenterProtectedGatewayRouting(store *wafEventStore, centerURL string, routeCfg centerProtectedGatewayRouteConfig) error {
	if err := bootstrapCenterProtectedGatewayProxyRoutes(store, centerURL, routeCfg); err != nil {
		return err
	}
	return bootstrapCenterProtectedGatewayWAFBypass(store, centerProtectedBypassPaths(routeCfg))
}

func bootstrapCenterProtectedGatewayProxyRoutes(store *wafEventStore, centerURL string, routeCfg centerProtectedGatewayRouteConfig) error {
	cfg, rec, found, err := store.loadActiveProxyConfig()
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	changed := false
	nextUpstream := ProxyUpstream{
		Enabled: true,
		Name:    centerProtectedUpstreamName,
		URL:     centerURL,
		Weight:  1,
	}
	upstreamFound := false
	for i := range cfg.Upstreams {
		if cfg.Upstreams[i].Name != centerProtectedUpstreamName {
			continue
		}
		upstreamFound = true
		if mustJSON(cfg.Upstreams[i]) != mustJSON(nextUpstream) {
			cfg.Upstreams[i] = nextUpstream
			changed = true
		}
		break
	}
	if !upstreamFound {
		cfg.Upstreams = append(cfg.Upstreams, nextUpstream)
		changed = true
	}

	for _, nextRoute := range centerProtectedGatewayRoutes(routeCfg) {
		routeFound := false
		for i := range cfg.Routes {
			if cfg.Routes[i].Name != nextRoute.Name {
				continue
			}
			routeFound = true
			if mustJSON(cfg.Routes[i]) != mustJSON(nextRoute) {
				cfg.Routes[i] = nextRoute
				changed = true
			}
			break
		}
		if !routeFound {
			cfg.Routes = append(cfg.Routes, nextRoute)
			changed = true
		}
	}
	if strings.TrimSpace(cfg.HealthCheckPath) == "" {
		cfg.HealthCheckPath = "/healthz"
		changed = true
	}
	if !changed {
		return nil
	}
	_, err = store.writeProxyConfigVersion(rec.ETag, cfg, configVersionSourceApply, centerProtectedBootstrapActor, "center-protected proxy route bootstrap", 0)
	return err
}

func centerProtectedGatewayRoutes(routeCfg centerProtectedGatewayRouteConfig) []ProxyRoute {
	apiAction := ProxyRouteAction{Upstream: centerProtectedUpstreamName}
	if routeCfg.GatewayAPIBasePath != routeCfg.CenterAPIBasePath {
		apiAction.PathRewrite = &ProxyRoutePathRewrite{Prefix: routeCfg.CenterAPIBasePath}
	}
	return []ProxyRoute{
		{
			Name:     "center-api",
			Priority: 10,
			Match: ProxyRouteMatch{Path: &ProxyRoutePathMatch{
				Type:  "prefix",
				Value: routeCfg.GatewayAPIBasePath,
			}},
			Action: apiAction,
		},
		{
			Name:     "center-ui",
			Priority: 20,
			Match: ProxyRouteMatch{Path: &ProxyRoutePathMatch{
				Type:  "prefix",
				Value: routeCfg.CenterUIBasePath,
			}},
			Action: ProxyRouteAction{Upstream: centerProtectedUpstreamName},
		},
	}
}

func normalizeCenterProtectedGatewayRouteConfig(opts CenterProtectedGatewayBootstrapOptions) (centerProtectedGatewayRouteConfig, error) {
	gatewayAPIBase, err := normalizeCenterProtectedGatewayBasePath(opts.GatewayAPIBasePath, centerProtectedDefaultGatewayAPIPath)
	if err != nil {
		return centerProtectedGatewayRouteConfig{}, fmt.Errorf("gateway api base path: %w", err)
	}
	centerAPIBase, err := normalizeCenterProtectedGatewayBasePath(opts.CenterAPIBasePath, centerProtectedDefaultCenterAPIPath)
	if err != nil {
		return centerProtectedGatewayRouteConfig{}, fmt.Errorf("center api base path: %w", err)
	}
	centerUIBase, err := normalizeCenterProtectedGatewayBasePath(opts.CenterUIBasePath, centerProtectedDefaultCenterUIPath)
	if err != nil {
		return centerProtectedGatewayRouteConfig{}, fmt.Errorf("center ui base path: %w", err)
	}
	if gatewayAPIBase == centerUIBase {
		return centerProtectedGatewayRouteConfig{}, fmt.Errorf("gateway api base path and center ui base path must differ")
	}
	if centerAPIBase == centerUIBase {
		return centerProtectedGatewayRouteConfig{}, fmt.Errorf("center api base path and center ui base path must differ")
	}
	return centerProtectedGatewayRouteConfig{
		GatewayAPIBasePath: gatewayAPIBase,
		CenterAPIBasePath:  centerAPIBase,
		CenterUIBasePath:   centerUIBase,
	}, nil
}

func normalizeCenterProtectedGatewayBasePath(raw, fallback string) (string, error) {
	base := strings.TrimSpace(raw)
	if base == "" {
		base = fallback
	}
	if base == "" {
		return "", fmt.Errorf("base path is empty")
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	for _, segment := range strings.Split(base, "/") {
		switch segment {
		case ".", "..":
			return "", fmt.Errorf("base path must not contain dot segments")
		}
	}
	clean := path.Clean(base)
	if clean == "." || clean == "/" {
		return "", fmt.Errorf("base path must not be root")
	}
	if strings.Contains(clean, "*") {
		return "", fmt.Errorf("base path must not contain wildcard")
	}
	return clean, nil
}

func centerProtectedBypassPaths(routeCfg centerProtectedGatewayRouteConfig) []string {
	seen := map[string]struct{}{}
	paths := make([]string, 0, 3)
	for _, raw := range []string{routeCfg.GatewayAPIBasePath, routeCfg.CenterAPIBasePath, routeCfg.CenterUIBasePath} {
		path := strings.TrimRight(strings.TrimSpace(raw), "/")
		if path == "" {
			continue
		}
		if _, ok := seen[path]; ok {
			continue
		}
		seen[path] = struct{}{}
		paths = append(paths, path)
	}
	return paths
}

func bootstrapCenterProtectedGatewayWAFBypass(store *wafEventStore, protectedPaths []string) error {
	spec := mustPolicyJSONSpec(bypassConfigBlobKey)
	raw, rec, found, err := store.loadActivePolicyJSONConfig(spec)
	if err != nil {
		return err
	}
	if !found {
		return nil
	}
	file, err := bypassconf.Parse(string(raw))
	if err != nil {
		return err
	}
	file, changed := removeCenterProtectedBypassEntries(file, protectedPaths)
	if !changed {
		return nil
	}
	normalized, err := bypassconf.MarshalJSON(file)
	if err != nil {
		return err
	}
	expectedETag := ""
	if found {
		expectedETag = rec.ETag
	}
	_, err = store.writePolicyJSONConfigVersion(expectedETag, spec, normalized, configVersionSourceApply, centerProtectedBootstrapActor, "center-protected WAF bypass bootstrap", 0)
	return err
}

func removeCenterProtectedBypassEntries(file bypassconf.File, protectedPaths []string) (bypassconf.File, bool) {
	changed := false
	protectedPathSet := centerProtectedBypassPathSet(protectedPaths)
	file.Default.Entries, changed = filterCenterProtectedBypassEntries(file.Default.Entries, protectedPathSet)
	for host, scope := range file.Hosts {
		var scopeChanged bool
		scope.Entries, scopeChanged = filterCenterProtectedBypassEntries(scope.Entries, protectedPathSet)
		if scopeChanged {
			file.Hosts[host] = scope
			changed = true
		}
	}
	return file, changed
}

func centerProtectedBypassPathSet(protectedPaths []string) map[string]struct{} {
	if len(protectedPaths) == 0 {
		protectedPaths = []string{centerProtectedDefaultGatewayAPIPath, centerProtectedDefaultCenterUIPath}
	}
	set := make(map[string]struct{}, len(protectedPaths))
	for _, raw := range protectedPaths {
		path := strings.TrimRight(strings.TrimSpace(raw), "/")
		if path != "" {
			set[path] = struct{}{}
		}
	}
	return set
}

func filterCenterProtectedBypassEntries(entries []bypassconf.Entry, protectedPathSet map[string]struct{}) ([]bypassconf.Entry, bool) {
	out := entries[:0]
	changed := false
	for _, entry := range entries {
		if isCenterProtectedBypassEntry(entry, protectedPathSet) {
			changed = true
			continue
		}
		out = append(out, entry)
	}
	return out, changed
}

func isCenterProtectedBypassEntry(entry bypassconf.Entry, protectedPathSet map[string]struct{}) bool {
	if strings.TrimSpace(entry.ExtraRule) != "" {
		return false
	}
	_, ok := protectedPathSet[strings.TrimRight(strings.TrimSpace(entry.Path), "/")]
	return ok
}

func edgeCanMarkBootstrapApproved(status string) bool {
	switch normalizeEdgeStatus(status) {
	case "", edgeEnrollmentStatusApproved, edgeEnrollmentStatusFailed, edgeEnrollmentStatusLocal, edgeEnrollmentStatusPending, edgeEnrollmentStatusUnconfigured:
		return true
	default:
		return false
	}
}

func edgeDevicePublicKeyPEM(identity edgeDeviceIdentityRecord) (string, error) {
	_, publicDER, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return "", err
	}
	publicPEM := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})))
	if publicPEM == "" {
		return "", fmt.Errorf("device public key is empty")
	}
	return publicPEM + "\n", nil
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

func centerRuntimeArtifactDownloadURL(centerBaseURL string) (string, error) {
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
	u.Path = "/v1/runtime-artifact-download"
	u.RawPath = ""
	return u.String(), nil
}

func centerProxyRulesBundleDownloadURL(centerBaseURL string) (string, error) {
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
	u.Path = "/v1/proxy-rules-bundle-download"
	u.RawPath = ""
	return u.String(), nil
}

func centerWAFRuleArtifactDownloadURL(centerBaseURL string) (string, error) {
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
	u.Path = "/v1/waf-rule-artifact-download"
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
	platform := currentEdgeGatewayPlatformMetadata()
	req.OS = platform.OS
	req.Arch = platform.Arch
	req.KernelVersion = platform.KernelVersion
	req.DistroID = platform.DistroID
	req.DistroIDLike = platform.DistroIDLike
	req.DistroVersion = platform.DistroVersion
	req.RuntimeDeploymentSupported = true
	req.RuntimeInventory = currentEdgeRuntimeInventorySummary()
	req.ProxyRuleApplyStatus = edgeProxyRuleApplyStatusSnapshot()
	req.WAFRuleApplyStatus = edgeWAFRuleApplyStatusSnapshot()
	req.BodyHash = edgeDeviceStatusBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func currentEdgeRuntimeInventorySummary() []edgeDeviceRuntimeSummary {
	out := make([]edgeDeviceRuntimeSummary, 0, 8)
	_, _, phpInventory, _ := PHPRuntimeInventorySnapshot()
	phpTargetsByRuntime := edgePHPRuntimeGeneratedTargets()
	phpRunningByRuntime := edgePHPRuntimeRunningState()
	for _, runtime := range phpInventory.Runtimes {
		runtimeID := clampEdgeMetadataText(runtime.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		targets := phpTargetsByRuntime[runtimeID]
		summary := edgeDeviceRuntimeSummary{
			RuntimeFamily:       "php-fpm",
			RuntimeID:           runtimeID,
			DisplayName:         clampEdgeMetadataText(runtime.DisplayName, 128),
			DetectedVersion:     clampEdgeMetadataText(runtime.DetectedVersion, 128),
			Source:              clampEdgeMetadataText(runtime.Source, 32),
			Available:           runtime.Available,
			AvailabilityMessage: clampEdgeMetadataText(runtime.AvailabilityMessage, 256),
			ModuleCount:         len(runtime.Modules),
			UsageReported:       true,
			AppCount:            len(targets),
			GeneratedTargets:    targets,
			ProcessRunning:      phpRunningByRuntime[runtimeID],
			ArtifactRevision:    normalizeEdgeHex64(runtime.ArtifactRevision),
			ArtifactHash:        normalizeEdgeHex64(runtime.SHA256),
		}
		if summary.ArtifactRevision != "" && summary.ArtifactHash != "" {
			summary.ApplyState = "installed"
		}
		out = append(out, summary)
	}
	_, _, psgiInventory, _ := PSGIRuntimeInventorySnapshot()
	psgiTargetsByRuntime := edgePSGIRuntimeGeneratedTargets()
	psgiRunningByRuntime := edgePSGIRuntimeRunningState()
	for _, runtime := range psgiInventory.Runtimes {
		runtimeID := clampEdgeMetadataText(runtime.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		targets := psgiTargetsByRuntime[runtimeID]
		summary := edgeDeviceRuntimeSummary{
			RuntimeFamily:       "psgi",
			RuntimeID:           runtimeID,
			DisplayName:         clampEdgeMetadataText(runtime.DisplayName, 128),
			DetectedVersion:     clampEdgeMetadataText(runtime.DetectedVersion, 128),
			Source:              clampEdgeMetadataText(runtime.Source, 32),
			Available:           runtime.Available,
			AvailabilityMessage: clampEdgeMetadataText(runtime.AvailabilityMessage, 256),
			ModuleCount:         len(runtime.Modules),
			UsageReported:       true,
			AppCount:            len(targets),
			GeneratedTargets:    targets,
			ProcessRunning:      psgiRunningByRuntime[runtimeID],
			ArtifactRevision:    normalizeEdgeHex64(runtime.ArtifactRevision),
			ArtifactHash:        normalizeEdgeHex64(runtime.SHA256),
		}
		if summary.ArtifactRevision != "" && summary.ArtifactHash != "" {
			summary.ApplyState = "installed"
		}
		out = append(out, summary)
	}
	applyStatuses := edgeRuntimeApplyStatusSnapshot()
	seen := make(map[string]struct{}, len(out))
	for i := range out {
		key := edgeRuntimeAssignmentKey(out[i].RuntimeFamily, out[i].RuntimeID)
		seen[key] = struct{}{}
		if status, ok := applyStatuses[key]; ok {
			out[i].ApplyState = clampEdgeMetadataText(status.ApplyState, 32)
			out[i].ApplyError = clampEdgeMetadataText(status.ApplyError, 256)
			out[i].ArtifactRevision = normalizeEdgeHex64(status.ArtifactRevision)
			if status.ArtifactHash != "" {
				out[i].ArtifactHash = normalizeEdgeHex64(status.ArtifactHash)
			}
		}
	}
	for key, status := range applyStatuses {
		if _, ok := seen[key]; ok || strings.TrimSpace(status.ApplyState) == "" {
			continue
		}
		out = append(out, edgeDeviceRuntimeSummary{
			RuntimeFamily:    status.RuntimeFamily,
			RuntimeID:        status.RuntimeID,
			Source:           "center",
			Available:        false,
			UsageReported:    true,
			ArtifactRevision: normalizeEdgeHex64(status.ArtifactRevision),
			ArtifactHash:     normalizeEdgeHex64(status.ArtifactHash),
			ApplyState:       clampEdgeMetadataText(status.ApplyState, 32),
			ApplyError:       clampEdgeMetadataText(status.ApplyError, 256),
		})
	}
	sortEdgeRuntimeSummaries(out)
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func edgePHPRuntimeGeneratedTargets() map[string][]string {
	out := map[string][]string{}
	for _, mat := range PHPRuntimeMaterializationSnapshot() {
		runtimeID := clampEdgeMetadataText(mat.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		targets := append([]string(nil), mat.GeneratedTarget...)
		for i := range targets {
			targets[i] = clampEdgeMetadataText(targets[i], 128)
		}
		targets = uniqueSortedNonEmptyStrings(targets, 64)
		out[runtimeID] = targets
	}
	return out
}

func edgePHPRuntimeRunningState() map[string]bool {
	out := map[string]bool{}
	for _, proc := range PHPRuntimeProcessSnapshot() {
		runtimeID := clampEdgeMetadataText(proc.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		out[runtimeID] = proc.Running
	}
	return out
}

func edgePSGIRuntimeGeneratedTargets() map[string][]string {
	out := map[string][]string{}
	for _, mat := range PSGIRuntimeMaterializationSnapshot() {
		runtimeID := clampEdgeMetadataText(mat.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		target := clampEdgeMetadataText(mat.GeneratedTarget, 128)
		out[runtimeID] = append(out[runtimeID], target)
	}
	for runtimeID, targets := range out {
		out[runtimeID] = uniqueSortedNonEmptyStrings(targets, 64)
	}
	return out
}

func edgePSGIRuntimeRunningState() map[string]bool {
	out := map[string]bool{}
	for _, proc := range PSGIRuntimeProcessSnapshot() {
		runtimeID := clampEdgeMetadataText(proc.RuntimeID, 64)
		if runtimeID == "" {
			continue
		}
		out[runtimeID] = out[runtimeID] || proc.Running
	}
	return out
}

func runningEdgePSGIProcessIDs(runtimeID string) []string {
	runtimeID = clampEdgeMetadataText(runtimeID, 64)
	out := []string{}
	for _, proc := range PSGIRuntimeProcessSnapshot() {
		if !proc.Running || clampEdgeMetadataText(proc.RuntimeID, 64) != runtimeID {
			continue
		}
		processID := normalizeConfigToken(proc.ProcessID)
		if processID != "" {
			out = append(out, processID)
		}
	}
	sort.Strings(out)
	return out
}

func sortEdgeRuntimeSummaries(items []edgeDeviceRuntimeSummary) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].RuntimeFamily != items[j].RuntimeFamily {
			return items[i].RuntimeFamily < items[j].RuntimeFamily
		}
		return items[i].RuntimeID < items[j].RuntimeID
	})
}

func uniqueSortedNonEmptyStrings(items []string, limit int) []string {
	if len(items) == 0 || limit <= 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func edgeRuntimeAssignmentKey(runtimeFamily, runtimeID string) string {
	return strings.TrimSpace(runtimeFamily) + "\x00" + strings.TrimSpace(runtimeID)
}

func edgeRuntimeApplyStatusSnapshot() map[string]edgeRuntimeApplyStatus {
	edgeRuntimeApplyStatusMu.RLock()
	defer edgeRuntimeApplyStatusMu.RUnlock()
	out := make(map[string]edgeRuntimeApplyStatus, len(edgeRuntimeApplyStatuses))
	for key, status := range edgeRuntimeApplyStatuses {
		out[key] = status
	}
	return out
}

func setEdgeRuntimeApplyStatus(status edgeRuntimeApplyStatus) {
	status.RuntimeFamily, status.RuntimeID, _ = normalizeEdgeRuntimeAssignmentIdentity(status.RuntimeFamily, status.RuntimeID)
	if status.RuntimeFamily == "" || status.RuntimeID == "" {
		return
	}
	status.ArtifactRevision = normalizeEdgeHex64(status.ArtifactRevision)
	status.ArtifactHash = normalizeEdgeHex64(status.ArtifactHash)
	status.ApplyState = clampEdgeMetadataText(status.ApplyState, 32)
	status.ApplyError = clampEdgeMetadataText(status.ApplyError, 256)
	edgeRuntimeApplyStatusMu.Lock()
	edgeRuntimeApplyStatuses[edgeRuntimeAssignmentKey(status.RuntimeFamily, status.RuntimeID)] = status
	edgeRuntimeApplyStatusMu.Unlock()
}

func edgeProxyRuleApplyStatusSnapshot() *edgeProxyRuleApplyStatus {
	edgeProxyRuleApplyStatusMu.RLock()
	defer edgeProxyRuleApplyStatusMu.RUnlock()
	if edgeProxyRuleApplyStatusCurrent == nil {
		return nil
	}
	out := *edgeProxyRuleApplyStatusCurrent
	return &out
}

func setEdgeProxyRuleApplyStatus(status edgeProxyRuleApplyStatus) {
	status.DesiredBundleRevision = normalizeEdgeHex64(status.DesiredBundleRevision)
	status.LocalProxyETag = clampEdgeMetadataText(status.LocalProxyETag, 128)
	status.ApplyState = clampEdgeMetadataText(status.ApplyState, 32)
	status.ApplyError = clampEdgeMetadataText(status.ApplyError, 256)
	if status.DesiredBundleRevision == "" && status.LocalProxyETag == "" && status.ApplyState == "" && status.ApplyError == "" {
		return
	}
	edgeProxyRuleApplyStatusMu.Lock()
	edgeProxyRuleApplyStatusCurrent = &status
	edgeProxyRuleApplyStatusMu.Unlock()
}

func edgeWAFRuleApplyStatusSnapshot() *edgeWAFRuleApplyStatus {
	edgeWAFRuleApplyStatusMu.RLock()
	defer edgeWAFRuleApplyStatusMu.RUnlock()
	if edgeWAFRuleApplyStatusCurrent == nil {
		return nil
	}
	out := *edgeWAFRuleApplyStatusCurrent
	return &out
}

func setEdgeWAFRuleApplyStatus(status edgeWAFRuleApplyStatus) {
	status.DesiredBundleRevision = normalizeEdgeHex64(status.DesiredBundleRevision)
	status.LocalBundleRevision = normalizeEdgeHex64(status.LocalBundleRevision)
	status.ApplyState = clampEdgeMetadataText(status.ApplyState, 32)
	status.ApplyError = clampEdgeMetadataText(status.ApplyError, 256)
	if status.DesiredBundleRevision == "" && status.LocalBundleRevision == "" && status.ApplyState == "" && status.ApplyError == "" {
		return
	}
	edgeWAFRuleApplyStatusMu.Lock()
	edgeWAFRuleApplyStatusCurrent = &status
	edgeWAFRuleApplyStatusMu.Unlock()
}

func pruneCompletedEdgeProxyRuleApplyStatus(assignment *edgeProxyRuleDeviceAssignment) {
	if assignment != nil {
		return
	}
	edgeProxyRuleApplyStatusMu.Lock()
	defer edgeProxyRuleApplyStatusMu.Unlock()
	if edgeProxyRuleApplyStatusCurrent == nil {
		return
	}
	switch edgeProxyRuleApplyStatusCurrent.ApplyState {
	case "applied", "failed", "blocked":
		edgeProxyRuleApplyStatusCurrent = nil
	}
}

func pruneCompletedEdgeWAFRuleApplyStatus(assignment *edgeWAFRuleDeviceAssignment) {
	if assignment != nil {
		return
	}
	edgeWAFRuleApplyStatusMu.Lock()
	defer edgeWAFRuleApplyStatusMu.Unlock()
	if edgeWAFRuleApplyStatusCurrent == nil {
		return
	}
	switch edgeWAFRuleApplyStatusCurrent.ApplyState {
	case "applied", "failed", "blocked":
		edgeWAFRuleApplyStatusCurrent = nil
	}
}

func pruneCompletedEdgeRuntimeApplyStatuses(assignments []edgeRuntimeDeviceAssignment) {
	desired := make(map[string]struct{}, len(assignments))
	for _, assignment := range assignments {
		family, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(assignment.RuntimeFamily, assignment.RuntimeID)
		if err != nil {
			continue
		}
		desired[edgeRuntimeAssignmentKey(family, runtimeID)] = struct{}{}
	}
	edgeRuntimeApplyStatusMu.Lock()
	for key, status := range edgeRuntimeApplyStatuses {
		if status.ApplyState != "removed" {
			continue
		}
		if _, ok := desired[key]; !ok {
			delete(edgeRuntimeApplyStatuses, key)
		}
	}
	edgeRuntimeApplyStatusMu.Unlock()
}

func beginEdgeProxyRuleAssignmentOp() bool {
	edgeProxyRuleAssignmentMu.Lock()
	defer edgeProxyRuleAssignmentMu.Unlock()
	if edgeProxyRuleAssignmentActive {
		return false
	}
	edgeProxyRuleAssignmentActive = true
	return true
}

func endEdgeProxyRuleAssignmentOp() {
	edgeProxyRuleAssignmentMu.Lock()
	edgeProxyRuleAssignmentActive = false
	edgeProxyRuleAssignmentMu.Unlock()
}

func beginEdgeWAFRuleAssignmentOp() bool {
	edgeWAFRuleAssignmentMu.Lock()
	defer edgeWAFRuleAssignmentMu.Unlock()
	if edgeWAFRuleAssignmentActive {
		return false
	}
	edgeWAFRuleAssignmentActive = true
	return true
}

func endEdgeWAFRuleAssignmentOp() {
	edgeWAFRuleAssignmentMu.Lock()
	edgeWAFRuleAssignmentActive = false
	edgeWAFRuleAssignmentMu.Unlock()
}

func beginEdgeRuntimeAssignmentOp(runtimeFamily, runtimeID string) bool {
	key := edgeRuntimeAssignmentKey(runtimeFamily, runtimeID)
	edgeRuntimeAssignmentMu.Lock()
	defer edgeRuntimeAssignmentMu.Unlock()
	if _, ok := edgeRuntimeAssignmentActive[key]; ok {
		return false
	}
	edgeRuntimeAssignmentActive[key] = struct{}{}
	return true
}

func endEdgeRuntimeAssignmentOp(runtimeFamily, runtimeID string) {
	key := edgeRuntimeAssignmentKey(runtimeFamily, runtimeID)
	edgeRuntimeAssignmentMu.Lock()
	delete(edgeRuntimeAssignmentActive, key)
	edgeRuntimeAssignmentMu.Unlock()
}

func applyEdgeProxyRuleAssignment(ctx context.Context, identity edgeDeviceIdentityRecord, assignment *edgeProxyRuleDeviceAssignment) {
	if assignment == nil {
		return
	}
	normalized, ok := normalizeEdgeProxyRuleAssignment(*assignment)
	if !ok {
		return
	}
	if !beginEdgeProxyRuleAssignmentOp() {
		return
	}
	defer endEdgeProxyRuleAssignmentOp()

	status := edgeProxyRuleApplyStatus{
		DesiredBundleRevision: normalized.BundleRevision,
		ApplyState:            "applying",
	}
	setEdgeProxyRuleApplyStatus(status)

	_, currentETag, _, _, _ := ProxyRulesSnapshot()
	if normalized.SourceProxyETag == "" {
		status.ApplyState = "blocked"
		status.LocalProxyETag = currentETag
		status.ApplyError = "proxy rules assignment is missing base etag"
		setEdgeProxyRuleApplyStatus(status)
		return
	}
	if !edgeProxyRuleAssignmentBaseMatches(currentETag, normalized.SourceProxyETag) {
		status.ApplyState = "blocked"
		status.LocalProxyETag = currentETag
		status.ApplyError = "local proxy rules changed after assignment"
		setEdgeProxyRuleApplyStatus(status)
		return
	}

	raw, err := downloadEdgeProxyRuleBundle(ctx, identity, normalized)
	if err != nil {
		status.ApplyState = "failed"
		status.LocalProxyETag = currentETag
		status.ApplyError = err.Error()
		setEdgeProxyRuleApplyStatus(status)
		return
	}
	nextETag, _, err := applyProxyRulesRaw(currentETag, string(raw), "center:"+identity.DeviceID)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			status.ApplyState = "blocked"
			status.LocalProxyETag = conflict.CurrentETag
			status.ApplyError = "local proxy rules changed during assignment"
			setEdgeProxyRuleApplyStatus(status)
			return
		}
		status.ApplyState = "failed"
		status.LocalProxyETag = currentETag
		status.ApplyError = err.Error()
		setEdgeProxyRuleApplyStatus(status)
		return
	}
	status.ApplyState = "applied"
	status.LocalProxyETag = nextETag
	status.ApplyError = ""
	setEdgeProxyRuleApplyStatus(status)
}

func edgeProxyRuleAssignmentBaseMatches(currentETag, sourceETag string) bool {
	currentETag = strings.TrimSpace(currentETag)
	sourceETag = strings.TrimSpace(sourceETag)
	if currentETag == "" || sourceETag == "" {
		return false
	}
	return currentETag == sourceETag || configVersionETagSameContent(currentETag, sourceETag)
}

func normalizeEdgeProxyRuleAssignment(in edgeProxyRuleDeviceAssignment) (edgeProxyRuleDeviceAssignment, bool) {
	out := edgeProxyRuleDeviceAssignment{
		BundleRevision:  normalizeEdgeHex64(in.BundleRevision),
		PayloadHash:     normalizeEdgeHex64(in.PayloadHash),
		PayloadETag:     clampEdgeMetadataText(in.PayloadETag, 128),
		SourceProxyETag: clampEdgeMetadataText(in.SourceProxyETag, 128),
		SizeBytes:       in.SizeBytes,
		AssignedAtUnix:  in.AssignedAtUnix,
	}
	if out.BundleRevision == "" || out.PayloadHash == "" || out.PayloadETag == "" {
		return edgeProxyRuleDeviceAssignment{}, false
	}
	if out.SizeBytes < 0 || out.SizeBytes > edgeProxyRuleBundleMaxBytes {
		return edgeProxyRuleDeviceAssignment{}, false
	}
	return out, true
}

func downloadEdgeProxyRuleBundle(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeProxyRuleDeviceAssignment) ([]byte, error) {
	downloadURL, err := centerProxyRulesBundleDownloadURL(identity.CenterURL)
	if err != nil {
		return nil, err
	}
	wireReq, err := signedEdgeProxyRulesBundleDownloadRequest(identity, assignment)
	if err != nil {
		return nil, err
	}
	maxBytes := assignment.SizeBytes
	if maxBytes <= 0 {
		maxBytes = edgeProxyRuleBundleMaxBytes
	}
	centerHTTPStatus, body, err := sendEdgeProxyRulesBundleDownload(ctx, downloadURL, wireReq, maxBytes)
	if err != nil {
		return nil, err
	}
	if centerHTTPStatus < 200 || centerHTTPStatus >= 300 {
		return nil, fmt.Errorf("%s", centerHTTPErrorMessage("center proxy rules bundle download failed", centerHTTPStatus, body))
	}
	if len(body) == 0 || len(body) > edgeProxyRuleBundleMaxBytes {
		return nil, fmt.Errorf("proxy rules bundle size is invalid")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != assignment.PayloadHash {
		return nil, fmt.Errorf("proxy rules bundle hash mismatch")
	}
	if etag := bypassconf.ComputeETag(body); etag != assignment.PayloadETag {
		return nil, fmt.Errorf("proxy rules bundle etag mismatch")
	}
	return body, nil
}

func applyEdgeWAFRuleAssignment(ctx context.Context, identity *edgeDeviceIdentityRecord, assignment *edgeWAFRuleDeviceAssignment) {
	if identity == nil || assignment == nil {
		return
	}
	normalized, ok := normalizeEdgeWAFRuleAssignment(*assignment)
	if !ok {
		return
	}
	if !beginEdgeWAFRuleAssignmentOp() {
		return
	}
	defer endEdgeWAFRuleAssignmentOp()

	status := edgeWAFRuleApplyStatus{
		DesiredBundleRevision: normalized.BundleRevision,
		ApplyState:            "applying",
	}
	setEdgeWAFRuleApplyStatus(status)

	currentRevision, err := currentEdgeWAFRuleBundleRevision()
	if err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeWAFRuleApplyStatus(status)
		return
	}
	status.LocalBundleRevision = currentRevision
	if normalized.BaseBundleRevision != "" && currentRevision != normalized.BaseBundleRevision {
		status.ApplyState = "blocked"
		status.ApplyError = "local WAF rules changed after assignment"
		setEdgeWAFRuleApplyStatus(status)
		return
	}

	artifact, err := downloadEdgeWAFRuleArtifact(ctx, *identity, normalized)
	if err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeWAFRuleApplyStatus(status)
		return
	}
	if err := applyEdgeWAFRuleArtifactBundle(artifact); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeWAFRuleApplyStatus(status)
		return
	}
	now := time.Now().UTC().Unix()
	identity.RuleArtifactRevision = artifact.Revision
	identity.RuleArtifactPushedAtUnix = now
	identity.RuleArtifactError = ""
	status.LocalBundleRevision = artifact.Revision
	status.ApplyState = "applied"
	status.ApplyError = ""
	setEdgeWAFRuleApplyStatus(status)
}

func currentEdgeWAFRuleBundleRevision() (string, error) {
	bundle, found, err := buildEdgeRuleArtifactBundle()
	if err != nil {
		return "", err
	}
	if !found {
		return "", fmt.Errorf("current WAF rule assets are not initialized")
	}
	return bundle.Revision, nil
}

func normalizeEdgeWAFRuleAssignment(in edgeWAFRuleDeviceAssignment) (edgeWAFRuleDeviceAssignment, bool) {
	out := edgeWAFRuleDeviceAssignment{
		BundleRevision:     normalizeEdgeHex64(in.BundleRevision),
		BaseBundleRevision: normalizeEdgeHex64(in.BaseBundleRevision),
		CompressedSize:     in.CompressedSize,
		UncompressedSize:   in.UncompressedSize,
		FileCount:          in.FileCount,
		AssignedAtUnix:     in.AssignedAtUnix,
	}
	if out.BundleRevision == "" {
		return edgeWAFRuleDeviceAssignment{}, false
	}
	if out.CompressedSize <= 0 || out.CompressedSize > edgeartifactbundle.MaxCompressedBytes ||
		out.UncompressedSize <= 0 || out.UncompressedSize > edgeartifactbundle.MaxUncompressedBytes ||
		out.FileCount <= 0 || out.FileCount > edgeartifactbundle.MaxFiles {
		return edgeWAFRuleDeviceAssignment{}, false
	}
	return out, true
}

func downloadEdgeWAFRuleArtifact(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeWAFRuleDeviceAssignment) (edgeartifactbundle.Parsed, error) {
	downloadURL, err := centerWAFRuleArtifactDownloadURL(identity.CenterURL)
	if err != nil {
		return edgeartifactbundle.Parsed{}, err
	}
	wireReq, err := signedEdgeWAFRuleArtifactDownloadRequest(identity, assignment)
	if err != nil {
		return edgeartifactbundle.Parsed{}, err
	}
	httpStatus, body, err := sendEdgeWAFRuleArtifactDownload(ctx, downloadURL, wireReq, assignment.CompressedSize)
	if err != nil {
		return edgeartifactbundle.Parsed{}, err
	}
	if httpStatus < 200 || httpStatus >= 300 {
		return edgeartifactbundle.Parsed{}, fmt.Errorf("%s", centerHTTPErrorMessage("center WAF rule artifact download failed", httpStatus, body))
	}
	if int64(len(body)) != assignment.CompressedSize {
		return edgeartifactbundle.Parsed{}, fmt.Errorf("WAF rule artifact compressed size mismatch")
	}
	parsed, err := edgeartifactbundle.Parse(body)
	if err != nil {
		return edgeartifactbundle.Parsed{}, err
	}
	if parsed.Revision != assignment.BundleRevision ||
		parsed.CompressedSize != assignment.CompressedSize ||
		parsed.UncompressedSize != assignment.UncompressedSize ||
		parsed.FileCount != assignment.FileCount {
		return edgeartifactbundle.Parsed{}, fmt.Errorf("WAF rule artifact metadata mismatch")
	}
	return parsed, nil
}

func applyEdgeWAFRuleArtifactBundle(parsed edgeartifactbundle.Parsed) error {
	if parsed.Revision == "" || len(parsed.Files) == 0 {
		return fmt.Errorf("WAF rule artifact is empty")
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("config DB store is not initialized")
	}
	currentAssets, currentRec, found, err := store.loadActiveWAFRuleAssets()
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("current WAF rule assets are not initialized")
	}
	next := make([]wafRuleAssetVersion, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		next = append(next, wafRuleAssetVersion{
			Path:     file.Path,
			Kind:     file.Kind,
			Raw:      append([]byte(nil), file.Body...),
			ETag:     file.ETag,
			Disabled: file.Disabled,
		})
	}
	normalizedNext := normalizeWAFRuleAssets(next)
	if len(normalizedNext) != len(next) {
		return fmt.Errorf("WAF rule artifact contains unsupported asset paths")
	}
	nextRec, _, err := store.writeWAFRuleAssetsVersion(
		currentRec.ETag,
		normalizedNext,
		configVersionSourceApply,
		"center",
		"center WAF rule artifact assignment",
		0,
	)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return fmt.Errorf("local WAF rules changed during assignment")
		}
		return err
	}
	if err := reloadWAFRuleAssetsAfterCenterApply(normalizedNext); err != nil {
		_, _, rollbackErr := store.writeWAFRuleAssetsVersion(
			nextRec.ETag,
			currentAssets,
			configVersionSourceRollback,
			"center",
			"rollback failed center WAF rule artifact assignment",
			currentRec.VersionID,
		)
		_ = waf.ReloadBaseWAF()
		if rollbackErr != nil {
			return fmt.Errorf("reload WAF after assignment: %w; rollback failed: %v", err, rollbackErr)
		}
		return fmt.Errorf("reload WAF after assignment: %w", err)
	}
	return nil
}

func reloadWAFRuleAssetsAfterCenterApply(assets []wafRuleAssetVersion) error {
	if err := waf.ReloadBaseWAF(); err != nil {
		return err
	}
	for _, asset := range normalizeWAFRuleAssets(assets) {
		if asset.Kind == wafRuleAssetKindBypassExtra {
			waf.InvalidateOverrideWAF(asset.Path)
		}
	}
	return nil
}

func normalizeEdgeRuntimeAssignmentIdentity(runtimeFamily, runtimeID string) (string, string, error) {
	family := strings.TrimSpace(runtimeFamily)
	id := strings.TrimSpace(runtimeID)
	switch family {
	case "php-fpm":
		switch id {
		case "php83", "php84", "php85":
		default:
			return "", "", fmt.Errorf("unsupported runtime id")
		}
	case "psgi":
		switch id {
		case "perl536", "perl538", "perl540":
		default:
			return "", "", fmt.Errorf("unsupported runtime id")
		}
	default:
		return "", "", fmt.Errorf("unsupported runtime family")
	}
	return family, id, nil
}

func applyEdgeRuntimeAssignments(ctx context.Context, identity edgeDeviceIdentityRecord, assignments []edgeRuntimeDeviceAssignment) {
	if len(assignments) == 0 {
		return
	}
	items := append([]edgeRuntimeDeviceAssignment(nil), assignments...)
	sort.Slice(items, func(i, j int) bool {
		if items[i].RuntimeFamily != items[j].RuntimeFamily {
			return items[i].RuntimeFamily < items[j].RuntimeFamily
		}
		return items[i].RuntimeID < items[j].RuntimeID
	})
	for _, assignment := range items {
		switch strings.TrimSpace(assignment.DesiredState) {
		case "installed":
			applyEdgeRuntimeInstall(ctx, identity, assignment)
		case "removed":
			applyEdgeRuntimeRemoval(assignment)
		default:
			continue
		}
	}
}

func applyEdgeRuntimeInstall(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeRuntimeDeviceAssignment) {
	family, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(assignment.RuntimeFamily, assignment.RuntimeID)
	if err != nil {
		return
	}
	switch family {
	case "php-fpm":
		applyEdgePHPRuntimeInstall(ctx, identity, assignment, runtimeID)
	case "psgi":
		applyEdgePSGIRuntimeInstall(ctx, identity, assignment, runtimeID)
	default:
		setEdgeRuntimeApplyStatus(edgeRuntimeApplyStatus{
			RuntimeFamily:    family,
			RuntimeID:        runtimeID,
			ArtifactRevision: assignment.ArtifactRevision,
			ArtifactHash:     assignment.ArtifactHash,
			ApplyState:       "failed",
			ApplyError:       "runtime install is not supported for this runtime family",
		})
	}
}

func applyEdgePHPRuntimeInstall(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeRuntimeDeviceAssignment, runtimeID string) {
	family := "php-fpm"
	if !beginEdgeRuntimeAssignmentOp(family, runtimeID) {
		return
	}
	defer endEdgeRuntimeAssignmentOp(family, runtimeID)

	status := edgeRuntimeApplyStatus{
		RuntimeFamily:    family,
		RuntimeID:        runtimeID,
		ArtifactRevision: assignment.ArtifactRevision,
		ArtifactHash:     assignment.ArtifactHash,
		ApplyState:       "installing",
	}
	setEdgeRuntimeApplyStatus(status)

	wasRunning := edgePHPRuntimeRunningState()[runtimeID]
	if wasRunning {
		status.ApplyState = "stopping"
		setEdgeRuntimeApplyStatus(status)
		if err := StopPHPRuntimeProcess(runtimeID); err != nil {
			status.ApplyState = "failed"
			status.ApplyError = err.Error()
			setEdgeRuntimeApplyStatus(status)
			return
		}
	}
	artifact, err := downloadEdgeRuntimeArtifact(ctx, identity, assignment)
	if err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := installEdgePHPRuntimeArtifact(artifact.Compressed, artifact.Parsed, assignment); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := RefreshPHPRuntimeMaterialization(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if wasRunning {
		if err := StartPHPRuntimeProcess(runtimeID); err != nil {
			status.ApplyState = "failed"
			status.ApplyError = err.Error()
			setEdgeRuntimeApplyStatus(status)
			return
		}
	}
	status.ArtifactRevision = artifact.Parsed.Revision
	status.ArtifactHash = artifact.Parsed.ArtifactHash
	status.ApplyState = "installed"
	status.ApplyError = ""
	setEdgeRuntimeApplyStatus(status)
}

type edgeDownloadedRuntimeArtifact struct {
	Compressed []byte
	Parsed     runtimeartifactbundle.Parsed
}

func downloadEdgeRuntimeArtifact(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeRuntimeDeviceAssignment) (edgeDownloadedRuntimeArtifact, error) {
	assignment.ArtifactRevision = normalizeEdgeHex64(assignment.ArtifactRevision)
	assignment.ArtifactHash = normalizeEdgeHex64(assignment.ArtifactHash)
	if assignment.ArtifactRevision == "" || assignment.ArtifactHash == "" {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact assignment is missing revision or hash")
	}
	if assignment.CompressedSize <= 0 || assignment.CompressedSize > runtimeartifactbundle.MaxCompressedBytes ||
		assignment.UncompressedSize <= 0 || assignment.UncompressedSize > runtimeartifactbundle.MaxUncompressedBytes ||
		assignment.FileCount <= 0 || assignment.FileCount > runtimeartifactbundle.MaxFiles {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact assignment has invalid size metadata")
	}
	downloadURL, err := centerRuntimeArtifactDownloadURL(identity.CenterURL)
	if err != nil {
		return edgeDownloadedRuntimeArtifact{}, err
	}
	wireReq, err := signedEdgeRuntimeArtifactDownloadRequest(identity, assignment)
	if err != nil {
		return edgeDownloadedRuntimeArtifact{}, err
	}
	httpStatus, body, err := sendEdgeRuntimeArtifactDownload(ctx, downloadURL, wireReq, assignment.CompressedSize)
	if err != nil {
		return edgeDownloadedRuntimeArtifact{}, err
	}
	if httpStatus < 200 || httpStatus >= 300 {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("%s", centerHTTPErrorMessage("center runtime artifact download failed", httpStatus, body))
	}
	if int64(len(body)) != assignment.CompressedSize {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact compressed size mismatch")
	}
	sum := sha256.Sum256(body)
	if hex.EncodeToString(sum[:]) != assignment.ArtifactHash {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact hash mismatch")
	}
	parsed, err := runtimeartifactbundle.Parse(body)
	if err != nil {
		return edgeDownloadedRuntimeArtifact{}, err
	}
	if parsed.Revision != assignment.ArtifactRevision || parsed.ArtifactHash != assignment.ArtifactHash ||
		parsed.CompressedSize != assignment.CompressedSize || parsed.UncompressedSize != assignment.UncompressedSize ||
		parsed.FileCount != assignment.FileCount {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact metadata mismatch")
	}
	if parsed.Manifest.RuntimeFamily != assignment.RuntimeFamily || parsed.Manifest.RuntimeID != assignment.RuntimeID {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact identity mismatch")
	}
	if !edgeRuntimeArtifactTargetMatchesGateway(parsed.Manifest.Target) {
		return edgeDownloadedRuntimeArtifact{}, fmt.Errorf("runtime artifact target does not match this Gateway platform")
	}
	return edgeDownloadedRuntimeArtifact{
		Compressed: append([]byte(nil), body...),
		Parsed:     parsed,
	}, nil
}

func edgeRuntimeArtifactTargetMatchesGateway(target runtimeartifactbundle.TargetKey) bool {
	platform := currentEdgeGatewayPlatformMetadata()
	if target.OS == "" || target.Arch == "" || target.DistroID == "" || target.DistroVersion == "" {
		return false
	}
	if platform.OS == "" || platform.Arch == "" || platform.DistroID == "" || platform.DistroVersion == "" {
		return false
	}
	if target.OS != platform.OS || target.Arch != platform.Arch || target.DistroID != platform.DistroID || target.DistroVersion != platform.DistroVersion {
		return false
	}
	return target.DistroIDLike == "" || target.DistroIDLike == platform.DistroIDLike
}

func installEdgePHPRuntimeArtifact(compressed []byte, parsed runtimeartifactbundle.Parsed, assignment edgeRuntimeDeviceAssignment) error {
	if parsed.Manifest.RuntimeFamily != "php-fpm" {
		return fmt.Errorf("runtime artifact family is not php-fpm")
	}
	if !edgeRuntimeArtifactTargetMatchesGateway(parsed.Manifest.Target) {
		return fmt.Errorf("runtime artifact target does not match this Gateway platform")
	}
	_, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(parsed.Manifest.RuntimeFamily, parsed.Manifest.RuntimeID)
	if err != nil {
		return err
	}
	if runtimeID != assignment.RuntimeID {
		return fmt.Errorf("runtime artifact id mismatch")
	}
	baseDir := filepath.Join(phpRuntimeRootDirFromInventoryPath(currentPHPRuntimeInventoryPath()), "binaries")
	baseAbs, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(baseAbs, 0o755); err != nil {
		return err
	}
	manifestTargetDir := filepath.Join(baseDir, runtimeID)
	stageDir, err := os.MkdirTemp(baseAbs, "."+runtimeID+".install-*")
	if err != nil {
		return err
	}
	stageMoved := false
	defer func() {
		if !stageMoved {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := extractEdgeRuntimeArtifactToStage(compressed, parsed, stageDir); err != nil {
		return err
	}
	if err := writeInstalledPHPRuntimeManifest(stageDir, manifestTargetDir, parsed); err != nil {
		return err
	}
	if err := validateStagedPHPRuntimeArtifact(stageDir); err != nil {
		return err
	}
	if err := replaceEdgeManagedRuntimeDir(baseAbs, "php-fpm", runtimeID, stageDir); err != nil {
		return err
	}
	stageMoved = true
	return nil
}

func applyEdgePSGIRuntimeInstall(ctx context.Context, identity edgeDeviceIdentityRecord, assignment edgeRuntimeDeviceAssignment, runtimeID string) {
	family := "psgi"
	if !beginEdgeRuntimeAssignmentOp(family, runtimeID) {
		return
	}
	defer endEdgeRuntimeAssignmentOp(family, runtimeID)

	status := edgeRuntimeApplyStatus{
		RuntimeFamily:    family,
		RuntimeID:        runtimeID,
		ArtifactRevision: assignment.ArtifactRevision,
		ArtifactHash:     assignment.ArtifactHash,
		ApplyState:       "installing",
	}
	setEdgeRuntimeApplyStatus(status)

	runningProcesses := runningEdgePSGIProcessIDs(runtimeID)
	if len(runningProcesses) > 0 {
		status.ApplyState = "stopping"
		setEdgeRuntimeApplyStatus(status)
		for _, processID := range runningProcesses {
			if err := StopPSGIProcess(processID); err != nil {
				status.ApplyState = "failed"
				status.ApplyError = err.Error()
				setEdgeRuntimeApplyStatus(status)
				return
			}
		}
	}
	artifact, err := downloadEdgeRuntimeArtifact(ctx, identity, assignment)
	if err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := installEdgePSGIRuntimeArtifact(artifact.Compressed, artifact.Parsed, assignment); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := RefreshPSGIRuntimeMaterialization(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	for _, processID := range runningProcesses {
		if err := StartPSGIProcess(processID); err != nil {
			status.ApplyState = "failed"
			status.ApplyError = err.Error()
			setEdgeRuntimeApplyStatus(status)
			return
		}
	}
	status.ArtifactRevision = artifact.Parsed.Revision
	status.ArtifactHash = artifact.Parsed.ArtifactHash
	status.ApplyState = "installed"
	status.ApplyError = ""
	setEdgeRuntimeApplyStatus(status)
}

func installEdgePSGIRuntimeArtifact(compressed []byte, parsed runtimeartifactbundle.Parsed, assignment edgeRuntimeDeviceAssignment) error {
	if parsed.Manifest.RuntimeFamily != "psgi" {
		return fmt.Errorf("runtime artifact family is not psgi")
	}
	if !edgeRuntimeArtifactTargetMatchesGateway(parsed.Manifest.Target) {
		return fmt.Errorf("runtime artifact target does not match this Gateway platform")
	}
	_, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(parsed.Manifest.RuntimeFamily, parsed.Manifest.RuntimeID)
	if err != nil {
		return err
	}
	if runtimeID != assignment.RuntimeID {
		return fmt.Errorf("runtime artifact id mismatch")
	}
	baseDir := filepath.Join(psgiRuntimeRootDirFromInventoryPath(currentPSGIRuntimeInventoryPath()), "binaries")
	baseAbs, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return err
	}
	if err := os.MkdirAll(baseAbs, 0o755); err != nil {
		return err
	}
	manifestTargetDir := filepath.Join(baseDir, runtimeID)
	stageDir, err := os.MkdirTemp(baseAbs, "."+runtimeID+".install-*")
	if err != nil {
		return err
	}
	stageMoved := false
	defer func() {
		if !stageMoved {
			_ = os.RemoveAll(stageDir)
		}
	}()
	if err := extractEdgeRuntimeArtifactToStage(compressed, parsed, stageDir); err != nil {
		return err
	}
	if err := writeInstalledPSGIRuntimeManifest(stageDir, manifestTargetDir, parsed); err != nil {
		return err
	}
	if err := validateStagedPSGIRuntimeArtifact(stageDir); err != nil {
		return err
	}
	if err := replaceEdgeManagedRuntimeDir(baseAbs, "psgi", runtimeID, stageDir); err != nil {
		return err
	}
	stageMoved = true
	return nil
}

func extractEdgeRuntimeArtifactToStage(compressed []byte, parsed runtimeartifactbundle.Parsed, stageDir string) error {
	stageAbs, err := filepath.Abs(filepath.Clean(stageDir))
	if err != nil {
		return err
	}
	allowed := make(map[string]runtimeartifactbundle.FileManifest, len(parsed.Manifest.Files))
	for _, file := range parsed.Manifest.Files {
		allowed[file.ArchivePath] = file
	}
	gr, err := gzip.NewReader(bytes.NewReader(compressed))
	if err != nil {
		return fmt.Errorf("open runtime artifact gzip: %w", err)
	}
	defer gr.Close()
	tr := tar.NewReader(gr)
	written := map[string]struct{}{}
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return fmt.Errorf("read runtime artifact tar: %w", err)
		}
		if hdr == nil || hdr.Typeflag == tar.TypeDir {
			continue
		}
		if hdr.Typeflag != tar.TypeReg && hdr.Typeflag != tar.TypeRegA {
			return fmt.Errorf("runtime artifact contains non-regular entry %q", hdr.Name)
		}
		name, err := cleanEdgeRuntimeArchivePath(hdr.Name)
		if err != nil {
			return err
		}
		if name == "manifest.json" || name == "runtime.json" {
			continue
		}
		manifestFile, ok := allowed[name]
		if !ok {
			return fmt.Errorf("runtime artifact contains unexpected archive path %q", name)
		}
		if _, exists := written[name]; exists {
			return fmt.Errorf("runtime artifact contains duplicate archive path %q", name)
		}
		written[name] = struct{}{}
		target := filepath.Join(stageAbs, filepath.FromSlash(name))
		if !edgePathWithin(stageAbs, target) {
			return fmt.Errorf("runtime artifact path escapes install directory")
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := writeEdgeRuntimeArtifactFile(target, tr, manifestFile.SizeBytes, manifestFile.Mode); err != nil {
			return err
		}
	}
	for _, file := range parsed.Manifest.Files {
		if file.ArchivePath == "runtime.json" {
			continue
		}
		if _, ok := written[file.ArchivePath]; !ok {
			return fmt.Errorf("runtime artifact file %q was not installed", file.ArchivePath)
		}
	}
	return nil
}

func validateStagedPHPRuntimeArtifact(stageDir string) error {
	binaryPath := filepath.Join(stageDir, "php-fpm")
	if ok, message := validatePHPRuntimeBinaryPath(binaryPath); !ok {
		return fmt.Errorf("installed runtime is not available: %s", message)
	}
	if _, err := readPHPRuntimeModuleManifest(binaryPath); err != nil {
		return fmt.Errorf("installed runtime is not available: %s", err.Error())
	}
	return nil
}

func validateStagedPSGIRuntimeArtifact(stageDir string) error {
	perlPath := filepath.Join(stageDir, "perl")
	starmanPath := filepath.Join(stageDir, "starman")
	if ok, message := validatePHPRuntimeBinaryPath(perlPath); !ok {
		return fmt.Errorf("installed runtime is not available: perl: %s", message)
	}
	if ok, message := validatePHPRuntimeBinaryPath(starmanPath); !ok {
		return fmt.Errorf("installed runtime is not available: starman: %s", message)
	}
	if _, err := readPSGIRuntimeModuleManifest(perlPath); err != nil {
		return fmt.Errorf("installed runtime is not available: %s", err.Error())
	}
	return nil
}

func writeInstalledPHPRuntimeManifest(stageDir string, targetDir string, parsed runtimeartifactbundle.Parsed) error {
	binaryPath := filepath.ToSlash(filepath.Join(targetDir, "php-fpm"))
	cliBinaryPath := filepath.ToSlash(filepath.Join(targetDir, "php"))
	manifest := phpRuntimeArtifactManifest{
		RuntimeID:        parsed.Manifest.RuntimeID,
		DisplayName:      parsed.Manifest.DisplayName,
		DetectedVersion:  parsed.Manifest.DetectedVersion,
		BinaryPath:       binaryPath,
		CLIBinaryPath:    cliBinaryPath,
		Source:           "center",
		ArtifactRevision: parsed.Revision,
		SHA256:           parsed.ArtifactHash,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stageDir, "runtime.json"), append(raw, '\n'), 0o644)
}

func writeInstalledPSGIRuntimeManifest(stageDir string, targetDir string, parsed runtimeartifactbundle.Parsed) error {
	perlPath := filepath.ToSlash(filepath.Join(targetDir, "perl"))
	starmanPath := filepath.ToSlash(filepath.Join(targetDir, "starman"))
	manifest := psgiRuntimeArtifactManifest{
		RuntimeID:        parsed.Manifest.RuntimeID,
		DisplayName:      parsed.Manifest.DisplayName,
		DetectedVersion:  parsed.Manifest.DetectedVersion,
		PerlPath:         perlPath,
		StarmanPath:      starmanPath,
		Source:           "center",
		ArtifactRevision: parsed.Revision,
		SHA256:           parsed.ArtifactHash,
	}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(stageDir, "runtime.json"), append(raw, '\n'), 0o644)
}

func writeEdgeRuntimeArtifactFile(target string, reader io.Reader, size int64, mode int64) error {
	if size < 0 || size > runtimeartifactbundle.MaxUncompressedBytes {
		return fmt.Errorf("runtime artifact file has invalid size")
	}
	if mode <= 0 {
		mode = 0o644
	}
	file, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, os.FileMode(mode)&0o777)
	if err != nil {
		return err
	}
	written, copyErr := io.Copy(file, io.LimitReader(reader, size+1))
	closeErr := file.Close()
	if copyErr != nil {
		_ = os.Remove(target)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(target)
		return closeErr
	}
	if written != size {
		_ = os.Remove(target)
		return fmt.Errorf("runtime artifact file size mismatch")
	}
	return nil
}

func replaceEdgeManagedRuntimeDir(baseAbs string, runtimeFamily string, runtimeID string, stageDir string) error {
	_, id, err := normalizeEdgeRuntimeAssignmentIdentity(runtimeFamily, runtimeID)
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(filepath.Join(baseAbs, id))
	if err != nil {
		return err
	}
	if !edgePathWithin(baseAbs, targetAbs) {
		return fmt.Errorf("runtime path escapes managed directory")
	}
	stageAbs, err := filepath.Abs(filepath.Clean(stageDir))
	if err != nil {
		return err
	}
	if !edgePathWithin(baseAbs, stageAbs) {
		return fmt.Errorf("runtime stage path escapes managed directory")
	}
	backupAbs := filepath.Join(baseAbs, "."+id+".backup-"+strconv.FormatInt(time.Now().UTC().UnixNano(), 36))
	backupMoved := false
	if _, err := os.Stat(targetAbs); err == nil {
		if err := os.Rename(targetAbs, backupAbs); err != nil {
			return err
		}
		backupMoved = true
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.Rename(stageAbs, targetAbs); err != nil {
		if backupMoved {
			_ = os.Rename(backupAbs, targetAbs)
		}
		return err
	}
	if backupMoved {
		_ = os.RemoveAll(backupAbs)
	}
	return nil
}

func cleanEdgeRuntimeArchivePath(raw string) (string, error) {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || strings.HasPrefix(raw, "/") {
		return "", fmt.Errorf("runtime artifact contains unsafe archive path")
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." {
		return "", fmt.Errorf("runtime artifact contains unsafe archive path")
	}
	return cleaned, nil
}

func edgePathWithin(root string, candidate string) bool {
	rootAbs, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return false
	}
	candidateAbs, err := filepath.Abs(filepath.Clean(candidate))
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false
	}
	return rel == "." || (rel != "" && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel))
}

func applyEdgeRuntimeRemoval(assignment edgeRuntimeDeviceAssignment) {
	family, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(assignment.RuntimeFamily, assignment.RuntimeID)
	if err != nil {
		return
	}
	switch family {
	case "php-fpm":
		applyEdgePHPRuntimeRemoval(assignment, runtimeID)
	case "psgi":
		applyEdgePSGIRuntimeRemoval(assignment, runtimeID)
	}
}

func applyEdgePHPRuntimeRemoval(assignment edgeRuntimeDeviceAssignment, runtimeID string) {
	family := "php-fpm"
	if !beginEdgeRuntimeAssignmentOp(family, runtimeID) {
		return
	}
	defer endEdgeRuntimeAssignmentOp(family, runtimeID)

	status := edgeRuntimeApplyStatus{
		RuntimeFamily:    family,
		RuntimeID:        runtimeID,
		ArtifactRevision: assignment.ArtifactRevision,
		ArtifactHash:     assignment.ArtifactHash,
		ApplyState:       "removing",
	}
	setEdgeRuntimeApplyStatus(status)

	refs := currentEdgePHPRuntimeReferences(runtimeID)
	if len(refs) > 0 {
		status.ApplyState = "blocked"
		status.ApplyError = "runtime is referenced by Runtime Apps: " + strings.Join(refs, ", ")
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if edgePHPRuntimeRunningState()[runtimeID] {
		status.ApplyState = "blocked"
		status.ApplyError = "runtime process is still running"
		setEdgeRuntimeApplyStatus(status)
		return
	}

	rootDir := phpRuntimeRootDirFromInventoryPath(currentPHPRuntimeInventoryPath())
	for _, base := range []string{
		filepath.Join(rootDir, "runtime"),
		filepath.Join(rootDir, "binaries"),
	} {
		if err := removeEdgeManagedRuntimeDir(base, family, runtimeID); err != nil {
			status.ApplyState = "failed"
			status.ApplyError = err.Error()
			setEdgeRuntimeApplyStatus(status)
			return
		}
	}
	if err := RefreshPHPRuntimeMaterialization(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	status.ApplyState = "removed"
	status.ApplyError = ""
	setEdgeRuntimeApplyStatus(status)
}

func applyEdgePSGIRuntimeRemoval(assignment edgeRuntimeDeviceAssignment, runtimeID string) {
	family := "psgi"
	if !beginEdgeRuntimeAssignmentOp(family, runtimeID) {
		return
	}
	defer endEdgeRuntimeAssignmentOp(family, runtimeID)

	status := edgeRuntimeApplyStatus{
		RuntimeFamily:    family,
		RuntimeID:        runtimeID,
		ArtifactRevision: assignment.ArtifactRevision,
		ArtifactHash:     assignment.ArtifactHash,
		ApplyState:       "removing",
	}
	setEdgeRuntimeApplyStatus(status)

	refs := currentEdgePSGIRuntimeReferences(runtimeID)
	if len(refs) > 0 {
		status.ApplyState = "blocked"
		status.ApplyError = "runtime is referenced by Runtime Apps: " + strings.Join(refs, ", ")
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if edgePSGIRuntimeRunningState()[runtimeID] {
		status.ApplyState = "blocked"
		status.ApplyError = "runtime process is still running"
		setEdgeRuntimeApplyStatus(status)
		return
	}

	rootDir := psgiRuntimeRootDirFromInventoryPath(currentPSGIRuntimeInventoryPath())
	for _, base := range []string{
		filepath.Join(rootDir, "runtime"),
		filepath.Join(rootDir, "binaries"),
	} {
		if err := removeEdgeManagedRuntimeDir(base, family, runtimeID); err != nil {
			status.ApplyState = "failed"
			status.ApplyError = err.Error()
			setEdgeRuntimeApplyStatus(status)
			return
		}
	}
	if err := RefreshPSGIRuntimeMaterialization(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		status.ApplyState = "failed"
		status.ApplyError = err.Error()
		setEdgeRuntimeApplyStatus(status)
		return
	}
	status.ApplyState = "removed"
	status.ApplyError = ""
	setEdgeRuntimeApplyStatus(status)
}

func currentEdgePHPRuntimeReferences(runtimeID string) []string {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return nil
	}
	refs := []string{}
	for _, vhost := range currentVhostConfig().Vhosts {
		if normalizeVhostMode(vhost.Mode) != "php-fpm" || strings.TrimSpace(vhost.RuntimeID) != runtimeID {
			continue
		}
		name := strings.TrimSpace(vhost.GeneratedTarget)
		if name == "" {
			name = strings.TrimSpace(vhost.Name)
		}
		if name == "" {
			name = runtimeID
		}
		refs = append(refs, name)
	}
	return uniqueSortedNonEmptyStrings(refs, 32)
}

func currentEdgePSGIRuntimeReferences(runtimeID string) []string {
	runtimeID = strings.TrimSpace(runtimeID)
	if runtimeID == "" {
		return nil
	}
	refs := []string{}
	for _, vhost := range currentVhostConfig().Vhosts {
		if normalizeVhostMode(vhost.Mode) != "psgi" || strings.TrimSpace(vhost.RuntimeID) != runtimeID {
			continue
		}
		name := strings.TrimSpace(vhost.GeneratedTarget)
		if name == "" {
			name = strings.TrimSpace(vhost.Name)
		}
		if name == "" {
			name = runtimeID
		}
		refs = append(refs, name)
	}
	return uniqueSortedNonEmptyStrings(refs, 32)
}

func removeEdgeManagedRuntimeDir(baseDir, runtimeFamily, runtimeID string) error {
	_, id, err := normalizeEdgeRuntimeAssignmentIdentity(runtimeFamily, runtimeID)
	if err != nil {
		return err
	}
	baseAbs, err := filepath.Abs(filepath.Clean(baseDir))
	if err != nil {
		return err
	}
	targetAbs, err := filepath.Abs(filepath.Join(baseAbs, id))
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(baseAbs, targetAbs)
	if err != nil {
		return err
	}
	if rel == "." || rel == "" || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || rel == ".." || filepath.IsAbs(rel) {
		return fmt.Errorf("runtime path escapes managed directory")
	}
	return os.RemoveAll(targetAbs)
}

func currentEdgeGatewayPlatformMetadata() edgeGatewayPlatformMetadata {
	platform := edgeGatewayPlatformMetadata{
		OS:   clampEdgeMetadataText(goruntime.GOOS, 32),
		Arch: clampEdgeMetadataText(goruntime.GOARCH, 32),
	}
	if platform.OS != "linux" {
		return platform
	}
	platform.KernelVersion = readEdgePlatformTextFile("/proc/sys/kernel/osrelease", 128)
	osRelease := readEdgeOSRelease()
	platform.DistroID = clampEdgeMetadataText(osRelease["ID"], 64)
	platform.DistroIDLike = clampEdgeMetadataText(osRelease["ID_LIKE"], 128)
	platform.DistroVersion = clampEdgeMetadataText(osRelease["VERSION_ID"], 64)
	return platform
}

func readEdgePlatformTextFile(path string, limit int) string {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return clampEdgeMetadataText(string(raw), limit)
}

func readEdgeOSRelease() map[string]string {
	for _, path := range []string{"/etc/os-release", "/usr/lib/os-release"} {
		raw, err := os.ReadFile(path)
		if err == nil {
			return parseEdgeOSRelease(raw)
		}
	}
	return map[string]string{}
}

func parseEdgeOSRelease(raw []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		switch key {
		case "ID", "ID_LIKE", "VERSION_ID":
		default:
			continue
		}
		value = strings.TrimSpace(value)
		if unquoted, err := strconv.Unquote(value); err == nil {
			value = unquoted
		}
		out[key] = value
	}
	return out
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

func signedEdgeRuntimeArtifactDownloadRequest(identity edgeDeviceIdentityRecord, assignment edgeRuntimeDeviceAssignment) (edgeRuntimeArtifactDownloadWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeRuntimeArtifactDownloadWireRequest{}, err
	}
	family, runtimeID, err := normalizeEdgeRuntimeAssignmentIdentity(assignment.RuntimeFamily, assignment.RuntimeID)
	if err != nil {
		return edgeRuntimeArtifactDownloadWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeRuntimeArtifactDownloadWireRequest{}, err
	}
	req := edgeRuntimeArtifactDownloadWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		RuntimeFamily:              family,
		RuntimeID:                  runtimeID,
		ArtifactRevision:           normalizeEdgeHex64(assignment.ArtifactRevision),
		ArtifactHash:               normalizeEdgeHex64(assignment.ArtifactHash),
	}
	if req.ArtifactRevision == "" || req.ArtifactHash == "" {
		return edgeRuntimeArtifactDownloadWireRequest{}, fmt.Errorf("runtime artifact assignment is missing revision or hash")
	}
	req.BodyHash = edgeRuntimeArtifactDownloadBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func signedEdgeProxyRulesBundleDownloadRequest(identity edgeDeviceIdentityRecord, assignment edgeProxyRuleDeviceAssignment) (edgeProxyRulesBundleDownloadWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeProxyRulesBundleDownloadWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeProxyRulesBundleDownloadWireRequest{}, err
	}
	req := edgeProxyRulesBundleDownloadWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		BundleRevision:             normalizeEdgeHex64(assignment.BundleRevision),
		PayloadHash:                normalizeEdgeHex64(assignment.PayloadHash),
	}
	if req.BundleRevision == "" || req.PayloadHash == "" {
		return edgeProxyRulesBundleDownloadWireRequest{}, fmt.Errorf("proxy rules assignment is missing revision or hash")
	}
	req.BodyHash = edgeProxyRulesBundleDownloadBodyHash(req)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)))
	req.SignatureB64 = base64.StdEncoding.EncodeToString(signature)
	return req, nil
}

func signedEdgeWAFRuleArtifactDownloadRequest(identity edgeDeviceIdentityRecord, assignment edgeWAFRuleDeviceAssignment) (edgeWAFRuleArtifactDownloadWireRequest, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return edgeWAFRuleArtifactDownloadWireRequest{}, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return edgeWAFRuleArtifactDownloadWireRequest{}, err
	}
	req := edgeWAFRuleArtifactDownloadWireRequest{
		DeviceID:                   identity.DeviceID,
		KeyID:                      identity.KeyID,
		PublicKeyFingerprintSHA256: identity.PublicKeyFingerprintSHA256,
		Timestamp:                  timestamp,
		Nonce:                      nonce,
		BundleRevision:             normalizeEdgeHex64(assignment.BundleRevision),
	}
	if req.BundleRevision == "" {
		return edgeWAFRuleArtifactDownloadWireRequest{}, fmt.Errorf("WAF rule assignment is missing revision")
	}
	req.BodyHash = edgeWAFRuleArtifactDownloadBodyHash(req)
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

func edgeCenterTLSConfig() centertls.Config {
	return centertls.Config{
		CABundleFile: config.RemoteSSHGatewayCenterTLSCABundleFile,
		ServerName:   config.RemoteSSHGatewayCenterTLSServerName,
	}
}

func edgeCenterHTTPClient() (*http.Client, error) {
	return centertls.HTTPClient(edgeCenterTLSConfig())
}

func edgeCenterHTTPClientForAppConfig(cfg config.AppConfigFile) (*http.Client, error) {
	return centertls.HTTPClient(centertls.Config{
		CABundleFile: cfg.RemoteSSH.Gateway.CenterTLSCABundleFile,
		ServerName:   cfg.RemoteSSH.Gateway.CenterTLSServerName,
	})
}

func ensureRemoteSSHGatewayCenterSigningKey(ctx context.Context, cfg *config.AppConfigFile) error {
	if cfg == nil || !cfg.RemoteSSH.Gateway.Enabled || !cfg.RemoteSSH.Gateway.EmbeddedServer.Enabled {
		return nil
	}
	if strings.TrimSpace(cfg.RemoteSSH.Gateway.CenterSigningPublicKey) != "" {
		return nil
	}
	identity, err := approvedEdgeDeviceIdentityForRemoteSSHCenterSigningKey()
	if err != nil {
		return err
	}
	key, err := fetchEdgeRemoteSSHCenterSigningPublicKeyForIdentity(ctx, identity, *cfg)
	if err != nil {
		return fmt.Errorf("remote ssh gateway could not fetch Center signing key: %w", err)
	}
	cfg.RemoteSSH.Gateway.CenterSigningPublicKey = key
	return nil
}

func approvedEdgeDeviceIdentityForRemoteSSHCenterSigningKey() (edgeDeviceIdentityRecord, error) {
	store := getLogsStatsStore()
	if store == nil {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("runtime DB store is not initialized")
	}
	identity, found, err := loadEdgeDeviceIdentity(store)
	if err != nil {
		return edgeDeviceIdentityRecord{}, err
	}
	if !found {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("Center enrollment is required before enabling Remote SSH on Gateway")
	}
	if normalizeEdgeStatus(identity.EnrollmentStatus) != edgeEnrollmentStatusApproved {
		return edgeDeviceIdentityRecord{}, fmt.Errorf("Center enrollment must be approved before enabling Remote SSH on Gateway")
	}
	return identity, nil
}

func fetchEdgeRemoteSSHCenterSigningPublicKeyForIdentity(ctx context.Context, identity edgeDeviceIdentityRecord, cfg config.AppConfigFile) (string, error) {
	if normalizeEdgeStatus(identity.EnrollmentStatus) != edgeEnrollmentStatusApproved {
		return "", fmt.Errorf("Center enrollment must be approved before enabling Remote SSH on Gateway")
	}
	signingKeyURL, err := centerRemoteSSHSigningKeyURL(identity.CenterURL)
	if err != nil {
		return "", err
	}
	client, err := edgeCenterHTTPClientForAppConfig(cfg)
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, signingKeyURL, nil)
	if err != nil {
		return "", err
	}
	res, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 4*1024))
	if err != nil {
		return "", err
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		if res.StatusCode == http.StatusConflict || res.StatusCode == http.StatusNotFound {
			return "", errEdgeRemoteSSHCenterSigningKeyUnavailable
		}
		return "", fmt.Errorf("%s", centerHTTPErrorMessage("center remote ssh signing key fetch failed", res.StatusCode, body))
	}
	var payload edgeRemoteSSHCenterSigningKeyResponse
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&payload); err != nil {
		return "", fmt.Errorf("center remote ssh signing key response is invalid JSON")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return "", fmt.Errorf("center remote ssh signing key response is invalid JSON")
	}
	if strings.TrimSpace(payload.Algorithm) != "ed25519" {
		return "", fmt.Errorf("center remote ssh signing key algorithm is unsupported")
	}
	publicKey := strings.TrimSpace(payload.PublicKey)
	if _, err := parseEdgeRemoteSSHCenterSigningPublicKey(publicKey); err != nil {
		return "", err
	}
	return publicKey, nil
}

func importRemoteSSHGatewayCenterSigningKeyFromApprovedCenter(ctx context.Context, identity edgeDeviceIdentityRecord) {
	if strings.TrimSpace(config.RemoteSSHGatewayCenterSigningPublicKey) != "" {
		return
	}
	if _, err := persistRemoteSSHGatewayCenterSigningKeyFromApprovedCenter(ctx, identity, false); err != nil {
		if errors.Is(err, errEdgeRemoteSSHCenterSigningKeyUnavailable) {
			return
		}
		log.Printf("[REMOTE_SSH][WARN] Center signing key import skipped: %v", err)
	}
}

func persistRemoteSSHGatewayCenterSigningKeyFromApprovedCenter(ctx context.Context, identity edgeDeviceIdentityRecord, force bool) (string, error) {
	if normalizeEdgeStatus(identity.EnrollmentStatus) != edgeEnrollmentStatusApproved {
		return "", nil
	}
	raw, etag, cfg, err := loadSettingsAppConfig()
	if err != nil {
		return "", err
	}
	if existing := strings.TrimSpace(cfg.RemoteSSH.Gateway.CenterSigningPublicKey); existing != "" && !force {
		config.RemoteSSHGatewayCenterSigningPublicKey = existing
		return existing, nil
	}
	key, err := fetchEdgeRemoteSSHCenterSigningPublicKeyForIdentity(ctx, identity, cfg)
	if err != nil {
		return "", err
	}
	cfg.RemoteSSH.Gateway.CenterSigningPublicKey = key
	normalized, err := config.NormalizeAndValidateAppConfigFile(cfg)
	if err != nil {
		return "", err
	}
	nextRaw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		return "", err
	}
	if nextRaw != raw {
		if _, err := persistSettingsAppConfig(normalized, etag); err != nil {
			return "", err
		}
	}
	config.RemoteSSHGatewayCenterSigningPublicKey = key
	action := "imported"
	if force {
		action = "refreshed"
	}
	log.Printf("[REMOTE_SSH] %s Center signing key from approved Center enrollment", action)
	return key, nil
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
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
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
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
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
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
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
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
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

func sendEdgeRuntimeArtifactDownload(ctx context.Context, downloadURL string, wireReq edgeRuntimeArtifactDownloadWireRequest, maxBytes int64) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	if maxBytes <= 0 || maxBytes > runtimeartifactbundle.MaxCompressedBytes {
		maxBytes = runtimeartifactbundle.MaxCompressedBytes
	}
	ctx, cancel := context.WithTimeout(ctx, edgeRuntimeArtifactTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, downloadURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	if int64(len(resBody)) > maxBytes {
		return res.StatusCode, nil, fmt.Errorf("runtime artifact download exceeds %d bytes", maxBytes)
	}
	return res.StatusCode, resBody, nil
}

func sendEdgeProxyRulesBundleDownload(ctx context.Context, downloadURL string, wireReq edgeProxyRulesBundleDownloadWireRequest, maxBytes int64) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	if maxBytes <= 0 || maxBytes > edgeProxyRuleBundleMaxBytes {
		maxBytes = edgeProxyRuleBundleMaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, downloadURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	if int64(len(resBody)) > maxBytes {
		return res.StatusCode, nil, fmt.Errorf("proxy rules bundle download exceeds %d bytes", maxBytes)
	}
	return res.StatusCode, resBody, nil
}

func sendEdgeWAFRuleArtifactDownload(ctx context.Context, downloadURL string, wireReq edgeWAFRuleArtifactDownloadWireRequest, maxBytes int64) (int, []byte, error) {
	body, err := json.Marshal(wireReq)
	if err != nil {
		return 0, nil, err
	}
	if maxBytes <= 0 || maxBytes > edgeWAFRuleArtifactMaxBytes {
		maxBytes = edgeWAFRuleArtifactMaxBytes
	}
	ctx, cancel := context.WithTimeout(ctx, edgeEnrollmentHTTPTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, downloadURL, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client, err := edgeCenterHTTPClient()
	if err != nil {
		return 0, nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer res.Body.Close()
	resBody, readErr := io.ReadAll(io.LimitReader(res.Body, maxBytes+1))
	if readErr != nil {
		return res.StatusCode, nil, readErr
	}
	if int64(len(resBody)) > maxBytes {
		return res.StatusCode, nil, fmt.Errorf("WAF rule artifact download exceeds %d bytes", maxBytes)
	}
	return res.StatusCode, resBody, nil
}

func pushEdgeRuleArtifactBundleIfChanged(ctx context.Context, identity *edgeDeviceIdentityRecord) bool {
	return pushEdgeRuleArtifactBundle(ctx, identity, false)
}

func pushEdgeRuleArtifactBundle(ctx context.Context, identity *edgeDeviceIdentityRecord, force bool) bool {
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
	if !force && bundle.Revision == strings.TrimSpace(identity.RuleArtifactRevision) {
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
		identity.RuleArtifactError = clampEdgeText(centerHTTPErrorMessage("center rule artifact upload failed", centerHTTPStatus, centerBody), 2048)
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
	pushEdgeConfigSnapshot(ctx, identity, false)
}

func pushEdgeConfigSnapshot(ctx context.Context, identity *edgeDeviceIdentityRecord, force bool) {
	if identity == nil {
		return
	}
	snapshot, err := buildEdgeConfigSnapshot(*identity)
	if err != nil {
		identity.ConfigSnapshotError = clampEdgeText(err.Error(), 2048)
		return
	}
	if !force && snapshot.Revision == strings.TrimSpace(identity.ConfigSnapshotRevision) {
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
		identity.ConfigSnapshotError = clampEdgeText(centerHTTPErrorMessage("center config snapshot upload failed", centerHTTPStatus, centerBody), 2048)
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
	return centerHTTPErrorMessage("center enrollment failed", status, body)
}

func centerHTTPErrorMessage(operation string, status int, body []byte) string {
	operation = strings.TrimSpace(operation)
	if operation == "" {
		operation = "center request failed"
	}
	var payload struct {
		Error   string `json:"error"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &payload); err == nil {
		if strings.TrimSpace(payload.Error) != "" {
			return fmt.Sprintf("%s: HTTP %d: %s", operation, status, strings.TrimSpace(payload.Error))
		}
		if strings.TrimSpace(payload.Message) != "" {
			return fmt.Sprintf("%s: HTTP %d: %s", operation, status, strings.TrimSpace(payload.Message))
		}
	}
	text := strings.TrimSpace(string(body))
	if text != "" {
		return fmt.Sprintf("%s: HTTP %d: %s", operation, status, clampEdgeText(text, 512))
	}
	return fmt.Sprintf("%s: HTTP %d", operation, status)
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
	body := req.DeviceID + "\n" +
		req.KeyID + "\n" +
		req.PublicKeyFingerprintSHA256 + "\n" +
		req.Timestamp + "\n" +
		req.Nonce + "\n" +
		req.RuntimeRole + "\n" +
		req.BuildVersion + "\n" +
		req.GoVersion + "\n" +
		req.OS + "\n" +
		req.Arch + "\n" +
		req.KernelVersion + "\n" +
		req.DistroID + "\n" +
		req.DistroIDLike + "\n" +
		req.DistroVersion + "\n" +
		strconv.FormatBool(req.RuntimeDeploymentSupported) + "\n" +
		edgeRuntimeInventoryCanonical(req.RuntimeInventory)
	if req.ProxyRuleApplyStatus != nil {
		body += "\n" + edgeProxyRuleApplyStatusCanonical(*req.ProxyRuleApplyStatus)
	}
	if req.WAFRuleApplyStatus != nil {
		body += "\n" + edgeWAFRuleApplyStatusCanonical(*req.WAFRuleApplyStatus)
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func edgeRuntimeInventoryCanonical(items []edgeDeviceRuntimeSummary) string {
	if len(items) == 0 {
		return "0"
	}
	sorted := append([]edgeDeviceRuntimeSummary(nil), items...)
	sortEdgeRuntimeSummaries(sorted)
	var b strings.Builder
	b.WriteString(strconv.Itoa(len(sorted)))
	for _, item := range sorted {
		b.WriteByte('\n')
		b.WriteString(item.RuntimeFamily)
		b.WriteByte('\t')
		b.WriteString(item.RuntimeID)
		b.WriteByte('\t')
		b.WriteString(item.DisplayName)
		b.WriteByte('\t')
		b.WriteString(item.DetectedVersion)
		b.WriteByte('\t')
		b.WriteString(item.Source)
		b.WriteByte('\t')
		b.WriteString(strconv.FormatBool(item.Available))
		b.WriteByte('\t')
		b.WriteString(item.AvailabilityMessage)
		b.WriteByte('\t')
		b.WriteString(strconv.Itoa(item.ModuleCount))
		b.WriteByte('\t')
		b.WriteString(strconv.FormatBool(item.UsageReported))
		b.WriteByte('\t')
		b.WriteString(strconv.Itoa(item.AppCount))
		b.WriteByte('\t')
		b.WriteString(strings.Join(uniqueSortedNonEmptyStrings(item.GeneratedTargets, 64), ","))
		b.WriteByte('\t')
		b.WriteString(strconv.FormatBool(item.ProcessRunning))
		b.WriteByte('\t')
		b.WriteString(item.ArtifactRevision)
		b.WriteByte('\t')
		b.WriteString(item.ArtifactHash)
		b.WriteByte('\t')
		b.WriteString(item.ApplyState)
		b.WriteByte('\t')
		b.WriteString(item.ApplyError)
	}
	return b.String()
}

func edgeProxyRuleApplyStatusCanonical(status edgeProxyRuleApplyStatus) string {
	return status.DesiredBundleRevision + "\n" +
		status.LocalProxyETag + "\n" +
		status.ApplyState + "\n" +
		status.ApplyError
}

func edgeWAFRuleApplyStatusCanonical(status edgeWAFRuleApplyStatus) string {
	return status.DesiredBundleRevision + "\n" +
		status.LocalBundleRevision + "\n" +
		status.ApplyState + "\n" +
		status.ApplyError
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

func edgeRuntimeArtifactDownloadBodyHash(req edgeRuntimeArtifactDownloadWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.RuntimeFamily + "\n" +
			req.RuntimeID + "\n" +
			req.ArtifactRevision + "\n" +
			req.ArtifactHash,
	))
	return hex.EncodeToString(sum[:])
}

func edgeProxyRulesBundleDownloadBodyHash(req edgeProxyRulesBundleDownloadWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.BundleRevision + "\n" +
			req.PayloadHash,
	))
	return hex.EncodeToString(sum[:])
}

func edgeWAFRuleArtifactDownloadBodyHash(req edgeWAFRuleArtifactDownloadWireRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce + "\n" +
			req.BundleRevision,
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

func clampEdgeMetadataText(raw string, limit int) string {
	raw = strings.TrimSpace(raw)
	if raw == "" || limit <= 0 {
		return ""
	}
	if len(raw) > limit {
		raw = raw[:limit]
	}
	for _, r := range raw {
		if r < 0x20 || r > 0x7e {
			return ""
		}
	}
	return raw
}

func normalizeEdgeHex64(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if len(raw) != 64 {
		return ""
	}
	for _, r := range raw {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return ""
		}
	}
	return raw
}

type edgeRemoteSSHDeviceSession struct {
	DeviceID                           string `json:"device_id"`
	SessionID                          string `json:"session_id"`
	OperatorPublicKey                  string `json:"operator_public_key"`
	OperatorPublicKeyFingerprintSHA256 string `json:"operator_public_key_fingerprint_sha256"`
	ExpiresAtUnix                      int64  `json:"expires_at_unix"`
	CreatedAtUnix                      int64  `json:"created_at_unix"`
	Nonce                              string `json:"nonce"`
	CenterSigningPublicKey             string `json:"center_signing_public_key"`
	Signature                          string `json:"signature"`
}

var edgeRemoteSSHActive sync.Map

var edgeRemoteSSHHostKeyMu sync.Mutex

func applyEdgeRemoteSSHSession(ctx context.Context, identity edgeDeviceIdentityRecord, session *edgeRemoteSSHDeviceSession) {
	if session == nil || !config.RemoteSSHGatewayEnabled || !config.RemoteSSHGatewayEmbeddedEnabled {
		return
	}
	if err := verifyEdgeRemoteSSHDeviceSession(ctx, identity, *session); err != nil {
		log.Printf("[REMOTE_SSH][WARN] rejected pending session: %v", err)
		return
	}
	if _, loaded := edgeRemoteSSHActive.LoadOrStore(session.SessionID, struct{}{}); loaded {
		return
	}
	go func() {
		defer edgeRemoteSSHActive.Delete(session.SessionID)
		runCtx := context.Background()
		if deadline := time.Unix(session.ExpiresAtUnix, 0).UTC(); time.Now().UTC().Before(deadline) {
			var cancel context.CancelFunc
			runCtx, cancel = context.WithDeadline(runCtx, deadline)
			defer cancel()
		}
		if err := runEdgeRemoteSSHSession(runCtx, identity, *session); err != nil {
			log.Printf("[REMOTE_SSH][WARN] session %s failed: %v", session.SessionID, err)
		}
	}()
	_ = ctx
}

func runEdgeRemoteSSHSession(ctx context.Context, identity edgeDeviceIdentityRecord, session edgeRemoteSSHDeviceSession) error {
	signer, hostFP, err := ensureEdgeRemoteSSHHostSigner(ctx)
	if err != nil {
		return err
	}
	streamURL, err := centerRemoteSSHGatewayStreamURL(identity.CenterURL)
	if err != nil {
		return err
	}
	hostPublicKey := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	headers, err := signedEdgeRemoteSSHGatewayStreamHeaders(identity, session.SessionID, hostFP, hostPublicKey)
	if err != nil {
		return err
	}
	tlsConfig, err := centertls.BuildTLSConfig(edgeCenterTLSConfig())
	if err != nil {
		return err
	}
	conn, err := remotestream.DialUpgradeWithOptions(ctx, streamURL, headers, remotestream.DialOptions{TLSConfig: tlsConfig})
	if err != nil {
		return err
	}
	defer conn.Close()
	return serveEdgeRemoteSSHConn(ctx, conn, session, signer)
}

func serveEdgeRemoteSSHConn(ctx context.Context, conn net.Conn, session edgeRemoteSSHDeviceSession, signer ssh.Signer) error {
	allowedKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(session.OperatorPublicKey)))
	if err != nil {
		return fmt.Errorf("parse operator public key: %w", err)
	}
	serverConfig := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-tukuyomi-remote-ssh",
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if string(key.Marshal()) != string(allowedKey.Marshal()) {
				return nil, fmt.Errorf("unauthorized remote ssh key")
			}
			return &ssh.Permissions{Extensions: map[string]string{"username": meta.User()}}, nil
		},
	}
	serverConfig.AddHostKey(signer)
	sshConn, channels, requests, err := ssh.NewServerConn(conn, serverConfig)
	if err != nil {
		return err
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(requests)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for newChannel := range channels {
			if newChannel.ChannelType() != "session" {
				_ = newChannel.Reject(ssh.UnknownChannelType, "only session channels are allowed")
				continue
			}
			channel, reqs, err := newChannel.Accept()
			if err != nil {
				continue
			}
			handleEdgeRemoteSSHSessionChannel(ctx, channel, reqs)
		}
	}()
	select {
	case <-ctx.Done():
		_ = sshConn.Close()
		return ctx.Err()
	case <-done:
		return nil
	}
}

type edgeRemoteSSHPTYRequest struct {
	Term     string
	Columns  uint32
	Rows     uint32
	WidthPX  uint32
	HeightPX uint32
	Modes    string
}

type edgeRemoteSSHWindowChangeRequest struct {
	Columns  uint32
	Rows     uint32
	WidthPX  uint32
	HeightPX uint32
}

func handleEdgeRemoteSSHSessionChannel(ctx context.Context, channel ssh.Channel, requests <-chan *ssh.Request) {
	defer channel.Close()
	var (
		ptyReq  = edgeRemoteSSHPTYRequest{Term: "xterm", Columns: 80, Rows: 24}
		ptyFile *os.File
		started bool
		done    chan struct{}
	)
	for req := range requests {
		switch req.Type {
		case "pty-req":
			if started {
				replySSHRequest(req, false)
				continue
			}
			var parsed edgeRemoteSSHPTYRequest
			if err := ssh.Unmarshal(req.Payload, &parsed); err != nil || parsed.Columns == 0 || parsed.Rows == 0 || parsed.Columns > 1000 || parsed.Rows > 1000 {
				replySSHRequest(req, false)
				continue
			}
			ptyReq = parsed
			replySSHRequest(req, true)
		case "window-change":
			var parsed edgeRemoteSSHWindowChangeRequest
			if err := ssh.Unmarshal(req.Payload, &parsed); err != nil || parsed.Columns == 0 || parsed.Rows == 0 || parsed.Columns > 1000 || parsed.Rows > 1000 {
				continue
			}
			if ptyFile != nil {
				_ = pty.Setsize(ptyFile, &pty.Winsize{Rows: uint16(parsed.Rows), Cols: uint16(parsed.Columns)})
			}
		case "shell":
			if started {
				replySSHRequest(req, false)
				continue
			}
			started = true
			var startErr error
			ptyFile, done, startErr = startEdgeRemoteSSHShell(ctx, channel, ptyReq)
			replySSHRequest(req, startErr == nil)
			if startErr != nil {
				return
			}
		default:
			replySSHRequest(req, false)
		}
	}
	if ptyFile != nil {
		_ = ptyFile.Close()
	}
	if done != nil {
		<-done
	}
}

func startEdgeRemoteSSHShell(ctx context.Context, channel ssh.Channel, req edgeRemoteSSHPTYRequest) (*os.File, chan struct{}, error) {
	if os.Geteuid() == 0 && strings.TrimSpace(config.RemoteSSHGatewayRunAsUser) == "" {
		return nil, nil, fmt.Errorf("remote ssh refuses to run shell as root without remote_ssh.gateway.embedded_server.run_as_user")
	}
	cmd := exec.CommandContext(ctx, config.RemoteSSHGatewayShell)
	cmd.Dir = config.RemoteSSHGatewayWorkingDir
	cmd.Env = buildEdgeRemoteSSHShellEnv(req.Term, config.RemoteSSHGatewayRunAsUser)
	if runAs := strings.TrimSpace(config.RemoteSSHGatewayRunAsUser); runAs != "" {
		cred, err := remoteSSHCredentialForUser(runAs)
		if err != nil {
			return nil, nil, err
		}
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: cred}
	}
	ptmx, err := pty.StartWithSize(cmd, &pty.Winsize{Rows: uint16(req.Rows), Cols: uint16(req.Columns)})
	if err != nil {
		return nil, nil, err
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer ptmx.Close()
		go func() {
			_, _ = io.Copy(ptmx, channel)
			_ = ptmx.Close()
		}()
		_, _ = io.Copy(channel, ptmx)
		_ = cmd.Wait()
	}()
	return ptmx, done, nil
}

func verifyEdgeRemoteSSHDeviceSession(ctx context.Context, identity edgeDeviceIdentityRecord, session edgeRemoteSSHDeviceSession) error {
	session.DeviceID = strings.TrimSpace(session.DeviceID)
	session.SessionID = strings.TrimSpace(session.SessionID)
	session.OperatorPublicKey = strings.TrimSpace(session.OperatorPublicKey)
	session.OperatorPublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(session.OperatorPublicKeyFingerprintSHA256))
	session.Nonce = strings.TrimSpace(session.Nonce)
	session.CenterSigningPublicKey = strings.TrimSpace(session.CenterSigningPublicKey)
	session.Signature = strings.TrimSpace(session.Signature)
	if session.DeviceID != identity.DeviceID {
		return fmt.Errorf("remote ssh session device mismatch")
	}
	if session.SessionID == "" || session.OperatorPublicKey == "" || session.Nonce == "" || session.ExpiresAtUnix <= time.Now().UTC().Unix() {
		return fmt.Errorf("remote ssh session payload is incomplete")
	}
	operatorKey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(session.OperatorPublicKey))
	if err != nil {
		return fmt.Errorf("remote ssh operator key is invalid: %w", err)
	}
	if got := remoteSSHPublicKeyFingerprintHex(operatorKey); got != session.OperatorPublicKeyFingerprintSHA256 {
		return fmt.Errorf("remote ssh operator key fingerprint mismatch")
	}
	if _, err := centerRemoteSSHGatewayStreamURL(identity.CenterURL); err != nil {
		return err
	}
	centerPublicKey, err := parseEdgeRemoteSSHCenterSigningPublicKey(config.RemoteSSHGatewayCenterSigningPublicKey)
	if err != nil {
		return err
	}
	if session.CenterSigningPublicKey != strings.TrimSpace(config.RemoteSSHGatewayCenterSigningPublicKey) {
		return fmt.Errorf("remote ssh center signing key mismatch")
	}
	signature, err := base64.StdEncoding.DecodeString(session.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("remote ssh session signature is invalid")
	}
	if !ed25519.Verify(centerPublicKey, []byte(edgeRemoteSSHDeviceSessionSignedMessage(session)), signature) {
		return fmt.Errorf("remote ssh session signature verification failed")
	}
	return acceptEdgeRemoteSSHSessionNonce(ctx, session.SessionID, session.Nonce, session.ExpiresAtUnix)
}

func parseEdgeRemoteSSHCenterSigningPublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	raw, ok := strings.CutPrefix(value, "ed25519:")
	if !ok || raw == "" {
		return nil, fmt.Errorf("remote ssh center signing public key is not configured")
	}
	decoded, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("remote ssh center signing public key is invalid")
	}
	return ed25519.PublicKey(decoded), nil
}

func edgeRemoteSSHDeviceSessionSignedMessage(session edgeRemoteSSHDeviceSession) string {
	return strings.Join([]string{
		"tukuyomi-remote-ssh-pending-v1",
		strings.TrimSpace(session.DeviceID),
		strings.TrimSpace(session.SessionID),
		strings.TrimSpace(session.OperatorPublicKey),
		strings.ToLower(strings.TrimSpace(session.OperatorPublicKeyFingerprintSHA256)),
		strconv.FormatInt(session.ExpiresAtUnix, 10),
		strconv.FormatInt(session.CreatedAtUnix, 10),
		strings.TrimSpace(session.Nonce),
	}, "\n")
}

func acceptEdgeRemoteSSHSessionNonce(ctx context.Context, sessionID string, nonce string, expiresAtUnix int64) error {
	sessionID = strings.TrimSpace(sessionID)
	nonce = strings.TrimSpace(nonce)
	if sessionID == "" || nonce == "" || expiresAtUnix <= time.Now().UTC().Unix() {
		return fmt.Errorf("remote ssh nonce payload is invalid")
	}
	sum := sha256.Sum256([]byte("remote-ssh-session-nonce\n" + sessionID + "\n" + nonce))
	nonceHash := hex.EncodeToString(sum[:])
	now := time.Now().UTC().Unix()
	return WithConfigDBStore(func(db *sql.DB, driver string) error {
		if _, err := db.ExecContext(ctx, `DELETE FROM remote_ssh_accepted_nonces WHERE expires_at_unix <= `+remoteSSHPlaceholder(driver, 1), now); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, `
INSERT INTO remote_ssh_accepted_nonces (nonce_hash, session_id, expires_at_unix, accepted_at_unix)
VALUES (`+remoteSSHPlaceholders(driver, 4, 1)+`)`,
			nonceHash,
			sessionID,
			expiresAtUnix,
			now,
		)
		if err != nil {
			return fmt.Errorf("remote ssh session nonce replay rejected")
		}
		return nil
	})
}

func remoteSSHPlaceholder(driver string, index int) string {
	if driver == "pgsql" {
		return fmt.Sprintf("$%d", index)
	}
	return "?"
}

func buildEdgeRemoteSSHShellEnv(term string, runAsUser string) []string {
	env := []string{
		"TERM=" + clampRemoteSSHTerm(term),
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	}
	username := strings.TrimSpace(runAsUser)
	home := ""
	if username != "" {
		if u, err := user.Lookup(username); err == nil {
			home = strings.TrimSpace(u.HomeDir)
		}
	} else if u, err := user.Current(); err == nil {
		username = strings.TrimSpace(u.Username)
		home = strings.TrimSpace(u.HomeDir)
		if slash := strings.LastIndex(username, string(os.PathSeparator)); slash >= 0 {
			username = username[slash+1:]
		}
	}
	if username != "" {
		env = append(env, "USER="+username, "LOGNAME="+username)
	}
	if strings.HasPrefix(home, "/") {
		env = append(env, "HOME="+home)
	}
	return env
}

func replySSHRequest(req *ssh.Request, ok bool) {
	if req.WantReply {
		_ = req.Reply(ok, nil)
	}
}

func remoteSSHCredentialForUser(name string) (*syscall.Credential, error) {
	u, err := user.Lookup(name)
	if err != nil {
		return nil, err
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid uid for %s", name)
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return nil, fmt.Errorf("invalid gid for %s", name)
	}
	return &syscall.Credential{Uid: uint32(uid), Gid: uint32(gid)}, nil
}

func ensureEdgeRemoteSSHHostSigner(ctx context.Context) (ssh.Signer, string, error) {
	edgeRemoteSSHHostKeyMu.Lock()
	defer edgeRemoteSSHHostKeyMu.Unlock()

	var signer ssh.Signer
	var fingerprint string
	err := WithConfigDBStore(func(db *sql.DB, driver string) error {
		row := db.QueryRowContext(ctx, `
SELECT private_key_pem, public_key_fingerprint_sha256
  FROM remote_ssh_host_keys
 ORDER BY created_at_unix ASC
 LIMIT 1`)
		var privatePEM string
		if err := row.Scan(&privatePEM, &fingerprint); err == nil {
			parsed, parseErr := signerFromRemoteSSHPrivateKeyPEM(privatePEM)
			if parseErr != nil {
				return parseErr
			}
			signer = parsed
			return nil
		} else if err != sql.ErrNoRows {
			return err
		}
		_, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
		if err != nil {
			return err
		}
		privatePEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
		parsed, err := ssh.NewSignerFromKey(privateKey)
		if err != nil {
			return err
		}
		fingerprint = remoteSSHPublicKeyFingerprintHex(parsed.PublicKey())
		keyID, err := remoteSSHHostKeyID()
		if err != nil {
			return err
		}
		_, err = db.ExecContext(ctx, `
INSERT INTO remote_ssh_host_keys
    (key_id, private_key_pem, public_key_fingerprint_sha256, created_at_unix, rotated_at_unix)
VALUES
    (`+remoteSSHPlaceholders(driver, 5, 1)+`)`,
			keyID,
			privatePEM,
			fingerprint,
			time.Now().UTC().Unix(),
			int64(0),
		)
		if err != nil {
			return err
		}
		signer = parsed
		return nil
	})
	return signer, fingerprint, err
}

func signerFromRemoteSSHPrivateKeyPEM(raw string) (ssh.Signer, error) {
	block, rest := pem.Decode([]byte(raw))
	if block == nil || block.Type != "PRIVATE KEY" || strings.TrimSpace(string(rest)) != "" {
		return nil, fmt.Errorf("invalid remote ssh host key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(key)
}

func remoteSSHPublicKeyFingerprintHex(key ssh.PublicKey) string {
	sum := sha256.Sum256(key.Marshal())
	return hex.EncodeToString(sum[:])
}

func remoteSSHHostKeyID() (string, error) {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return "host-" + hex.EncodeToString(raw[:]), nil
}

func signedEdgeRemoteSSHGatewayStreamHeaders(identity edgeDeviceIdentityRecord, sessionID string, hostKeyFingerprint string, hostPublicKey string) (http.Header, error) {
	privateKey, _, err := parseEdgeDevicePrivateKey(identity.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	timestamp := time.Now().UTC().Format(time.RFC3339Nano)
	nonce, err := randomEdgeIdentifier("nonce")
	if err != nil {
		return nil, err
	}
	bodyHash := edgeRemoteSSHGatewayStreamBodyHash(sessionID, hostKeyFingerprint, hostPublicKey)
	signature := ed25519.Sign(privateKey, []byte(edgeEnrollmentSignedMessage(identity.DeviceID, identity.KeyID, timestamp, nonce, bodyHash)))
	headers := http.Header{}
	headers.Set("X-Tukuyomi-Device-ID", identity.DeviceID)
	headers.Set("X-Tukuyomi-Key-ID", identity.KeyID)
	headers.Set("X-Tukuyomi-Public-Key-Fingerprint-SHA256", identity.PublicKeyFingerprintSHA256)
	headers.Set("X-Tukuyomi-Remote-SSH-Session-ID", strings.TrimSpace(sessionID))
	headers.Set("X-Tukuyomi-Remote-SSH-Host-Key-Fingerprint-SHA256", strings.ToLower(strings.TrimSpace(hostKeyFingerprint)))
	headers.Set("X-Tukuyomi-Remote-SSH-Host-Public-Key", strings.TrimSpace(hostPublicKey))
	headers.Set("X-Tukuyomi-Timestamp", timestamp)
	headers.Set("X-Tukuyomi-Nonce", nonce)
	headers.Set("X-Tukuyomi-Body-Hash", bodyHash)
	headers.Set("X-Tukuyomi-Signature", base64.StdEncoding.EncodeToString(signature))
	return headers, nil
}

func edgeRemoteSSHGatewayStreamBodyHash(sessionID string, hostKeyFingerprint string, hostPublicKey string) string {
	sum := sha256.Sum256([]byte("remote-ssh-gateway-stream\n" + strings.TrimSpace(sessionID) + "\n" + strings.ToLower(strings.TrimSpace(hostKeyFingerprint)) + "\n" + strings.TrimSpace(hostPublicKey)))
	return hex.EncodeToString(sum[:])
}

func centerRemoteSSHGatewayStreamURL(centerBaseURL string) (string, error) {
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
	if u.Scheme != "https" && !config.AllowInsecureDefaults {
		return "", fmt.Errorf("remote ssh center URL must use https unless admin.allow_insecure_defaults is enabled for local testing")
	}
	u.Path = "/v1/remote-ssh/gateway-stream"
	u.RawPath = ""
	return u.String(), nil
}

func centerRemoteSSHSigningKeyURL(centerBaseURL string) (string, error) {
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
	if u.Scheme != "https" && !config.AllowInsecureDefaults {
		return "", fmt.Errorf("remote ssh center URL must use https unless admin.allow_insecure_defaults is enabled for local testing")
	}
	u.Path = "/v1/remote-ssh/signing-key"
	u.RawPath = ""
	return u.String(), nil
}

func remoteSSHPlaceholders(driver string, count int, start int) string {
	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		if driver == "pgsql" {
			parts = append(parts, fmt.Sprintf("$%d", start+i))
		} else {
			parts = append(parts, "?")
		}
	}
	return strings.Join(parts, ", ")
}

func clampRemoteSSHTerm(term string) string {
	term = strings.TrimSpace(term)
	if term == "" || len(term) > 64 {
		return "xterm"
	}
	for _, r := range term {
		if r < 32 || r > 126 || r == '=' {
			return "xterm"
		}
	}
	return term
}
