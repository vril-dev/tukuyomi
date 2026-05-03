package center

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"tukuyomi/internal/edgeartifactbundle"
)

const (
	MaxEnrollmentBodyBytes               = 64 * 1024
	MaxDeviceStatusBodyBytes             = 64 * 1024
	MaxDeviceConfigSnapshotBodyBytes     = 3 * 1024 * 1024
	MaxDeviceConfigSnapshotPayloadBytes  = 2 * 1024 * 1024
	MaxRuleArtifactBundleBodyBytes       = 12 * 1024 * 1024
	MaxRuntimeArtifactDownloadBodyBytes  = 16 * 1024
	MaxProxyRulesBundleDownloadBodyBytes = 16 * 1024
	MaxWAFRuleArtifactDownloadBodyBytes  = 16 * 1024
	enrollmentFreshness                  = 10 * time.Minute
)

var (
	deviceIDPattern  = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	keyIDPattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	runtimeIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
	noncePattern     = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	hex64Pattern     = regexp.MustCompile(`^[a-f0-9]{64}$`)
	metadataPattern  = regexp.MustCompile(`^[ -~]{0,128}$`)

	ErrInvalidEnrollment = errors.New("invalid device enrollment")
)

type EnrollmentRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyPEMB64            string `json:"public_key_pem_b64"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type DeviceStatusRequest struct {
	DeviceID                   string                      `json:"device_id"`
	KeyID                      string                      `json:"key_id"`
	PublicKeyFingerprintSHA256 string                      `json:"public_key_fingerprint_sha256"`
	Timestamp                  string                      `json:"timestamp"`
	Nonce                      string                      `json:"nonce"`
	RuntimeRole                string                      `json:"runtime_role,omitempty"`
	BuildVersion               string                      `json:"build_version,omitempty"`
	GoVersion                  string                      `json:"go_version,omitempty"`
	OS                         string                      `json:"os,omitempty"`
	Arch                       string                      `json:"arch,omitempty"`
	KernelVersion              string                      `json:"kernel_version,omitempty"`
	DistroID                   string                      `json:"distro_id,omitempty"`
	DistroIDLike               string                      `json:"distro_id_like,omitempty"`
	DistroVersion              string                      `json:"distro_version,omitempty"`
	RuntimeDeploymentSupported bool                        `json:"runtime_deployment_supported,omitempty"`
	RuntimeInventory           []DeviceRuntimeSummary      `json:"runtime_inventory,omitempty"`
	ProxyRuleApplyStatus       *DeviceProxyRuleApplyStatus `json:"proxy_rule_apply_status,omitempty"`
	WAFRuleApplyStatus         *DeviceWAFRuleApplyStatus   `json:"waf_rule_apply_status,omitempty"`
	BodyHash                   string                      `json:"body_hash"`
	SignatureB64               string                      `json:"signature_b64"`
}

type DeviceRuntimeSummary struct {
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
	UpdatedAtUnix       int64    `json:"updated_at_unix,omitempty"`
}

type DeviceProxyRuleApplyStatus struct {
	DesiredBundleRevision string `json:"desired_bundle_revision,omitempty"`
	LocalProxyETag        string `json:"local_proxy_etag,omitempty"`
	ApplyState            string `json:"apply_state,omitempty"`
	ApplyError            string `json:"apply_error,omitempty"`
}

type DeviceWAFRuleApplyStatus struct {
	DesiredBundleRevision string `json:"desired_bundle_revision,omitempty"`
	LocalBundleRevision   string `json:"local_bundle_revision,omitempty"`
	ApplyState            string `json:"apply_state,omitempty"`
	ApplyError            string `json:"apply_error,omitempty"`
}

type DeviceConfigSnapshotRequest struct {
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

type RuleArtifactBundleRequest struct {
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

type RuntimeArtifactDownloadRequest struct {
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

type ProxyRulesBundleDownloadRequest struct {
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

type WAFRuleArtifactDownloadRequest struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Timestamp                  string `json:"timestamp"`
	Nonce                      string `json:"nonce"`
	BundleRevision             string `json:"bundle_revision"`
	BodyHash                   string `json:"body_hash"`
	SignatureB64               string `json:"signature_b64"`
}

type verifiedEnrollment struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyPEM               string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	NonceHash                  string
	BodyHash                   string
	SignatureB64               string
}

type verifiedDeviceStatusRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	RuntimeRole                string
	BuildVersion               string
	GoVersion                  string
	OS                         string
	Arch                       string
	KernelVersion              string
	DistroID                   string
	DistroIDLike               string
	DistroVersion              string
	RuntimeDeploymentSupported bool
	RuntimeInventory           []DeviceRuntimeSummary
	ProxyRuleApplyStatus       *DeviceProxyRuleApplyStatus
	WAFRuleApplyStatus         *DeviceWAFRuleApplyStatus
	BodyHash                   string
	SignatureB64               string
}

type verifiedDeviceConfigSnapshotRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	ConfigRevision             string
	PayloadHash                string
	PayloadJSON                []byte
	BodyHash                   string
	SignatureB64               string
}

type verifiedRuleArtifactBundleRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	BundleRevision             string
	BundleHash                 string
	CompressedSize             int64
	UncompressedSize           int64
	FileCount                  int
	BundleBytes                []byte
	BodyHash                   string
	SignatureB64               string
}

type verifiedRuntimeArtifactDownloadRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	RuntimeFamily              string
	RuntimeID                  string
	ArtifactRevision           string
	ArtifactHash               string
	BodyHash                   string
	SignatureB64               string
}

type verifiedProxyRulesBundleDownloadRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	BundleRevision             string
	PayloadHash                string
	BodyHash                   string
	SignatureB64               string
}

type verifiedWAFRuleArtifactDownloadRequest struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  time.Time
	BundleRevision             string
	BodyHash                   string
	SignatureB64               string
}

func VerifyEnrollmentRequest(req EnrollmentRequest, now time.Time) (verifiedEnrollment, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyPEMB64 = strings.TrimSpace(req.PublicKeyPEMB64)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.PublicKeyPEMB64 == "" || len(req.PublicKeyPEMB64) > MaxEnrollmentBodyBytes {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid public key payload", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return verifiedEnrollment{}, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}

	pemBytes, publicKeyDER, publicKey, err := parseEnrollmentPublicKey(req.PublicKeyPEMB64)
	if err != nil {
		return verifiedEnrollment{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedEnrollment{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}

	bodyHash := enrollmentBodyHash(req)
	if !secureEqualHex(bodyHash, req.BodyHash) {
		return verifiedEnrollment{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}

	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedEnrollment{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedEnrollment{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}

	nonceHash := sha256.Sum256([]byte(req.DeviceID + "\n" + req.KeyID + "\n" + req.Nonce))
	return verifiedEnrollment{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyPEM:               string(pemBytes),
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		NonceHash:                  hex.EncodeToString(nonceHash[:]),
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyDeviceStatusRequest(req DeviceStatusRequest, publicKeyPEM string, now time.Time) (verifiedDeviceStatusRequest, error) {
	normalized, ts, err := normalizeDeviceStatusRequest(req, now)
	if err != nil {
		return verifiedDeviceStatusRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedDeviceStatusRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedDeviceStatusRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	if !deviceStatusBodyHashMatches(req) {
		return verifiedDeviceStatusRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedDeviceStatusRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedDeviceStatusRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedDeviceStatusRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		RuntimeRole:                req.RuntimeRole,
		BuildVersion:               req.BuildVersion,
		GoVersion:                  req.GoVersion,
		OS:                         req.OS,
		Arch:                       req.Arch,
		KernelVersion:              req.KernelVersion,
		DistroID:                   req.DistroID,
		DistroIDLike:               req.DistroIDLike,
		DistroVersion:              req.DistroVersion,
		RuntimeDeploymentSupported: req.RuntimeDeploymentSupported,
		RuntimeInventory:           append([]DeviceRuntimeSummary(nil), req.RuntimeInventory...),
		ProxyRuleApplyStatus:       req.ProxyRuleApplyStatus,
		WAFRuleApplyStatus:         req.WAFRuleApplyStatus,
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyDeviceConfigSnapshotRequest(req DeviceConfigSnapshotRequest, publicKeyPEM string, now time.Time) (verifiedDeviceConfigSnapshotRequest, error) {
	normalized, ts, payloadJSON, err := normalizeDeviceConfigSnapshotRequest(req, now)
	if err != nil {
		return verifiedDeviceConfigSnapshotRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedDeviceConfigSnapshotRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedDeviceConfigSnapshotRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	payloadHash := sha256.Sum256(payloadJSON)
	if !secureEqualHex(hex.EncodeToString(payloadHash[:]), req.PayloadHash) {
		return verifiedDeviceConfigSnapshotRequest{}, fmt.Errorf("%w: payload_hash mismatch", ErrInvalidEnrollment)
	}
	if !secureEqualHex(deviceConfigSnapshotBodyHash(req), req.BodyHash) {
		return verifiedDeviceConfigSnapshotRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedDeviceConfigSnapshotRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedDeviceConfigSnapshotRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedDeviceConfigSnapshotRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		ConfigRevision:             req.ConfigRevision,
		PayloadHash:                req.PayloadHash,
		PayloadJSON:                payloadJSON,
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyRuleArtifactBundleRequest(req RuleArtifactBundleRequest, publicKeyPEM string, now time.Time) (verifiedRuleArtifactBundleRequest, error) {
	normalized, ts, bundleBytes, err := normalizeRuleArtifactBundleRequest(req, now)
	if err != nil {
		return verifiedRuleArtifactBundleRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedRuleArtifactBundleRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedRuleArtifactBundleRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	bundleHash := sha256.Sum256(bundleBytes)
	if !secureEqualHex(hex.EncodeToString(bundleHash[:]), req.BundleHash) {
		return verifiedRuleArtifactBundleRequest{}, fmt.Errorf("%w: bundle_hash mismatch", ErrInvalidEnrollment)
	}
	if !secureEqualHex(ruleArtifactBundleBodyHash(req), req.BodyHash) {
		return verifiedRuleArtifactBundleRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedRuleArtifactBundleRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedRuleArtifactBundleRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedRuleArtifactBundleRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		BundleRevision:             req.BundleRevision,
		BundleHash:                 req.BundleHash,
		CompressedSize:             req.CompressedSize,
		UncompressedSize:           req.UncompressedSize,
		FileCount:                  req.FileCount,
		BundleBytes:                append([]byte(nil), bundleBytes...),
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyRuntimeArtifactDownloadRequest(req RuntimeArtifactDownloadRequest, publicKeyPEM string, now time.Time) (verifiedRuntimeArtifactDownloadRequest, error) {
	normalized, ts, err := normalizeRuntimeArtifactDownloadRequest(req, now)
	if err != nil {
		return verifiedRuntimeArtifactDownloadRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedRuntimeArtifactDownloadRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedRuntimeArtifactDownloadRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	if !secureEqualHex(runtimeArtifactDownloadBodyHash(req), req.BodyHash) {
		return verifiedRuntimeArtifactDownloadRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedRuntimeArtifactDownloadRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedRuntimeArtifactDownloadRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedRuntimeArtifactDownloadRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		RuntimeFamily:              req.RuntimeFamily,
		RuntimeID:                  req.RuntimeID,
		ArtifactRevision:           req.ArtifactRevision,
		ArtifactHash:               req.ArtifactHash,
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyProxyRulesBundleDownloadRequest(req ProxyRulesBundleDownloadRequest, publicKeyPEM string, now time.Time) (verifiedProxyRulesBundleDownloadRequest, error) {
	normalized, ts, err := normalizeProxyRulesBundleDownloadRequest(req, now)
	if err != nil {
		return verifiedProxyRulesBundleDownloadRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedProxyRulesBundleDownloadRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedProxyRulesBundleDownloadRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	if !secureEqualHex(proxyRulesBundleDownloadBodyHash(req), req.BodyHash) {
		return verifiedProxyRulesBundleDownloadRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedProxyRulesBundleDownloadRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedProxyRulesBundleDownloadRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedProxyRulesBundleDownloadRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		BundleRevision:             req.BundleRevision,
		PayloadHash:                req.PayloadHash,
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func VerifyWAFRuleArtifactDownloadRequest(req WAFRuleArtifactDownloadRequest, publicKeyPEM string, now time.Time) (verifiedWAFRuleArtifactDownloadRequest, error) {
	normalized, ts, err := normalizeWAFRuleArtifactDownloadRequest(req, now)
	if err != nil {
		return verifiedWAFRuleArtifactDownloadRequest{}, err
	}
	req = normalized

	publicKeyDER, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return verifiedWAFRuleArtifactDownloadRequest{}, err
	}
	fingerprint := sha256.Sum256(publicKeyDER)
	if !secureEqualHex(hex.EncodeToString(fingerprint[:]), req.PublicKeyFingerprintSHA256) {
		return verifiedWAFRuleArtifactDownloadRequest{}, fmt.Errorf("%w: public key fingerprint mismatch", ErrInvalidEnrollment)
	}
	if !secureEqualHex(wafRuleArtifactDownloadBodyHash(req), req.BodyHash) {
		return verifiedWAFRuleArtifactDownloadRequest{}, fmt.Errorf("%w: body_hash mismatch", ErrInvalidEnrollment)
	}
	signature, err := base64.StdEncoding.DecodeString(req.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return verifiedWAFRuleArtifactDownloadRequest{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(req.DeviceID, req.KeyID, req.Timestamp, req.Nonce, req.BodyHash)), signature) {
		return verifiedWAFRuleArtifactDownloadRequest{}, fmt.Errorf("%w: signature verification failed", ErrInvalidEnrollment)
	}
	return verifiedWAFRuleArtifactDownloadRequest{
		DeviceID:                   req.DeviceID,
		KeyID:                      req.KeyID,
		PublicKeyFingerprintSHA256: req.PublicKeyFingerprintSHA256,
		Timestamp:                  ts.UTC(),
		BundleRevision:             req.BundleRevision,
		BodyHash:                   req.BodyHash,
		SignatureB64:               req.SignatureB64,
	}, nil
}

func normalizeDeviceStatusRequest(req DeviceStatusRequest, now time.Time) (DeviceStatusRequest, time.Time, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.RuntimeRole = strings.TrimSpace(req.RuntimeRole)
	req.BuildVersion = strings.TrimSpace(req.BuildVersion)
	req.GoVersion = strings.TrimSpace(req.GoVersion)
	req.OS = strings.TrimSpace(req.OS)
	req.Arch = strings.TrimSpace(req.Arch)
	req.KernelVersion = strings.TrimSpace(req.KernelVersion)
	req.DistroID = strings.TrimSpace(req.DistroID)
	req.DistroIDLike = strings.TrimSpace(req.DistroIDLike)
	req.DistroVersion = strings.TrimSpace(req.DistroVersion)
	var err error
	req.RuntimeInventory, err = normalizeDeviceRuntimeSummaries(req.RuntimeInventory)
	if err != nil {
		return DeviceStatusRequest{}, time.Time{}, err
	}
	req.ProxyRuleApplyStatus, err = normalizeDeviceProxyRuleApplyStatus(req.ProxyRuleApplyStatus)
	if err != nil {
		return DeviceStatusRequest{}, time.Time{}, err
	}
	req.WAFRuleApplyStatus, err = normalizeDeviceWAFRuleApplyStatus(req.WAFRuleApplyStatus)
	if err != nil {
		return DeviceStatusRequest{}, time.Time{}, err
	}
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.RuntimeRole) || len(req.RuntimeRole) > 64 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid runtime_role", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.BuildVersion) || len(req.BuildVersion) > 128 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid build_version", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.GoVersion) || len(req.GoVersion) > 64 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid go_version", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.OS) || len(req.OS) > 32 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid os", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.Arch) || len(req.Arch) > 32 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid arch", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.KernelVersion) || len(req.KernelVersion) > 128 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid kernel_version", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.DistroID) || len(req.DistroID) > 64 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid distro_id", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.DistroIDLike) || len(req.DistroIDLike) > 128 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid distro_id_like", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(req.DistroVersion) || len(req.DistroVersion) > 64 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid distro_version", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return DeviceStatusRequest{}, time.Time{}, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), nil
}

func normalizeDeviceProxyRuleApplyStatus(status *DeviceProxyRuleApplyStatus) (*DeviceProxyRuleApplyStatus, error) {
	if status == nil {
		return nil, nil
	}
	out := *status
	out.DesiredBundleRevision = strings.ToLower(strings.TrimSpace(out.DesiredBundleRevision))
	out.LocalProxyETag = strings.TrimSpace(out.LocalProxyETag)
	out.ApplyState = strings.TrimSpace(out.ApplyState)
	out.ApplyError = strings.TrimSpace(out.ApplyError)
	if out.DesiredBundleRevision == "" && out.LocalProxyETag == "" && out.ApplyState == "" && out.ApplyError == "" {
		return nil, nil
	}
	if out.DesiredBundleRevision != "" && !hex64Pattern.MatchString(out.DesiredBundleRevision) {
		return nil, fmt.Errorf("%w: invalid proxy_rule_apply_status.desired_bundle_revision", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(out.LocalProxyETag) || len(out.LocalProxyETag) > 128 {
		return nil, fmt.Errorf("%w: invalid proxy_rule_apply_status.local_proxy_etag", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(out.ApplyState) || len(out.ApplyState) > 32 {
		return nil, fmt.Errorf("%w: invalid proxy_rule_apply_status.apply_state", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(out.ApplyError) || len(out.ApplyError) > 256 {
		return nil, fmt.Errorf("%w: invalid proxy_rule_apply_status.apply_error", ErrInvalidEnrollment)
	}
	return &out, nil
}

func normalizeDeviceWAFRuleApplyStatus(status *DeviceWAFRuleApplyStatus) (*DeviceWAFRuleApplyStatus, error) {
	if status == nil {
		return nil, nil
	}
	out := *status
	out.DesiredBundleRevision = strings.ToLower(strings.TrimSpace(out.DesiredBundleRevision))
	out.LocalBundleRevision = strings.ToLower(strings.TrimSpace(out.LocalBundleRevision))
	out.ApplyState = strings.TrimSpace(out.ApplyState)
	out.ApplyError = strings.TrimSpace(out.ApplyError)
	if out.DesiredBundleRevision == "" && out.LocalBundleRevision == "" && out.ApplyState == "" && out.ApplyError == "" {
		return nil, nil
	}
	if out.DesiredBundleRevision != "" && !hex64Pattern.MatchString(out.DesiredBundleRevision) {
		return nil, fmt.Errorf("%w: invalid waf_rule_apply_status.desired_bundle_revision", ErrInvalidEnrollment)
	}
	if out.LocalBundleRevision != "" && !hex64Pattern.MatchString(out.LocalBundleRevision) {
		return nil, fmt.Errorf("%w: invalid waf_rule_apply_status.local_bundle_revision", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(out.ApplyState) || len(out.ApplyState) > 32 {
		return nil, fmt.Errorf("%w: invalid waf_rule_apply_status.apply_state", ErrInvalidEnrollment)
	}
	if !metadataPattern.MatchString(out.ApplyError) || len(out.ApplyError) > 256 {
		return nil, fmt.Errorf("%w: invalid waf_rule_apply_status.apply_error", ErrInvalidEnrollment)
	}
	return &out, nil
}

func normalizeDeviceRuntimeSummaries(items []DeviceRuntimeSummary) ([]DeviceRuntimeSummary, error) {
	if len(items) > 64 {
		return nil, fmt.Errorf("%w: invalid runtime_inventory", ErrInvalidEnrollment)
	}
	out := make([]DeviceRuntimeSummary, 0, len(items))
	seen := map[string]struct{}{}
	for i, item := range items {
		item.RuntimeFamily = strings.TrimSpace(item.RuntimeFamily)
		item.RuntimeID = strings.TrimSpace(item.RuntimeID)
		item.DisplayName = strings.TrimSpace(item.DisplayName)
		item.DetectedVersion = strings.TrimSpace(item.DetectedVersion)
		item.Source = strings.TrimSpace(item.Source)
		item.AvailabilityMessage = strings.TrimSpace(item.AvailabilityMessage)
		item.GeneratedTargets = normalizeDeviceRuntimeGeneratedTargets(item.GeneratedTargets)
		item.ArtifactRevision = strings.ToLower(strings.TrimSpace(item.ArtifactRevision))
		item.ArtifactHash = strings.ToLower(strings.TrimSpace(item.ArtifactHash))
		item.ApplyState = strings.TrimSpace(item.ApplyState)
		item.ApplyError = strings.TrimSpace(item.ApplyError)
		item.UpdatedAtUnix = 0

		switch item.RuntimeFamily {
		case "php-fpm", "psgi":
		default:
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].runtime_family", ErrInvalidEnrollment, i)
		}
		if !runtimeIDPattern.MatchString(item.RuntimeID) {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].runtime_id", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.DisplayName) || len(item.DisplayName) > 128 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].display_name", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.DetectedVersion) || len(item.DetectedVersion) > 128 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].detected_version", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.Source) || len(item.Source) > 32 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].source", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.AvailabilityMessage) || len(item.AvailabilityMessage) > 256 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].availability_message", ErrInvalidEnrollment, i)
		}
		if item.ModuleCount < 0 || item.ModuleCount > 100000 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].module_count", ErrInvalidEnrollment, i)
		}
		if item.AppCount < 0 || item.AppCount > 100000 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].app_count", ErrInvalidEnrollment, i)
		}
		if item.AppCount < len(item.GeneratedTargets) {
			item.AppCount = len(item.GeneratedTargets)
		}
		if !item.UsageReported {
			item.AppCount = 0
			item.GeneratedTargets = nil
			item.ProcessRunning = false
		}
		for j, target := range item.GeneratedTargets {
			if !metadataPattern.MatchString(target) || len(target) > 128 {
				return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].generated_targets[%d]", ErrInvalidEnrollment, i, j)
			}
		}
		if item.ArtifactRevision != "" && !hex64Pattern.MatchString(item.ArtifactRevision) {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].artifact_revision", ErrInvalidEnrollment, i)
		}
		if item.ArtifactHash != "" && !hex64Pattern.MatchString(item.ArtifactHash) {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].artifact_hash", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.ApplyState) || len(item.ApplyState) > 32 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].apply_state", ErrInvalidEnrollment, i)
		}
		if !metadataPattern.MatchString(item.ApplyError) || len(item.ApplyError) > 256 {
			return nil, fmt.Errorf("%w: invalid runtime_inventory[%d].apply_error", ErrInvalidEnrollment, i)
		}
		key := item.RuntimeFamily + "\x00" + item.RuntimeID
		if _, ok := seen[key]; ok {
			return nil, fmt.Errorf("%w: duplicate runtime_inventory entry", ErrInvalidEnrollment)
		}
		seen[key] = struct{}{}
		out = append(out, item)
	}
	sortDeviceRuntimeSummaries(out)
	return out, nil
}

func normalizeDeviceRuntimeGeneratedTargets(items []string) []string {
	if len(items) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
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
	if len(out) > 64 {
		out = out[:64]
	}
	return out
}

func sortDeviceRuntimeSummaries(items []DeviceRuntimeSummary) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].RuntimeFamily != items[j].RuntimeFamily {
			return items[i].RuntimeFamily < items[j].RuntimeFamily
		}
		return items[i].RuntimeID < items[j].RuntimeID
	})
}

func normalizeDeviceConfigSnapshotRequest(req DeviceConfigSnapshotRequest, now time.Time) (DeviceConfigSnapshotRequest, time.Time, []byte, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.ConfigRevision = strings.ToLower(strings.TrimSpace(req.ConfigRevision))
	req.PayloadHash = strings.ToLower(strings.TrimSpace(req.PayloadHash))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.ConfigRevision) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid config_revision", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PayloadHash) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid payload_hash", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	raw := bytes.TrimSpace(req.Snapshot)
	if len(raw) == 0 || len(raw) > MaxDeviceConfigSnapshotPayloadBytes {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid snapshot size", ErrInvalidEnrollment)
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid snapshot JSON", ErrInvalidEnrollment)
	}
	if _, ok := decoded.(map[string]any); !ok {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: snapshot must be a JSON object", ErrInvalidEnrollment)
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, raw); err != nil {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid snapshot JSON", ErrInvalidEnrollment)
	}
	payloadJSON := compacted.Bytes()
	req.Snapshot = append(json.RawMessage(nil), payloadJSON...)

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return DeviceConfigSnapshotRequest{}, time.Time{}, nil, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), payloadJSON, nil
}

func normalizeRuleArtifactBundleRequest(req RuleArtifactBundleRequest, now time.Time) (RuleArtifactBundleRequest, time.Time, []byte, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.BundleRevision = strings.ToLower(strings.TrimSpace(req.BundleRevision))
	req.BundleHash = strings.ToLower(strings.TrimSpace(req.BundleHash))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)
	req.BundleB64 = strings.TrimSpace(req.BundleB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BundleRevision) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid bundle_revision", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BundleHash) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid bundle_hash", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.CompressedSize <= 0 || req.CompressedSize > edgeartifactbundle.MaxCompressedBytes {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid compressed_size", ErrInvalidEnrollment)
	}
	if req.UncompressedSize <= 0 || req.UncompressedSize > edgeartifactbundle.MaxUncompressedBytes {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid uncompressed_size", ErrInvalidEnrollment)
	}
	if req.FileCount <= 0 || req.FileCount > edgeartifactbundle.MaxFiles {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid file_count", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}
	if req.BundleB64 == "" || len(req.BundleB64) > MaxRuleArtifactBundleBodyBytes {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid bundle payload", ErrInvalidEnrollment)
	}
	bundleBytes, err := base64.StdEncoding.DecodeString(req.BundleB64)
	if err != nil {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: bundle payload is not base64", ErrInvalidEnrollment)
	}
	if int64(len(bundleBytes)) != req.CompressedSize {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: compressed_size mismatch", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return RuleArtifactBundleRequest{}, time.Time{}, nil, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), bundleBytes, nil
}

func normalizeRuntimeArtifactDownloadRequest(req RuntimeArtifactDownloadRequest, now time.Time) (RuntimeArtifactDownloadRequest, time.Time, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.RuntimeFamily = strings.TrimSpace(req.RuntimeFamily)
	req.RuntimeID = strings.TrimSpace(req.RuntimeID)
	req.ArtifactRevision = strings.ToLower(strings.TrimSpace(req.ArtifactRevision))
	req.ArtifactHash = strings.ToLower(strings.TrimSpace(req.ArtifactHash))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	switch req.RuntimeFamily {
	case RuntimeFamilyPHPFPM:
		switch req.RuntimeID {
		case "php83", "php84", "php85":
		default:
			return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid runtime_id", ErrInvalidEnrollment)
		}
	case RuntimeFamilyPSGI:
		switch req.RuntimeID {
		case "perl536", "perl538", "perl540":
		default:
			return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid runtime_id", ErrInvalidEnrollment)
		}
	default:
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid runtime_family", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.ArtifactRevision) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid artifact_revision", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.ArtifactHash) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid artifact_hash", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return RuntimeArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), nil
}

func normalizeProxyRulesBundleDownloadRequest(req ProxyRulesBundleDownloadRequest, now time.Time) (ProxyRulesBundleDownloadRequest, time.Time, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.BundleRevision = strings.ToLower(strings.TrimSpace(req.BundleRevision))
	req.PayloadHash = strings.ToLower(strings.TrimSpace(req.PayloadHash))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BundleRevision) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid bundle_revision", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PayloadHash) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid payload_hash", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return ProxyRulesBundleDownloadRequest{}, time.Time{}, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), nil
}

func normalizeWAFRuleArtifactDownloadRequest(req WAFRuleArtifactDownloadRequest, now time.Time) (WAFRuleArtifactDownloadRequest, time.Time, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.BundleRevision = strings.ToLower(strings.TrimSpace(req.BundleRevision))
	req.BodyHash = strings.ToLower(strings.TrimSpace(req.BodyHash))
	req.SignatureB64 = strings.TrimSpace(req.SignatureB64)

	if !deviceIDPattern.MatchString(req.DeviceID) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid device_id", ErrInvalidEnrollment)
	}
	if !keyIDPattern.MatchString(req.KeyID) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid key_id", ErrInvalidEnrollment)
	}
	if !noncePattern.MatchString(req.Nonce) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid nonce", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.PublicKeyFingerprintSHA256) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid public key fingerprint", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BundleRevision) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid bundle_revision", ErrInvalidEnrollment)
	}
	if !hex64Pattern.MatchString(req.BodyHash) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid body_hash", ErrInvalidEnrollment)
	}
	if req.SignatureB64 == "" || len(req.SignatureB64) > 4096 {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid signature", ErrInvalidEnrollment)
	}

	ts, err := time.Parse(time.RFC3339Nano, req.Timestamp)
	if err != nil {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: invalid timestamp", ErrInvalidEnrollment)
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return WAFRuleArtifactDownloadRequest{}, time.Time{}, fmt.Errorf("%w: stale timestamp", ErrInvalidEnrollment)
	}
	return req, ts.UTC(), nil
}

func parseEnrollmentPublicKey(publicKeyPEMB64 string) ([]byte, []byte, ed25519.PublicKey, error) {
	pemBytes, err := base64.StdEncoding.DecodeString(publicKeyPEMB64)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: public key is not base64", ErrInvalidEnrollment)
	}
	if len(pemBytes) == 0 || len(pemBytes) > MaxEnrollmentBodyBytes {
		return nil, nil, nil, fmt.Errorf("%w: invalid public key size", ErrInvalidEnrollment)
	}
	block, rest := pem.Decode(pemBytes)
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, nil, fmt.Errorf("%w: public key must be a single PEM block", ErrInvalidEnrollment)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("%w: parse public key", ErrInvalidEnrollment)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, nil, fmt.Errorf("%w: public key must be Ed25519", ErrInvalidEnrollment)
	}
	return pemBytes, block.Bytes, pub, nil
}

func parseStoredEnrollmentPublicKey(publicKeyPEM string) ([]byte, ed25519.PublicKey, error) {
	block, rest := pem.Decode([]byte(publicKeyPEM))
	if block == nil || len(strings.TrimSpace(string(rest))) != 0 {
		return nil, nil, fmt.Errorf("%w: public key must be a single PEM block", ErrInvalidEnrollment)
	}
	pubAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: parse public key", ErrInvalidEnrollment)
	}
	pub, ok := pubAny.(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, nil, fmt.Errorf("%w: public key must be Ed25519", ErrInvalidEnrollment)
	}
	return block.Bytes, pub, nil
}

func enrollmentBodyHash(req EnrollmentRequest) string {
	sum := sha256.Sum256([]byte(enrollmentBodyCanonical(req)))
	return hex.EncodeToString(sum[:])
}

func deviceStatusBodyHash(req DeviceStatusRequest) string {
	body := deviceStatusBodyCanonical(req) + "\n" + strconv.FormatBool(req.RuntimeDeploymentSupported) + "\n" + deviceRuntimeInventoryCanonical(req.RuntimeInventory)
	if req.ProxyRuleApplyStatus != nil {
		body += "\n" + deviceProxyRuleApplyStatusCanonical(*req.ProxyRuleApplyStatus)
	}
	if req.WAFRuleApplyStatus != nil {
		body += "\n" + deviceWAFRuleApplyStatusCanonical(*req.WAFRuleApplyStatus)
	}
	sum := sha256.Sum256([]byte(body))
	return hex.EncodeToString(sum[:])
}

func platformDeviceStatusBodyHash(req DeviceStatusRequest) string {
	sum := sha256.Sum256([]byte(deviceStatusBodyCanonical(req)))
	return hex.EncodeToString(sum[:])
}

func deviceStatusBodyCanonical(req DeviceStatusRequest) string {
	return req.DeviceID + "\n" +
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
		req.DistroVersion
}

func deviceRuntimeInventoryCanonical(items []DeviceRuntimeSummary) string {
	if len(items) == 0 {
		return "0"
	}
	sorted := append([]DeviceRuntimeSummary(nil), items...)
	sortDeviceRuntimeSummaries(sorted)
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
		b.WriteString(strings.Join(normalizeDeviceRuntimeGeneratedTargets(item.GeneratedTargets), ","))
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

func deviceProxyRuleApplyStatusCanonical(status DeviceProxyRuleApplyStatus) string {
	return status.DesiredBundleRevision + "\n" +
		status.LocalProxyETag + "\n" +
		status.ApplyState + "\n" +
		status.ApplyError
}

func deviceWAFRuleApplyStatusCanonical(status DeviceWAFRuleApplyStatus) string {
	return status.DesiredBundleRevision + "\n" +
		status.LocalBundleRevision + "\n" +
		status.ApplyState + "\n" +
		status.ApplyError
}

func deviceConfigSnapshotBodyHash(req DeviceConfigSnapshotRequest) string {
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

func ruleArtifactBundleBodyHash(req RuleArtifactBundleRequest) string {
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

func runtimeArtifactDownloadBodyHash(req RuntimeArtifactDownloadRequest) string {
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

func proxyRulesBundleDownloadBodyHash(req ProxyRulesBundleDownloadRequest) string {
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

func wafRuleArtifactDownloadBodyHash(req WAFRuleArtifactDownloadRequest) string {
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

func deviceStatusBodyHashMatches(req DeviceStatusRequest) bool {
	if secureEqualHex(deviceStatusBodyHash(req), req.BodyHash) {
		return true
	}
	if req.ProxyRuleApplyStatus != nil || req.WAFRuleApplyStatus != nil {
		return false
	}
	if req.RuntimeDeploymentSupported || len(req.RuntimeInventory) > 0 {
		return secureEqualHex(deviceStatusBodyHashV1RuntimeInventory(req), req.BodyHash)
	}
	if secureEqualHex(platformDeviceStatusBodyHash(req), req.BodyHash) {
		return true
	}
	if req.OS != "" || req.Arch != "" || req.KernelVersion != "" || req.DistroID != "" || req.DistroIDLike != "" || req.DistroVersion != "" {
		return false
	}
	if secureEqualHex(runtimeInventoryDeviceStatusBodyHash(req), req.BodyHash) {
		return true
	}
	if req.RuntimeRole != "" || req.BuildVersion != "" || req.GoVersion != "" {
		return false
	}
	return secureEqualHex(legacyDeviceStatusBodyHash(req), req.BodyHash)
}

func deviceStatusBodyHashV1RuntimeInventory(req DeviceStatusRequest) string {
	sum := sha256.Sum256([]byte(deviceStatusBodyCanonical(req) + "\n" + strconv.FormatBool(req.RuntimeDeploymentSupported) + "\n" + deviceRuntimeInventoryCanonicalV1(req.RuntimeInventory)))
	return hex.EncodeToString(sum[:])
}

func deviceRuntimeInventoryCanonicalV1(items []DeviceRuntimeSummary) string {
	if len(items) == 0 {
		return "0"
	}
	sorted := append([]DeviceRuntimeSummary(nil), items...)
	sortDeviceRuntimeSummaries(sorted)
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

func runtimeInventoryDeviceStatusBodyHash(req DeviceStatusRequest) string {
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

func legacyDeviceStatusBodyHash(req DeviceStatusRequest) string {
	sum := sha256.Sum256([]byte(
		req.DeviceID + "\n" +
			req.KeyID + "\n" +
			req.PublicKeyFingerprintSHA256 + "\n" +
			req.Timestamp + "\n" +
			req.Nonce,
	))
	return hex.EncodeToString(sum[:])
}

func enrollmentBodyCanonical(req EnrollmentRequest) string {
	return req.DeviceID + "\n" +
		req.KeyID + "\n" +
		req.PublicKeyPEMB64 + "\n" +
		req.PublicKeyFingerprintSHA256 + "\n" +
		req.Timestamp + "\n" +
		req.Nonce
}

func signedEnvelopeMessage(deviceID, keyID, timestamp, nonce, bodyHash string) string {
	return deviceID + "\n" + keyID + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash
}

func enrollmentLicenseKeyHash(r *http.Request) string {
	if r == nil {
		return ""
	}
	raw := strings.TrimSpace(r.Header.Get("X-Enrollment-Token"))
	if raw == "" {
		raw = strings.TrimSpace(r.Header.Get("X-License-Key"))
	}
	if raw == "" {
		return ""
	}
	if len(raw) > enrollmentTokenMaxBytes {
		return ""
	}
	return enrollmentTokenHash(raw)
}

func secureEqualHex(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
