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
	"strings"
	"time"

	"tukuyomi/internal/edgeartifactbundle"
)

const (
	MaxEnrollmentBodyBytes              = 64 * 1024
	MaxDeviceConfigSnapshotBodyBytes    = 3 * 1024 * 1024
	MaxDeviceConfigSnapshotPayloadBytes = 2 * 1024 * 1024
	MaxRuleArtifactBundleBodyBytes      = 12 * 1024 * 1024
	enrollmentFreshness                 = 10 * time.Minute
)

var (
	deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	keyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	noncePattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	hex64Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)
	metadataPattern = regexp.MustCompile(`^[ -~]{0,128}$`)

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

func normalizeDeviceStatusRequest(req DeviceStatusRequest, now time.Time) (DeviceStatusRequest, time.Time, error) {
	req.DeviceID = strings.TrimSpace(req.DeviceID)
	req.KeyID = strings.TrimSpace(req.KeyID)
	req.PublicKeyFingerprintSHA256 = strings.ToLower(strings.TrimSpace(req.PublicKeyFingerprintSHA256))
	req.Timestamp = strings.TrimSpace(req.Timestamp)
	req.Nonce = strings.TrimSpace(req.Nonce)
	req.RuntimeRole = strings.TrimSpace(req.RuntimeRole)
	req.BuildVersion = strings.TrimSpace(req.BuildVersion)
	req.GoVersion = strings.TrimSpace(req.GoVersion)
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

func deviceStatusBodyHashMatches(req DeviceStatusRequest) bool {
	if secureEqualHex(deviceStatusBodyHash(req), req.BodyHash) {
		return true
	}
	if req.RuntimeRole != "" || req.BuildVersion != "" || req.GoVersion != "" {
		return false
	}
	return secureEqualHex(legacyDeviceStatusBodyHash(req), req.BodyHash)
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
