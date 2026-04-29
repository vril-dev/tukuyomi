package center

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	MaxEnrollmentBodyBytes = 64 * 1024
	enrollmentFreshness    = 10 * time.Minute
)

var (
	deviceIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	keyIDPattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)
	noncePattern    = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)
	hex64Pattern    = regexp.MustCompile(`^[a-f0-9]{64}$`)

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

func enrollmentBodyHash(req EnrollmentRequest) string {
	sum := sha256.Sum256([]byte(enrollmentBodyCanonical(req)))
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
	raw := strings.TrimSpace(r.Header.Get("X-License-Key"))
	if raw == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func secureEqualHex(a, b string) bool {
	a = strings.ToLower(strings.TrimSpace(a))
	b = strings.ToLower(strings.TrimSpace(b))
	if len(a) != len(b) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
