package center

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const deviceUploadSignerContextKey = "center_device_upload_signer"

var errDeviceUploadContentMismatch = errors.New("device upload content hash mismatch")

var (
	deviceUploadLegacyWarningMu   sync.Mutex
	lastDeviceUploadLegacyWarning time.Time
)

type deviceUploadSignedHeaders struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyFingerprintSHA256 string
	Timestamp                  string
	Nonce                      string
	ContentSHA256              string
	BodyHash                   string
	SignatureB64               string
}

// deviceUploadSignatureMiddleware checks the upload signature that the
// Gateway sends in headers before the handler reads the body, as the Remote
// SSH Gateway stream does. The handler still checks the signature in the
// JSON body.
func deviceUploadSignatureMiddleware(endpoint string, requireHeaders bool) gin.HandlerFunc {
	return func(c *gin.Context) {
		if !deviceUploadSignedHeadersPresent(c.Request) {
			if requireHeaders {
				c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "signed device upload headers are required"})
				return
			}
			logDeviceUploadLegacyWarning(endpoint)
			c.Next()
			return
		}
		signed, err := parseDeviceUploadSignedHeaders(c.Request, endpoint)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusBadRequest, gin.H{"error": "invalid device upload signature headers"})
			return
		}
		record, err := LookupDeviceStatus(c.Request.Context(), signed.DeviceID, signed.KeyID, signed.PublicKeyFingerprintSHA256)
		if err != nil {
			switch {
			case errors.Is(err, ErrDeviceStatusNotFound):
				c.AbortWithStatusJSON(http.StatusNotFound, gin.H{"error": "device status not found"})
			case errors.Is(err, ErrDeviceStatusKeyMismatch):
				c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "device key mismatch"})
			default:
				c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "failed to load device status"})
			}
			return
		}
		if !record.FromApprovedDevice || record.Status != DeviceStatusApproved {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "device is not approved"})
			return
		}
		if err := verifyDeviceUploadSignedHeaders(signed, record.PublicKeyPEM, time.Now().UTC()); err != nil {
			c.AbortWithStatusJSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		c.Request.Body = newDeviceUploadContentReader(c.Request.Body, signed.ContentSHA256)
		c.Set(deviceUploadSignerContextKey, signed.DeviceID)
		c.Next()
	}
}

func deviceUploadSignedHeadersPresent(r *http.Request) bool {
	for _, name := range []string{
		"X-Tukuyomi-Device-ID",
		"X-Tukuyomi-Key-ID",
		"X-Tukuyomi-Public-Key-Fingerprint-SHA256",
		"X-Tukuyomi-Timestamp",
		"X-Tukuyomi-Nonce",
		"X-Tukuyomi-Content-SHA256",
		"X-Tukuyomi-Body-Hash",
		"X-Tukuyomi-Signature",
	} {
		if strings.TrimSpace(r.Header.Get(name)) != "" {
			return true
		}
	}
	return false
}

func parseDeviceUploadSignedHeaders(r *http.Request, endpoint string) (deviceUploadSignedHeaders, error) {
	signed := deviceUploadSignedHeaders{
		DeviceID:                   strings.TrimSpace(r.Header.Get("X-Tukuyomi-Device-ID")),
		KeyID:                      strings.TrimSpace(r.Header.Get("X-Tukuyomi-Key-ID")),
		PublicKeyFingerprintSHA256: strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Public-Key-Fingerprint-SHA256"))),
		Timestamp:                  strings.TrimSpace(r.Header.Get("X-Tukuyomi-Timestamp")),
		Nonce:                      strings.TrimSpace(r.Header.Get("X-Tukuyomi-Nonce")),
		ContentSHA256:              strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Content-SHA256"))),
		BodyHash:                   strings.ToLower(strings.TrimSpace(r.Header.Get("X-Tukuyomi-Body-Hash"))),
		SignatureB64:               strings.TrimSpace(r.Header.Get("X-Tukuyomi-Signature")),
	}
	if !deviceIDPattern.MatchString(signed.DeviceID) || !keyIDPattern.MatchString(signed.KeyID) ||
		!hex64Pattern.MatchString(signed.PublicKeyFingerprintSHA256) || !hex64Pattern.MatchString(signed.ContentSHA256) ||
		!hex64Pattern.MatchString(signed.BodyHash) || signed.SignatureB64 == "" || len(signed.SignatureB64) > 4096 ||
		len(signed.Nonce) < 8 || len(signed.Nonce) > 128 {
		return deviceUploadSignedHeaders{}, ErrInvalidEnrollment
	}
	if !secureEqualHex(signed.BodyHash, deviceUploadBodyHash(endpoint, signed.ContentSHA256)) {
		return deviceUploadSignedHeaders{}, ErrInvalidEnrollment
	}
	return signed, nil
}

func verifyDeviceUploadSignedHeaders(signed deviceUploadSignedHeaders, publicKeyPEM string, now time.Time) error {
	_, publicKey, err := parseStoredEnrollmentPublicKey(publicKeyPEM)
	if err != nil {
		return err
	}
	signature, err := base64.StdEncoding.DecodeString(signed.SignatureB64)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidEnrollment
	}
	if !ed25519.Verify(publicKey, []byte(signedEnvelopeMessage(signed.DeviceID, signed.KeyID, signed.Timestamp, signed.Nonce, signed.BodyHash)), signature) {
		return ErrInvalidEnrollment
	}
	ts, err := time.Parse(time.RFC3339Nano, signed.Timestamp)
	if err != nil {
		return ErrInvalidEnrollment
	}
	if ts.After(now.Add(enrollmentFreshness)) || ts.Before(now.Add(-enrollmentFreshness)) {
		return ErrInvalidEnrollment
	}
	return nil
}

func deviceUploadBodyHash(endpoint string, contentSHA256 string) string {
	sum := sha256.Sum256([]byte("device-upload\n" + strings.TrimSpace(endpoint) + "\n" + strings.ToLower(strings.TrimSpace(contentSHA256))))
	return hex.EncodeToString(sum[:])
}

// deviceUploadSignerMatches reports whether the JSON body belongs to the
// device that signed the upload headers. Uploads without the headers have no
// header signer.
func deviceUploadSignerMatches(c *gin.Context, deviceID string) bool {
	signer, ok := c.Get(deviceUploadSignerContextKey)
	if !ok {
		return true
	}
	signerID, _ := signer.(string)
	return signerID != "" && signerID == deviceID
}

type deviceUploadContentReader struct {
	body io.ReadCloser
	hash hash.Hash
	want string
}

func newDeviceUploadContentReader(body io.ReadCloser, want string) io.ReadCloser {
	return &deviceUploadContentReader{body: body, hash: sha256.New(), want: want}
}

// Read hashes the body and turns the end of the body into an error when the
// hash differs from the signed content hash. The upload handlers read to the
// end before they act, so a changed body is rejected.
func (r *deviceUploadContentReader) Read(p []byte) (int, error) {
	n, err := r.body.Read(p)
	if n > 0 {
		_, _ = r.hash.Write(p[:n])
	}
	if errors.Is(err, io.EOF) && !secureEqualHex(hex.EncodeToString(r.hash.Sum(nil)), r.want) {
		return n, errDeviceUploadContentMismatch
	}
	return n, err
}

func (r *deviceUploadContentReader) Close() error {
	return r.body.Close()
}

func logDeviceUploadLegacyWarning(endpoint string) {
	deviceUploadLegacyWarningMu.Lock()
	defer deviceUploadLegacyWarningMu.Unlock()

	now := time.Now()
	if now.Sub(lastDeviceUploadLegacyWarning) < time.Minute {
		return
	}
	lastDeviceUploadLegacyWarning = now
	log.Printf("[CENTER][DEVICE_UPLOAD][WARN] accepted %s without signed upload headers; upgrade the Gateway, then set %s=true", endpoint, RequireSignedDeviceUploadHeadersEnv)
}
