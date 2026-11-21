package center

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestDeviceUploadBodyHashMatchesGatewayVector(t *testing.T) {
	// The Gateway computes the same value in handler.edgeDeviceUploadBodyHash,
	// and its tests check the same vector, because Center cannot import it.
	got := deviceUploadBodyHash("/v1/device-config-snapshot", strings.Repeat("ab", 32))
	const want = "f066826cc5728195f6273622772b37dc38ea5fc800c7f6a10da4e92449b806c0"
	if got != want {
		t.Fatalf("deviceUploadBodyHash=%s want %s", got, want)
	}
}

func TestDeviceUploadSignatureChecksHeadersBeforeTheBody(t *testing.T) {
	router, fixture, other := newDeviceUploadSignatureTestRouter(t, false)
	const endpoint = "/v1/device-config-snapshot"
	body := deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-body")
	now := time.Now().UTC()

	cases := []struct {
		name   string
		mutate func(http.Header)
		want   int
	}{
		{name: "bad signature", mutate: func(h http.Header) {
			h.Set("X-Tukuyomi-Signature", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, ed25519.SignatureSize)))
		}, want: http.StatusUnprocessableEntity},
		{name: "unknown device", mutate: func(h http.Header) {
			h.Set("X-Tukuyomi-Device-ID", "unknown-device")
		}, want: http.StatusNotFound},
		{name: "key mismatch", mutate: func(h http.Header) {
			h.Set("X-Tukuyomi-Public-Key-Fingerprint-SHA256", other.Fingerprint)
		}, want: http.StatusForbidden},
		{name: "signed for another endpoint", mutate: func(h http.Header) {
			signed := signedDeviceUploadHeadersForTest(t, fixture, "/v1/rule-artifact-bundle", body, now)
			for name := range signed {
				h.Set(name, signed.Get(name))
			}
		}, want: http.StatusBadRequest},
		{name: "partial headers", mutate: func(h http.Header) {
			h.Del("X-Tukuyomi-Signature")
		}, want: http.StatusBadRequest},
		{name: "stale timestamp", mutate: func(h http.Header) {
			signed := signedDeviceUploadHeadersForTest(t, fixture, endpoint, body, now.Add(-time.Hour))
			for name := range signed {
				h.Set(name, signed.Get(name))
			}
		}, want: http.StatusUnprocessableEntity},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			headers := signedDeviceUploadHeadersForTest(t, fixture, endpoint, body, now)
			tc.mutate(headers)
			reader := &deviceUploadReadTracker{body: bytes.NewReader(body)}
			rec := serveDeviceUploadForTest(router, endpoint, headers, reader)
			if rec.Code != tc.want {
				t.Fatalf("status=%d want %d body=%s", rec.Code, tc.want, rec.Body.String())
			}
			if reader.reads != 0 {
				t.Fatalf("body was read %d times before the headers were rejected", reader.reads)
			}
		})
	}

	t.Run("unapproved device", func(t *testing.T) {
		setDeviceStatusForUploadTest(t, fixture.Request.DeviceID, DeviceStatusRevoked)
		defer setDeviceStatusForUploadTest(t, fixture.Request.DeviceID, DeviceStatusApproved)
		reader := &deviceUploadReadTracker{body: bytes.NewReader(body)}
		rec := serveDeviceUploadForTest(router, endpoint, signedDeviceUploadHeadersForTest(t, fixture, endpoint, body, now), reader)
		if rec.Code != http.StatusForbidden || reader.reads != 0 {
			t.Fatalf("status=%d reads=%d want 403 without reading the body", rec.Code, reader.reads)
		}
	})
}

func TestDeviceUploadSignatureAcceptsSignedUploadAndChecksTheBody(t *testing.T) {
	router, fixture, other := newDeviceUploadSignatureTestRouter(t, false)
	const endpoint = "/v1/device-config-snapshot"
	now := time.Now().UTC()

	body := deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-accepted")
	rec := serveDeviceUploadForTest(router, endpoint, signedDeviceUploadHeadersForTest(t, fixture, endpoint, body, now), bytes.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("signed upload status=%d body=%s", rec.Code, rec.Body.String())
	}

	signedFor := deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-signed")
	changed := deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-changed")
	rec = serveDeviceUploadForTest(router, endpoint, signedDeviceUploadHeadersForTest(t, fixture, endpoint, signedFor, now), bytes.NewReader(changed))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("changed body status=%d want 400 body=%s", rec.Code, rec.Body.String())
	}

	otherBody := deviceConfigSnapshotUploadBodyForTest(t, other, "nonce-upload-other")
	rec = serveDeviceUploadForTest(router, endpoint, signedDeviceUploadHeadersForTest(t, fixture, endpoint, otherBody, now), bytes.NewReader(otherBody))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "signer mismatch") {
		t.Fatalf("other device body status=%d body=%s want signer mismatch", rec.Code, rec.Body.String())
	}
}

func TestDeviceUploadSignatureHandlesUploadsWithoutHeaders(t *testing.T) {
	const endpoint = "/v1/device-config-snapshot"

	router, fixture, _ := newDeviceUploadSignatureTestRouter(t, false)
	body := deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-legacy")
	rec := serveDeviceUploadForTest(router, endpoint, http.Header{}, bytes.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("legacy upload status=%d body=%s want accepted by default", rec.Code, rec.Body.String())
	}

	required, fixture, _ := newDeviceUploadSignatureTestRouter(t, true)
	body = deviceConfigSnapshotUploadBodyForTest(t, fixture, "nonce-upload-required")
	reader := &deviceUploadReadTracker{body: bytes.NewReader(body)}
	rec = serveDeviceUploadForTest(required, endpoint, http.Header{}, reader)
	if rec.Code != http.StatusUnauthorized || reader.reads != 0 {
		t.Fatalf("required legacy upload status=%d reads=%d want 401 without reading the body", rec.Code, reader.reads)
	}
	rec = serveDeviceUploadForTest(required, endpoint, signedDeviceUploadHeadersForTest(t, fixture, endpoint, body, time.Now().UTC()), bytes.NewReader(body))
	if rec.Code != http.StatusOK {
		t.Fatalf("required signed upload status=%d body=%s", rec.Code, rec.Body.String())
	}
}

type deviceUploadReadTracker struct {
	body  *bytes.Reader
	reads int
}

func (r *deviceUploadReadTracker) Read(p []byte) (int, error) {
	r.reads++
	return r.body.Read(p)
}

func newDeviceUploadSignatureTestRouter(t *testing.T, requireHeaders bool) (http.Handler, signedEnrollmentFixture, signedEnrollmentFixture) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	restore := configureCenterAuthTest(t)
	t.Cleanup(restore)
	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", config.DBPath, "", 32); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() { handler.InitLogsStatsStore(false, "", 0) })
	prevAppDeploy := centerExperimentalAppDeployDeviceAPI.Load()
	t.Cleanup(func() { centerExperimentalAppDeployDeviceAPI.Store(prevAppDeploy) })

	now := time.Now().UTC()
	fixture := signedEnrollmentFixtureForTest(t, "upload-device-1", "default", "nonce-enroll-upload-1", now)
	other := signedEnrollmentFixtureForTest(t, "upload-device-2", "default", "nonce-enroll-upload-2", now)
	insertDeviceForUploadTest(t, fixture, DeviceStatusApproved)
	insertDeviceForUploadTest(t, other, DeviceStatusApproved)

	r := gin.New()
	registerDeviceEnrollmentRoutes(r, RuntimeConfig{RequireSignedDeviceUploadHeaders: requireHeaders})
	return r, fixture, other
}

func insertDeviceForUploadTest(t *testing.T, fixture signedEnrollmentFixture, status string) {
	t.Helper()
	publicKeyPEM, err := base64.StdEncoding.DecodeString(fixture.Request.PublicKeyPEMB64)
	if err != nil {
		t.Fatalf("decode public key: %v", err)
	}
	now := time.Now().UTC().Unix()
	if err := withCenterDB(context.Background(), func(db *sql.DB, driver string) error {
		_, err := db.ExecContext(context.Background(), `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
     approved_at_unix, approved_by, created_at_unix, updated_at_unix, last_seen_at_unix,
     runtime_role, build_version, go_version, os, arch, kernel_version,
     distro_id, distro_id_like, distro_version, runtime_deployment_supported)
VALUES
    (`+placeholders(driver, 20, 1)+`)`,
			fixture.Request.DeviceID,
			fixture.Request.KeyID,
			string(publicKeyPEM),
			fixture.Fingerprint,
			status,
			now,
			"test",
			now,
			now,
			now,
			"gateway",
			"test-build",
			"go-test",
			"linux",
			"amd64",
			"6.8.0-test",
			"ubuntu",
			"debian",
			"24.04",
			1,
		)
		return err
	}); err != nil {
		t.Fatalf("insert device: %v", err)
	}
}

func setDeviceStatusForUploadTest(t *testing.T, deviceID string, status string) {
	t.Helper()
	if err := withCenterDB(context.Background(), func(db *sql.DB, driver string) error {
		_, err := db.ExecContext(context.Background(), `UPDATE center_devices SET status = `+placeholder(driver, 1)+` WHERE device_id = `+placeholder(driver, 2), status, deviceID)
		return err
	}); err != nil {
		t.Fatalf("set device status: %v", err)
	}
}

func deviceConfigSnapshotUploadBodyForTest(t *testing.T, fixture signedEnrollmentFixture, nonce string) []byte {
	t.Helper()
	payload := []byte(`{"schema_version":1,"domains":{"proxy":{"etag":"` + nonce + `","raw":{"routes":[]}}}}`)
	revisionSum := sha256.Sum256([]byte(nonce))
	req := signedDeviceConfigSnapshotForTest(t, fixture, nonce, time.Now().UTC(), hex.EncodeToString(revisionSum[:]), payload)
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("marshal config snapshot: %v", err)
	}
	return body
}

// signedDeviceUploadHeadersForTest signs headers the way the Gateway does in
// handler.signedEdgeDeviceUploadHeaders.
func signedDeviceUploadHeadersForTest(t *testing.T, fixture signedEnrollmentFixture, endpoint string, body []byte, ts time.Time) http.Header {
	t.Helper()
	contentSum := sha256.Sum256(body)
	contentHash := hex.EncodeToString(contentSum[:])
	bodyHash := deviceUploadBodyHash(endpoint, contentHash)
	timestamp := ts.UTC().Format(time.RFC3339Nano)
	nonce := "nonce-header-" + hex.EncodeToString(contentSum[:4])
	signature := ed25519.Sign(fixture.PrivateKey, []byte(signedEnvelopeMessage(fixture.Request.DeviceID, fixture.Request.KeyID, timestamp, nonce, bodyHash)))
	headers := http.Header{}
	headers.Set("X-Tukuyomi-Device-ID", fixture.Request.DeviceID)
	headers.Set("X-Tukuyomi-Key-ID", fixture.Request.KeyID)
	headers.Set("X-Tukuyomi-Public-Key-Fingerprint-SHA256", fixture.Fingerprint)
	headers.Set("X-Tukuyomi-Timestamp", timestamp)
	headers.Set("X-Tukuyomi-Nonce", nonce)
	headers.Set("X-Tukuyomi-Content-SHA256", contentHash)
	headers.Set("X-Tukuyomi-Body-Hash", bodyHash)
	headers.Set("X-Tukuyomi-Signature", base64.StdEncoding.EncodeToString(signature))
	return headers
}

func serveDeviceUploadForTest(router http.Handler, endpoint string, headers http.Header, body interface{ Read([]byte) (int, error) }) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, endpoint, body)
	req.Header.Set("Content-Type", "application/json")
	for name, values := range headers {
		for _, value := range values {
			req.Header.Add(name, value)
		}
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}
