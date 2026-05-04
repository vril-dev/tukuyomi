package center

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
)

func TestRemoteSSHPolicyAndSessionLifecycle(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	insertRemoteSSHApprovedDeviceForTest(t, "edge-remote-1")

	ctx := context.Background()
	if _, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-1",
		Reason:            "initial disabled policy check",
		OperatorPublicKey: remoteSSHPublicKeyForTest(t),
		CreatedAtUnix:     1000,
	}); !errors.Is(err, ErrRemoteSSHPolicyDisabled) {
		t.Fatalf("CreateRemoteSSHSession disabled policy error=%v want ErrRemoteSSHPolicyDisabled", err)
	}

	policy, err := UpsertRemoteSSHPolicy(ctx, RemoteSSHPolicyUpdate{
		DeviceID:          "edge-remote-1",
		Enabled:           true,
		MaxTTLSec:         120,
		RequireReason:     true,
		AllowedRunAsUser:  "tukuyomi",
		UpdatedByUserID:   1,
		UpdatedByUsername: "owner",
		UpdatedAtUnix:     1000,
	})
	if err != nil {
		t.Fatalf("UpsertRemoteSSHPolicy: %v", err)
	}
	if !policy.Enabled || policy.MaxTTLSec != 120 || policy.AllowedRunAsUser != "tukuyomi" || !policy.RequireReason {
		t.Fatalf("policy not normalized as expected: %+v", policy)
	}

	pub := remoteSSHPublicKeyForTest(t)
	session, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-1",
		Reason:            "investigate offline sensor",
		OperatorPublicKey: pub,
		TTLSec:            300,
		RequestedByUserID: 1,
		RequestedBy:       "owner",
		OperatorIP:        "203.0.113.10",
		OperatorUserAgent: "test-client",
		CreatedAtUnix:     1000,
	})
	if err != nil {
		t.Fatalf("CreateRemoteSSHSession: %v", err)
	}
	if session.Status != RemoteSSHSessionStatusPending || session.TTLSec != 120 || session.ExpiresAtUnix != 1120 {
		t.Fatalf("session lifecycle fields unexpected: %+v", session)
	}
	if session.AttachToken == "" {
		t.Fatal("create response must include one-time attach token")
	}
	if len(session.OperatorPublicKeyFingerprintSHA256) != 64 {
		t.Fatalf("operator key fingerprint length=%d want 64", len(session.OperatorPublicKeyFingerprintSHA256))
	}

	pending, err := PendingRemoteSSHSessionForDevice(ctx, "edge-remote-1", 1001)
	if err != nil {
		t.Fatalf("PendingRemoteSSHSessionForDevice: %v", err)
	}
	if pending == nil || pending.SessionID != session.SessionID || pending.OperatorPublicKey != pub {
		t.Fatalf("pending session mismatch: got=%+v want session_id=%s", pending, session.SessionID)
	}
	assertRemoteSSHDeviceSessionSignature(t, *pending)

	if _, err := AttachRemoteSSHOperator(ctx, RemoteSSHOperatorAttach{
		SessionID:      session.SessionID,
		AttachToken:    session.AttachToken,
		OperatorIP:     "203.0.113.10",
		UserAgent:      "test-client",
		AttachedAtUnix: 1002,
	}); err != nil {
		t.Fatalf("AttachRemoteSSHOperator: %v", err)
	}
	if _, err := AttachRemoteSSHOperator(ctx, RemoteSSHOperatorAttach{
		SessionID:      session.SessionID,
		AttachToken:    session.AttachToken,
		OperatorIP:     "203.0.113.10",
		UserAgent:      "test-client",
		AttachedAtUnix: 1002,
	}); !errors.Is(err, ErrRemoteSSHSessionNotFound) {
		t.Fatalf("AttachRemoteSSHOperator replay error=%v want ErrRemoteSSHSessionNotFound", err)
	}
	pending, err = PendingRemoteSSHSessionForDevice(ctx, "edge-remote-1", 1003)
	if err != nil {
		t.Fatalf("PendingRemoteSSHSessionForDevice after operator attach: %v", err)
	}
	if pending == nil || pending.SessionID != session.SessionID {
		t.Fatalf("operator-attached session should still be visible to gateway: %+v", pending)
	}
	assertRemoteSSHDeviceSessionSignature(t, *pending)

	hostPub, hostFP := remoteSSHHostPublicKeyForTest(t)
	if _, err := AttachRemoteSSHGateway(ctx, RemoteSSHGatewayAttach{
		SessionID:                       session.SessionID,
		DeviceID:                        "edge-remote-1",
		GatewayHostKeyFingerprintSHA256: strings.Repeat("b", 64),
		GatewayHostPublicKey:            hostPub,
		AttachedAtUnix:                  1003,
	}); !errors.Is(err, ErrRemoteSSHInvalid) {
		t.Fatalf("AttachRemoteSSHGateway mismatched host key error=%v want ErrRemoteSSHInvalid", err)
	}
	attached, err := AttachRemoteSSHGateway(ctx, RemoteSSHGatewayAttach{
		SessionID:                       session.SessionID,
		DeviceID:                        "edge-remote-1",
		GatewayHostKeyFingerprintSHA256: hostFP,
		GatewayHostPublicKey:            hostPub,
		AttachedAtUnix:                  1003,
	})
	if err != nil {
		t.Fatalf("AttachRemoteSSHGateway: %v", err)
	}
	if attached.Status != RemoteSSHSessionStatusActive || attached.GatewayHostPublicKey != hostPub {
		t.Fatalf("gateway attach not recorded as expected: %+v", attached)
	}

	if _, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-1",
		Reason:            "second session should be blocked",
		OperatorPublicKey: remoteSSHPublicKeyForTest(t),
		CreatedAtUnix:     1004,
	}); !errors.Is(err, ErrRemoteSSHSessionLimit) {
		t.Fatalf("CreateRemoteSSHSession second error=%v want ErrRemoteSSHSessionLimit", err)
	}

	pending, err = PendingRemoteSSHSessionForDevice(ctx, "edge-remote-1", 1121)
	if err != nil {
		t.Fatalf("PendingRemoteSSHSessionForDevice after expiry: %v", err)
	}
	if pending != nil {
		t.Fatalf("expired session should not be pending: %+v", pending)
	}
	view, err := RemoteSSHViewForDevice(ctx, "edge-remote-1", 10)
	if err != nil {
		t.Fatalf("RemoteSSHViewForDevice: %v", err)
	}
	if len(view.Sessions) != 1 || view.Sessions[0].Status != RemoteSSHSessionStatusExpired {
		t.Fatalf("expired session not recorded in view: %+v", view.Sessions)
	}
	if !view.CenterEnabled {
		t.Fatal("view should include enabled Center Remote SSH runtime state")
	}
	if view.Sessions[0].GatewayHostPublicKey != hostPub {
		t.Fatalf("gateway host public key not retained in view: %+v", view.Sessions[0])
	}
}

func TestRemoteSSHSessionValidation(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	insertRemoteSSHApprovedDeviceForTest(t, "edge-remote-2")

	ctx := context.Background()
	if _, err := UpsertRemoteSSHPolicy(ctx, RemoteSSHPolicyUpdate{
		DeviceID:      "edge-remote-2",
		Enabled:       true,
		MaxTTLSec:     120,
		RequireReason: true,
		UpdatedAtUnix: 1000,
	}); err != nil {
		t.Fatalf("UpsertRemoteSSHPolicy: %v", err)
	}

	if _, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-2",
		OperatorPublicKey: remoteSSHPublicKeyForTest(t),
		CreatedAtUnix:     1000,
	}); !errors.Is(err, ErrRemoteSSHInvalid) {
		t.Fatalf("CreateRemoteSSHSession missing reason error=%v want ErrRemoteSSHInvalid", err)
	}

	if _, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-2",
		Reason:            "bad key",
		OperatorPublicKey: "not-a-valid-authorized-key",
		CreatedAtUnix:     1000,
	}); !errors.Is(err, ErrRemoteSSHInvalid) {
		t.Fatalf("CreateRemoteSSHSession invalid key error=%v want ErrRemoteSSHInvalid", err)
	}
}

func TestRemoteSSHCenterSigningKeyRotation(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	insertRemoteSSHApprovedDeviceForTest(t, "edge-remote-rotate")

	ctx := context.Background()
	before, err := RemoteSSHCenterSigningPublicKey(ctx)
	if err != nil {
		t.Fatalf("RemoteSSHCenterSigningPublicKey before rotate: %v", err)
	}
	after, err := RotateRemoteSSHCenterSigningKey(ctx)
	if err != nil {
		t.Fatalf("RotateRemoteSSHCenterSigningKey: %v", err)
	}
	if after == "" || after == before {
		t.Fatalf("rotated key=%q before=%q", after, before)
	}
	loaded, err := RemoteSSHCenterSigningPublicKey(ctx)
	if err != nil {
		t.Fatalf("RemoteSSHCenterSigningPublicKey after rotate: %v", err)
	}
	if loaded != after {
		t.Fatalf("loaded key=%q want rotated=%q", loaded, after)
	}
	if _, err := UpsertRemoteSSHPolicy(ctx, RemoteSSHPolicyUpdate{
		DeviceID:         "edge-remote-rotate",
		Enabled:          true,
		MaxTTLSec:        120,
		AllowedRunAsUser: "tukuyomi",
		RequireReason:    true,
		UpdatedAtUnix:    1000,
	}); err != nil {
		t.Fatalf("UpsertRemoteSSHPolicy: %v", err)
	}
	session, err := CreateRemoteSSHSession(ctx, RemoteSSHSessionCreate{
		DeviceID:          "edge-remote-rotate",
		Reason:            "verify rotated key",
		OperatorPublicKey: remoteSSHPublicKeyForTest(t),
		CreatedAtUnix:     1000,
	})
	if err != nil {
		t.Fatalf("CreateRemoteSSHSession: %v", err)
	}
	pending, err := PendingRemoteSSHSessionForDevice(ctx, "edge-remote-rotate", 1001)
	if err != nil {
		t.Fatalf("PendingRemoteSSHSessionForDevice: %v", err)
	}
	if pending == nil || pending.SessionID != session.SessionID {
		t.Fatalf("pending session mismatch after rotate: %+v", pending)
	}
	if pending.CenterSigningPublicKey != after {
		t.Fatalf("pending center signing key=%q want %q", pending.CenterSigningPublicKey, after)
	}
	assertRemoteSSHDeviceSessionSignature(t, *pending)
}

func setupRemoteSSHStoreTest(t *testing.T) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "center.db")
	if err := handler.InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 0); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = handler.InitLogsStatsStore(false, "", 0)
	})
	oldCenterEnabled := config.RemoteSSHCenterEnabled
	oldMaxTTL := config.RemoteSSHMaxTTL
	oldMaxTotal := config.RemoteSSHMaxSessionsTotal
	oldMaxPerDevice := config.RemoteSSHMaxSessionsPerDevice
	config.RemoteSSHCenterEnabled = true
	config.RemoteSSHMaxTTL = 15 * time.Minute
	config.RemoteSSHMaxSessionsTotal = 16
	config.RemoteSSHMaxSessionsPerDevice = 1
	t.Cleanup(func() {
		config.RemoteSSHCenterEnabled = oldCenterEnabled
		config.RemoteSSHMaxTTL = oldMaxTTL
		config.RemoteSSHMaxSessionsTotal = oldMaxTotal
		config.RemoteSSHMaxSessionsPerDevice = oldMaxPerDevice
	})
}

func insertRemoteSSHApprovedDeviceForTest(t *testing.T, deviceID string) {
	t.Helper()
	err := withCenterDB(context.Background(), func(db *sql.DB, driver string) error {
		_, err := db.ExecContext(context.Background(), `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status, approved_at_unix, approved_by, created_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 9, 1)+`)`,
			deviceID,
			"default",
			"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA0000000000000000000000000000000000000000000=\n-----END PUBLIC KEY-----",
			strings.Repeat("a", 64),
			DeviceStatusApproved,
			int64(1000),
			"test",
			int64(1000),
			int64(1000),
		)
		return err
	})
	if err != nil {
		t.Fatalf("insert approved device: %v", err)
	}
}

func remoteSSHPublicKeyForTest(t *testing.T) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub)))
}

func remoteSSHHostPublicKeyForTest(t *testing.T) (string, string) {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))), remoteSSHPublicKeyFingerprintHex(sshPub)
}

func assertRemoteSSHDeviceSessionSignature(t *testing.T, session RemoteSSHDeviceSession) {
	t.Helper()
	if session.DeviceID == "" || session.Nonce == "" || session.CenterSigningPublicKey == "" || session.Signature == "" {
		t.Fatalf("signed pending session fields are incomplete: %+v", session)
	}
	rawPublicKey, ok := strings.CutPrefix(session.CenterSigningPublicKey, remoteSSHCenterSigningKeyPrefix)
	if !ok {
		t.Fatalf("center signing public key prefix mismatch: %q", session.CenterSigningPublicKey)
	}
	publicKey, err := base64.StdEncoding.DecodeString(rawPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		t.Fatalf("center signing public key invalid: len=%d err=%v", len(publicKey), err)
	}
	signature, err := base64.StdEncoding.DecodeString(session.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		t.Fatalf("pending session signature invalid: len=%d err=%v", len(signature), err)
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(remoteSSHDeviceSessionSignedMessage(session)), signature) {
		t.Fatal("pending session signature did not verify")
	}
}
