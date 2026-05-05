package handler

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"tukuyomi/internal/config"
)

func TestEnsureEdgeRemoteSSHHostSignerPersistsKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "remote-ssh.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 0); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	first, firstFP, err := ensureEdgeRemoteSSHHostSigner(context.Background())
	if err != nil {
		t.Fatalf("ensureEdgeRemoteSSHHostSigner first: %v", err)
	}
	second, secondFP, err := ensureEdgeRemoteSSHHostSigner(context.Background())
	if err != nil {
		t.Fatalf("ensureEdgeRemoteSSHHostSigner second: %v", err)
	}
	if firstFP == "" || len(firstFP) != 64 || firstFP != secondFP {
		t.Fatalf("fingerprints first=%q second=%q", firstFP, secondFP)
	}
	if string(first.PublicKey().Marshal()) != string(second.PublicKey().Marshal()) {
		t.Fatal("persisted host signer changed between loads")
	}
}

func TestVerifyEdgeRemoteSSHDeviceSessionRequiresSignatureAndRejectsReplay(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "remote-ssh-nonce.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 0); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	centerPublicKey, centerPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey center: %v", err)
	}
	centerPublicKeyText := "ed25519:" + base64.StdEncoding.EncodeToString(centerPublicKey)
	oldSigningKey := config.RemoteSSHGatewayCenterSigningPublicKey
	config.RemoteSSHGatewayCenterSigningPublicKey = centerPublicKeyText
	t.Cleanup(func() {
		config.RemoteSSHGatewayCenterSigningPublicKey = oldSigningKey
	})

	operatorPublicKey, operatorFP := edgeRemoteSSHPublicKeyForTest(t)
	now := time.Now().UTC().Unix()
	session := edgeRemoteSSHDeviceSession{
		DeviceID:                           "edge-verify-1",
		SessionID:                          "session-verify-1",
		OperatorPublicKey:                  operatorPublicKey,
		OperatorPublicKeyFingerprintSHA256: operatorFP,
		ExpiresAtUnix:                      now + 120,
		CreatedAtUnix:                      now,
		Nonce:                              "nonce-verify-1",
		CenterSigningPublicKey:             centerPublicKeyText,
	}
	session.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(centerPrivateKey, []byte(edgeRemoteSSHDeviceSessionSignedMessage(session))))
	identity := edgeDeviceIdentityRecord{DeviceID: session.DeviceID, CenterURL: "https://center.example.test"}

	if err := verifyEdgeRemoteSSHDeviceSession(context.Background(), identity, session); err != nil {
		t.Fatalf("verifyEdgeRemoteSSHDeviceSession: %v", err)
	}
	if err := verifyEdgeRemoteSSHDeviceSession(context.Background(), identity, session); err == nil || !strings.Contains(err.Error(), "replay") {
		t.Fatalf("expected replay rejection, got %v", err)
	}

	tampered := session
	tampered.SessionID = "session-verify-2"
	tampered.Nonce = "nonce-verify-2"
	tampered.CenterSigningPublicKey = "ed25519:" + base64.StdEncoding.EncodeToString(bytesOfLengthForTest(ed25519.PublicKeySize, 0x42))
	if err := verifyEdgeRemoteSSHDeviceSession(context.Background(), identity, tampered); err == nil || !strings.Contains(err.Error(), "signing key mismatch") {
		t.Fatalf("expected signing key mismatch, got %v", err)
	}
}

func TestVerifyEdgeRemoteSSHDeviceSessionRefreshesRotatedCenterSigningKey(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restoreConfig := saveConfigFilePathForTest(t, cfgPath)
	t.Cleanup(restoreConfig)
	initSettingsDBStoreForTest(t)

	stalePublicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey stale center: %v", err)
	}
	rotatedPublicKey, rotatedPrivateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey rotated center: %v", err)
	}
	staleCenterKey := "ed25519:" + base64.StdEncoding.EncodeToString(stalePublicKey)
	rotatedCenterKey := "ed25519:" + base64.StdEncoding.EncodeToString(rotatedPublicKey)

	oldAllowInsecureDefaults := config.AllowInsecureDefaults
	oldSigningKey := config.RemoteSSHGatewayCenterSigningPublicKey
	config.AllowInsecureDefaults = true
	config.RemoteSSHGatewayCenterSigningPublicKey = staleCenterKey
	t.Cleanup(func() {
		config.AllowInsecureDefaults = oldAllowInsecureDefaults
		config.RemoteSSHGatewayCenterSigningPublicKey = oldSigningKey
	})

	signingKeyCalls := 0
	center := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/remote-ssh/signing-key" {
			t.Fatalf("path=%q", r.URL.Path)
		}
		signingKeyCalls++
		_, _ = w.Write([]byte(`{"public_key":` + quoteJSON(rotatedCenterKey) + `,"algorithm":"ed25519"}`))
	}))
	t.Cleanup(center.Close)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("logs stats store is not initialized")
	}
	if err := upsertEdgeDeviceIdentity(store, edgeDeviceIdentityRecord{
		DeviceID:         "edge-refresh-1",
		KeyID:            "default",
		EnrollmentStatus: edgeEnrollmentStatusApproved,
		CenterURL:        center.URL,
	}); err != nil {
		t.Fatalf("upsert identity: %v", err)
	}

	operatorPublicKey, operatorFP := edgeRemoteSSHPublicKeyForTest(t)
	now := time.Now().UTC().Unix()
	session := edgeRemoteSSHDeviceSession{
		DeviceID:                           "edge-refresh-1",
		SessionID:                          "session-refresh-1",
		OperatorPublicKey:                  operatorPublicKey,
		OperatorPublicKeyFingerprintSHA256: operatorFP,
		ExpiresAtUnix:                      now + 120,
		CreatedAtUnix:                      now,
		Nonce:                              "nonce-refresh-1",
		CenterSigningPublicKey:             rotatedCenterKey,
	}
	session.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(rotatedPrivateKey, []byte(edgeRemoteSSHDeviceSessionSignedMessage(session))))
	identity := edgeDeviceIdentityRecord{DeviceID: session.DeviceID, CenterURL: center.URL, EnrollmentStatus: edgeEnrollmentStatusApproved}

	if err := verifyEdgeRemoteSSHDeviceSession(context.Background(), identity, session); err != nil {
		t.Fatalf("verifyEdgeRemoteSSHDeviceSession: %v", err)
	}
	if signingKeyCalls != 1 {
		t.Fatalf("signingKeyCalls=%d want 1", signingKeyCalls)
	}
	if config.RemoteSSHGatewayCenterSigningPublicKey != rotatedCenterKey {
		t.Fatalf("runtime center signing key=%q want %q", config.RemoteSSHGatewayCenterSigningPublicKey, rotatedCenterKey)
	}
	saved, err := loadSettingsAppConfigOnly()
	if err != nil {
		t.Fatalf("loadSettingsAppConfigOnly: %v", err)
	}
	if saved.RemoteSSH.Gateway.CenterSigningPublicKey != rotatedCenterKey {
		t.Fatalf("saved center signing key=%q want %q", saved.RemoteSSH.Gateway.CenterSigningPublicKey, rotatedCenterKey)
	}
}

func TestCenterRemoteSSHGatewayStreamURLRejectsHTTPByDefault(t *testing.T) {
	oldAllowInsecureDefaults := config.AllowInsecureDefaults
	config.AllowInsecureDefaults = false
	t.Cleanup(func() {
		config.AllowInsecureDefaults = oldAllowInsecureDefaults
	})

	if _, err := centerRemoteSSHGatewayStreamURL("http://center.example.test"); err == nil {
		t.Fatal("expected http center URL rejection")
	}
	config.AllowInsecureDefaults = true
	got, err := centerRemoteSSHGatewayStreamURL("http://center.example.test/base")
	if err != nil {
		t.Fatalf("centerRemoteSSHGatewayStreamURL with insecure defaults: %v", err)
	}
	if got != "http://center.example.test/v1/remote-ssh/gateway-stream" {
		t.Fatalf("url=%q", got)
	}
}

func TestBuildEdgeRemoteSSHShellEnvDoesNotInheritProcessEnvironment(t *testing.T) {
	t.Setenv("TUKUYOMI_SECRET_SHOULD_NOT_LEAK", "secret")
	t.Setenv("LD_PRELOAD", "/tmp/injected.so")

	env := buildEdgeRemoteSSHShellEnv("xterm-256color", "")
	joined := "\x00" + strings.Join(env, "\x00") + "\x00"
	for _, forbidden := range []string{"TUKUYOMI_SECRET_SHOULD_NOT_LEAK=", "LD_PRELOAD="} {
		if strings.Contains(joined, "\x00"+forbidden) {
			t.Fatalf("environment leaked forbidden variable %q: %v", forbidden, env)
		}
	}
	if !strings.Contains(joined, "\x00TERM=xterm-256color\x00") || !strings.Contains(joined, "\x00PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\x00") {
		t.Fatalf("minimal shell environment missing required values: %v", env)
	}
}

func edgeRemoteSSHPublicKeyForTest(t *testing.T) (string, string) {
	t.Helper()
	publicKey, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey operator: %v", err)
	}
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		t.Fatalf("NewPublicKey: %v", err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPublicKey))), remoteSSHPublicKeyFingerprintHex(sshPublicKey)
}

func bytesOfLengthForTest(length int, value byte) []byte {
	out := make([]byte, length)
	for i := range out {
		out[i] = value
	}
	return out
}
