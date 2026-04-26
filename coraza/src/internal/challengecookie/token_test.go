package challengecookie

import (
	"testing"
	"time"
)

func TestIssueAndVerifyHMAC(t *testing.T) {
	now := time.Unix(1_700_000_000, 0).UTC()
	secret := []byte("test-secret-12345")
	token := IssueHMAC(secret, time.Minute, "10.0.0.1", "Mozilla/5.0", now)
	if !VerifyHMAC(secret, token, "10.0.0.1", "Mozilla/5.0", now.Add(time.Second)) {
		t.Fatal("token should verify before expiry")
	}
	if VerifyHMAC(secret, token, "10.0.0.2", "Mozilla/5.0", now.Add(time.Second)) {
		t.Fatal("token should bind to ip")
	}
	if VerifyHMAC(secret, token, "10.0.0.1", "Mozilla/5.0", now.Add(2*time.Minute)) {
		t.Fatal("token should expire")
	}
}

func TestConstantTimeHexEqualRejectsInvalidHex(t *testing.T) {
	if ConstantTimeHexEqual("zz", "zz") {
		t.Fatal("invalid hex should not match")
	}
	if !ConstantTimeHexEqual("0a", "0a") {
		t.Fatal("equal hex should match")
	}
}
