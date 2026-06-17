package adminauth

import (
	"strings"
	"testing"
	"time"
)

func TestTOTPCodeMatchesRFC6238SHA1Vectors(t *testing.T) {
	secret := secretForTOTPTest("12345678901234567890")
	tests := []struct {
		unix int64
		code string
	}{
		{59, "287082"},
		{1111111109, "081804"},
		{1111111111, "050471"},
		{1234567890, "005924"},
		{2000000000, "279037"},
		{20000000000, "353130"},
	}
	for _, tt := range tests {
		got, _, err := TOTPCode(secret, time.Unix(tt.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", tt.unix, err)
		}
		if got != tt.code {
			t.Fatalf("TOTPCode(%d)=%s want=%s", tt.unix, got, tt.code)
		}
	}
}

func TestVerifyTOTPRejectsReplayedCounter(t *testing.T) {
	secret := secretForTOTPTest("12345678901234567890")
	now := time.Unix(1234567890, 0).UTC()
	code, counter, err := TOTPCode(secret, now)
	if err != nil {
		t.Fatalf("TOTPCode: %v", err)
	}
	used, ok, err := VerifyTOTP(secret, code, now, nil)
	if err != nil || !ok || used != counter {
		t.Fatalf("VerifyTOTP ok=%v used=%d err=%v", ok, used, err)
	}
	used, ok, err = VerifyTOTP(secret, code, now, &counter)
	if err != nil {
		t.Fatalf("VerifyTOTP replay err=%v", err)
	}
	if ok || used != 0 {
		t.Fatalf("replayed TOTP accepted used=%d", used)
	}
}

func TestRecoveryCodeHashAndVerify(t *testing.T) {
	codes, err := GenerateRecoveryCodes(3)
	if err != nil {
		t.Fatalf("GenerateRecoveryCodes: %v", err)
	}
	if len(codes) != 3 {
		t.Fatalf("len(codes)=%d want=3", len(codes))
	}
	hash, err := HashRecoveryCode(codes[0], "pepper")
	if err != nil {
		t.Fatalf("HashRecoveryCode: %v", err)
	}
	ok, err := VerifyRecoveryCode(strings.ReplaceAll(codes[0], "-", " "), hash, "pepper")
	if err != nil || !ok {
		t.Fatalf("VerifyRecoveryCode ok=%v err=%v", ok, err)
	}
	ok, err = VerifyRecoveryCode(codes[0], hash, "other")
	if err != nil {
		t.Fatalf("VerifyRecoveryCode wrong pepper err=%v", err)
	}
	if ok {
		t.Fatal("recovery code accepted with wrong pepper")
	}
}
