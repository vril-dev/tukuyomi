package adminauth

import (
	"errors"
	"strings"
	"testing"
)

func TestHashPasswordWithParamsArgon2IDRoundTrip(t *testing.T) {
	params := PasswordHashParams{
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}

	encoded, err := hashPasswordWithParams("correct horse battery staple", params)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if !strings.HasPrefix(encoded, "$argon2id$v=19$m=8,t=1,p=1$") {
		t.Fatalf("encoded hash prefix=%q", encoded)
	}

	ok, err := VerifyPassword(encoded, "correct horse battery staple")
	if err != nil {
		t.Fatalf("verify password: %v", err)
	}
	if !ok {
		t.Fatalf("verify password ok=false want true")
	}

	ok, err = VerifyPassword(encoded, "wrong horse battery staple")
	if err != nil {
		t.Fatalf("verify wrong password: %v", err)
	}
	if ok {
		t.Fatalf("verify wrong password ok=true want false")
	}
}

func TestHashPasswordRejectsInvalidInputs(t *testing.T) {
	params := PasswordHashParams{
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	if _, err := hashPasswordWithParams("", params); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("hash empty password error=%v want ErrInvalidPassword", err)
	}
	if _, err := hashPasswordWithParams(strings.Repeat("a", maxPasswordBytes+1), params); !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("hash long password error=%v want ErrInvalidPassword", err)
	}

	params.MemoryKiB = 0
	if _, err := hashPasswordWithParams("password", params); !errors.Is(err, ErrInvalidPasswordHash) {
		t.Fatalf("hash invalid params error=%v want ErrInvalidPasswordHash", err)
	}
}

func TestVerifyPasswordRejectsMalformedHash(t *testing.T) {
	params := PasswordHashParams{
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	encoded, err := hashPasswordWithParams("password", params)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	for name, encodedHash := range map[string]string{
		"empty":               "",
		"unknown_algorithm":   strings.Replace(encoded, "$argon2id$", "$scrypt$", 1),
		"unsupported_version": strings.Replace(encoded, "$v=19$", "$v=18$", 1),
		"huge_memory":         strings.Replace(encoded, "$m=8,", "$m=262145,", 1),
		"bad_base64":          strings.TrimSuffix(encoded, "A") + "*",
		"leading_space":       " " + encoded,
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPassword(encodedHash, "password")
			if err == nil {
				t.Fatalf("verify malformed hash ok=%v err=nil", ok)
			}
			if ok {
				t.Fatalf("verify malformed hash ok=true want false")
			}
		})
	}
}

func TestVerifyPasswordRejectsOversizedPassword(t *testing.T) {
	params := PasswordHashParams{
		MemoryKiB:   8,
		Iterations:  1,
		Parallelism: 1,
		SaltLength:  16,
		KeyLength:   32,
	}
	encoded, err := hashPasswordWithParams("password", params)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	ok, err := VerifyPassword(encoded, strings.Repeat("a", maxPasswordBytes+1))
	if !errors.Is(err, ErrInvalidPassword) {
		t.Fatalf("verify oversized password error=%v want ErrInvalidPassword", err)
	}
	if ok {
		t.Fatalf("verify oversized password ok=true want false")
	}
}
