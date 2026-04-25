package adminauth

import (
	"errors"
	"strings"
	"testing"
)

func TestPersonalAccessTokenGenerateParseAndHash(t *testing.T) {
	pat, err := GeneratePersonalAccessToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	if !strings.HasPrefix(pat.Token, PersonalAccessTokenPrefix) {
		t.Fatalf("token prefix=%q", pat.Token)
	}

	parts, err := ParsePersonalAccessToken(pat.Token)
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}
	if parts.Prefix != pat.Prefix {
		t.Fatalf("parts prefix=%q want %q", parts.Prefix, pat.Prefix)
	}
	if len(parts.Secret) != tokenSecretHexLength {
		t.Fatalf("secret length=%d want %d", len(parts.Secret), tokenSecretHexLength)
	}

	hash, err := HashPersonalAccessToken(pat.Token, "")
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}
	if !strings.HasPrefix(hash, tokenHashPrefixSHA256) {
		t.Fatalf("hash prefix=%q", hash)
	}

	ok, err := VerifyPersonalAccessToken(pat.Token, hash, "")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if !ok {
		t.Fatalf("verify token ok=false want true")
	}

	other, err := GeneratePersonalAccessToken()
	if err != nil {
		t.Fatalf("generate second token: %v", err)
	}
	ok, err = VerifyPersonalAccessToken(other.Token, hash, "")
	if err != nil {
		t.Fatalf("verify wrong token: %v", err)
	}
	if ok {
		t.Fatalf("verify wrong token ok=true want false")
	}
}

func TestPersonalAccessTokenHMACHashRequiresPepperForVerify(t *testing.T) {
	pat, err := GeneratePersonalAccessToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}
	hash, err := HashPersonalAccessToken(pat.Token, "server-pepper")
	if err != nil {
		t.Fatalf("hash token: %v", err)
	}
	if !strings.HasPrefix(hash, tokenHashPrefixHMACSHA256) {
		t.Fatalf("hash prefix=%q", hash)
	}

	ok, err := VerifyPersonalAccessToken(pat.Token, hash, "server-pepper")
	if err != nil {
		t.Fatalf("verify token: %v", err)
	}
	if !ok {
		t.Fatalf("verify token ok=false want true")
	}

	ok, err = VerifyPersonalAccessToken(pat.Token, hash, "")
	if !errors.Is(err, ErrPersonalAccessTokenPepperRequired) {
		t.Fatalf("verify token without pepper error=%v want ErrPersonalAccessTokenPepperRequired", err)
	}
	if ok {
		t.Fatalf("verify token without pepper ok=true want false")
	}
}

func TestPersonalAccessTokenRejectsMalformedInput(t *testing.T) {
	pat, err := GeneratePersonalAccessToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	for name, token := range map[string]string{
		"empty":           "",
		"leading_space":   " " + pat.Token,
		"missing_prefix":  strings.TrimPrefix(pat.Token, PersonalAccessTokenPrefix),
		"uppercase_hex":   strings.ToUpper(pat.Token),
		"missing_secret":  PersonalAccessTokenPrefix + pat.Prefix + "_",
		"missing_divider": strings.Replace(pat.Token, "_", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			parts, err := ParsePersonalAccessToken(token)
			if !errors.Is(err, ErrInvalidPersonalAccessToken) {
				t.Fatalf("parse token parts=%+v err=%v want ErrInvalidPersonalAccessToken", parts, err)
			}
		})
	}
}

func TestPersonalAccessTokenRejectsMalformedHash(t *testing.T) {
	pat, err := GeneratePersonalAccessToken()
	if err != nil {
		t.Fatalf("generate token: %v", err)
	}

	for name, hash := range map[string]string{
		"empty":            "",
		"unknown_prefix":   "bcrypt:" + strings.Repeat("a", sha256HexLengthForTest()),
		"short_digest":     tokenHashPrefixSHA256 + strings.Repeat("a", sha256HexLengthForTest()-1),
		"uppercase_digest": tokenHashPrefixSHA256 + strings.Repeat("A", sha256HexLengthForTest()),
	} {
		t.Run(name, func(t *testing.T) {
			ok, err := VerifyPersonalAccessToken(pat.Token, hash, "")
			if !errors.Is(err, ErrInvalidPersonalAccessTokenHash) {
				t.Fatalf("verify malformed hash ok=%v err=%v want ErrInvalidPersonalAccessTokenHash", ok, err)
			}
			if ok {
				t.Fatalf("verify malformed hash ok=true want false")
			}
		})
	}
}

func sha256HexLengthForTest() int {
	return 64
}
