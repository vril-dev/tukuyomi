package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
)

const (
	PersonalAccessTokenPrefix = "tky_pat_"
	tokenPrefixBytes          = 6
	tokenSecretBytes          = 32
	tokenPrefixHexLength      = tokenPrefixBytes * 2
	tokenSecretHexLength      = tokenSecretBytes * 2
	tokenHashPrefixSHA256     = "sha256:"
	tokenHashPrefixHMACSHA256 = "hmac-sha256:"
)

var (
	ErrInvalidPersonalAccessToken        = errors.New("invalid personal access token")
	ErrInvalidPersonalAccessTokenHash    = errors.New("invalid personal access token hash")
	ErrPersonalAccessTokenPepperRequired = errors.New("personal access token pepper required")
)

type PersonalAccessToken struct {
	Token  string
	Prefix string
}

type PersonalAccessTokenParts struct {
	Prefix string
	Secret string
}

func GeneratePersonalAccessToken() (PersonalAccessToken, error) {
	prefix, err := randomLowerHex(tokenPrefixBytes)
	if err != nil {
		return PersonalAccessToken{}, err
	}
	secret, err := randomLowerHex(tokenSecretBytes)
	if err != nil {
		return PersonalAccessToken{}, err
	}
	return PersonalAccessToken{
		Token:  PersonalAccessTokenPrefix + prefix + "_" + secret,
		Prefix: prefix,
	}, nil
}

func ParsePersonalAccessToken(token string) (PersonalAccessTokenParts, error) {
	if token == "" || strings.TrimSpace(token) != token {
		return PersonalAccessTokenParts{}, ErrInvalidPersonalAccessToken
	}
	rest, ok := strings.CutPrefix(token, PersonalAccessTokenPrefix)
	if !ok {
		return PersonalAccessTokenParts{}, ErrInvalidPersonalAccessToken
	}
	prefix, secret, ok := strings.Cut(rest, "_")
	if !ok || !isLowerHex(prefix, tokenPrefixHexLength) || !isLowerHex(secret, tokenSecretHexLength) {
		return PersonalAccessTokenParts{}, ErrInvalidPersonalAccessToken
	}
	return PersonalAccessTokenParts{Prefix: prefix, Secret: secret}, nil
}

func HashPersonalAccessToken(token, pepper string) (string, error) {
	parts, err := ParsePersonalAccessToken(token)
	if err != nil {
		return "", err
	}
	return hashPersonalAccessTokenSecret(parts.Secret, pepper), nil
}

func VerifyPersonalAccessToken(token, storedHash, pepper string) (bool, error) {
	parts, err := ParsePersonalAccessToken(token)
	if err != nil {
		return false, err
	}

	storedHash = strings.TrimSpace(storedHash)
	if !validTokenHash(storedHash) {
		return false, ErrInvalidPersonalAccessTokenHash
	}

	var got string
	switch {
	case strings.HasPrefix(storedHash, tokenHashPrefixHMACSHA256):
		if strings.TrimSpace(pepper) == "" {
			return false, ErrPersonalAccessTokenPepperRequired
		}
		got = hmacSHA256TokenHash(parts.Secret, pepper)
	case strings.HasPrefix(storedHash, tokenHashPrefixSHA256):
		got = sha256TokenHash(parts.Secret)
	default:
		return false, ErrInvalidPersonalAccessTokenHash
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(storedHash)) == 1, nil
}

func hashPersonalAccessTokenSecret(secret, pepper string) string {
	if strings.TrimSpace(pepper) == "" {
		return sha256TokenHash(secret)
	}
	return hmacSHA256TokenHash(secret, pepper)
}

func sha256TokenHash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return tokenHashPrefixSHA256 + hex.EncodeToString(sum[:])
}

func hmacSHA256TokenHash(secret, pepper string) string {
	mac := hmac.New(sha256.New, []byte(pepper))
	_, _ = mac.Write([]byte(secret))
	return tokenHashPrefixHMACSHA256 + hex.EncodeToString(mac.Sum(nil))
}

func validTokenHash(storedHash string) bool {
	switch {
	case strings.HasPrefix(storedHash, tokenHashPrefixHMACSHA256):
		return isLowerHex(strings.TrimPrefix(storedHash, tokenHashPrefixHMACSHA256), sha256.Size*2)
	case strings.HasPrefix(storedHash, tokenHashPrefixSHA256):
		return isLowerHex(strings.TrimPrefix(storedHash, tokenHashPrefixSHA256), sha256.Size*2)
	default:
		return false
	}
}

func randomLowerHex(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func isLowerHex(value string, wantLength int) bool {
	if len(value) != wantLength {
		return false
	}
	for i := 0; i < len(value); i++ {
		c := value[i]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			continue
		}
		return false
	}
	return true
}
