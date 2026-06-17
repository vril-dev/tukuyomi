package adminauth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	TOTPPeriodSeconds = 30
	TOTPDigits        = 6
	TOTPSecretBytes   = 20

	maxTOTPSecretChars       = 128
	maxTOTPCodeChars         = 16
	recoveryCodeRandomBytes  = 10
	recoveryCodeDisplayGroup = 4
)

var (
	ErrInvalidTOTPSecret   = errors.New("invalid totp secret")
	ErrInvalidTOTPCode     = errors.New("invalid totp code")
	ErrInvalidRecoveryCode = errors.New("invalid recovery code")
)

var totpBase32 = base32.StdEncoding.WithPadding(base32.NoPadding)

func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return totpBase32.EncodeToString(buf), nil
}

func TOTPAuthURI(issuer string, account string, secret string) (string, error) {
	issuer = strings.TrimSpace(issuer)
	account = strings.TrimSpace(account)
	if issuer == "" || account == "" {
		return "", fmt.Errorf("issuer and account are required")
	}
	if _, err := decodeTOTPSecret(secret); err != nil {
		return "", err
	}
	v := url.Values{}
	v.Set("secret", normalizeTOTPSecret(secret))
	v.Set("issuer", issuer)
	v.Set("algorithm", "SHA1")
	v.Set("digits", strconv.Itoa(TOTPDigits))
	v.Set("period", strconv.Itoa(TOTPPeriodSeconds))
	return "otpauth://totp/" + url.PathEscape(issuer+":"+account) + "?" + v.Encode(), nil
}

func TOTPCode(secret string, now time.Time) (string, int64, error) {
	counter := totpCounter(now)
	code, err := totpCodeForCounter(secret, counter, TOTPDigits)
	return code, counter, err
}

func VerifyTOTP(secret string, code string, now time.Time, lastUsedCounter *int64) (int64, bool, error) {
	code, err := normalizeTOTPCode(code)
	if err != nil {
		return 0, false, err
	}
	counter := totpCounter(now)
	for _, candidate := range []int64{counter - 1, counter, counter + 1} {
		if candidate < 0 {
			continue
		}
		if lastUsedCounter != nil && candidate <= *lastUsedCounter {
			continue
		}
		expected, err := totpCodeForCounter(secret, candidate, TOTPDigits)
		if err != nil {
			return 0, false, err
		}
		if subtle.ConstantTimeCompare([]byte(code), []byte(expected)) == 1 {
			return candidate, true, nil
		}
	}
	return 0, false, nil
}

func GenerateRecoveryCodes(count int) ([]string, error) {
	if count < 1 || count > 20 {
		return nil, ErrInvalidRecoveryCode
	}
	codes := make([]string, 0, count)
	for len(codes) < count {
		buf := make([]byte, recoveryCodeRandomBytes)
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		raw := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf))
		codes = append(codes, groupRecoveryCode(raw))
	}
	return codes, nil
}

func NormalizeRecoveryCode(code string) (string, error) {
	code = strings.ToLower(strings.TrimSpace(code))
	code = strings.ReplaceAll(code, "-", "")
	code = strings.ReplaceAll(code, " ", "")
	if len(code) < 12 || len(code) > 32 {
		return "", ErrInvalidRecoveryCode
	}
	for _, r := range code {
		if (r < 'a' || r > 'z') && (r < '2' || r > '7') {
			return "", ErrInvalidRecoveryCode
		}
	}
	return code, nil
}

func HashRecoveryCode(code string, pepper string) (string, error) {
	normalized, err := NormalizeRecoveryCode(code)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, []byte(strings.TrimSpace(pepper)))
	_, _ = mac.Write([]byte("admin-mfa-recovery\n"))
	_, _ = mac.Write([]byte(normalized))
	return "hmac-sha256:" + hex.EncodeToString(mac.Sum(nil)), nil
}

func VerifyRecoveryCode(code string, hash string, pepper string) (bool, error) {
	got, err := HashRecoveryCode(code, pepper)
	if err != nil {
		return false, err
	}
	hash = strings.TrimSpace(hash)
	if got == "" || hash == "" || len(got) != len(hash) {
		return false, nil
	}
	return subtle.ConstantTimeCompare([]byte(got), []byte(hash)) == 1, nil
}

func normalizeTOTPSecret(secret string) string {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	secret = strings.ReplaceAll(secret, " ", "")
	secret = strings.TrimRight(secret, "=")
	return secret
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = normalizeTOTPSecret(secret)
	if secret == "" || len(secret) > maxTOTPSecretChars {
		return nil, ErrInvalidTOTPSecret
	}
	raw, err := totpBase32.DecodeString(secret)
	if err != nil || len(raw) < 10 || len(raw) > 64 {
		return nil, ErrInvalidTOTPSecret
	}
	return raw, nil
}

func normalizeTOTPCode(code string) (string, error) {
	code = strings.TrimSpace(code)
	code = strings.ReplaceAll(code, " ", "")
	if code == "" || len(code) > maxTOTPCodeChars {
		return "", ErrInvalidTOTPCode
	}
	for _, r := range code {
		if r < '0' || r > '9' {
			return "", ErrInvalidTOTPCode
		}
	}
	if len(code) != TOTPDigits {
		return "", ErrInvalidTOTPCode
	}
	return code, nil
}

func totpCounter(now time.Time) int64 {
	unix := now.UTC().Unix()
	if unix < 0 {
		return 0
	}
	return unix / TOTPPeriodSeconds
}

func totpCodeForCounter(secret string, counter int64, digits int) (string, error) {
	raw, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(counter))
	mac := hmac.New(sha1.New, raw)
	_, _ = mac.Write(buf[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	binCode := (uint32(sum[offset])&0x7f)<<24 |
		(uint32(sum[offset+1])&0xff)<<16 |
		(uint32(sum[offset+2])&0xff)<<8 |
		(uint32(sum[offset+3]) & 0xff)
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	value := binCode % mod
	return fmt.Sprintf("%0*d", digits, value), nil
}

func groupRecoveryCode(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%recoveryCodeDisplayGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

func secretForTOTPTest(raw string) string {
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte(raw))
}
