package challengecookie

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

func IssueHMAC(secret []byte, ttl time.Duration, ip, userAgent string, now time.Time) string {
	exp := now.Add(ttl).Unix()
	payload := strconv.FormatInt(exp, 10)
	sig := signHMAC(secret, ip, userAgent, payload)
	return payload + "." + sig
}

func VerifyHMAC(secret []byte, token, ip, userAgent string, now time.Time) bool {
	parts := strings.Split(strings.TrimSpace(token), ".")
	if len(parts) != 2 {
		return false
	}

	expUnix, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || expUnix <= 0 {
		return false
	}
	if now.Unix() > expUnix {
		return false
	}

	expected := signHMAC(secret, ip, userAgent, parts[0])
	return ConstantTimeHexEqual(parts[1], expected)
}

func ConstantTimeHexEqual(a, b string) bool {
	ab, errA := hex.DecodeString(strings.TrimSpace(a))
	bb, errB := hex.DecodeString(strings.TrimSpace(b))
	if errA != nil || errB != nil || len(ab) != len(bb) {
		return false
	}
	return hmac.Equal(ab, bb)
}

func signHMAC(secret []byte, ip, userAgent, payload string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(strings.TrimSpace(ip)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(userAgent))))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}
