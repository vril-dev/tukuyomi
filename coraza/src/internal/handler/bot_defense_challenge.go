package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func WriteBotDefenseChallenge(w http.ResponseWriter, r *http.Request, d botDefenseDecision) {
	status := d.Status
	if status == 0 {
		status = http.StatusTooManyRequests
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Tukuyomi-Bot-Challenge", "required")

	if !acceptsHTML(r.Header.Get("Accept")) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(`{"error":"bot challenge required"}`))
		return
	}

	maxAge := d.TTLSeconds
	if maxAge < 1 {
		maxAge = 1
	}
	html := fmt.Sprintf(`<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Challenge Required</title></head>
<body>
<p>Verifying browser...</p>
<script>
(() => {
  const token = %q;
  const cookieName = %q;
  document.cookie = cookieName + "=" + token + "; Path=/; Max-Age=%d; SameSite=Lax";
  window.location.replace(window.location.href);
})();
</script>
<noscript>JavaScript is required to continue.</noscript>
</body></html>`, d.Token, d.CookieName, maxAge)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(html))
}

func issueBotDefenseToken(rt *runtimeBotDefenseConfig, ip, userAgent string, now time.Time) string {
	exp := now.Add(rt.ChallengeTTL).Unix()
	payload := strconv.FormatInt(exp, 10)
	sig := signBotDefenseToken(rt, ip, userAgent, payload)
	return payload + "." + sig
}

func verifyBotDefenseToken(rt *runtimeBotDefenseConfig, token, ip, userAgent string, now time.Time) bool {
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

	expected := signBotDefenseToken(rt, ip, userAgent, parts[0])
	return subtleConstantTimeHexEqual(parts[1], expected)
}

func signBotDefenseToken(rt *runtimeBotDefenseConfig, ip, userAgent, payload string) string {
	mac := hmac.New(sha256.New, rt.Secret)
	_, _ = mac.Write([]byte(strings.TrimSpace(ip)))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(strings.ToLower(strings.TrimSpace(userAgent))))
	_, _ = mac.Write([]byte{'\n'})
	_, _ = mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

func subtleConstantTimeHexEqual(a, b string) bool {
	ab, errA := hex.DecodeString(strings.TrimSpace(a))
	bb, errB := hex.DecodeString(strings.TrimSpace(b))
	if errA != nil || errB != nil || len(ab) != len(bb) {
		return false
	}
	return hmac.Equal(ab, bb)
}
