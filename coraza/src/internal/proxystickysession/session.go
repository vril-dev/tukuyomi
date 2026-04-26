package proxystickysession

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultTTLSeconds = 86400
	MaxTTLSeconds     = 30 * 24 * 60 * 60
	MaxCookieBytes    = 4096
)

type Config struct {
	Enabled    bool   `json:"enabled"`
	CookieName string `json:"cookie_name,omitempty"`
	TTLSeconds int    `json:"ttl_seconds,omitempty"`
	Path       string `json:"path,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Secure     bool   `json:"secure,omitempty"`
	HTTPOnly   *bool  `json:"http_only,omitempty"`
	SameSite   string `json:"same_site,omitempty"`
}

var signingKey = newSigningKey()

func newSigningKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		return key
	}
	panic("proxy sticky session signing key generation failed")
}

func RequestID(req *http.Request, cfg Config, now time.Time) (string, bool) {
	if req == nil || !cfg.Enabled || cfg.CookieName == "" {
		return "", false
	}
	cookie, err := req.Cookie(cfg.CookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" || len(cookie.Value) > MaxCookieBytes {
		return "", false
	}
	return ParseValue(cfg.CookieName, cookie.Value, now)
}

func MatchesID(req *http.Request, cfg Config, stickyID string, now time.Time) bool {
	if strings.TrimSpace(stickyID) == "" {
		return false
	}
	selectedID, ok := RequestID(req, cfg, now)
	return ok && selectedID == stickyID
}

func Cookie(cfg Config, stickyID string, now time.Time) *http.Cookie {
	if !cfg.Enabled || cfg.CookieName == "" || stickyID == "" {
		return nil
	}
	ttl := cfg.TTLSeconds
	if ttl <= 0 {
		ttl = DefaultTTLSeconds
	}
	expires := now.Add(time.Duration(ttl) * time.Second)
	return &http.Cookie{
		Name:     cfg.CookieName,
		Value:    BuildValue(cfg.CookieName, stickyID, expires),
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  expires,
		MaxAge:   ttl,
		Secure:   cfg.Secure,
		HttpOnly: HTTPOnly(cfg),
		SameSite: SameSite(cfg.SameSite),
	}
}

func BuildValue(cookieName string, stickyID string, expires time.Time) string {
	expiry := strconv.FormatInt(expires.Unix(), 10)
	encodedID := base64.RawURLEncoding.EncodeToString([]byte(stickyID))
	payload := strings.Join([]string{"v1", encodedID, expiry}, "|")
	sig := signature(cookieName, payload)
	raw := strings.Join([]string{payload, sig}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func ParseValue(cookieName string, value string, now time.Time) (string, bool) {
	raw, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return "", false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 4 || parts[0] != "v1" {
		return "", false
	}
	expiresUnix, err := strconv.ParseInt(parts[2], 10, 64)
	if err != nil {
		return "", false
	}
	if !now.Before(time.Unix(expiresUnix, 0)) {
		return "", false
	}
	payload := strings.Join(parts[:3], "|")
	expected := signature(cookieName, payload)
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return "", false
	}
	stickyIDRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	stickyID := strings.TrimSpace(string(stickyIDRaw))
	if stickyID == "" {
		return "", false
	}
	return stickyID, true
}

func HTTPOnly(cfg Config) bool {
	if cfg.HTTPOnly == nil {
		return true
	}
	return *cfg.HTTPOnly
}

func SameSite(raw string) http.SameSite {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "strict":
		return http.SameSiteStrictMode
	case "none":
		return http.SameSiteNoneMode
	case "lax", "":
		return http.SameSiteLaxMode
	default:
		return http.SameSiteDefaultMode
	}
}

func signature(cookieName string, payload string) string {
	mac := hmac.New(sha256.New, signingKey)
	mac.Write([]byte(cookieName))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
