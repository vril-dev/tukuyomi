package handler

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

var proxyStickySessionSigningKey = newProxyStickySessionSigningKey()

func newProxyStickySessionSigningKey() []byte {
	key := make([]byte, 32)
	if _, err := rand.Read(key); err == nil {
		return key
	}
	panic("proxy sticky session signing key generation failed")
}

func proxyStickySessionCandidateIndex(req *http.Request, candidates []proxyRouteTargetCandidate, eligible []int, cfg ProxyStickySessionConfig) (int, bool) {
	stickyID, ok := proxyStickySessionRequestUpstream(req, cfg, time.Now().UTC())
	if !ok {
		return 0, false
	}
	for _, idx := range eligible {
		if idx < 0 || idx >= len(candidates) {
			continue
		}
		if proxyRouteCandidateStickyID(candidates[idx]) == stickyID {
			return idx, true
		}
	}
	return 0, false
}

func proxyStickySessionRequestUpstream(req *http.Request, cfg ProxyStickySessionConfig, now time.Time) (string, bool) {
	if req == nil || !cfg.Enabled || cfg.CookieName == "" {
		return "", false
	}
	cookie, err := req.Cookie(cfg.CookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" || len(cookie.Value) > 4096 {
		return "", false
	}
	return parseProxyStickySessionCookieValue(cfg.CookieName, cookie.Value, now)
}

func proxyStickySessionMatchesUpstream(req *http.Request, cfg ProxyStickySessionConfig, upstreamName string, now time.Time) bool {
	return proxyStickySessionMatchesID(req, cfg, upstreamName, now)
}

func proxyStickySessionMatchesID(req *http.Request, cfg ProxyStickySessionConfig, stickyID string, now time.Time) bool {
	if strings.TrimSpace(stickyID) == "" {
		return false
	}
	selectedID, ok := proxyStickySessionRequestUpstream(req, cfg, now)
	return ok && selectedID == stickyID
}

func applyProxyStickySessionCookie(res *http.Response) {
	if res == nil || res.Request == nil {
		return
	}
	selection, ok := proxyRouteTransportSelectionFromContext(res.Request.Context())
	if !ok || !selection.StickySession.Enabled {
		return
	}
	stickyID := strings.TrimSpace(selection.StickyTargetID)
	if stickyID == "" {
		stickyID = selection.SelectedUpstream
	}
	cookie := proxyStickySessionCookie(selection.StickySession, stickyID, time.Now().UTC())
	if cookie == nil {
		return
	}
	res.Header.Add("Set-Cookie", cookie.String())
}

func proxyStickySessionCookie(cfg ProxyStickySessionConfig, upstreamName string, now time.Time) *http.Cookie {
	if !cfg.Enabled || cfg.CookieName == "" || upstreamName == "" {
		return nil
	}
	ttl := cfg.TTLSeconds
	if ttl <= 0 {
		ttl = defaultProxyStickySessionTTLSeconds
	}
	expires := now.Add(time.Duration(ttl) * time.Second)
	return &http.Cookie{
		Name:     cfg.CookieName,
		Value:    buildProxyStickySessionCookieValue(cfg.CookieName, upstreamName, expires),
		Path:     cfg.Path,
		Domain:   cfg.Domain,
		Expires:  expires,
		MaxAge:   ttl,
		Secure:   cfg.Secure,
		HttpOnly: proxyStickySessionHTTPOnly(cfg),
		SameSite: proxyStickySessionSameSite(cfg.SameSite),
	}
}

func buildProxyStickySessionCookieValue(cookieName string, upstreamName string, expires time.Time) string {
	expiry := strconv.FormatInt(expires.Unix(), 10)
	encodedUpstreamName := base64.RawURLEncoding.EncodeToString([]byte(upstreamName))
	payload := strings.Join([]string{"v1", encodedUpstreamName, expiry}, "|")
	sig := proxyStickySessionSignature(cookieName, payload)
	raw := strings.Join([]string{payload, sig}, "|")
	return base64.RawURLEncoding.EncodeToString([]byte(raw))
}

func parseProxyStickySessionCookieValue(cookieName string, value string, now time.Time) (string, bool) {
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
	expected := proxyStickySessionSignature(cookieName, payload)
	if !hmac.Equal([]byte(expected), []byte(parts[3])) {
		return "", false
	}
	upstreamNameRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	upstreamName := strings.TrimSpace(string(upstreamNameRaw))
	if upstreamName == "" {
		return "", false
	}
	return upstreamName, true
}

func proxyStickySessionSignature(cookieName string, payload string) string {
	mac := hmac.New(sha256.New, proxyStickySessionSigningKey)
	mac.Write([]byte(cookieName))
	mac.Write([]byte{0})
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func proxyStickySessionHTTPOnly(cfg ProxyStickySessionConfig) bool {
	if cfg.HTTPOnly == nil {
		return true
	}
	return *cfg.HTTPOnly
}

func proxyStickySessionSameSite(raw string) http.SameSite {
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
