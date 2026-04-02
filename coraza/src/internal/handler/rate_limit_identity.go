package handler

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"sort"
	"strings"
)

const (
	rateLimitKeyBySession   = "session"
	rateLimitKeyByIPSession = "ip_session"
	rateLimitKeyByJWTSub    = "jwt_sub"
	rateLimitKeyByIPJWTSub  = "ip_jwt_sub"

	defaultAdaptiveScoreThreshold     = 6
	defaultAdaptiveLimitFactorPercent = 50
	defaultAdaptiveBurstFactorPercent = 50
	maxRateLimitJWTTokenBytes         = 4096
	maxRateLimitJWTPayloadChars       = 3072
)

var (
	defaultRateLimitSessionCookieNames = []string{"session", "sid", "connect.sid", "_session"}
	defaultRateLimitJWTHeaderNames     = []string{"Authorization", "X-Auth-Token"}
	defaultRateLimitJWTCookieNames     = []string{"token", "access_token", "jwt"}
)

type rateLimitIdentityConfig struct {
	SessionCookieNames     []string `json:"session_cookie_names,omitempty"`
	JWTHeaderNames         []string `json:"jwt_header_names,omitempty"`
	JWTCookieNames         []string `json:"jwt_cookie_names,omitempty"`
	AdaptiveEnabled        bool     `json:"adaptive_enabled,omitempty"`
	AdaptiveScoreThreshold int      `json:"adaptive_score_threshold,omitempty"`
	AdaptiveLimitFactorPct int      `json:"adaptive_limit_factor_percent,omitempty"`
	AdaptiveBurstFactorPct int      `json:"adaptive_burst_factor_percent,omitempty"`
}

type rateLimitIdentity struct {
	Session string
	JWTSub  string
}

func normalizeRateLimitIdentityConfig(cfg *rateLimitIdentityConfig) {
	if cfg == nil {
		return
	}
	cfg.SessionCookieNames = normalizeRateLimitNameList(cfg.SessionCookieNames, defaultRateLimitSessionCookieNames)
	cfg.JWTHeaderNames = normalizeRateLimitNameList(cfg.JWTHeaderNames, defaultRateLimitJWTHeaderNames)
	cfg.JWTCookieNames = normalizeRateLimitNameList(cfg.JWTCookieNames, defaultRateLimitJWTCookieNames)
	if cfg.AdaptiveEnabled {
		if cfg.AdaptiveScoreThreshold <= 0 {
			cfg.AdaptiveScoreThreshold = defaultAdaptiveScoreThreshold
		}
		if cfg.AdaptiveLimitFactorPct <= 0 {
			cfg.AdaptiveLimitFactorPct = defaultAdaptiveLimitFactorPercent
		}
		if cfg.AdaptiveBurstFactorPct <= 0 {
			cfg.AdaptiveBurstFactorPct = defaultAdaptiveBurstFactorPercent
		}
	}
}

func normalizeRateLimitNameList(in, fallback []string) []string {
	values := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		k := strings.ToLower(v)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		values = append(values, v)
	}
	if len(values) > 0 {
		return values
	}
	return append([]string(nil), fallback...)
}

func extractRateLimitIdentity(r *http.Request, cfg rateLimitIdentityConfig) rateLimitIdentity {
	if r == nil {
		return rateLimitIdentity{}
	}
	return rateLimitIdentity{
		Session: extractRateLimitSession(r, cfg.SessionCookieNames),
		JWTSub:  extractRateLimitJWTSub(r, cfg.JWTHeaderNames, cfg.JWTCookieNames),
	}
}

func extractRateLimitSession(r *http.Request, cookieNames []string) string {
	for _, name := range cookieNames {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if value := clampRateLimitIdentityToken(c.Value); value != "" {
			return value
		}
	}
	return ""
}

func extractRateLimitJWTSub(r *http.Request, headerNames, cookieNames []string) string {
	for _, name := range headerNames {
		token := strings.TrimSpace(r.Header.Get(name))
		if token == "" {
			continue
		}
		if strings.Contains(strings.ToLower(name), "authorization") {
			token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
			token = strings.TrimSpace(strings.TrimPrefix(token, "bearer "))
		}
		if sub := parseJWTSubject(token); sub != "" {
			return sub
		}
	}
	for _, name := range cookieNames {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if sub := parseJWTSubject(strings.TrimSpace(c.Value)); sub != "" {
			return sub
		}
	}
	return ""
}

func parseJWTSubject(token string) string {
	if len(token) == 0 || len(token) > maxRateLimitJWTTokenBytes {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload := parts[1]
	if payload == "" || len(payload) > maxRateLimitJWTPayloadChars {
		return ""
	}
	data, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return ""
	}
	var body map[string]any
	if err := json.Unmarshal(data, &body); err != nil {
		return ""
	}
	if sub, _ := body["sub"].(string); sub != "" {
		return clampRateLimitIdentityToken(sub)
	}
	return ""
}

func clampRateLimitIdentityToken(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if len(v) > 128 {
		return v[:128]
	}
	return v
}

func buildRateLimitKey(kind, ip, country string, identity rateLimitIdentity) string {
	sessionKey := fallbackRateLimitIdentity(identity.Session, ip)
	jwtKey := fallbackRateLimitIdentity(identity.JWTSub, ip)
	switch kind {
	case rateLimitKeyByCountry:
		return country
	case rateLimitKeyByIPCountry:
		if ip == "" {
			return country
		}
		return ip + "|" + country
	case rateLimitKeyBySession:
		return sessionKey
	case rateLimitKeyByIPSession:
		if ip == "" {
			return sessionKey
		}
		return ip + "|" + sessionKey
	case rateLimitKeyByJWTSub:
		return jwtKey
	case rateLimitKeyByIPJWTSub:
		if ip == "" {
			return jwtKey
		}
		return ip + "|" + jwtKey
	default:
		return ip
	}
}

func fallbackRateLimitIdentity(value, ip string) string {
	if value != "" {
		return value
	}
	return ip
}

func applyAdaptiveRateLimit(cfg rateLimitIdentityConfig, policy rateLimitPolicy, riskScore int) (rateLimitPolicy, bool) {
	if !cfg.AdaptiveEnabled || riskScore < cfg.AdaptiveScoreThreshold {
		return policy, false
	}
	over := riskScore - cfg.AdaptiveScoreThreshold
	limitPct := clampAdaptivePercent(cfg.AdaptiveLimitFactorPct - over*10)
	burstPct := clampAdaptivePercent(cfg.AdaptiveBurstFactorPct - over*10)
	out := policy
	out.Limit = scaleRateLimitValue(policy.Limit, limitPct, 1)
	out.Burst = scaleRateLimitValue(policy.Burst, burstPct, 0)
	return out, true
}

func clampAdaptivePercent(v int) int {
	if v < 10 {
		return 10
	}
	if v > 100 {
		return 100
	}
	return v
}

func scaleRateLimitValue(base, pct, min int) int {
	if base <= 0 {
		return 0
	}
	scaled := (base*pct + 99) / 100
	if scaled < min {
		return min
	}
	return scaled
}

func hashRateLimitKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedMethodList(methods map[string]struct{}) []string {
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}
