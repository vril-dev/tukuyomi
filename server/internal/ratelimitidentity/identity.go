package ratelimitidentity

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
	KeyByIP        = "ip"
	KeyByCountry   = "country"
	KeyByIPCountry = "ip_country"
	KeyBySession   = "session"
	KeyByIPSession = "ip_session"
	KeyByJWTSub    = "jwt_sub"
	KeyByIPJWTSub  = "ip_jwt_sub"

	DefaultAdaptiveScoreThreshold     = 6
	DefaultAdaptiveLimitFactorPercent = 50
	DefaultAdaptiveBurstFactorPercent = 50
	MaxJWTTokenBytes                  = 4096
	MaxJWTPayloadChars                = 3072
)

var (
	DefaultSessionCookieNames = []string{"session", "sid", "connect.sid", "_session"}
	DefaultJWTHeaderNames     = []string{"Authorization", "X-Auth-Token"}
	DefaultJWTCookieNames     = []string{"token", "access_token", "jwt"}
)

type Config struct {
	SessionCookieNames     []string `json:"session_cookie_names,omitempty"`
	JWTHeaderNames         []string `json:"jwt_header_names,omitempty"`
	JWTCookieNames         []string `json:"jwt_cookie_names,omitempty"`
	AdaptiveEnabled        bool     `json:"adaptive_enabled,omitempty"`
	AdaptiveScoreThreshold int      `json:"adaptive_score_threshold,omitempty"`
	AdaptiveLimitFactorPct int      `json:"adaptive_limit_factor_percent,omitempty"`
	AdaptiveBurstFactorPct int      `json:"adaptive_burst_factor_percent,omitempty"`
}

type Identity struct {
	Session string
	JWTSub  string
}

type Policy struct {
	Limit int
	Burst int
}

func NormalizeConfig(cfg *Config) {
	if cfg == nil {
		return
	}
	cfg.SessionCookieNames = NormalizeNameList(cfg.SessionCookieNames, DefaultSessionCookieNames)
	cfg.JWTHeaderNames = NormalizeNameList(cfg.JWTHeaderNames, DefaultJWTHeaderNames)
	cfg.JWTCookieNames = NormalizeNameList(cfg.JWTCookieNames, DefaultJWTCookieNames)
	if cfg.AdaptiveEnabled {
		if cfg.AdaptiveScoreThreshold <= 0 {
			cfg.AdaptiveScoreThreshold = DefaultAdaptiveScoreThreshold
		}
		if cfg.AdaptiveLimitFactorPct <= 0 {
			cfg.AdaptiveLimitFactorPct = DefaultAdaptiveLimitFactorPercent
		}
		if cfg.AdaptiveBurstFactorPct <= 0 {
			cfg.AdaptiveBurstFactorPct = DefaultAdaptiveBurstFactorPercent
		}
	}
}

func NormalizeNameList(in, fallback []string) []string {
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

func Extract(r *http.Request, cfg Config) Identity {
	if r == nil {
		return Identity{}
	}
	return Identity{
		Session: ExtractSession(r, cfg.SessionCookieNames),
		JWTSub:  ExtractJWTSub(r, cfg.JWTHeaderNames, cfg.JWTCookieNames),
	}
}

func ExtractSession(r *http.Request, cookieNames []string) string {
	for _, name := range cookieNames {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if value := ClampToken(c.Value); value != "" {
			return value
		}
	}
	return ""
}

func ExtractJWTSub(r *http.Request, headerNames, cookieNames []string) string {
	for _, name := range headerNames {
		token := strings.TrimSpace(r.Header.Get(name))
		if token == "" {
			continue
		}
		if strings.Contains(strings.ToLower(name), "authorization") {
			token = strings.TrimSpace(strings.TrimPrefix(token, "Bearer "))
			token = strings.TrimSpace(strings.TrimPrefix(token, "bearer "))
		}
		if sub := ParseJWTSubject(token); sub != "" {
			return sub
		}
	}
	for _, name := range cookieNames {
		c, err := r.Cookie(name)
		if err != nil {
			continue
		}
		if sub := ParseJWTSubject(strings.TrimSpace(c.Value)); sub != "" {
			return sub
		}
	}
	return ""
}

func ParseJWTSubject(token string) string {
	if len(token) == 0 || len(token) > MaxJWTTokenBytes {
		return ""
	}
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return ""
	}
	payload := parts[1]
	if payload == "" || len(payload) > MaxJWTPayloadChars {
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
		return ClampToken(sub)
	}
	return ""
}

func ClampToken(raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if len(v) > 128 {
		return v[:128]
	}
	return v
}

func BuildKey(kind, ip, country string, identity Identity) string {
	sessionKey := fallbackIdentity(identity.Session, ip)
	jwtKey := fallbackIdentity(identity.JWTSub, ip)
	switch kind {
	case KeyByCountry:
		return country
	case KeyByIPCountry:
		if ip == "" {
			return country
		}
		return ip + "|" + country
	case KeyBySession:
		return sessionKey
	case KeyByIPSession:
		if ip == "" {
			return sessionKey
		}
		return ip + "|" + sessionKey
	case KeyByJWTSub:
		return jwtKey
	case KeyByIPJWTSub:
		if ip == "" {
			return jwtKey
		}
		return ip + "|" + jwtKey
	default:
		return ip
	}
}

func ApplyAdaptive(cfg Config, policy Policy, riskScore int) (Policy, bool) {
	if !cfg.AdaptiveEnabled || riskScore < cfg.AdaptiveScoreThreshold {
		return policy, false
	}
	over := riskScore - cfg.AdaptiveScoreThreshold
	limitPct := clampAdaptivePercent(cfg.AdaptiveLimitFactorPct - over*10)
	burstPct := clampAdaptivePercent(cfg.AdaptiveBurstFactorPct - over*10)
	out := policy
	out.Limit = scaleValue(policy.Limit, limitPct, 1)
	out.Burst = scaleValue(policy.Burst, burstPct, 0)
	return out, true
}

func HashKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:8])
}

func SortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func SortedMethodList(methods map[string]struct{}) []string {
	out := make([]string, 0, len(methods))
	for method := range methods {
		out = append(out, method)
	}
	sort.Strings(out)
	return out
}

func fallbackIdentity(value, ip string) string {
	if value != "" {
		return value
	}
	return ip
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

func scaleValue(base, pct, min int) int {
	if base <= 0 {
		return 0
	}
	scaled := (base*pct + 99) / 100
	if scaled < min {
		return min
	}
	return scaled
}
