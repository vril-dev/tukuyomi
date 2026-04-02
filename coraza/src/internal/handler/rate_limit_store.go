package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	rateLimitKeyByIP        = "ip"
	rateLimitKeyByCountry   = "country"
	rateLimitKeyByIPCountry = "ip_country"
)

type rateLimitAction struct {
	Status            int `json:"status"`
	RetryAfterSeconds int `json:"retry_after_seconds"`
}

type rateLimitPolicy struct {
	Enabled       bool            `json:"enabled"`
	Limit         int             `json:"limit"`
	WindowSeconds int             `json:"window_seconds"`
	Burst         int             `json:"burst"`
	KeyBy         string          `json:"key_by"`
	Action        rateLimitAction `json:"action"`
}

type rateLimitRule struct {
	Name       string          `json:"name"`
	MatchType  string          `json:"match_type"`
	MatchValue string          `json:"match_value"`
	Methods    []string        `json:"methods,omitempty"`
	Policy     rateLimitPolicy `json:"policy"`
}

type rateLimitConfig struct {
	Enabled            bool            `json:"enabled"`
	AllowlistIPs       []string        `json:"allowlist_ips,omitempty"`
	AllowlistCountries []string        `json:"allowlist_countries,omitempty"`
	DefaultPolicy      rateLimitPolicy `json:"default_policy"`
	Rules              []rateLimitRule `json:"rules,omitempty"`
	rateLimitIdentityConfig
}

type compiledRateLimitRule struct {
	Raw      rateLimitRule
	Policy   rateLimitPolicy
	Methods  map[string]struct{}
	Regex    *regexp.Regexp
	PolicyID string
}

type runtimeRateLimitConfig struct {
	Raw               rateLimitConfig
	AllowlistPrefixes []netip.Prefix
	AllowCountries    map[string]struct{}
	Rules             []compiledRateLimitRule
	DefaultPolicy     rateLimitPolicy
}

type rateCounter struct {
	WindowID int64
	Count    int
	Updated  time.Time
}

type rateLimitDecision struct {
	Allowed           bool
	Status            int
	RetryAfterSeconds int
	PolicyID          string
	Key               string
	Limit             int
	BaseLimit         int
	WindowSeconds     int
	KeyBy             string
	Adaptive          bool
	RiskScore         int
}

type rateLimitStats struct {
	Requests          uint64 `json:"requests"`
	Allowed           uint64 `json:"allowed"`
	Blocked           uint64 `json:"blocked"`
	AdaptiveDecisions uint64 `json:"adaptive_decisions"`
}

var (
	rateLimitMu      sync.RWMutex
	rateLimitPath    string
	rateLimitRuntime *runtimeRateLimitConfig

	rateCounterMu    sync.Mutex
	rateCounters     = map[string]rateCounter{}
	rateCounterSweep int

	rateLimitRequestsTotal atomic.Uint64
	rateLimitAllowedTotal  atomic.Uint64
	rateLimitBlockedTotal  atomic.Uint64
	rateLimitAdaptiveTotal atomic.Uint64
)

func InitRateLimit(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("rate limit path is empty")
	}
	if err := ensureRateLimitFile(target); err != nil {
		return err
	}

	rateLimitMu.Lock()
	rateLimitPath = target
	rateLimitMu.Unlock()

	return ReloadRateLimit()
}

func GetRateLimitPath() string {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()
	return rateLimitPath
}

func GetRateLimitConfig() rateLimitConfig {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()
	if rateLimitRuntime == nil {
		return rateLimitConfig{}
	}
	return rateLimitRuntime.Raw
}

func ReloadRateLimit() error {
	path := GetRateLimitPath()
	if path == "" {
		return fmt.Errorf("rate limit path is empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := buildRateLimitRuntimeFromRaw(raw)
	if err != nil {
		return err
	}

	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()

	// Start counters from clean state whenever settings are reloaded.
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	return nil
}

func ValidateRateLimitRaw(raw string) (*runtimeRateLimitConfig, error) {
	return buildRateLimitRuntimeFromRaw([]byte(raw))
}

func GetRateLimitStats() rateLimitStats {
	return rateLimitStats{
		Requests:          rateLimitRequestsTotal.Load(),
		Allowed:           rateLimitAllowedTotal.Load(),
		Blocked:           rateLimitBlockedTotal.Load(),
		AdaptiveDecisions: rateLimitAdaptiveTotal.Load(),
	}
}

func EvaluateRateLimit(r *http.Request, clientIP, country string, riskScore int, now time.Time) rateLimitDecision {
	rt := currentRateLimitRuntime()
	if rt == nil || !rt.Raw.Enabled {
		return rateLimitDecision{Allowed: true}
	}
	rateLimitRequestsTotal.Add(1)

	ip := normalizeClientIP(clientIP)
	cc := normalizeCountryCode(country)
	if isAllowlistedIP(rt, ip) || isAllowlistedCountry(rt, cc) {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}

	method, path := http.MethodGet, ""
	if r != nil {
		method = r.Method
		if r.URL != nil {
			path = r.URL.Path
		}
	}
	policy, policyID := pickRateLimitPolicy(rt, method, path)
	if !policy.Enabled {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}

	identity := extractRateLimitIdentity(r, rt.Raw.rateLimitIdentityConfig)
	effectivePolicy, adaptive := applyAdaptiveRateLimit(rt.Raw.rateLimitIdentityConfig, policy, riskScore)
	if adaptive {
		rateLimitAdaptiveTotal.Add(1)
	}
	key := buildRateLimitKey(effectivePolicy.KeyBy, ip, cc, identity)
	if key == "" {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}

	baseHits := policy.Limit + policy.Burst
	maxHits := effectivePolicy.Limit + effectivePolicy.Burst
	if maxHits <= 0 || effectivePolicy.WindowSeconds <= 0 {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}

	windowID := now.Unix() / int64(effectivePolicy.WindowSeconds)
	counterKey := policyID + "|" + key

	rateCounterMu.Lock()
	rateCounterSweep++
	c := rateCounters[counterKey]
	if c.WindowID != windowID {
		c.WindowID = windowID
		c.Count = 0
	}

	allowed := c.Count < maxHits
	if allowed {
		c.Count++
	}
	c.Updated = now
	rateCounters[counterKey] = c

	if rateCounterSweep%1000 == 0 {
		cleanupBefore := now.Add(-10 * time.Minute)
		for k, v := range rateCounters {
			if v.Updated.Before(cleanupBefore) {
				delete(rateCounters, k)
			}
		}
	}
	rateCounterMu.Unlock()

	if allowed {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}
	rateLimitBlockedTotal.Add(1)

	retryAfter := effectivePolicy.Action.RetryAfterSeconds
	if retryAfter <= 0 {
		nextWindowUnix := (windowID + 1) * int64(effectivePolicy.WindowSeconds)
		retryAfter = int(nextWindowUnix - now.Unix())
		if retryAfter < 1 {
			retryAfter = 1
		}
	}

	status := effectivePolicy.Action.Status
	if status == 0 {
		status = 429
	}

	return rateLimitDecision{
		Allowed:           false,
		Status:            status,
		RetryAfterSeconds: retryAfter,
		PolicyID:          policyID,
		Key:               hashRateLimitKey(key),
		Limit:             maxHits,
		BaseLimit:         baseHits,
		WindowSeconds:     effectivePolicy.WindowSeconds,
		KeyBy:             effectivePolicy.KeyBy,
		Adaptive:          adaptive,
		RiskScore:         riskScore,
	}
}

func currentRateLimitRuntime() *runtimeRateLimitConfig {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()
	return rateLimitRuntime
}

func pickRateLimitPolicy(rt *runtimeRateLimitConfig, method, path string) (rateLimitPolicy, string) {
	for _, rule := range rt.Rules {
		if !rule.Policy.Enabled {
			continue
		}
		if !matchesMethod(rule.Methods, method) {
			continue
		}
		if !matchesPathRule(rule, path) {
			continue
		}

		return rule.Policy, rule.PolicyID
	}

	return rt.DefaultPolicy, "default"
}

func matchesPathRule(rule compiledRateLimitRule, path string) bool {
	switch rule.Raw.MatchType {
	case "exact":
		return path == rule.Raw.MatchValue
	case "prefix":
		return strings.HasPrefix(path, rule.Raw.MatchValue)
	case "regex":
		return rule.Regex != nil && rule.Regex.MatchString(path)
	default:
		return false
	}
}

func matchesMethod(methods map[string]struct{}, method string) bool {
	if len(methods) == 0 {
		return true
	}
	_, ok := methods[strings.ToUpper(strings.TrimSpace(method))]
	return ok
}

func isAllowlistedCountry(rt *runtimeRateLimitConfig, country string) bool {
	_, ok := rt.AllowCountries[country]
	return ok
}

func isAllowlistedIP(rt *runtimeRateLimitConfig, ip string) bool {
	if ip == "" {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, pfx := range rt.AllowlistPrefixes {
		if pfx.Contains(addr) {
			return true
		}
	}
	return false
}

func normalizeClientIP(ip string) string {
	v := strings.TrimSpace(ip)
	if i := strings.Index(v, ","); i >= 0 {
		v = strings.TrimSpace(v[:i])
	}
	return v
}

func buildRateLimitRuntimeFromRaw(raw []byte) (*runtimeRateLimitConfig, error) {
	var cfg rateLimitConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}
	normalizeRateLimitIdentityConfig(&cfg.rateLimitIdentityConfig)

	if cfg.DefaultPolicy == (rateLimitPolicy{}) {
		cfg.DefaultPolicy = rateLimitPolicy{
			Enabled:       true,
			Limit:         120,
			WindowSeconds: 60,
			Burst:         20,
			KeyBy:         rateLimitKeyByIP,
			Action: rateLimitAction{
				Status:            429,
				RetryAfterSeconds: 60,
			},
		}
	}

	defaultPolicy, err := normalizeRateLimitPolicy(cfg.DefaultPolicy, "default_policy")
	if err != nil {
		return nil, err
	}

	allowCountries := map[string]struct{}{}
	for _, c := range cfg.AllowlistCountries {
		code := normalizeCountryCode(c)
		if code == "" {
			continue
		}
		allowCountries[code] = struct{}{}
	}

	allowPrefixes := make([]netip.Prefix, 0, len(cfg.AllowlistIPs))
	for _, rawIP := range cfg.AllowlistIPs {
		entry := strings.TrimSpace(rawIP)
		if entry == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(entry); err == nil {
			allowPrefixes = append(allowPrefixes, pfx)
			continue
		}
		addr, err := netip.ParseAddr(entry)
		if err != nil {
			return nil, fmt.Errorf("invalid allowlist_ips entry: %s", entry)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		allowPrefixes = append(allowPrefixes, netip.PrefixFrom(addr, bits))
	}

	compiledRules := make([]compiledRateLimitRule, 0, len(cfg.Rules))
	for i, rule := range cfg.Rules {
		rule.MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
		rule.MatchValue = strings.TrimSpace(rule.MatchValue)
		if rule.MatchType == "" {
			return nil, fmt.Errorf("rules[%d]: match_type is required", i)
		}
		if rule.MatchValue == "" {
			return nil, fmt.Errorf("rules[%d]: match_value is required", i)
		}
		switch rule.MatchType {
		case "exact", "prefix", "regex":
		default:
			return nil, fmt.Errorf("rules[%d]: match_type must be exact|prefix|regex", i)
		}

		policy, err := normalizeRateLimitPolicy(rule.Policy, fmt.Sprintf("rules[%d].policy", i))
		if err != nil {
			return nil, err
		}
		methods := make(map[string]struct{}, len(rule.Methods))
		for _, m := range rule.Methods {
			mv := strings.ToUpper(strings.TrimSpace(m))
			if mv == "" {
				continue
			}
			methods[mv] = struct{}{}
		}

		compiled := compiledRateLimitRule{
			Raw:      rule,
			Policy:   policy,
			Methods:  methods,
			PolicyID: fmt.Sprintf("rule:%d:%s", i, strings.TrimSpace(rule.Name)),
		}
		if rule.MatchType == "regex" {
			re, err := regexp.Compile(rule.MatchValue)
			if err != nil {
				return nil, fmt.Errorf("rules[%d]: invalid regex: %v", i, err)
			}
			compiled.Regex = re
		}

		compiledRules = append(compiledRules, compiled)
	}

	sort.Slice(compiledRules, func(i, j int) bool { return i < j })
	cfg.DefaultPolicy = defaultPolicy
	cfg.AllowlistCountries = sortedKeys(allowCountries)
	cfg.AllowlistIPs = make([]string, 0, len(allowPrefixes))
	for _, pfx := range allowPrefixes {
		cfg.AllowlistIPs = append(cfg.AllowlistIPs, pfx.String())
	}
	for i, rule := range cfg.Rules {
		cfg.Rules[i].MatchType = strings.ToLower(strings.TrimSpace(rule.MatchType))
		cfg.Rules[i].MatchValue = strings.TrimSpace(rule.MatchValue)
		cfg.Rules[i].Policy = compiledRules[i].Policy
		cfg.Rules[i].Methods = sortedMethodList(compiledRules[i].Methods)
	}

	return &runtimeRateLimitConfig{
		Raw:               cfg,
		AllowlistPrefixes: allowPrefixes,
		AllowCountries:    allowCountries,
		Rules:             compiledRules,
		DefaultPolicy:     defaultPolicy,
	}, nil
}

func normalizeRateLimitPolicy(p rateLimitPolicy, field string) (rateLimitPolicy, error) {
	if p.Action.Status == 0 {
		p.Action.Status = 429
	}
	if p.Action.Status < 400 || p.Action.Status > 599 {
		return p, fmt.Errorf("%s.action.status must be 400-599", field)
	}
	if p.Action.RetryAfterSeconds < 0 {
		return p, fmt.Errorf("%s.action.retry_after_seconds must be >= 0", field)
	}
	if p.Burst < 0 {
		return p, fmt.Errorf("%s.burst must be >= 0", field)
	}

	p.KeyBy = strings.ToLower(strings.TrimSpace(p.KeyBy))
	if p.KeyBy == "" {
		p.KeyBy = rateLimitKeyByIP
	}
	switch p.KeyBy {
	case rateLimitKeyByIP, rateLimitKeyByCountry, rateLimitKeyByIPCountry, rateLimitKeyBySession, rateLimitKeyByIPSession, rateLimitKeyByJWTSub, rateLimitKeyByIPJWTSub:
	default:
		return p, fmt.Errorf("%s.key_by must be ip|country|ip_country|session|ip_session|jwt_sub|ip_jwt_sub", field)
	}

	if p.Enabled {
		if p.Limit <= 0 {
			return p, fmt.Errorf("%s.limit must be > 0 when enabled", field)
		}
		if p.WindowSeconds <= 0 {
			return p, fmt.Errorf("%s.window_seconds must be > 0 when enabled", field)
		}
	}

	return p, nil
}

func ensureRateLimitFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	const defaultRaw = `{
  "enabled": true,
  "allowlist_ips": [],
  "allowlist_countries": [],
  "session_cookie_names": ["session", "sid"],
  "jwt_header_names": ["Authorization"],
  "jwt_cookie_names": ["token", "access_token"],
  "adaptive_enabled": false,
  "adaptive_score_threshold": 6,
  "adaptive_limit_factor_percent": 50,
  "adaptive_burst_factor_percent": 50,
  "default_policy": {
    "enabled": true,
    "limit": 120,
    "window_seconds": 60,
    "burst": 20,
    "key_by": "ip",
    "action": {
      "status": 429,
      "retry_after_seconds": 60
    }
  },
  "rules": [
    {
      "name": "login",
      "match_type": "prefix",
      "match_value": "/login",
      "methods": ["POST"],
      "policy": {
        "enabled": true,
        "limit": 10,
        "window_seconds": 60,
        "burst": 0,
        "key_by": "ip",
        "action": {
          "status": 429,
          "retry_after_seconds": 60
        }
      }
    }
  ]
}
`
	return os.WriteFile(path, []byte(defaultRaw), 0o644)
}
