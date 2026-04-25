package handler

import (
	"encoding/json"
	"fmt"
	"io"
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

	"tukuyomi/internal/policyhost"
)

const (
	rateLimitKeyByIP        = "ip"
	rateLimitKeyByCountry   = "country"
	rateLimitKeyByIPCountry = "ip_country"
	rateLimitDefaultScope   = "default"
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
	Enabled            bool                    `json:"enabled"`
	AllowlistIPs       []string                `json:"allowlist_ips,omitempty"`
	AllowlistCountries []string                `json:"allowlist_countries,omitempty"`
	Feedback           rateLimitFeedbackConfig `json:"feedback,omitempty"`
	DefaultPolicy      rateLimitPolicy         `json:"default_policy"`
	Rules              []rateLimitRule         `json:"rules,omitempty"`
	rateLimitIdentityConfig
}

type rateLimitFile struct {
	Default rateLimitConfig            `json:"default"`
	Hosts   map[string]rateLimitConfig `json:"hosts,omitempty"`
}

type compiledRateLimitRule struct {
	Raw      rateLimitRule
	Policy   rateLimitPolicy
	Methods  map[string]struct{}
	Regex    *regexp.Regexp
	PolicyID string
}

type compiledRateLimitScope struct {
	Raw               rateLimitConfig
	AllowlistPrefixes []netip.Prefix
	AllowCountries    map[string]struct{}
	Rules             []compiledRateLimitRule
	DefaultPolicy     rateLimitPolicy
	Feedback          runtimeRateLimitFeedbackConfig
}

type runtimeRateLimitConfig struct {
	Raw     rateLimitFile
	Default compiledRateLimitScope
	Hosts   map[string]compiledRateLimitScope
}

type rateLimitScopeSelection struct {
	Raw               rateLimitConfig
	AllowlistPrefixes []netip.Prefix
	AllowCountries    map[string]struct{}
	Rules             []compiledRateLimitRule
	DefaultPolicy     rateLimitPolicy
	Feedback          runtimeRateLimitFeedbackConfig
	ScopeKey          string
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
	HostScope         string
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
	rateLimitMu.Lock()
	rateLimitPath = target
	rateLimitMu.Unlock()

	if store := getLogsStatsStore(); store != nil {
		raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(rateLimitConfigBlobKey), normalizeRateLimitPolicyRaw, "rate limit rules")
		if err != nil {
			return fmt.Errorf("read rate limit config db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized rate limit config missing in db; run make db-import before removing seed files")
		}
		return applyRateLimitPolicyRaw(raw)
	}

	if err := ensureRateLimitFile(target); err != nil {
		return err
	}

	return ReloadRateLimit()
}

func GetRateLimitPath() string {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()
	return rateLimitPath
}

func GetRateLimitConfig() rateLimitFile {
	rateLimitMu.RLock()
	defer rateLimitMu.RUnlock()
	if rateLimitRuntime == nil {
		return rateLimitFile{}
	}
	return cloneRateLimitFile(rateLimitRuntime.Raw)
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
	resetRateLimitFeedbackState()

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
	if rt == nil {
		return rateLimitDecision{Allowed: true}
	}
	scope := selectRateLimitScope(rt, r)
	if !scope.Raw.Enabled {
		return rateLimitDecision{Allowed: true}
	}
	rateLimitRequestsTotal.Add(1)

	ip := normalizeClientIP(clientIP)
	cc := normalizeCountryCode(country)
	if isAllowlistedIP(scope, ip) || isAllowlistedCountry(scope, cc) {
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
	policy, policyID := pickRateLimitPolicy(scope, method, path)
	if !policy.Enabled {
		rateLimitAllowedTotal.Add(1)
		return rateLimitDecision{Allowed: true}
	}

	scopedPolicyID := rateLimitScopedPolicyID(scope.ScopeKey, policyID)
	identity := extractRateLimitIdentity(r, scope.Raw.rateLimitIdentityConfig)
	effectivePolicy, adaptive := applyAdaptiveRateLimit(scope.Raw.rateLimitIdentityConfig, policy, riskScore)
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
	counterKey := scopedPolicyID + "|" + key

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
		PolicyID:          scopedPolicyID,
		HostScope:         scope.ScopeKey,
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

func selectRateLimitScope(rt *runtimeRateLimitConfig, req *http.Request) rateLimitScopeSelection {
	if rt == nil {
		return rateLimitScopeSelection{ScopeKey: rateLimitDefaultScope}
	}
	if req != nil {
		for _, candidate := range policyhost.Candidates(req.Host, req.TLS != nil) {
			if scope, ok := rt.Hosts[candidate]; ok {
				return rateLimitScopeSelection{
					Raw:               scope.Raw,
					AllowlistPrefixes: scope.AllowlistPrefixes,
					AllowCountries:    scope.AllowCountries,
					Rules:             scope.Rules,
					DefaultPolicy:     scope.DefaultPolicy,
					Feedback:          scope.Feedback,
					ScopeKey:          candidate,
				}
			}
		}
	}
	return rateLimitScopeSelection{
		Raw:               rt.Default.Raw,
		AllowlistPrefixes: rt.Default.AllowlistPrefixes,
		AllowCountries:    rt.Default.AllowCountries,
		Rules:             rt.Default.Rules,
		DefaultPolicy:     rt.Default.DefaultPolicy,
		Feedback:          rt.Default.Feedback,
		ScopeKey:          rateLimitDefaultScope,
	}
}

func pickRateLimitPolicy(scope rateLimitScopeSelection, method, path string) (rateLimitPolicy, string) {
	for _, rule := range scope.Rules {
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

	return scope.DefaultPolicy, rateLimitDefaultScope
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

func isAllowlistedCountry(scope rateLimitScopeSelection, country string) bool {
	_, ok := scope.AllowCountries[country]
	return ok
}

func isAllowlistedIP(scope rateLimitScopeSelection, ip string) bool {
	if ip == "" {
		return false
	}

	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	for _, pfx := range scope.AllowlistPrefixes {
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
	top, err := decodeRateLimitJSONObject(raw)
	if err != nil {
		return nil, err
	}

	if _, hasDefault := top["default"]; !hasDefault {
		if _, hasHosts := top["hosts"]; !hasHosts {
			scope, err := buildCompiledRateLimitScopeFromRaw(raw)
			if err != nil {
				return nil, err
			}
			return &runtimeRateLimitConfig{
				Raw: rateLimitFile{
					Default: cloneRateLimitConfig(scope.Raw),
				},
				Default: scope,
				Hosts:   map[string]compiledRateLimitScope{},
			}, nil
		}
	}

	for key := range top {
		if key != "default" && key != "hosts" {
			return nil, fmt.Errorf("invalid json")
		}
	}

	defaultObject, err := decodeRateLimitObjectValue(top["default"], "default")
	if err != nil {
		return nil, err
	}
	defaultScope, err := buildCompiledRateLimitScopeFromRaw(mustMarshalRateLimitObject(defaultObject))
	if err != nil {
		return nil, err
	}

	file := rateLimitFile{
		Default: cloneRateLimitConfig(defaultScope.Raw),
	}
	runtime := &runtimeRateLimitConfig{
		Raw:     file,
		Default: defaultScope,
		Hosts:   map[string]compiledRateLimitScope{},
	}

	hosts, err := decodeRateLimitHosts(top["hosts"])
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return runtime, nil
	}

	runtime.Raw.Hosts = make(map[string]rateLimitConfig, len(hosts))
	for rawHost, rawScope := range hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return nil, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		hostObject, err := decodeRateLimitObjectValue(rawScope, fmt.Sprintf("hosts[%q]", rawHost))
		if err != nil {
			return nil, err
		}
		mergedObject := mergeRateLimitJSONObject(defaultObject, hostObject)
		scope, err := buildCompiledRateLimitScopeFromRaw(mustMarshalRateLimitObject(mergedObject))
		if err != nil {
			return nil, err
		}
		runtime.Raw.Hosts[hostKey] = cloneRateLimitConfig(scope.Raw)
		runtime.Hosts[hostKey] = scope
	}

	return runtime, nil
}

func buildCompiledRateLimitScopeFromRaw(raw []byte) (compiledRateLimitScope, error) {
	cfg, err := decodeRateLimitConfig(raw)
	if err != nil {
		return compiledRateLimitScope{}, err
	}
	return buildCompiledRateLimitScope(cfg)
}

func decodeRateLimitConfig(raw []byte) (rateLimitConfig, error) {
	var cfg rateLimitConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return rateLimitConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return rateLimitConfig{}, fmt.Errorf("invalid json")
	}
	return cfg, nil
}

func buildCompiledRateLimitScope(cfg rateLimitConfig) (compiledRateLimitScope, error) {
	normalizeRateLimitIdentityConfig(&cfg.rateLimitIdentityConfig)
	cfg.Feedback = normalizeRateLimitFeedbackConfig(cfg.Feedback)

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
		return compiledRateLimitScope{}, err
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
			return compiledRateLimitScope{}, fmt.Errorf("invalid allowlist_ips entry: %s", entry)
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
			return compiledRateLimitScope{}, fmt.Errorf("rules[%d]: match_type is required", i)
		}
		if rule.MatchValue == "" {
			return compiledRateLimitScope{}, fmt.Errorf("rules[%d]: match_value is required", i)
		}
		switch rule.MatchType {
		case "exact", "prefix", "regex":
		default:
			return compiledRateLimitScope{}, fmt.Errorf("rules[%d]: match_type must be exact|prefix|regex", i)
		}

		policy, err := normalizeRateLimitPolicy(rule.Policy, fmt.Sprintf("rules[%d].policy", i))
		if err != nil {
			return compiledRateLimitScope{}, err
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
				return compiledRateLimitScope{}, fmt.Errorf("rules[%d]: invalid regex: %v", i, err)
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

	return compiledRateLimitScope{
		Raw:               cfg,
		AllowlistPrefixes: allowPrefixes,
		AllowCountries:    allowCountries,
		Rules:             compiledRules,
		DefaultPolicy:     defaultPolicy,
		Feedback: runtimeRateLimitFeedbackConfig{
			Enabled:         cfg.Feedback.Enabled,
			StrikesRequired: cfg.Feedback.StrikesRequired,
			StrikeWindow:    time.Duration(cfg.Feedback.StrikeWindowSeconds) * time.Second,
			AdaptiveOnly:    cfg.Feedback.AdaptiveOnly,
			DryRun:          cfg.Feedback.DryRun,
		},
	}, nil
}

func decodeRateLimitJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("rate limit config must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return obj, nil
}

func decodeRateLimitObjectValue(raw json.RawMessage, field string) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func decodeRateLimitHosts(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var out map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("hosts must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func mergeRateLimitJSONObject(base, override map[string]any) map[string]any {
	out := cloneRateLimitJSONValue(base).(map[string]any)
	for key, value := range override {
		out[key] = mergeRateLimitJSONValue(out[key], value)
	}
	return out
}

func mergeRateLimitJSONValue(base, override any) any {
	baseObject, baseOK := base.(map[string]any)
	overrideObject, overrideOK := override.(map[string]any)
	if baseOK && overrideOK {
		return mergeRateLimitJSONObject(baseObject, overrideObject)
	}
	return cloneRateLimitJSONValue(override)
}

func cloneRateLimitJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneRateLimitJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = cloneRateLimitJSONValue(item)
		}
		return out
	default:
		return typed
	}
}

func mustMarshalRateLimitObject(value map[string]any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func cloneRateLimitFile(in rateLimitFile) rateLimitFile {
	out := rateLimitFile{
		Default: cloneRateLimitConfig(in.Default),
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]rateLimitConfig, len(in.Hosts))
		for host, cfg := range in.Hosts {
			out.Hosts[host] = cloneRateLimitConfig(cfg)
		}
	}
	return out
}

func cloneRateLimitConfig(in rateLimitConfig) rateLimitConfig {
	out := in
	out.AllowlistIPs = append([]string(nil), in.AllowlistIPs...)
	out.AllowlistCountries = append([]string(nil), in.AllowlistCountries...)
	out.Rules = append([]rateLimitRule(nil), in.Rules...)
	out.SessionCookieNames = append([]string(nil), in.SessionCookieNames...)
	out.JWTHeaderNames = append([]string(nil), in.JWTHeaderNames...)
	out.JWTCookieNames = append([]string(nil), in.JWTCookieNames...)
	for index := range out.Rules {
		out.Rules[index].Methods = append([]string(nil), in.Rules[index].Methods...)
	}
	return out
}

func rateLimitScopedPolicyID(scopeKey, policyID string) string {
	scope := strings.TrimSpace(scopeKey)
	if scope == "" {
		scope = rateLimitDefaultScope
	}
	return scope + "|" + strings.TrimSpace(policyID)
}

func rateLimitEnabled(file rateLimitFile) bool {
	if file.Default.Enabled {
		return true
	}
	for _, scope := range file.Hosts {
		if scope.Enabled {
			return true
		}
	}
	return false
}

func rateLimitRuleCount(file rateLimitFile) int {
	total := len(file.Default.Rules)
	for _, scope := range file.Hosts {
		total += len(scope.Rules)
	}
	return total
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
	return os.WriteFile(path, []byte(defaultRateLimitPolicyRaw()), 0o644)
}

func defaultRateLimitPolicyRaw() string {
	return `{
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
  "feedback": {
    "enabled": false,
    "strikes_required": 3,
    "strike_window_seconds": 300,
    "adaptive_only": true,
    "dry_run": false
  },
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
}
