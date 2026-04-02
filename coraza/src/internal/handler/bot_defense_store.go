package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	botDefenseModeSuspicious  = "suspicious"
	botDefenseModeAlways      = "always"
	botDefenseActionChallenge = "challenge"
)

type botDefenseConfig struct {
	Enabled              bool                         `json:"enabled"`
	DryRun               bool                         `json:"dry_run"`
	Mode                 string                       `json:"mode"`
	PathPrefixes         []string                     `json:"path_prefixes,omitempty"`
	PathPolicies         []botDefensePathPolicyConfig `json:"path_policies,omitempty"`
	ExemptCIDRs          []string                     `json:"exempt_cidrs,omitempty"`
	SuspiciousUserAgents []string                     `json:"suspicious_user_agents,omitempty"`
	BehavioralDetection  botDefenseBehavioralConfig   `json:"behavioral_detection,omitempty"`
	ChallengeCookieName  string                       `json:"challenge_cookie_name,omitempty"`
	ChallengeSecret      string                       `json:"challenge_secret,omitempty"`
	ChallengeTTLSeconds  int                          `json:"challenge_ttl_seconds"`
	ChallengeStatusCode  int                          `json:"challenge_status_code"`
}

type botDefensePathPolicyConfig struct {
	Name                       string   `json:"name,omitempty"`
	PathPrefixes               []string `json:"path_prefixes,omitempty"`
	Mode                       string   `json:"mode,omitempty"`
	DryRun                     *bool    `json:"dry_run,omitempty"`
	RiskScoreMultiplierPercent int      `json:"risk_score_multiplier_percent,omitempty"`
	RiskScoreOffset            int      `json:"risk_score_offset,omitempty"`
}

type botDefenseBehavioralConfig struct {
	Enabled                bool `json:"enabled"`
	WindowSeconds          int  `json:"window_seconds"`
	BurstThreshold         int  `json:"burst_threshold"`
	PathFanoutThreshold    int  `json:"path_fanout_threshold"`
	UAChurnThreshold       int  `json:"ua_churn_threshold"`
	MissingCookieThreshold int  `json:"missing_cookie_threshold"`
	ScoreThreshold         int  `json:"score_threshold"`
	RiskScorePerSignal     int  `json:"risk_score_per_signal"`
}

type runtimeBotDefenseConfig struct {
	Raw             botDefenseConfig
	DryRun          bool
	Mode            string
	PathPrefixes    []string
	PathPolicies    []runtimeBotDefensePathPolicy
	ExemptPrefixes  []netip.Prefix
	SuspiciousUA    []string
	Behavioral      runtimeBotDefenseBehavioralConfig
	CookieName      string
	Secret          []byte
	ChallengeTTL    time.Duration
	ChallengeStatus int
	EphemeralSecret bool
}

type runtimeBotDefensePathPolicy struct {
	Name                       string
	PathPrefixes               []string
	Mode                       string
	DryRun                     *bool
	RiskScoreMultiplierPercent int
	RiskScoreOffset            int
}

type runtimeBotDefenseBehavioralConfig struct {
	Enabled                bool
	WindowSeconds          int
	BurstThreshold         int
	PathFanoutThreshold    int
	UAChurnThreshold       int
	MissingCookieThreshold int
	ScoreThreshold         int
	RiskScorePerSignal     int
}

type botDefenseDecision struct {
	Allowed    bool
	Action     string
	DryRun     bool
	Status     int
	Mode       string
	FlowPolicy string
	CookieName string
	Token      string
	TTLSeconds int
	RiskScore  int
	Signals    []string
}

type botDefenseBehaviorState struct {
	WindowID           int64
	RequestCount       int
	MissingCookieCount int
	Paths              map[string]struct{}
	UserAgents         map[string]struct{}
	Updated            time.Time
}

type botDefenseBehaviorSnapshot struct {
	RequestCount       int
	PathFanout         int
	UAChurn            int
	MissingCookieCount int
}

var (
	botDefenseMu      sync.RWMutex
	botDefensePath    string
	botDefenseRuntime *runtimeBotDefenseConfig
)

func InitBotDefense(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("bot defense path is empty")
	}
	if err := ensureBotDefenseFile(target); err != nil {
		return err
	}

	botDefenseMu.Lock()
	botDefensePath = target
	botDefenseMu.Unlock()

	return ReloadBotDefense()
}

func GetBotDefensePath() string {
	botDefenseMu.RLock()
	defer botDefenseMu.RUnlock()
	return botDefensePath
}

func GetBotDefenseConfig() botDefenseConfig {
	botDefenseMu.RLock()
	defer botDefenseMu.RUnlock()
	if botDefenseRuntime == nil {
		return botDefenseConfig{}
	}
	return botDefenseRuntime.Raw
}

func ReloadBotDefense() error {
	path := GetBotDefensePath()
	if path == "" {
		return fmt.Errorf("bot defense path is empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := buildBotDefenseRuntimeFromRaw(raw)
	if err != nil {
		return err
	}

	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()
	resetBotDefenseBehaviorState()

	if rt.EphemeralSecret && rt.Raw.Enabled {
		log.Printf("[BOT_DEFENSE][WARN] challenge_secret is empty; generated ephemeral secret for this process")
	}

	return nil
}

func ValidateBotDefenseRaw(raw string) (*runtimeBotDefenseConfig, error) {
	return buildBotDefenseRuntimeFromRaw([]byte(raw))
}

func EvaluateBotDefense(r *http.Request, clientIP string, now time.Time) botDefenseDecision {
	rt := currentBotDefenseRuntime()
	if rt == nil || !rt.Raw.Enabled {
		return botDefenseDecision{Allowed: true}
	}
	if r == nil || r.URL == nil {
		return botDefenseDecision{Allowed: true}
	}
	if r.Method != http.MethodGet {
		return botDefenseDecision{Allowed: true}
	}

	reqPath := strings.TrimSpace(r.URL.Path)
	if reqPath == "" {
		reqPath = "/"
	}
	if !pathMatchesAnyPrefix(rt.PathPrefixes, reqPath) {
		return botDefenseDecision{Allowed: true}
	}
	policy := matchedBotDefensePathPolicy(rt.PathPolicies, reqPath)
	effectiveMode := rt.Mode
	if policy != nil && policy.Mode != "" {
		effectiveMode = policy.Mode
	}
	effectiveDryRun := rt.DryRun
	if policy != nil && policy.DryRun != nil {
		effectiveDryRun = *policy.DryRun
	}

	clientIP = normalizeClientIP(clientIP)
	if isBotDefenseExemptIP(rt, clientIP) {
		return botDefenseDecision{Allowed: true}
	}

	userAgent := r.UserAgent()
	validCookie := hasValidBotDefenseCookie(rt, r, clientIP, userAgent, now.UTC())
	behaviorSnapshot := observeBotDefenseBehavior(rt, clientIP, reqPath, userAgent, validCookie, now.UTC())
	riskScore, signals := evaluateBotDefenseBehavior(rt, behaviorSnapshot)
	riskScore = applyBotDefensePathPolicyRisk(riskScore, policy)
	suspiciousUA := isSuspiciousUserAgent(rt.SuspiciousUA, userAgent)

	if validCookie {
		return botDefenseDecision{
			Allowed:    true,
			FlowPolicy: matchedBotDefensePolicyName(policy),
			RiskScore:  riskScore,
			Signals:    signals,
		}
	}
	if effectiveMode == botDefenseModeSuspicious && !suspiciousUA && riskScore == 0 {
		return botDefenseDecision{Allowed: true}
	}

	ttlSeconds := int(rt.ChallengeTTL.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	return botDefenseDecision{
		Allowed:    effectiveDryRun,
		Action:     botDefenseActionChallenge,
		DryRun:     effectiveDryRun,
		Status:     rt.ChallengeStatus,
		Mode:       effectiveMode,
		FlowPolicy: matchedBotDefensePolicyName(policy),
		CookieName: rt.CookieName,
		Token:      issueBotDefenseToken(rt, clientIP, userAgent, now.UTC()),
		TTLSeconds: ttlSeconds,
		RiskScore:  riskScore,
		Signals:    signals,
	}
}

func currentBotDefenseRuntime() *runtimeBotDefenseConfig {
	botDefenseMu.RLock()
	defer botDefenseMu.RUnlock()
	return botDefenseRuntime
}

func buildBotDefenseRuntimeFromRaw(raw []byte) (*runtimeBotDefenseConfig, error) {
	var cfg botDefenseConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, err
	}

	cfg.Mode = normalizeBotDefenseMode(cfg.Mode)
	if cfg.Mode == "" {
		cfg.Mode = botDefenseModeSuspicious
	}
	if cfg.Mode != botDefenseModeSuspicious && cfg.Mode != botDefenseModeAlways {
		return nil, fmt.Errorf("mode must be suspicious|always")
	}

	cfg.PathPrefixes = normalizePathPrefixes(cfg.PathPrefixes)
	if len(cfg.PathPrefixes) == 0 {
		cfg.PathPrefixes = []string{"/"}
	}
	pathPolicies, err := normalizeBotDefensePathPolicies(cfg.PathPolicies)
	if err != nil {
		return nil, err
	}
	cfg.PathPolicies = pathPolicies

	exempt, err := normalizeBotDefenseCIDRs(cfg.ExemptCIDRs)
	if err != nil {
		return nil, err
	}
	cfg.ExemptCIDRs = make([]string, 0, len(exempt))
	for _, pfx := range exempt {
		cfg.ExemptCIDRs = append(cfg.ExemptCIDRs, pfx.String())
	}

	cfg.SuspiciousUserAgents = normalizeLowerStringList(cfg.SuspiciousUserAgents)
	if len(cfg.SuspiciousUserAgents) == 0 {
		cfg.SuspiciousUserAgents = defaultSuspiciousUserAgents()
	}
	cfg.BehavioralDetection = normalizeBotDefenseBehavioralConfig(cfg.BehavioralDetection)

	cfg.ChallengeCookieName = strings.TrimSpace(cfg.ChallengeCookieName)
	if cfg.ChallengeCookieName == "" {
		cfg.ChallengeCookieName = "__tukuyomi_bot_ok"
	}
	if !isValidCookieName(cfg.ChallengeCookieName) {
		return nil, fmt.Errorf("challenge_cookie_name is invalid")
	}

	if cfg.ChallengeTTLSeconds <= 0 {
		cfg.ChallengeTTLSeconds = 24 * 60 * 60
	}
	if cfg.ChallengeStatusCode == 0 {
		cfg.ChallengeStatusCode = http.StatusTooManyRequests
	}
	if cfg.ChallengeStatusCode < 400 || cfg.ChallengeStatusCode > 599 {
		return nil, fmt.Errorf("challenge_status_code must be 400-599")
	}

	secret := []byte(strings.TrimSpace(cfg.ChallengeSecret))
	ephemeral := false
	if len(secret) == 0 {
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			secret = []byte("tukuyomi-bot-defense-ephemeral")
		}
		ephemeral = true
	}

	return &runtimeBotDefenseConfig{
		Raw:            cfg,
		DryRun:         cfg.DryRun,
		Mode:           cfg.Mode,
		PathPrefixes:   append([]string(nil), cfg.PathPrefixes...),
		PathPolicies:   buildRuntimeBotDefensePathPolicies(cfg.PathPolicies),
		ExemptPrefixes: exempt,
		SuspiciousUA:   append([]string(nil), cfg.SuspiciousUserAgents...),
		Behavioral: runtimeBotDefenseBehavioralConfig{
			Enabled:                cfg.BehavioralDetection.Enabled,
			WindowSeconds:          cfg.BehavioralDetection.WindowSeconds,
			BurstThreshold:         cfg.BehavioralDetection.BurstThreshold,
			PathFanoutThreshold:    cfg.BehavioralDetection.PathFanoutThreshold,
			UAChurnThreshold:       cfg.BehavioralDetection.UAChurnThreshold,
			MissingCookieThreshold: cfg.BehavioralDetection.MissingCookieThreshold,
			ScoreThreshold:         cfg.BehavioralDetection.ScoreThreshold,
			RiskScorePerSignal:     cfg.BehavioralDetection.RiskScorePerSignal,
		},
		CookieName:      cfg.ChallengeCookieName,
		Secret:          secret,
		ChallengeTTL:    time.Duration(cfg.ChallengeTTLSeconds) * time.Second,
		ChallengeStatus: cfg.ChallengeStatusCode,
		EphemeralSecret: ephemeral,
	}, nil
}

func normalizeBotDefenseBehavioralConfig(cfg botDefenseBehavioralConfig) botDefenseBehavioralConfig {
	if !cfg.Enabled {
		return botDefenseBehavioralConfig{}
	}
	if cfg.WindowSeconds <= 0 {
		cfg.WindowSeconds = 60
	}
	if cfg.BurstThreshold <= 0 {
		cfg.BurstThreshold = 12
	}
	if cfg.PathFanoutThreshold <= 0 {
		cfg.PathFanoutThreshold = 6
	}
	if cfg.UAChurnThreshold <= 0 {
		cfg.UAChurnThreshold = 4
	}
	if cfg.MissingCookieThreshold <= 0 {
		cfg.MissingCookieThreshold = 6
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 2
	}
	if cfg.RiskScorePerSignal <= 0 {
		cfg.RiskScorePerSignal = 2
	}
	return cfg
}

func normalizeBotDefenseMode(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func normalizeOptionalBotDefenseMode(v string) (string, error) {
	mode := strings.ToLower(strings.TrimSpace(v))
	switch mode {
	case "":
		return "", nil
	case botDefenseModeSuspicious, botDefenseModeAlways:
		return mode, nil
	default:
		return "", fmt.Errorf("path_policies.mode must be suspicious|always when set")
	}
}

func normalizeBotDefensePathPolicies(in []botDefensePathPolicyConfig) ([]botDefensePathPolicyConfig, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := make([]botDefensePathPolicyConfig, 0, len(in))
	for idx, raw := range in {
		next := raw
		next.Name = strings.TrimSpace(next.Name)
		if next.Name == "" {
			next.Name = fmt.Sprintf("policy-%d", idx+1)
		}
		next.PathPrefixes = normalizePathPrefixes(next.PathPrefixes)
		if len(next.PathPrefixes) == 0 {
			return nil, fmt.Errorf("path_policies[%d].path_prefixes must not be empty", idx)
		}
		mode, err := normalizeOptionalBotDefenseMode(next.Mode)
		if err != nil {
			return nil, err
		}
		next.Mode = mode
		if next.RiskScoreMultiplierPercent <= 0 {
			next.RiskScoreMultiplierPercent = 100
		}
		out = append(out, next)
	}
	return out, nil
}

func buildRuntimeBotDefensePathPolicies(in []botDefensePathPolicyConfig) []runtimeBotDefensePathPolicy {
	if len(in) == 0 {
		return nil
	}
	out := make([]runtimeBotDefensePathPolicy, 0, len(in))
	for _, policy := range in {
		out = append(out, runtimeBotDefensePathPolicy{
			Name:                       policy.Name,
			PathPrefixes:               append([]string(nil), policy.PathPrefixes...),
			Mode:                       policy.Mode,
			DryRun:                     policy.DryRun,
			RiskScoreMultiplierPercent: policy.RiskScoreMultiplierPercent,
			RiskScoreOffset:            policy.RiskScoreOffset,
		})
	}
	return out
}

func normalizePathPrefixes(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}
		if !strings.HasPrefix(v, "/") {
			v = "/" + v
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeLowerStringList(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		v := strings.ToLower(strings.TrimSpace(raw))
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	return out
}

func normalizeBotDefenseCIDRs(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	seen := map[string]struct{}{}
	for i, raw := range in {
		v := strings.TrimSpace(raw)
		if v == "" {
			continue
		}

		if pfx, err := netip.ParsePrefix(v); err == nil {
			if _, ok := seen[pfx.String()]; ok {
				continue
			}
			seen[pfx.String()] = struct{}{}
			out = append(out, pfx)
			continue
		}

		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, fmt.Errorf("exempt_cidrs[%d]: invalid address/CIDR: %s", i, v)
		}
		bits := 32
		if addr.Is6() {
			bits = 128
		}
		pfx := netip.PrefixFrom(addr, bits)
		if _, ok := seen[pfx.String()]; ok {
			continue
		}
		seen[pfx.String()] = struct{}{}
		out = append(out, pfx)
	}
	return out, nil
}

func defaultSuspiciousUserAgents() []string {
	return []string{
		"curl",
		"wget",
		"python-requests",
		"python-urllib",
		"go-http-client",
		"libwww-perl",
		"scrapy",
		"sqlmap",
		"nikto",
		"nmap",
		"masscan",
	}
}

func isValidCookieName(v string) bool {
	if strings.TrimSpace(v) == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		ch := v[i]
		if ch <= 0x20 || ch >= 0x7f {
			return false
		}
		switch ch {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"', '/', '[', ']', '?', '=', '{', '}', ' ':
			return false
		}
	}
	return true
}

func isBotDefenseExemptIP(rt *runtimeBotDefenseConfig, ipStr string) bool {
	if ipStr == "" || rt == nil || len(rt.ExemptPrefixes) == 0 {
		return false
	}
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false
	}
	for _, pfx := range rt.ExemptPrefixes {
		if pfx.Contains(ip) {
			return true
		}
	}
	return false
}

func isSuspiciousUserAgent(list []string, ua string) bool {
	v := strings.ToLower(strings.TrimSpace(ua))
	if v == "" {
		return true
	}
	for _, needle := range list {
		if needle != "" && strings.Contains(v, needle) {
			return true
		}
	}
	return false
}

func hasValidBotDefenseCookie(rt *runtimeBotDefenseConfig, r *http.Request, ip, userAgent string, now time.Time) bool {
	if rt == nil || r == nil {
		return false
	}
	c, err := r.Cookie(rt.CookieName)
	if err != nil {
		return false
	}
	return verifyBotDefenseToken(rt, c.Value, ip, userAgent, now)
}

func matchedBotDefensePathPolicy(policies []runtimeBotDefensePathPolicy, reqPath string) *runtimeBotDefensePathPolicy {
	if len(policies) == 0 {
		return nil
	}
	var match *runtimeBotDefensePathPolicy
	bestLen := -1
	for i := range policies {
		policy := &policies[i]
		for _, prefix := range policy.PathPrefixes {
			if prefix == "/" || strings.HasPrefix(reqPath, prefix) {
				if len(prefix) > bestLen {
					match = policy
					bestLen = len(prefix)
				}
			}
		}
	}
	return match
}

func matchedBotDefensePolicyName(policy *runtimeBotDefensePathPolicy) string {
	if policy == nil {
		return ""
	}
	return policy.Name
}

func applyBotDefensePathPolicyRisk(riskScore int, policy *runtimeBotDefensePathPolicy) int {
	if policy == nil {
		return riskScore
	}
	scaled := riskScore
	if policy.RiskScoreMultiplierPercent > 0 && policy.RiskScoreMultiplierPercent != 100 {
		scaled = (scaled*policy.RiskScoreMultiplierPercent + 50) / 100
	}
	scaled += policy.RiskScoreOffset
	if scaled < 0 {
		return 0
	}
	return scaled
}

func countBotDefensePathPoliciesDryRun(cfg botDefenseConfig) int {
	if len(cfg.PathPolicies) == 0 {
		return 0
	}
	count := 0
	for _, policy := range cfg.PathPolicies {
		if policy.DryRun != nil && *policy.DryRun {
			count++
		}
	}
	return count
}

func acceptsHTML(rawAccept string) bool {
	v := strings.ToLower(strings.TrimSpace(rawAccept))
	if v == "" {
		return false
	}
	return strings.Contains(v, "text/html") || strings.Contains(v, "*/*")
}

func pathMatchesAnyPrefix(prefixes []string, path string) bool {
	if path == "" {
		path = "/"
	}
	for _, pfx := range prefixes {
		if pfx == "/" || strings.HasPrefix(path, pfx) {
			return true
		}
	}
	return false
}

func ensureBotDefenseFile(path string) error {
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
  "dry_run": false,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "path_policies": [],
  "exempt_cidrs": [
    "127.0.0.1/32",
    "::1/128",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "fc00::/7"
  ],
  "suspicious_user_agents": [
    "curl",
    "wget",
    "python-requests",
    "python-urllib",
    "go-http-client",
    "libwww-perl",
    "scrapy",
    "headless",
    "selenium",
    "puppeteer",
    "playwright",
    "sqlmap",
    "nikto",
    "nmap",
    "masscan"
  ],
  "behavioral_detection": {
    "enabled": false,
    "window_seconds": 60,
    "burst_threshold": 12,
    "path_fanout_threshold": 6,
    "ua_churn_threshold": 4,
    "missing_cookie_threshold": 6,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "",
  "challenge_ttl_seconds": 21600,
  "challenge_status_code": 429
}
`
	return os.WriteFile(path, []byte(defaultRaw), 0o644)
}
