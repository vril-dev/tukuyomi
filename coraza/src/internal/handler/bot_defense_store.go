package handler

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/policyhost"
)

const (
	botDefenseModeSuspicious            = "suspicious"
	botDefenseModeAlways                = "always"
	botDefenseActionChallenge           = "challenge"
	botDefenseActionQuarantine          = "quarantine"
	botDefenseChallengeOutcomeIssued    = "issued"
	botDefenseChallengeOutcomePassed    = "passed"
	botDefenseChallengeOutcomeFailed    = "failed"
	botDefenseCookieStateMissing        = "missing"
	botDefenseCookieStateValid          = "valid"
	botDefenseCookieStateInvalid        = "invalid"
	defaultBotDefenseInvisibleBodyBytes = int64(256 * 1024)
	botDefenseDefaultScope              = "default"
)

type botDefenseConfig struct {
	Enabled                  bool                                     `json:"enabled"`
	DryRun                   bool                                     `json:"dry_run"`
	Mode                     string                                   `json:"mode"`
	PathPrefixes             []string                                 `json:"path_prefixes,omitempty"`
	PathPolicies             []botDefensePathPolicyConfig             `json:"path_policies,omitempty"`
	ExemptCIDRs              []string                                 `json:"exempt_cidrs,omitempty"`
	SuspiciousUserAgents     []string                                 `json:"suspicious_user_agents,omitempty"`
	BehavioralDetection      botDefenseBehavioralConfig               `json:"behavioral_detection,omitempty"`
	BrowserSignals           botDefenseBrowserSignalsConfig           `json:"browser_signals,omitempty"`
	DeviceSignals            botDefenseDeviceSignalsConfig            `json:"device_signals,omitempty"`
	HeaderSignals            botDefenseHeaderSignalsConfig            `json:"header_signals,omitempty"`
	TLSSignals               botDefenseTLSSignalsConfig               `json:"tls_signals,omitempty"`
	Quarantine               botDefenseQuarantineConfig               `json:"quarantine,omitempty"`
	ChallengeFailureFeedback botDefenseChallengeFailureFeedbackConfig `json:"challenge_failure_feedback,omitempty"`
	ChallengeCookieName      string                                   `json:"challenge_cookie_name,omitempty"`
	ChallengeSecret          string                                   `json:"challenge_secret,omitempty"`
	ChallengeTTLSeconds      int                                      `json:"challenge_ttl_seconds"`
	ChallengeStatusCode      int                                      `json:"challenge_status_code"`
}

type botDefenseFile struct {
	Default botDefenseConfig            `json:"default"`
	Hosts   map[string]botDefenseConfig `json:"hosts,omitempty"`
}

type botDefensePathPolicyConfig struct {
	Name                       string   `json:"name,omitempty"`
	PathPrefixes               []string `json:"path_prefixes,omitempty"`
	Mode                       string   `json:"mode,omitempty"`
	DryRun                     *bool    `json:"dry_run,omitempty"`
	RiskScoreMultiplierPercent int      `json:"risk_score_multiplier_percent,omitempty"`
	RiskScoreOffset            int      `json:"risk_score_offset,omitempty"`
	TelemetryCookieRequired    bool     `json:"telemetry_cookie_required,omitempty"`
	DisableQuarantine          bool     `json:"disable_quarantine,omitempty"`
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

type botDefenseBrowserSignalsConfig struct {
	Enabled            bool   `json:"enabled"`
	JSCookieName       string `json:"js_cookie_name,omitempty"`
	ScoreThreshold     int    `json:"score_threshold"`
	RiskScorePerSignal int    `json:"risk_score_per_signal"`
}

type botDefenseDeviceSignalsConfig struct {
	Enabled                    bool  `json:"enabled"`
	RequireTimeZone            bool  `json:"require_time_zone"`
	RequirePlatform            bool  `json:"require_platform"`
	RequireHardwareConcurrency bool  `json:"require_hardware_concurrency"`
	CheckMobileTouch           bool  `json:"check_mobile_touch"`
	InvisibleHTMLInjection     bool  `json:"invisible_html_injection"`
	InvisibleMaxBodyBytes      int64 `json:"invisible_max_body_bytes,omitempty"`
	ScoreThreshold             int   `json:"score_threshold"`
	RiskScorePerSignal         int   `json:"risk_score_per_signal"`
}

type botDefenseHeaderSignalsConfig struct {
	Enabled                bool `json:"enabled"`
	RequireAcceptLanguage  bool `json:"require_accept_language"`
	RequireFetchMetadata   bool `json:"require_fetch_metadata"`
	RequireClientHints     bool `json:"require_client_hints"`
	RequireUpgradeInsecure bool `json:"require_upgrade_insecure_requests"`
	ScoreThreshold         int  `json:"score_threshold"`
	RiskScorePerSignal     int  `json:"risk_score_per_signal"`
}

type botDefenseTLSSignalsConfig struct {
	Enabled            bool `json:"enabled"`
	RequireSNI         bool `json:"require_sni"`
	RequireALPN        bool `json:"require_alpn"`
	RequireModernTLS   bool `json:"require_modern_tls"`
	ScoreThreshold     int  `json:"score_threshold"`
	RiskScorePerSignal int  `json:"risk_score_per_signal"`
}

type botDefenseQuarantineConfig struct {
	Enabled                   bool `json:"enabled"`
	Threshold                 int  `json:"threshold"`
	StrikesRequired           int  `json:"strikes_required"`
	StrikeWindowSeconds       int  `json:"strike_window_seconds"`
	TTLSeconds                int  `json:"ttl_seconds"`
	StatusCode                int  `json:"status_code"`
	ReputationFeedbackSeconds int  `json:"reputation_feedback_seconds"`
}

type runtimeBotDefenseConfig struct {
	File                     botDefenseFile
	Raw                      botDefenseConfig
	DryRun                   bool
	Mode                     string
	PathPrefixes             []string
	PathPolicies             []runtimeBotDefensePathPolicy
	ExemptPrefixes           []netip.Prefix
	SuspiciousUA             []string
	Behavioral               runtimeBotDefenseBehavioralConfig
	BrowserSignals           runtimeBotDefenseBrowserSignalsConfig
	DeviceSignals            runtimeBotDefenseDeviceSignalsConfig
	HeaderSignals            runtimeBotDefenseHeaderSignalsConfig
	TLSSignals               runtimeBotDefenseTLSSignalsConfig
	Quarantine               runtimeBotDefenseQuarantineConfig
	ChallengeFailureFeedback runtimeBotDefenseChallengeFailureFeedbackConfig
	CookieName               string
	Secret                   []byte
	ChallengeTTL             time.Duration
	ChallengeStatus          int
	EphemeralSecret          bool
	Hosts                    map[string]*runtimeBotDefenseConfig
}

type runtimeBotDefensePathPolicy struct {
	Name                       string
	PathPrefixes               []string
	Mode                       string
	DryRun                     *bool
	RiskScoreMultiplierPercent int
	RiskScoreOffset            int
	TelemetryCookieRequired    bool
	DisableQuarantine          bool
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

type runtimeBotDefenseBrowserSignalsConfig struct {
	Enabled            bool
	JSCookieName       string
	ScoreThreshold     int
	RiskScorePerSignal int
}

type runtimeBotDefenseDeviceSignalsConfig struct {
	Enabled                    bool
	RequireTimeZone            bool
	RequirePlatform            bool
	RequireHardwareConcurrency bool
	CheckMobileTouch           bool
	InvisibleHTMLInjection     bool
	InvisibleMaxBodyBytes      int64
	ScoreThreshold             int
	RiskScorePerSignal         int
}

type runtimeBotDefenseHeaderSignalsConfig struct {
	Enabled                bool
	RequireAcceptLanguage  bool
	RequireFetchMetadata   bool
	RequireClientHints     bool
	RequireUpgradeInsecure bool
	ScoreThreshold         int
	RiskScorePerSignal     int
}

type runtimeBotDefenseTLSSignalsConfig struct {
	Enabled            bool
	RequireSNI         bool
	RequireALPN        bool
	RequireModernTLS   bool
	ScoreThreshold     int
	RiskScorePerSignal int
}

type runtimeBotDefenseQuarantineConfig struct {
	Enabled            bool
	Threshold          int
	StrikesRequired    int
	StrikeWindow       time.Duration
	TTL                time.Duration
	StatusCode         int
	ReputationFeedback time.Duration
}

type botDefenseDecision struct {
	Allowed                 bool
	Action                  string
	DryRun                  bool
	Status                  int
	Mode                    string
	HostScope               string
	FlowPolicy              string
	CookieName              string
	BrowserCookieName       string
	Token                   string
	TTLSeconds              int
	RiskScore               int
	Signals                 []string
	ChallengeOutcome        string
	ChallengeFailureReason  string
	TelemetryCookieRequired bool
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

type botDefenseBrowserSignalCookie struct {
	WebDriver           bool   `json:"wd"`
	LanguageCount       int    `json:"lc"`
	ScreenWidth         int    `json:"sw"`
	ScreenHeight        int    `json:"sh"`
	TimeZone            string `json:"tz"`
	Platform            string `json:"pf"`
	HardwareConcurrency int    `json:"hc"`
	MaxTouchPoints      int    `json:"mt"`
}

type botDefenseQuarantineState struct {
	Strikes      int
	WindowEnd    time.Time
	BlockedUntil time.Time
}

type botDefenseFeatureSummary struct {
	Enabled                    bool
	DryRunEnabled              bool
	PathPolicyCount            int
	PathPolicyDryRunCount      int
	BehavioralEnabled          bool
	BrowserSignalsEnabled      bool
	DeviceSignalsEnabled       bool
	DeviceInvisibleEnabled     bool
	HeaderSignalsEnabled       bool
	TLSSignalsEnabled          bool
	QuarantineEnabled          bool
	ChallengeFailureFeedbackOn bool
	HostScopeCount             int
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
	botDefenseMu.Lock()
	botDefensePath = target
	botDefenseMu.Unlock()

	if store := getLogsStatsStore(); store != nil {
		raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(botDefenseConfigBlobKey), normalizeBotDefensePolicyRaw, "bot defense rules")
		if err != nil {
			return fmt.Errorf("read bot defense config db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized bot defense config missing in db; run make db-import before removing seed files")
		}
		return applyBotDefensePolicyRaw(raw)
	}

	if err := ensureBotDefenseFile(target); err != nil {
		return err
	}

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

func GetBotDefenseFile() botDefenseFile {
	botDefenseMu.RLock()
	defer botDefenseMu.RUnlock()
	if botDefenseRuntime == nil {
		return botDefenseFile{}
	}
	return cloneBotDefenseFile(botDefenseRuntime.File)
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
	resetBotDefenseQuarantineState()
	resetBotDefenseChallengeState()

	if botDefenseHasEnabledEphemeralSecret(rt) {
		log.Printf("[BOT_DEFENSE][WARN] challenge_secret is empty; generated ephemeral secret for this process")
	}

	return nil
}

func ValidateBotDefenseRaw(raw string) (*runtimeBotDefenseConfig, error) {
	return buildBotDefenseRuntimeFromRaw([]byte(raw))
}

func EvaluateBotDefense(r *http.Request, clientIP string, now time.Time) botDefenseDecision {
	rt := currentBotDefenseRuntime()
	if rt == nil {
		return botDefenseDecision{Allowed: true}
	}
	if r == nil || r.URL == nil {
		return botDefenseDecision{Allowed: true}
	}
	scopeRT, scopeKey := selectBotDefenseRuntime(rt, r)
	if scopeRT == nil || !scopeRT.Raw.Enabled {
		return botDefenseDecision{Allowed: true}
	}
	if r.Method != http.MethodGet {
		return botDefenseDecision{Allowed: true}
	}

	reqPath := strings.TrimSpace(r.URL.Path)
	if reqPath == "" {
		reqPath = "/"
	}
	if !pathMatchesAnyPrefix(scopeRT.PathPrefixes, reqPath) {
		return botDefenseDecision{Allowed: true}
	}
	policy := matchedBotDefensePathPolicy(scopeRT.PathPolicies, reqPath)
	effectiveMode := scopeRT.Mode
	if policy != nil && policy.Mode != "" {
		effectiveMode = policy.Mode
	}
	effectiveDryRun := scopeRT.DryRun
	if policy != nil && policy.DryRun != nil {
		effectiveDryRun = *policy.DryRun
	}

	clientIP = normalizeClientIP(clientIP)
	if isBotDefenseExemptIP(scopeRT, clientIP) {
		return botDefenseDecision{Allowed: true}
	}
	if quarantined, status, until := botDefenseQuarantineStatusForScope(scopeKey, scopeRT, clientIP, now.UTC()); quarantined {
		return botDefenseDecision{
			Allowed:    effectiveDryRun,
			Action:     botDefenseActionQuarantine,
			DryRun:     effectiveDryRun,
			Status:     status,
			Mode:       effectiveMode,
			HostScope:  scopeKey,
			FlowPolicy: matchedBotDefensePolicyName(policy),
			Signals:    []string{"quarantine_active_until:" + until.Format(time.RFC3339)},
		}
	}

	userAgent := r.UserAgent()
	challengeState, hasChallengeState := currentBotDefenseChallengeState(scopeKey, clientIP, userAgent, now.UTC())
	challengeCookieState := botDefenseChallengeCookieState(scopeRT, r, clientIP, userAgent, now.UTC())
	validCookie := challengeCookieState == botDefenseCookieStateValid
	behaviorSnapshot := observeBotDefenseBehaviorForScope(scopeKey, scopeRT, clientIP, reqPath, userAgent, validCookie, now.UTC())
	behavioralRiskScore, behavioralSignals := evaluateBotDefenseBehavior(scopeRT, behaviorSnapshot)
	browserRiskScore, browserSignals := evaluateBotDefenseBrowserSignals(scopeRT, r, validCookie)
	deviceRiskScore, deviceSignals := evaluateBotDefenseDeviceSignals(scopeRT, r)
	headerRiskScore, headerSignals := evaluateBotDefenseHeaderSignals(scopeRT, r)
	tlsRiskScore, tlsSignals := evaluateBotDefenseTLSSignals(scopeRT, r)
	riskScore := behavioralRiskScore + browserRiskScore + deviceRiskScore + headerRiskScore + tlsRiskScore
	signals := append(append(append(append(append([]string(nil), behavioralSignals...), browserSignals...), deviceSignals...), headerSignals...), tlsSignals...)
	forceChallenge := false
	flowPolicy := matchedBotDefensePolicyName(policy)
	telemetryRequired := policy != nil && policy.TelemetryCookieRequired && looksLikeBrowserRequest(r)
	if hasChallengeState {
		if challengeState.TelemetryRequired {
			telemetryRequired = true
		}
		if flowPolicy == "" && strings.TrimSpace(challengeState.FlowPolicy) != "" {
			flowPolicy = challengeState.FlowPolicy
		}
	}
	telemetryCookieState := botDefenseTelemetryCookieState(scopeRT, r)
	if telemetryRequired && telemetryCookieState != botDefenseCookieStateValid {
		signals = append(signals, "flow_telemetry_missing")
		riskScore += maxBotDefenseRiskWeight(scopeRT)
		forceChallenge = true
	}
	riskScore = applyBotDefensePathPolicyRisk(riskScore, policy)
	suspiciousUA := isSuspiciousUserAgent(scopeRT.SuspiciousUA, userAgent)
	quarantineTriggered := false
	if !effectiveDryRun && (policy == nil || !policy.DisableQuarantine) {
		quarantineTriggered = maybeEscalateBotDefenseQuarantineForScope(scopeKey, scopeRT, clientIP, riskScore, now.UTC())
	}
	challengeOutcome := ""
	challengeFailureReason := ""
	if hasChallengeState {
		switch {
		case validCookie && !forceChallenge:
			challengeOutcome = botDefenseChallengeOutcomePassed
			clearBotDefenseChallengeState(scopeKey, clientIP, userAgent)
		case challengeCookieState == botDefenseCookieStateInvalid:
			challengeOutcome = botDefenseChallengeOutcomeFailed
			challengeFailureReason = "challenge_cookie_invalid"
		case telemetryRequired && telemetryCookieState == botDefenseCookieStateInvalid:
			challengeOutcome = botDefenseChallengeOutcomeFailed
			challengeFailureReason = "telemetry_cookie_invalid"
		case telemetryRequired && telemetryCookieState == botDefenseCookieStateMissing:
			challengeOutcome = botDefenseChallengeOutcomeFailed
			challengeFailureReason = "telemetry_cookie_missing_after_challenge"
		case challengeCookieState == botDefenseCookieStateMissing:
			challengeOutcome = botDefenseChallengeOutcomeFailed
			challengeFailureReason = "challenge_cookie_missing_after_issue"
		}
		if challengeFailureReason == "" && challengeOutcome == botDefenseChallengeOutcomeFailed && strings.TrimSpace(challengeState.FlowPolicy) != "" && flowPolicy == "" {
			flowPolicy = challengeState.FlowPolicy
		}
	}
	if validCookie {
		if quarantineTriggered {
			if scopeRT.Quarantine.ReputationFeedback > 0 {
				_ = ApplyIPReputationPenaltyForRequest(r, clientIP, scopeRT.Quarantine.ReputationFeedback, now.UTC())
			}
			return botDefenseDecision{
				Allowed:                 effectiveDryRun,
				Action:                  botDefenseActionQuarantine,
				DryRun:                  effectiveDryRun,
				Status:                  scopeRT.Quarantine.StatusCode,
				Mode:                    effectiveMode,
				HostScope:               scopeKey,
				FlowPolicy:              flowPolicy,
				RiskScore:               riskScore,
				Signals:                 append(signals, "quarantine_triggered"),
				ChallengeOutcome:        challengeOutcome,
				ChallengeFailureReason:  challengeFailureReason,
				TelemetryCookieRequired: telemetryRequired,
			}
		}
		if forceChallenge {
			ttlSeconds := int(scopeRT.ChallengeTTL.Seconds())
			if ttlSeconds < 1 {
				ttlSeconds = 1
			}
			return botDefenseDecision{
				Allowed:                 effectiveDryRun,
				Action:                  botDefenseActionChallenge,
				DryRun:                  effectiveDryRun,
				Status:                  scopeRT.ChallengeStatus,
				Mode:                    effectiveMode,
				HostScope:               scopeKey,
				FlowPolicy:              flowPolicy,
				CookieName:              scopeRT.CookieName,
				BrowserCookieName:       scopeRT.BrowserSignals.JSCookieName,
				Token:                   issueBotDefenseToken(scopeRT, clientIP, userAgent, now.UTC()),
				TTLSeconds:              ttlSeconds,
				RiskScore:               riskScore,
				Signals:                 signals,
				ChallengeOutcome:        challengeOutcome,
				ChallengeFailureReason:  challengeFailureReason,
				TelemetryCookieRequired: telemetryRequired,
			}
		}
		return botDefenseDecision{
			Allowed:                 true,
			HostScope:               scopeKey,
			FlowPolicy:              flowPolicy,
			RiskScore:               riskScore,
			Signals:                 signals,
			ChallengeOutcome:        challengeOutcome,
			ChallengeFailureReason:  challengeFailureReason,
			TelemetryCookieRequired: telemetryRequired,
		}
	}
	if effectiveMode == botDefenseModeSuspicious && !suspiciousUA && riskScore == 0 && !forceChallenge {
		return botDefenseDecision{Allowed: true}
	}

	ttlSeconds := int(scopeRT.ChallengeTTL.Seconds())
	if ttlSeconds < 1 {
		ttlSeconds = 1
	}
	if quarantineTriggered {
		if scopeRT.Quarantine.ReputationFeedback > 0 {
			_ = ApplyIPReputationPenaltyForRequest(r, clientIP, scopeRT.Quarantine.ReputationFeedback, now.UTC())
		}
		return botDefenseDecision{
			Allowed:                 effectiveDryRun,
			Action:                  botDefenseActionQuarantine,
			DryRun:                  effectiveDryRun,
			Status:                  scopeRT.Quarantine.StatusCode,
			Mode:                    effectiveMode,
			HostScope:               scopeKey,
			FlowPolicy:              flowPolicy,
			RiskScore:               riskScore,
			Signals:                 append(signals, "quarantine_triggered"),
			ChallengeOutcome:        challengeOutcome,
			ChallengeFailureReason:  challengeFailureReason,
			TelemetryCookieRequired: telemetryRequired,
		}
	}
	return botDefenseDecision{
		Allowed:                 effectiveDryRun,
		Action:                  botDefenseActionChallenge,
		DryRun:                  effectiveDryRun,
		Status:                  scopeRT.ChallengeStatus,
		Mode:                    effectiveMode,
		HostScope:               scopeKey,
		FlowPolicy:              flowPolicy,
		CookieName:              scopeRT.CookieName,
		BrowserCookieName:       scopeRT.BrowserSignals.JSCookieName,
		Token:                   issueBotDefenseToken(scopeRT, clientIP, userAgent, now.UTC()),
		TTLSeconds:              ttlSeconds,
		RiskScore:               riskScore,
		Signals:                 signals,
		ChallengeOutcome:        challengeOutcome,
		ChallengeFailureReason:  challengeFailureReason,
		TelemetryCookieRequired: telemetryRequired,
	}
}

func currentBotDefenseRuntime() *runtimeBotDefenseConfig {
	botDefenseMu.RLock()
	defer botDefenseMu.RUnlock()
	return botDefenseRuntime
}

func selectBotDefenseRuntime(rt *runtimeBotDefenseConfig, req *http.Request) (*runtimeBotDefenseConfig, string) {
	if rt == nil {
		return nil, botDefenseDefaultScope
	}
	if req != nil {
		return selectBotDefenseRuntimeForHost(rt, req.Host, req.TLS != nil)
	}
	return rt, botDefenseDefaultScope
}

func selectBotDefenseRuntimeForHost(rt *runtimeBotDefenseConfig, host string, tls bool) (*runtimeBotDefenseConfig, string) {
	if rt == nil {
		return nil, botDefenseDefaultScope
	}
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := rt.Hosts[candidate]; ok {
			return scope, candidate
		}
	}
	return rt, botDefenseDefaultScope
}

func selectBotDefenseRuntimeByScopeKey(rt *runtimeBotDefenseConfig, scopeKey string) *runtimeBotDefenseConfig {
	if rt == nil {
		return nil
	}
	scope := strings.TrimSpace(scopeKey)
	if scope == "" || scope == botDefenseDefaultScope {
		return rt
	}
	if candidate, ok := rt.Hosts[scope]; ok {
		return candidate
	}
	return rt
}

func botDefenseHasEnabledEphemeralSecret(rt *runtimeBotDefenseConfig) bool {
	if rt == nil {
		return false
	}
	if rt.EphemeralSecret && rt.Raw.Enabled {
		return true
	}
	for _, scope := range rt.Hosts {
		if scope != nil && scope.EphemeralSecret && scope.Raw.Enabled {
			return true
		}
	}
	return false
}

func botDefenseEnabled(file botDefenseFile) bool {
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

func buildBotDefenseRuntimeFromRaw(raw []byte) (*runtimeBotDefenseConfig, error) {
	top, err := decodeBotDefenseJSONObject(raw)
	if err != nil {
		return nil, err
	}

	if _, hasDefault := top["default"]; !hasDefault {
		if _, hasHosts := top["hosts"]; !hasHosts {
			rt, err := buildSingleBotDefenseRuntimeFromRaw(raw)
			if err != nil {
				return nil, err
			}
			rt.File = botDefenseFile{Default: cloneBotDefenseConfig(rt.Raw)}
			rt.Hosts = map[string]*runtimeBotDefenseConfig{}
			return rt, nil
		}
	}

	for key := range top {
		if key != "default" && key != "hosts" {
			return nil, fmt.Errorf("invalid json")
		}
	}

	defaultObject, err := decodeBotDefenseObjectValue(top["default"], "default")
	if err != nil {
		return nil, err
	}
	rt, err := buildSingleBotDefenseRuntimeFromRaw(mustMarshalBotDefenseObject(defaultObject))
	if err != nil {
		return nil, err
	}
	rt.File = botDefenseFile{Default: cloneBotDefenseConfig(rt.Raw)}
	rt.Hosts = map[string]*runtimeBotDefenseConfig{}

	hosts, err := decodeBotDefenseHosts(top["hosts"])
	if err != nil {
		return nil, err
	}
	if len(hosts) == 0 {
		return rt, nil
	}
	rt.File.Hosts = make(map[string]botDefenseConfig, len(hosts))
	for rawHost, rawScope := range hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return nil, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		hostObject, err := decodeBotDefenseObjectValue(rawScope, fmt.Sprintf("hosts[%q]", rawHost))
		if err != nil {
			return nil, err
		}
		mergedObject := mergeBotDefenseJSONObject(defaultObject, hostObject)
		scopeRT, err := buildSingleBotDefenseRuntimeFromRaw(mustMarshalBotDefenseObject(mergedObject))
		if err != nil {
			return nil, err
		}
		rt.File.Hosts[hostKey] = cloneBotDefenseConfig(scopeRT.Raw)
		rt.Hosts[hostKey] = scopeRT
	}
	return rt, nil
}

func buildSingleBotDefenseRuntimeFromRaw(raw []byte) (*runtimeBotDefenseConfig, error) {
	cfg, err := decodeBotDefenseConfig(raw)
	if err != nil {
		return nil, err
	}
	return buildSingleBotDefenseRuntime(cfg)
}

func buildSingleBotDefenseRuntime(cfg botDefenseConfig) (*runtimeBotDefenseConfig, error) {
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
	cfg.BrowserSignals = normalizeBotDefenseBrowserSignalsConfig(cfg.BrowserSignals)
	cfg.DeviceSignals = normalizeBotDefenseDeviceSignalsConfig(cfg.DeviceSignals)
	cfg.HeaderSignals = normalizeBotDefenseHeaderSignalsConfig(cfg.HeaderSignals)
	cfg.TLSSignals = normalizeBotDefenseTLSSignalsConfig(cfg.TLSSignals)
	cfg.Quarantine = normalizeBotDefenseQuarantineConfig(cfg.Quarantine)
	cfg.ChallengeFailureFeedback = normalizeBotDefenseChallengeFailureFeedbackConfig(cfg.ChallengeFailureFeedback)

	cfg.ChallengeCookieName = strings.TrimSpace(cfg.ChallengeCookieName)
	if cfg.ChallengeCookieName == "" {
		cfg.ChallengeCookieName = "__tukuyomi_bot_ok"
	}
	if !isValidCookieName(cfg.ChallengeCookieName) {
		return nil, fmt.Errorf("challenge_cookie_name is invalid")
	}
	if cfg.BrowserSignals.Enabled || cfg.DeviceSignals.Enabled {
		if strings.TrimSpace(cfg.BrowserSignals.JSCookieName) == "" {
			cfg.BrowserSignals.JSCookieName = "__tukuyomi_bot_js"
		}
		if !isValidCookieName(cfg.BrowserSignals.JSCookieName) {
			return nil, fmt.Errorf("browser_signals.js_cookie_name is invalid")
		}
		if cfg.BrowserSignals.JSCookieName == cfg.ChallengeCookieName {
			return nil, fmt.Errorf("browser_signals.js_cookie_name must differ from challenge_cookie_name")
		}
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
		BrowserSignals: runtimeBotDefenseBrowserSignalsConfig{
			Enabled:            cfg.BrowserSignals.Enabled,
			JSCookieName:       cfg.BrowserSignals.JSCookieName,
			ScoreThreshold:     cfg.BrowserSignals.ScoreThreshold,
			RiskScorePerSignal: cfg.BrowserSignals.RiskScorePerSignal,
		},
		DeviceSignals: runtimeBotDefenseDeviceSignalsConfig{
			Enabled:                    cfg.DeviceSignals.Enabled,
			RequireTimeZone:            cfg.DeviceSignals.RequireTimeZone,
			RequirePlatform:            cfg.DeviceSignals.RequirePlatform,
			RequireHardwareConcurrency: cfg.DeviceSignals.RequireHardwareConcurrency,
			CheckMobileTouch:           cfg.DeviceSignals.CheckMobileTouch,
			InvisibleHTMLInjection:     cfg.DeviceSignals.InvisibleHTMLInjection,
			InvisibleMaxBodyBytes:      cfg.DeviceSignals.InvisibleMaxBodyBytes,
			ScoreThreshold:             cfg.DeviceSignals.ScoreThreshold,
			RiskScorePerSignal:         cfg.DeviceSignals.RiskScorePerSignal,
		},
		HeaderSignals: runtimeBotDefenseHeaderSignalsConfig{
			Enabled:                cfg.HeaderSignals.Enabled,
			RequireAcceptLanguage:  cfg.HeaderSignals.RequireAcceptLanguage,
			RequireFetchMetadata:   cfg.HeaderSignals.RequireFetchMetadata,
			RequireClientHints:     cfg.HeaderSignals.RequireClientHints,
			RequireUpgradeInsecure: cfg.HeaderSignals.RequireUpgradeInsecure,
			ScoreThreshold:         cfg.HeaderSignals.ScoreThreshold,
			RiskScorePerSignal:     cfg.HeaderSignals.RiskScorePerSignal,
		},
		TLSSignals: runtimeBotDefenseTLSSignalsConfig{
			Enabled:            cfg.TLSSignals.Enabled,
			RequireSNI:         cfg.TLSSignals.RequireSNI,
			RequireALPN:        cfg.TLSSignals.RequireALPN,
			RequireModernTLS:   cfg.TLSSignals.RequireModernTLS,
			ScoreThreshold:     cfg.TLSSignals.ScoreThreshold,
			RiskScorePerSignal: cfg.TLSSignals.RiskScorePerSignal,
		},
		Quarantine: runtimeBotDefenseQuarantineConfig{
			Enabled:            cfg.Quarantine.Enabled,
			Threshold:          cfg.Quarantine.Threshold,
			StrikesRequired:    cfg.Quarantine.StrikesRequired,
			StrikeWindow:       time.Duration(cfg.Quarantine.StrikeWindowSeconds) * time.Second,
			TTL:                time.Duration(cfg.Quarantine.TTLSeconds) * time.Second,
			StatusCode:         cfg.Quarantine.StatusCode,
			ReputationFeedback: time.Duration(cfg.Quarantine.ReputationFeedbackSeconds) * time.Second,
		},
		ChallengeFailureFeedback: runtimeBotDefenseChallengeFailureFeedbackConfig{
			Enabled:            cfg.ChallengeFailureFeedback.Enabled,
			ReputationFeedback: time.Duration(cfg.ChallengeFailureFeedback.ReputationFeedback) * time.Second,
		},
		CookieName:      cfg.ChallengeCookieName,
		Secret:          secret,
		ChallengeTTL:    time.Duration(cfg.ChallengeTTLSeconds) * time.Second,
		ChallengeStatus: cfg.ChallengeStatusCode,
		EphemeralSecret: ephemeral,
		Hosts:           map[string]*runtimeBotDefenseConfig{},
	}, nil
}

func decodeBotDefenseConfig(raw []byte) (botDefenseConfig, error) {
	var cfg botDefenseConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return botDefenseConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return botDefenseConfig{}, fmt.Errorf("invalid json")
	}
	return cfg, nil
}

func decodeBotDefenseJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("bot defense config must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return obj, nil
}

func decodeBotDefenseObjectValue(raw json.RawMessage, field string) (map[string]any, error) {
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

func decodeBotDefenseHosts(raw json.RawMessage) (map[string]json.RawMessage, error) {
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

func mergeBotDefenseJSONObject(base, override map[string]any) map[string]any {
	out := cloneBotDefenseJSONValue(base).(map[string]any)
	for key, value := range override {
		out[key] = mergeBotDefenseJSONValue(out[key], value)
	}
	return out
}

func mergeBotDefenseJSONValue(base, override any) any {
	baseObject, baseOK := base.(map[string]any)
	overrideObject, overrideOK := override.(map[string]any)
	if baseOK && overrideOK {
		return mergeBotDefenseJSONObject(baseObject, overrideObject)
	}
	return cloneBotDefenseJSONValue(override)
}

func cloneBotDefenseJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneBotDefenseJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = cloneBotDefenseJSONValue(item)
		}
		return out
	default:
		return typed
	}
}

func mustMarshalBotDefenseObject(value map[string]any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func cloneBotDefenseFile(in botDefenseFile) botDefenseFile {
	out := botDefenseFile{
		Default: cloneBotDefenseConfig(in.Default),
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]botDefenseConfig, len(in.Hosts))
		for host, cfg := range in.Hosts {
			out.Hosts[host] = cloneBotDefenseConfig(cfg)
		}
	}
	return out
}

func cloneBotDefenseConfig(in botDefenseConfig) botDefenseConfig {
	out := in
	out.PathPrefixes = append([]string(nil), in.PathPrefixes...)
	if len(in.PathPolicies) > 0 {
		out.PathPolicies = make([]botDefensePathPolicyConfig, len(in.PathPolicies))
		for index, policy := range in.PathPolicies {
			next := policy
			next.PathPrefixes = append([]string(nil), policy.PathPrefixes...)
			if policy.DryRun != nil {
				dryRun := *policy.DryRun
				next.DryRun = &dryRun
			}
			out.PathPolicies[index] = next
		}
	}
	out.ExemptCIDRs = append([]string(nil), in.ExemptCIDRs...)
	out.SuspiciousUserAgents = append([]string(nil), in.SuspiciousUserAgents...)
	return out
}

func summarizeBotDefenseFile(file botDefenseFile) botDefenseFeatureSummary {
	summary := botDefenseFeatureSummary{
		HostScopeCount: len(file.Hosts),
	}
	visit := func(cfg botDefenseConfig) {
		if cfg.Enabled {
			summary.Enabled = true
		}
		if cfg.DryRun {
			summary.DryRunEnabled = true
		}
		summary.PathPolicyCount += len(cfg.PathPolicies)
		summary.PathPolicyDryRunCount += countBotDefensePathPoliciesDryRun(cfg)
		if cfg.BehavioralDetection.Enabled {
			summary.BehavioralEnabled = true
		}
		if cfg.BrowserSignals.Enabled {
			summary.BrowserSignalsEnabled = true
		}
		if cfg.DeviceSignals.Enabled {
			summary.DeviceSignalsEnabled = true
		}
		if cfg.DeviceSignals.Enabled && cfg.DeviceSignals.InvisibleHTMLInjection {
			summary.DeviceInvisibleEnabled = true
		}
		if cfg.HeaderSignals.Enabled {
			summary.HeaderSignalsEnabled = true
		}
		if cfg.TLSSignals.Enabled {
			summary.TLSSignalsEnabled = true
		}
		if cfg.Quarantine.Enabled {
			summary.QuarantineEnabled = true
		}
		if cfg.ChallengeFailureFeedback.Enabled {
			summary.ChallengeFailureFeedbackOn = true
		}
	}
	visit(file.Default)
	for _, scope := range file.Hosts {
		visit(scope)
	}
	return summary
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

func normalizeBotDefenseBrowserSignalsConfig(cfg botDefenseBrowserSignalsConfig) botDefenseBrowserSignalsConfig {
	if !cfg.Enabled {
		return botDefenseBrowserSignalsConfig{}
	}
	cfg.JSCookieName = strings.TrimSpace(cfg.JSCookieName)
	if cfg.JSCookieName == "" {
		cfg.JSCookieName = "__tukuyomi_bot_js"
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 1
	}
	if cfg.RiskScorePerSignal <= 0 {
		cfg.RiskScorePerSignal = 2
	}
	return cfg
}

func normalizeBotDefenseDeviceSignalsConfig(cfg botDefenseDeviceSignalsConfig) botDefenseDeviceSignalsConfig {
	if !cfg.Enabled {
		return botDefenseDeviceSignalsConfig{}
	}
	if !cfg.RequireTimeZone && !cfg.RequirePlatform && !cfg.RequireHardwareConcurrency && !cfg.CheckMobileTouch {
		cfg.RequireTimeZone = true
		cfg.RequirePlatform = true
		cfg.RequireHardwareConcurrency = true
		cfg.CheckMobileTouch = true
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 2
	}
	if cfg.RiskScorePerSignal <= 0 {
		cfg.RiskScorePerSignal = 2
	}
	if cfg.InvisibleMaxBodyBytes <= 0 {
		cfg.InvisibleMaxBodyBytes = defaultBotDefenseInvisibleBodyBytes
	}
	return cfg
}

func normalizeBotDefenseHeaderSignalsConfig(cfg botDefenseHeaderSignalsConfig) botDefenseHeaderSignalsConfig {
	if !cfg.Enabled {
		return botDefenseHeaderSignalsConfig{}
	}
	if !cfg.RequireAcceptLanguage && !cfg.RequireFetchMetadata && !cfg.RequireClientHints && !cfg.RequireUpgradeInsecure {
		cfg.RequireAcceptLanguage = true
		cfg.RequireFetchMetadata = true
		cfg.RequireClientHints = true
		cfg.RequireUpgradeInsecure = true
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 2
	}
	if cfg.RiskScorePerSignal <= 0 {
		cfg.RiskScorePerSignal = 2
	}
	return cfg
}

func normalizeBotDefenseTLSSignalsConfig(cfg botDefenseTLSSignalsConfig) botDefenseTLSSignalsConfig {
	if !cfg.Enabled {
		return botDefenseTLSSignalsConfig{}
	}
	if !cfg.RequireSNI && !cfg.RequireALPN && !cfg.RequireModernTLS {
		cfg.RequireSNI = true
		cfg.RequireALPN = true
		cfg.RequireModernTLS = true
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = 2
	}
	if cfg.RiskScorePerSignal <= 0 {
		cfg.RiskScorePerSignal = 2
	}
	return cfg
}

func normalizeBotDefenseQuarantineConfig(cfg botDefenseQuarantineConfig) botDefenseQuarantineConfig {
	if !cfg.Enabled {
		return botDefenseQuarantineConfig{}
	}
	if cfg.Threshold <= 0 {
		cfg.Threshold = 8
	}
	if cfg.StrikesRequired <= 0 {
		cfg.StrikesRequired = 2
	}
	if cfg.StrikeWindowSeconds <= 0 {
		cfg.StrikeWindowSeconds = 300
	}
	if cfg.TTLSeconds <= 0 {
		cfg.TTLSeconds = 900
	}
	if cfg.ReputationFeedbackSeconds < 0 {
		cfg.ReputationFeedbackSeconds = 0
	}
	if cfg.StatusCode == 0 {
		cfg.StatusCode = http.StatusForbidden
	}
	if cfg.StatusCode < 400 || cfg.StatusCode > 599 {
		cfg.StatusCode = http.StatusForbidden
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
			TelemetryCookieRequired:    policy.TelemetryCookieRequired,
			DisableQuarantine:          policy.DisableQuarantine,
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

func botDefenseChallengeCookieState(rt *runtimeBotDefenseConfig, r *http.Request, ip, userAgent string, now time.Time) string {
	if rt == nil || r == nil {
		return botDefenseCookieStateMissing
	}
	c, err := r.Cookie(rt.CookieName)
	if err != nil {
		return botDefenseCookieStateMissing
	}
	if verifyBotDefenseToken(rt, c.Value, ip, userAgent, now) {
		return botDefenseCookieStateValid
	}
	return botDefenseCookieStateInvalid
}

func hasBotDefenseTelemetryCookie(rt *runtimeBotDefenseConfig, r *http.Request) bool {
	if rt == nil || r == nil {
		return false
	}
	cookieName := botDefenseTelemetryCookieName(rt)
	if cookieName == "" {
		return false
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return false
	}
	_, ok := parseBotDefenseBrowserSignalCookie(c.Value)
	return ok
}

func botDefenseTelemetryCookieState(rt *runtimeBotDefenseConfig, r *http.Request) string {
	if rt == nil || r == nil {
		return botDefenseCookieStateMissing
	}
	cookieName := botDefenseTelemetryCookieName(rt)
	if cookieName == "" {
		return botDefenseCookieStateMissing
	}
	c, err := r.Cookie(cookieName)
	if err != nil {
		return botDefenseCookieStateMissing
	}
	if _, ok := parseBotDefenseBrowserSignalCookie(c.Value); ok {
		return botDefenseCookieStateValid
	}
	return botDefenseCookieStateInvalid
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

func maxBotDefenseRiskWeight(rt *runtimeBotDefenseConfig) int {
	if rt == nil {
		return 2
	}
	maxScore := 2
	for _, candidate := range []int{
		rt.Behavioral.RiskScorePerSignal,
		rt.BrowserSignals.RiskScorePerSignal,
		rt.DeviceSignals.RiskScorePerSignal,
		rt.HeaderSignals.RiskScorePerSignal,
		rt.TLSSignals.RiskScorePerSignal,
	} {
		if candidate > maxScore {
			maxScore = candidate
		}
	}
	return maxScore
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
    "python-httpx",
    "go-http-client",
    "aiohttp",
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
  "challenge_cookie_name": "__tukuyomi_bot_ok",
  "challenge_secret": "",
  "challenge_ttl_seconds": 21600,
  "challenge_status_code": 429,
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
  "browser_signals": {
    "enabled": false,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  },
  "device_signals": {
    "enabled": false,
    "require_time_zone": true,
    "require_platform": true,
    "require_hardware_concurrency": true,
    "check_mobile_touch": true,
    "invisible_html_injection": false,
    "invisible_max_body_bytes": 262144,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "header_signals": {
    "enabled": false,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "tls_signals": {
    "enabled": false,
    "require_sni": true,
    "require_alpn": true,
    "require_modern_tls": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  },
  "quarantine": {
    "enabled": false,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 900,
    "status_code": 403,
    "reputation_feedback_seconds": 0
  }
}
	`
	return os.WriteFile(path, []byte(defaultRaw), 0o644)
}
