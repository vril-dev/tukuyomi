package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/policyhost"
)

const verifyManifestSchemaVersion = "tukuyomi.verify/v1alpha1"

type verifyManifest struct {
	SchemaVersion      string                            `json:"schema_version"`
	Product            string                            `json:"product"`
	GeneratedAt        string                            `json:"generated_at"`
	BaseURL            string                            `json:"base_url,omitempty"`
	APIBasePath        string                            `json:"api_base_path,omitempty"`
	ConfigHash         string                            `json:"config_hash"`
	ComponentHashes    verifyManifestComponentHashes     `json:"component_hashes,omitempty"`
	WAF                verifyManifestWAF                 `json:"waf"`
	Security           verifyManifestSecuritySummary     `json:"security"`
	CountryBlock       verifyManifestCountryBlockSummary `json:"country_block"`
	RateLimit          verifyManifestRateLimitSummary    `json:"rate_limit"`
	IPReputation       verifyManifestIPReputationSummary `json:"ip_reputation"`
	Semantic           verifyManifestSemanticSummary     `json:"semantic"`
	BotDefense         verifyManifestBotDefenseSummary   `json:"bot_defense"`
	Routes             []verifyManifestRoute             `json:"routes,omitempty"`
	Routing            verifyManifestRoutingSummary      `json:"routing"`
	BypassRules        []verifyManifestBypassRule        `json:"bypass_rules"`
	CacheRules         []verifyManifestCacheRule         `json:"cache_rules"`
	NormalFlows        []verifyManifestExpectedFlow      `json:"normal_flows"`
	AttackExpectations []verifyManifestAttackExpectation `json:"attack_expectations"`
}

type verifyManifestComponentHashes struct {
	WAF                string `json:"waf,omitempty"`
	Security           string `json:"security,omitempty"`
	CountryBlock       string `json:"country_block,omitempty"`
	RateLimit          string `json:"rate_limit,omitempty"`
	IPReputation       string `json:"ip_reputation,omitempty"`
	Semantic           string `json:"semantic,omitempty"`
	BotDefense         string `json:"bot_defense,omitempty"`
	Routes             string `json:"routes,omitempty"`
	Routing            string `json:"routing,omitempty"`
	BypassRules        string `json:"bypass_rules,omitempty"`
	CacheRules         string `json:"cache_rules,omitempty"`
	NormalFlows        string `json:"normal_flows,omitempty"`
	AttackExpectations string `json:"attack_expectations,omitempty"`
}

type verifyManifestWAF struct {
	Engine     string   `json:"engine"`
	CRSEnabled bool     `json:"crs_enabled"`
	RuleFiles  []string `json:"rule_files,omitempty"`
}

type verifyManifestSecuritySummary struct {
	CountryBlockEnabled              bool `json:"country_block_enabled"`
	RateLimitEnabled                 bool `json:"rate_limit_enabled"`
	RateLimitRuleCount               int  `json:"rate_limit_rule_count"`
	IPReputationEnabled              bool `json:"ip_reputation_enabled"`
	BotDefenseEnabled                bool `json:"bot_defense_enabled"`
	BotDefenseDryRunEnabled          bool `json:"bot_defense_dry_run_enabled"`
	BotDefensePathPolicyCount        int  `json:"bot_defense_path_policy_count"`
	BotDefensePathPolicyDryRunCount  int  `json:"bot_defense_path_policy_dry_run_count"`
	BotDefenseBehavioralEnabled      bool `json:"bot_defense_behavioral_enabled"`
	BotDefenseBrowserSignalsEnabled  bool `json:"bot_defense_browser_signals_enabled"`
	BotDefenseDeviceSignalsEnabled   bool `json:"bot_defense_device_signals_enabled"`
	BotDefenseDeviceInvisibleEnabled bool `json:"bot_defense_device_invisible_enabled"`
	BotDefenseHeaderSignalsEnabled   bool `json:"bot_defense_header_signals_enabled"`
	BotDefenseTLSSignalsEnabled      bool `json:"bot_defense_tls_signals_enabled"`
	BotDefenseQuarantineEnabled      bool `json:"bot_defense_quarantine_enabled"`
	SemanticEnabled                  bool `json:"semantic_enabled"`
}

type verifyManifestCountryBlockSummary struct {
	Enabled          bool     `json:"enabled"`
	BlockedCountries []string `json:"blocked_countries,omitempty"`
}

type verifyManifestRateLimitSummary struct {
	Default verifyManifestRateLimitScopeSummary            `json:"default"`
	Hosts   map[string]verifyManifestRateLimitScopeSummary `json:"hosts,omitempty"`
}

type verifyManifestRateLimitScopeSummary struct {
	Enabled                    bool                              `json:"enabled"`
	AllowlistIPs               []string                          `json:"allowlist_ips,omitempty"`
	AllowlistCountries         []string                          `json:"allowlist_countries,omitempty"`
	DefaultPolicy              verifyManifestRateLimitRulePolicy `json:"default_policy"`
	Rules                      []verifyManifestRateLimitRule     `json:"rules,omitempty"`
	SessionCookieNames         []string                          `json:"session_cookie_names,omitempty"`
	JWTHeaderNames             []string                          `json:"jwt_header_names,omitempty"`
	JWTCookieNames             []string                          `json:"jwt_cookie_names,omitempty"`
	AdaptiveEnabled            bool                              `json:"adaptive_enabled,omitempty"`
	AdaptiveScoreThreshold     int                               `json:"adaptive_score_threshold,omitempty"`
	AdaptiveLimitFactorPercent int                               `json:"adaptive_limit_factor_percent,omitempty"`
	AdaptiveBurstFactorPercent int                               `json:"adaptive_burst_factor_percent,omitempty"`
}

type verifyManifestRateLimitRule struct {
	Name       string                            `json:"name"`
	MatchType  string                            `json:"match_type"`
	MatchValue string                            `json:"match_value"`
	Methods    []string                          `json:"methods,omitempty"`
	Policy     verifyManifestRateLimitRulePolicy `json:"policy"`
}

type verifyManifestRateLimitRulePolicy struct {
	Enabled       bool                          `json:"enabled"`
	Limit         int                           `json:"limit"`
	WindowSeconds int                           `json:"window_seconds"`
	Burst         int                           `json:"burst"`
	KeyBy         string                        `json:"key_by"`
	Action        verifyManifestRateLimitAction `json:"action"`
}

type verifyManifestRateLimitAction struct {
	Status            int `json:"status,omitempty"`
	RetryAfterSeconds int `json:"retry_after_seconds,omitempty"`
}

type verifyManifestIPReputationSummary struct {
	Default verifyManifestIPReputationScopeSummary            `json:"default"`
	Hosts   map[string]verifyManifestIPReputationScopeSummary `json:"hosts,omitempty"`
}

type verifyManifestIPReputationScopeSummary struct {
	Enabled             bool     `json:"enabled"`
	FeedURLs            []string `json:"feed_urls,omitempty"`
	Allowlist           []string `json:"allowlist,omitempty"`
	Blocklist           []string `json:"blocklist,omitempty"`
	RefreshIntervalSec  int      `json:"refresh_interval_sec,omitempty"`
	RequestTimeoutSec   int      `json:"request_timeout_sec,omitempty"`
	BlockStatusCode     int      `json:"block_status_code,omitempty"`
	FailOpen            bool     `json:"fail_open"`
	EffectiveAllowCount int      `json:"effective_allow_count,omitempty"`
	EffectiveBlockCount int      `json:"effective_block_count,omitempty"`
	FeedAllowCount      int      `json:"feed_allow_count,omitempty"`
	FeedBlockCount      int      `json:"feed_block_count,omitempty"`
	DynamicPenaltyCount int      `json:"dynamic_penalty_count,omitempty"`
}

type verifyManifestSemanticSummary struct {
	Default verifyManifestSemanticScopeSummary            `json:"default"`
	Hosts   map[string]verifyManifestSemanticScopeSummary `json:"hosts,omitempty"`
}

type verifyManifestSemanticScopeSummary struct {
	Enabled                     bool     `json:"enabled"`
	Mode                        string   `json:"mode,omitempty"`
	ProviderEnabled             bool     `json:"provider_enabled,omitempty"`
	ProviderName                string   `json:"provider_name,omitempty"`
	ProviderTimeoutMS           int      `json:"provider_timeout_ms,omitempty"`
	ChallengeStatusCode         int      `json:"challenge_status_code,omitempty"`
	BlockStatusCode             int      `json:"block_status_code,omitempty"`
	ExemptPathPrefixes          []string `json:"exempt_path_prefixes,omitempty"`
	LogThreshold                int      `json:"log_threshold,omitempty"`
	ChallengeThreshold          int      `json:"challenge_threshold,omitempty"`
	BlockThreshold              int      `json:"block_threshold,omitempty"`
	MaxInspectBody              int64    `json:"max_inspect_body,omitempty"`
	TemporalWindowSeconds       int      `json:"temporal_window_seconds,omitempty"`
	TemporalMaxEntriesPerIP     int      `json:"temporal_max_entries_per_ip,omitempty"`
	TemporalBurstThreshold      int      `json:"temporal_burst_threshold,omitempty"`
	TemporalBurstScore          int      `json:"temporal_burst_score,omitempty"`
	TemporalPathFanoutThreshold int      `json:"temporal_path_fanout_threshold,omitempty"`
	TemporalPathFanoutScore     int      `json:"temporal_path_fanout_score,omitempty"`
	TemporalUAChurnThreshold    int      `json:"temporal_ua_churn_threshold,omitempty"`
	TemporalUAChurnScore        int      `json:"temporal_ua_churn_score,omitempty"`
}

type verifyManifestBotDefenseSummary struct {
	Default verifyManifestBotDefenseScopeSummary            `json:"default"`
	Hosts   map[string]verifyManifestBotDefenseScopeSummary `json:"hosts,omitempty"`
}

type verifyManifestBotDefenseScopeSummary struct {
	Enabled              bool                                       `json:"enabled"`
	DryRun               bool                                       `json:"dry_run"`
	Mode                 string                                     `json:"mode,omitempty"`
	ChallengeStatusCode  int                                        `json:"challenge_status_code,omitempty"`
	ChallengeTTLSeconds  int                                        `json:"challenge_ttl_seconds,omitempty"`
	PathPrefixes         []string                                   `json:"path_prefixes,omitempty"`
	PathPolicies         []verifyManifestBotDefensePathPolicy       `json:"path_policies,omitempty"`
	ExemptCIDRs          []string                                   `json:"exempt_cidrs,omitempty"`
	SuspiciousUserAgents []string                                   `json:"suspicious_user_agents,omitempty"`
	BehavioralDetection  *verifyManifestBotDefenseBehavioralSummary `json:"behavioral_detection,omitempty"`
	BrowserSignals       *verifyManifestBotDefenseBrowserSummary    `json:"browser_signals,omitempty"`
	DeviceSignals        *verifyManifestBotDefenseDeviceSummary     `json:"device_signals,omitempty"`
	HeaderSignals        *verifyManifestBotDefenseHeaderSummary     `json:"header_signals,omitempty"`
	TLSSignals           *verifyManifestBotDefenseTLSSummary        `json:"tls_signals,omitempty"`
	Quarantine           *verifyManifestBotDefenseQuarantineSummary `json:"quarantine,omitempty"`
}

type verifyManifestBotDefensePathPolicy struct {
	Name                       string   `json:"name"`
	PathPrefixes               []string `json:"path_prefixes,omitempty"`
	Mode                       string   `json:"mode,omitempty"`
	DryRun                     *bool    `json:"dry_run,omitempty"`
	RiskScoreMultiplierPercent int      `json:"risk_score_multiplier_percent,omitempty"`
	RiskScoreOffset            int      `json:"risk_score_offset,omitempty"`
	TelemetryCookieRequired    bool     `json:"telemetry_cookie_required,omitempty"`
	DisableQuarantine          bool     `json:"disable_quarantine,omitempty"`
}

type verifyManifestBotDefenseBehavioralSummary struct {
	Enabled                bool `json:"enabled"`
	WindowSeconds          int  `json:"window_seconds,omitempty"`
	BurstThreshold         int  `json:"burst_threshold,omitempty"`
	PathFanoutThreshold    int  `json:"path_fanout_threshold,omitempty"`
	UAChurnThreshold       int  `json:"ua_churn_threshold,omitempty"`
	MissingCookieThreshold int  `json:"missing_cookie_threshold,omitempty"`
	ScoreThreshold         int  `json:"score_threshold,omitempty"`
	RiskScorePerSignal     int  `json:"risk_score_per_signal,omitempty"`
}

type verifyManifestBotDefenseBrowserSummary struct {
	Enabled            bool   `json:"enabled"`
	JSCookieName       string `json:"js_cookie_name,omitempty"`
	ScoreThreshold     int    `json:"score_threshold,omitempty"`
	RiskScorePerSignal int    `json:"risk_score_per_signal,omitempty"`
}

type verifyManifestBotDefenseDeviceSummary struct {
	Enabled                    bool  `json:"enabled"`
	RequireTimeZone            bool  `json:"require_time_zone,omitempty"`
	RequirePlatform            bool  `json:"require_platform,omitempty"`
	RequireHardwareConcurrency bool  `json:"require_hardware_concurrency,omitempty"`
	CheckMobileTouch           bool  `json:"check_mobile_touch,omitempty"`
	InvisibleHTMLInjection     bool  `json:"invisible_html_injection,omitempty"`
	InvisibleMaxBodyBytes      int64 `json:"invisible_max_body_bytes,omitempty"`
	ScoreThreshold             int   `json:"score_threshold,omitempty"`
	RiskScorePerSignal         int   `json:"risk_score_per_signal,omitempty"`
}

type verifyManifestBotDefenseHeaderSummary struct {
	Enabled                bool `json:"enabled"`
	RequireAcceptLanguage  bool `json:"require_accept_language,omitempty"`
	RequireFetchMetadata   bool `json:"require_fetch_metadata,omitempty"`
	RequireClientHints     bool `json:"require_client_hints,omitempty"`
	RequireUpgradeInsecure bool `json:"require_upgrade_insecure_requests,omitempty"`
	ScoreThreshold         int  `json:"score_threshold,omitempty"`
	RiskScorePerSignal     int  `json:"risk_score_per_signal,omitempty"`
}

type verifyManifestBotDefenseTLSSummary struct {
	Enabled            bool `json:"enabled"`
	RequireSNI         bool `json:"require_sni,omitempty"`
	RequireALPN        bool `json:"require_alpn,omitempty"`
	RequireModernTLS   bool `json:"require_modern_tls,omitempty"`
	ScoreThreshold     int  `json:"score_threshold,omitempty"`
	RiskScorePerSignal int  `json:"risk_score_per_signal,omitempty"`
}

type verifyManifestBotDefenseQuarantineSummary struct {
	Enabled                   bool `json:"enabled"`
	Threshold                 int  `json:"threshold,omitempty"`
	StrikesRequired           int  `json:"strikes_required,omitempty"`
	StrikeWindowSeconds       int  `json:"strike_window_seconds,omitempty"`
	TTLSeconds                int  `json:"ttl_seconds,omitempty"`
	StatusCode                int  `json:"status_code,omitempty"`
	ReputationFeedbackSeconds int  `json:"reputation_feedback_seconds,omitempty"`
}

type verifyManifestRoutingSummary struct {
	Upstreams             []verifyManifestUpstreamInfo `json:"upstreams,omitempty"`
	LoadBalancingStrategy string                       `json:"load_balancing_strategy,omitempty"`
	Routes                []verifyManifestRouteSummary `json:"routes"`
	DefaultRoute          *verifyManifestRouteSummary  `json:"default_route,omitempty"`
}

type verifyManifestUpstreamInfo struct {
	Name      string `json:"name"`
	URL       string `json:"url"`
	Weight    int    `json:"weight,omitempty"`
	Enabled   bool   `json:"enabled"`
	HTTP2Mode string `json:"http2_mode,omitempty"`
}

type verifyManifestRouteSummary struct {
	Name                string   `json:"name"`
	Enabled             bool     `json:"enabled"`
	Hosts               []string `json:"hosts,omitempty"`
	PathType            string   `json:"path_type,omitempty"`
	PathValue           string   `json:"path_value,omitempty"`
	Upstream            string   `json:"upstream,omitempty"`
	CanaryUpstream      string   `json:"canary_upstream,omitempty"`
	CanaryWeightPercent int      `json:"canary_weight_percent,omitempty"`
	HashPolicy          string   `json:"hash_policy,omitempty"`
	HashKey             string   `json:"hash_key,omitempty"`
}

type verifyManifestBypassRule struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	ExtraRule string `json:"extra_rule,omitempty"`
}

type verifyManifestCacheRule struct {
	HostScope  string   `json:"host_scope,omitempty"`
	Kind       string   `json:"kind"`
	MatchType  string   `json:"match_type"`
	MatchValue string   `json:"match_value"`
	Methods    []string `json:"methods,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Vary       []string `json:"vary,omitempty"`
}

type verifyManifestRoute struct {
	Name                string                         `json:"name"`
	RouteHash           string                         `json:"route_hash,omitempty"`
	Host                string                         `json:"host,omitempty"`
	RouteMode           string                         `json:"route_mode,omitempty"`
	MatchType           string                         `json:"match_type,omitempty"`
	MatchValue          string                         `json:"match_value,omitempty"`
	Methods             []string                       `json:"methods,omitempty"`
	Upstream            string                         `json:"upstream,omitempty"`
	CanaryUpstream      string                         `json:"canary_upstream,omitempty"`
	CanaryWeightPercent int                            `json:"canary_weight_percent,omitempty"`
	HashPolicy          string                         `json:"hash_policy,omitempty"`
	HashKey             string                         `json:"hash_key,omitempty"`
	PathPrefix          string                         `json:"path_prefix"`
	WAFMode             string                         `json:"waf_mode"`
	Bypass              bool                           `json:"bypass,omitempty"`
	BypassModes         []string                       `json:"bypass_modes,omitempty"`
	Cache               *verifyManifestRouteCache      `json:"cache,omitempty"`
	RateLimit           *verifyManifestRouteRateLimit  `json:"rate_limit,omitempty"`
	BotDefense          *verifyManifestRouteBotDefense `json:"bot_defense,omitempty"`
	Security            *verifyManifestRouteSecurity   `json:"security,omitempty"`
}

type verifyManifestRouteSecurity struct {
	CountryBlockEnabled        bool   `json:"country_block_enabled,omitempty"`
	BlockedCountriesCount      int    `json:"blocked_countries_count,omitempty"`
	CountryBlockStatusCode     int    `json:"country_block_status_code,omitempty"`
	IPReputationEnabled        bool   `json:"ip_reputation_enabled,omitempty"`
	IPReputationFailOpen       bool   `json:"ip_reputation_fail_open,omitempty"`
	IPReputationBlockStatus    int    `json:"ip_reputation_block_status_code,omitempty"`
	SemanticEnabled            bool   `json:"semantic_enabled,omitempty"`
	SemanticMode               string `json:"semantic_mode,omitempty"`
	SemanticChallengeStatus    int    `json:"semantic_challenge_status_code,omitempty"`
	SemanticBlockStatus        int    `json:"semantic_block_status_code,omitempty"`
	SemanticChallengeThreshold int    `json:"semantic_challenge_threshold,omitempty"`
	SemanticBlockThreshold     int    `json:"semantic_block_threshold,omitempty"`
}

type verifyManifestRouteCache struct {
	Mode       string   `json:"mode"`
	MatchType  string   `json:"match_type,omitempty"`
	MatchValue string   `json:"match_value,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Vary       []string `json:"vary,omitempty"`
}

type verifyManifestRouteRateLimit struct {
	DefaultPolicy     bool                                 `json:"default_policy,omitempty"`
	RuleNames         []string                             `json:"rule_names,omitempty"`
	EffectivePolicies []verifyManifestRouteRateLimitPolicy `json:"effective_policies,omitempty"`
}

type verifyManifestRouteRateLimitPolicy struct {
	Source            string `json:"source"`
	Limit             int    `json:"limit"`
	WindowSeconds     int    `json:"window_seconds"`
	Burst             int    `json:"burst"`
	KeyBy             string `json:"key_by,omitempty"`
	Status            int    `json:"status,omitempty"`
	RetryAfterSeconds int    `json:"retry_after_seconds,omitempty"`
}

type verifyManifestRouteBotDefense struct {
	Enabled                   bool     `json:"enabled"`
	DryRun                    bool     `json:"dry_run,omitempty"`
	Mode                      string   `json:"mode,omitempty"`
	ChallengeTTLSeconds       int      `json:"challenge_ttl_seconds,omitempty"`
	ChallengeStatusCode       int      `json:"challenge_status_code,omitempty"`
	QuarantineStatusCode      int      `json:"quarantine_status_code,omitempty"`
	BehavioralEnabled         bool     `json:"behavioral_enabled,omitempty"`
	BrowserSignalsEnabled     bool     `json:"browser_signals_enabled,omitempty"`
	DeviceSignalsEnabled      bool     `json:"device_signals_enabled,omitempty"`
	InvisibleDeviceCheck      bool     `json:"invisible_device_check,omitempty"`
	HeaderSignalsEnabled      bool     `json:"header_signals_enabled,omitempty"`
	TLSSignalsEnabled         bool     `json:"tls_signals_enabled,omitempty"`
	QuarantineEnabled         bool     `json:"quarantine_enabled,omitempty"`
	ReputationFeedbackEnabled bool     `json:"reputation_feedback_enabled,omitempty"`
	PathPolicyNames           []string `json:"path_policy_names,omitempty"`
	TelemetryCookieRequired   bool     `json:"telemetry_cookie_required,omitempty"`
	DisableQuarantine         bool     `json:"disable_quarantine,omitempty"`
}

type verifyManifestScenarioRequest struct {
	Query   map[string]string `json:"query,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Cookies map[string]string `json:"cookies,omitempty"`
	Form    map[string]string `json:"form,omitempty"`
	JSON    map[string]string `json:"json,omitempty"`
}

type verifyManifestScenarioAssertions struct {
	StatusCodes      []int    `json:"status_codes,omitempty"`
	FinalURLPrefixes []string `json:"final_url_prefixes,omitempty"`
	MaxConsoleErrors *int     `json:"max_console_errors,omitempty"`
	MaxNetworkErrors *int     `json:"max_network_errors,omitempty"`
}

type verifyManifestExpectedFlow struct {
	Name          string                            `json:"name"`
	Path          string                            `json:"path"`
	Method        string                            `json:"method"`
	Expect        string                            `json:"expect"`
	Route         string                            `json:"route,omitempty"`
	RouteHash     string                            `json:"route_hash,omitempty"`
	RequiresAuth  bool                              `json:"requires_auth,omitempty"`
	ExecutionMode string                            `json:"execution_mode,omitempty"`
	Request       *verifyManifestScenarioRequest    `json:"request,omitempty"`
	Assertions    *verifyManifestScenarioAssertions `json:"assertions,omitempty"`
}

type verifyManifestAttackExpectation struct {
	Name         string                            `json:"name"`
	Route        string                            `json:"route,omitempty"`
	RouteHash    string                            `json:"route_hash,omitempty"`
	Path         string                            `json:"path"`
	Method       string                            `json:"method"`
	Carrier      string                            `json:"carrier"`
	Param        string                            `json:"param,omitempty"`
	PayloadType  string                            `json:"payload_type"`
	PayloadValue string                            `json:"payload_value,omitempty"`
	Technique    string                            `json:"technique,omitempty"`
	Expect       string                            `json:"expect"`
	RequiresAuth bool                              `json:"requires_auth,omitempty"`
	UseBrowser   bool                              `json:"use_browser,omitempty"`
	Request      *verifyManifestScenarioRequest    `json:"request,omitempty"`
	Assertions   *verifyManifestScenarioAssertions `json:"assertions,omitempty"`
}

type verifyManifestState struct {
	GeneratedAt                      time.Time
	BaseURL                          string
	APIBasePath                      string
	RuleFiles                        []string
	CRSEnabled                       bool
	CountryBlock                     verifyManifestCountryBlockSummary
	BlockedCountries                 []string
	RateLimit                        verifyManifestRateLimitSummary
	RateLimitFile                    rateLimitFile
	RateLimitEnabled                 bool
	RateLimitRuleCount               int
	IPReputation                     verifyManifestIPReputationSummary
	IPReputationFile                 ipReputationFile
	IPReputationEnabled              bool
	BotDefenseEnabled                bool
	BotDefenseDryRunEnabled          bool
	BotDefensePathPolicyCount        int
	BotDefensePathPolicyDryRunCount  int
	BotDefenseBehavioralEnabled      bool
	BotDefenseBrowserSignalsEnabled  bool
	BotDefenseDeviceSignalsEnabled   bool
	BotDefenseDeviceInvisibleEnabled bool
	BotDefenseHeaderSignalsEnabled   bool
	BotDefenseTLSSignalsEnabled      bool
	BotDefenseQuarantineEnabled      bool
	BotDefenseFile                   botDefenseFile
	BotDefenseConfig                 botDefenseConfig
	Semantic                         verifyManifestSemanticSummary
	SemanticFile                     semanticFile
	SemanticEnabled                  bool
	Routing                          verifyManifestRoutingSummary
	BypassRules                      []verifyManifestBypassRule
	CacheRules                       []verifyManifestCacheRule
}

func GetVerifyManifest(c *gin.Context) {
	_, _, proxyCfg, _, _ := ProxyRulesSnapshot()
	blockedCountries := GetBlockedCountries()
	rateLimitCfg := GetRateLimitConfig()
	ipReputationCfg := GetIPReputationConfig()
	ipReputationStatuses := map[string]ipReputationStatusSnapshot{}
	for host := range ipReputationCfg.Hosts {
		ipReputationStatuses[host] = IPReputationStatusForHost(host, config.ServerTLSEnabled)
	}
	botDefenseFile := GetBotDefenseFile()
	botDefenseSummary := summarizeBotDefenseFile(botDefenseFile)
	botDefenseCfg := GetBotDefenseConfig()
	semanticCfg := GetSemanticFile()
	c.JSON(http.StatusOK, buildVerifyManifestFromState(verifyManifestState{
		GeneratedAt:                      time.Now().UTC(),
		BaseURL:                          currentVerifyManifestBaseURL(currentVerifyManifestRouting(proxyCfg)),
		APIBasePath:                      config.APIBasePath,
		RuleFiles:                        configuredRuleFiles(),
		CRSEnabled:                       config.CRSEnable,
		CountryBlock:                     buildVerifyManifestCountryBlockSummary(blockedCountries),
		BlockedCountries:                 blockedCountries,
		RateLimit:                        buildVerifyManifestRateLimitSummary(rateLimitCfg),
		RateLimitFile:                    rateLimitCfg,
		RateLimitEnabled:                 rateLimitEnabled(rateLimitCfg),
		RateLimitRuleCount:               rateLimitRuleCount(rateLimitCfg),
		IPReputation:                     buildVerifyManifestIPReputationSummary(ipReputationCfg, IPReputationStatus(), ipReputationStatuses),
		IPReputationFile:                 ipReputationCfg,
		IPReputationEnabled:              ipReputationEnabled(ipReputationCfg),
		BotDefenseEnabled:                botDefenseSummary.Enabled,
		BotDefenseDryRunEnabled:          botDefenseSummary.DryRunEnabled,
		BotDefensePathPolicyCount:        botDefenseSummary.PathPolicyCount,
		BotDefensePathPolicyDryRunCount:  botDefenseSummary.PathPolicyDryRunCount,
		BotDefenseBehavioralEnabled:      botDefenseSummary.BehavioralEnabled,
		BotDefenseBrowserSignalsEnabled:  botDefenseSummary.BrowserSignalsEnabled,
		BotDefenseDeviceSignalsEnabled:   botDefenseSummary.DeviceSignalsEnabled,
		BotDefenseDeviceInvisibleEnabled: botDefenseSummary.DeviceInvisibleEnabled,
		BotDefenseHeaderSignalsEnabled:   botDefenseSummary.HeaderSignalsEnabled,
		BotDefenseTLSSignalsEnabled:      botDefenseSummary.TLSSignalsEnabled,
		BotDefenseQuarantineEnabled:      botDefenseSummary.QuarantineEnabled,
		BotDefenseFile:                   botDefenseFile,
		BotDefenseConfig:                 botDefenseCfg,
		Semantic:                         buildVerifyManifestSemanticSummary(semanticCfg),
		SemanticFile:                     semanticCfg,
		SemanticEnabled:                  semanticEnabled(semanticCfg),
		Routing:                          currentVerifyManifestRouting(proxyCfg),
		BypassRules:                      currentVerifyManifestBypassRules(config.BypassFile),
		CacheRules:                       currentVerifyManifestCacheRules(),
	}))
}

func buildVerifyManifestFromState(state verifyManifestState) verifyManifest {
	state.Semantic = normalizeVerifyManifestSemanticSummary(state.Semantic)
	routes := currentVerifyManifestRoutes(state.Routing, state.BypassRules, state.CacheRules, state.RateLimitFile, state.BotDefenseFile, state.CountryBlock, state.IPReputationFile, state.SemanticFile, state.BaseURL)
	normalFlows, attackExpectations := deriveVerifyManifestBotDefenseScenarios(state.BotDefenseConfig, state.Routing, routes, state.BaseURL)
	manifest := verifyManifest{
		SchemaVersion: verifyManifestSchemaVersion,
		Product:       "tukuyomi",
		GeneratedAt:   state.GeneratedAt.UTC().Format(time.RFC3339Nano),
		BaseURL:       strings.TrimSpace(state.BaseURL),
		APIBasePath:   strings.TrimSpace(state.APIBasePath),
		WAF: verifyManifestWAF{
			Engine:     "coraza",
			CRSEnabled: state.CRSEnabled,
			RuleFiles:  append([]string(nil), state.RuleFiles...),
		},
		CountryBlock: state.CountryBlock,
		RateLimit:    state.RateLimit,
		IPReputation: state.IPReputation,
		Semantic:     state.Semantic,
		Security: verifyManifestSecuritySummary{
			CountryBlockEnabled:              len(state.BlockedCountries) > 0,
			RateLimitEnabled:                 state.RateLimitEnabled,
			RateLimitRuleCount:               state.RateLimitRuleCount,
			IPReputationEnabled:              state.IPReputationEnabled,
			BotDefenseEnabled:                state.BotDefenseEnabled,
			BotDefenseDryRunEnabled:          state.BotDefenseDryRunEnabled,
			BotDefensePathPolicyCount:        state.BotDefensePathPolicyCount,
			BotDefensePathPolicyDryRunCount:  state.BotDefensePathPolicyDryRunCount,
			BotDefenseBehavioralEnabled:      state.BotDefenseBehavioralEnabled,
			BotDefenseBrowserSignalsEnabled:  state.BotDefenseBrowserSignalsEnabled,
			BotDefenseDeviceSignalsEnabled:   state.BotDefenseDeviceSignalsEnabled,
			BotDefenseDeviceInvisibleEnabled: state.BotDefenseDeviceInvisibleEnabled,
			BotDefenseHeaderSignalsEnabled:   state.BotDefenseHeaderSignalsEnabled,
			BotDefenseTLSSignalsEnabled:      state.BotDefenseTLSSignalsEnabled,
			BotDefenseQuarantineEnabled:      state.BotDefenseQuarantineEnabled,
			SemanticEnabled:                  state.SemanticEnabled,
		},
		BotDefense:         buildVerifyManifestBotDefenseSummary(state.BotDefenseFile),
		Routes:             routes,
		Routing:            state.Routing,
		BypassRules:        append([]verifyManifestBypassRule(nil), state.BypassRules...),
		CacheRules:         append([]verifyManifestCacheRule(nil), state.CacheRules...),
		NormalFlows:        normalFlows,
		AttackExpectations: attackExpectations,
	}
	assignVerifyManifestRouteHashes(manifest.Routes)
	assignVerifyManifestScenarioRouteHashes(manifest.NormalFlows, manifest.AttackExpectations, manifest.Routes)
	assignVerifyManifestHashes(&manifest)
	return manifest
}

func normalizeVerifyManifestSemanticSummary(summary verifyManifestSemanticSummary) verifyManifestSemanticSummary {
	summary.Default = normalizeVerifyManifestSemanticScopeSummary(summary.Default)
	if len(summary.Hosts) > 0 {
		hosts := make(map[string]verifyManifestSemanticScopeSummary, len(summary.Hosts))
		for host, scope := range summary.Hosts {
			hosts[host] = normalizeVerifyManifestSemanticScopeSummary(scope)
		}
		summary.Hosts = hosts
	}
	return summary
}

func normalizeVerifyManifestSemanticScopeSummary(summary verifyManifestSemanticScopeSummary) verifyManifestSemanticScopeSummary {
	if !summary.Enabled {
		return summary
	}
	if summary.ChallengeStatusCode == 0 {
		summary.ChallengeStatusCode = http.StatusTooManyRequests
	}
	if summary.BlockStatusCode == 0 {
		summary.BlockStatusCode = http.StatusForbidden
	}
	return summary
}

func buildVerifyManifestBotDefenseSummary(file botDefenseFile) verifyManifestBotDefenseSummary {
	out := verifyManifestBotDefenseSummary{
		Default: buildVerifyManifestBotDefenseScopeSummary(file.Default),
	}
	if len(file.Hosts) > 0 {
		out.Hosts = make(map[string]verifyManifestBotDefenseScopeSummary, len(file.Hosts))
		for host, cfg := range file.Hosts {
			out.Hosts[host] = buildVerifyManifestBotDefenseScopeSummary(cfg)
		}
	}
	return out
}

func buildVerifyManifestBotDefenseScopeSummary(cfg botDefenseConfig) verifyManifestBotDefenseScopeSummary {
	out := verifyManifestBotDefenseScopeSummary{
		Enabled:              cfg.Enabled,
		DryRun:               cfg.DryRun,
		Mode:                 cfg.Mode,
		ChallengeStatusCode:  cfg.ChallengeStatusCode,
		ChallengeTTLSeconds:  cfg.ChallengeTTLSeconds,
		PathPrefixes:         append([]string(nil), cfg.PathPrefixes...),
		PathPolicies:         make([]verifyManifestBotDefensePathPolicy, 0, len(cfg.PathPolicies)),
		ExemptCIDRs:          append([]string(nil), cfg.ExemptCIDRs...),
		SuspiciousUserAgents: append([]string(nil), cfg.SuspiciousUserAgents...),
		BehavioralDetection: &verifyManifestBotDefenseBehavioralSummary{
			Enabled:                cfg.BehavioralDetection.Enabled,
			WindowSeconds:          cfg.BehavioralDetection.WindowSeconds,
			BurstThreshold:         cfg.BehavioralDetection.BurstThreshold,
			PathFanoutThreshold:    cfg.BehavioralDetection.PathFanoutThreshold,
			UAChurnThreshold:       cfg.BehavioralDetection.UAChurnThreshold,
			MissingCookieThreshold: cfg.BehavioralDetection.MissingCookieThreshold,
			ScoreThreshold:         cfg.BehavioralDetection.ScoreThreshold,
			RiskScorePerSignal:     cfg.BehavioralDetection.RiskScorePerSignal,
		},
		BrowserSignals: &verifyManifestBotDefenseBrowserSummary{
			Enabled:            cfg.BrowserSignals.Enabled,
			JSCookieName:       cfg.BrowserSignals.JSCookieName,
			ScoreThreshold:     cfg.BrowserSignals.ScoreThreshold,
			RiskScorePerSignal: cfg.BrowserSignals.RiskScorePerSignal,
		},
		DeviceSignals: &verifyManifestBotDefenseDeviceSummary{
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
		HeaderSignals: &verifyManifestBotDefenseHeaderSummary{
			Enabled:                cfg.HeaderSignals.Enabled,
			RequireAcceptLanguage:  cfg.HeaderSignals.RequireAcceptLanguage,
			RequireFetchMetadata:   cfg.HeaderSignals.RequireFetchMetadata,
			RequireClientHints:     cfg.HeaderSignals.RequireClientHints,
			RequireUpgradeInsecure: cfg.HeaderSignals.RequireUpgradeInsecure,
			ScoreThreshold:         cfg.HeaderSignals.ScoreThreshold,
			RiskScorePerSignal:     cfg.HeaderSignals.RiskScorePerSignal,
		},
		TLSSignals: &verifyManifestBotDefenseTLSSummary{
			Enabled:            cfg.TLSSignals.Enabled,
			RequireSNI:         cfg.TLSSignals.RequireSNI,
			RequireALPN:        cfg.TLSSignals.RequireALPN,
			RequireModernTLS:   cfg.TLSSignals.RequireModernTLS,
			ScoreThreshold:     cfg.TLSSignals.ScoreThreshold,
			RiskScorePerSignal: cfg.TLSSignals.RiskScorePerSignal,
		},
		Quarantine: &verifyManifestBotDefenseQuarantineSummary{
			Enabled:                   cfg.Quarantine.Enabled,
			Threshold:                 cfg.Quarantine.Threshold,
			StrikesRequired:           cfg.Quarantine.StrikesRequired,
			StrikeWindowSeconds:       cfg.Quarantine.StrikeWindowSeconds,
			TTLSeconds:                cfg.Quarantine.TTLSeconds,
			StatusCode:                cfg.Quarantine.StatusCode,
			ReputationFeedbackSeconds: cfg.Quarantine.ReputationFeedbackSeconds,
		},
	}
	for _, policy := range cfg.PathPolicies {
		out.PathPolicies = append(out.PathPolicies, verifyManifestBotDefensePathPolicy{
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

func buildVerifyManifestCountryBlockSummary(blocked []string) verifyManifestCountryBlockSummary {
	return verifyManifestCountryBlockSummary{
		Enabled:          len(blocked) > 0,
		BlockedCountries: append([]string(nil), blocked...),
	}
}

func buildVerifyManifestRateLimitSummary(file rateLimitFile) verifyManifestRateLimitSummary {
	out := verifyManifestRateLimitSummary{
		Default: buildVerifyManifestRateLimitScopeSummary(file.Default),
	}
	if len(file.Hosts) > 0 {
		out.Hosts = make(map[string]verifyManifestRateLimitScopeSummary, len(file.Hosts))
		for host, cfg := range file.Hosts {
			out.Hosts[host] = buildVerifyManifestRateLimitScopeSummary(cfg)
		}
	}
	return out
}

func buildVerifyManifestRateLimitScopeSummary(cfg rateLimitConfig) verifyManifestRateLimitScopeSummary {
	out := verifyManifestRateLimitScopeSummary{
		Enabled:                    cfg.Enabled,
		AllowlistIPs:               append([]string(nil), cfg.AllowlistIPs...),
		AllowlistCountries:         append([]string(nil), cfg.AllowlistCountries...),
		DefaultPolicy:              buildVerifyManifestRateLimitPolicy(cfg.DefaultPolicy),
		Rules:                      make([]verifyManifestRateLimitRule, 0, len(cfg.Rules)),
		SessionCookieNames:         append([]string(nil), cfg.SessionCookieNames...),
		JWTHeaderNames:             append([]string(nil), cfg.JWTHeaderNames...),
		JWTCookieNames:             append([]string(nil), cfg.JWTCookieNames...),
		AdaptiveEnabled:            cfg.AdaptiveEnabled,
		AdaptiveScoreThreshold:     cfg.AdaptiveScoreThreshold,
		AdaptiveLimitFactorPercent: cfg.AdaptiveLimitFactorPct,
		AdaptiveBurstFactorPercent: cfg.AdaptiveBurstFactorPct,
	}
	for _, rule := range cfg.Rules {
		out.Rules = append(out.Rules, verifyManifestRateLimitRule{
			Name:       rule.Name,
			MatchType:  rule.MatchType,
			MatchValue: rule.MatchValue,
			Methods:    append([]string(nil), rule.Methods...),
			Policy:     buildVerifyManifestRateLimitPolicy(rule.Policy),
		})
	}
	return out
}

func buildVerifyManifestRateLimitPolicy(policy rateLimitPolicy) verifyManifestRateLimitRulePolicy {
	return verifyManifestRateLimitRulePolicy{
		Enabled:       policy.Enabled,
		Limit:         policy.Limit,
		WindowSeconds: policy.WindowSeconds,
		Burst:         policy.Burst,
		KeyBy:         policy.KeyBy,
		Action: verifyManifestRateLimitAction{
			Status:            policy.Action.Status,
			RetryAfterSeconds: policy.Action.RetryAfterSeconds,
		},
	}
}

func buildVerifyManifestIPReputationSummary(file ipReputationFile, defaultStatus ipReputationStatusSnapshot, hostStatuses map[string]ipReputationStatusSnapshot) verifyManifestIPReputationSummary {
	out := verifyManifestIPReputationSummary{
		Default: buildVerifyManifestIPReputationScopeSummary(file.Default, defaultStatus),
	}
	if len(file.Hosts) > 0 {
		out.Hosts = make(map[string]verifyManifestIPReputationScopeSummary, len(file.Hosts))
		for host, cfg := range file.Hosts {
			out.Hosts[host] = buildVerifyManifestIPReputationScopeSummary(cfg, hostStatuses[host])
		}
	}
	return out
}

func buildVerifyManifestIPReputationScopeSummary(cfg ipReputationConfig, status ipReputationStatusSnapshot) verifyManifestIPReputationScopeSummary {
	return verifyManifestIPReputationScopeSummary{
		Enabled:             cfg.Enabled,
		FeedURLs:            append([]string(nil), cfg.FeedURLs...),
		Allowlist:           append([]string(nil), cfg.Allowlist...),
		Blocklist:           append([]string(nil), cfg.Blocklist...),
		RefreshIntervalSec:  cfg.RefreshIntervalSec,
		RequestTimeoutSec:   cfg.RequestTimeoutSec,
		BlockStatusCode:     cfg.BlockStatusCode,
		FailOpen:            cfg.FailOpen,
		EffectiveAllowCount: status.EffectiveAllowCount,
		EffectiveBlockCount: status.EffectiveBlockCount,
		FeedAllowCount:      status.FeedAllowCount,
		FeedBlockCount:      status.FeedBlockCount,
		DynamicPenaltyCount: status.DynamicPenaltyCount,
	}
}

func buildVerifyManifestSemanticSummary(file semanticFile) verifyManifestSemanticSummary {
	out := verifyManifestSemanticSummary{
		Default: buildVerifyManifestSemanticScopeSummary(file.Default),
	}
	if len(file.Hosts) > 0 {
		out.Hosts = make(map[string]verifyManifestSemanticScopeSummary, len(file.Hosts))
		for host, cfg := range file.Hosts {
			out.Hosts[host] = buildVerifyManifestSemanticScopeSummary(cfg)
		}
	}
	return out
}

func buildVerifyManifestSemanticScopeSummary(cfg semanticConfig) verifyManifestSemanticScopeSummary {
	return verifyManifestSemanticScopeSummary{
		Enabled:                     cfg.Enabled,
		Mode:                        cfg.Mode,
		ProviderEnabled:             cfg.Provider.Enabled,
		ProviderName:                cfg.Provider.Name,
		ProviderTimeoutMS:           cfg.Provider.TimeoutMS,
		ChallengeStatusCode:         http.StatusTooManyRequests,
		BlockStatusCode:             http.StatusForbidden,
		ExemptPathPrefixes:          append([]string(nil), cfg.ExemptPathPrefixes...),
		LogThreshold:                cfg.LogThreshold,
		ChallengeThreshold:          cfg.ChallengeThreshold,
		BlockThreshold:              cfg.BlockThreshold,
		MaxInspectBody:              cfg.MaxInspectBody,
		TemporalWindowSeconds:       cfg.TemporalWindowSeconds,
		TemporalMaxEntriesPerIP:     cfg.TemporalMaxEntriesPerIP,
		TemporalBurstThreshold:      cfg.TemporalBurstThreshold,
		TemporalBurstScore:          cfg.TemporalBurstScore,
		TemporalPathFanoutThreshold: cfg.TemporalPathFanoutThreshold,
		TemporalPathFanoutScore:     cfg.TemporalPathFanoutScore,
		TemporalUAChurnThreshold:    cfg.TemporalUAChurnThreshold,
		TemporalUAChurnScore:        cfg.TemporalUAChurnScore,
	}
}

func deriveVerifyManifestBotDefenseScenarios(cfg botDefenseConfig, routing verifyManifestRoutingSummary, routes []verifyManifestRoute, baseURL string) ([]verifyManifestExpectedFlow, []verifyManifestAttackExpectation) {
	if !cfg.Enabled {
		return []verifyManifestExpectedFlow{}, []verifyManifestAttackExpectation{}
	}
	normalCap := len(cfg.PathPolicies)
	if normalCap < 1 {
		normalCap = 1
	}
	attackCap := len(cfg.PathPolicies)
	if attackCap < 1 {
		attackCap = 1
	}
	normalFlows := make([]verifyManifestExpectedFlow, 0, normalCap)
	attacks := make([]verifyManifestAttackExpectation, 0, attackCap)
	seenNormal := map[string]struct{}{}
	seenAttack := map[string]struct{}{}

	addNormal := func(name, path string) {
		key := name + "|" + path
		if _, ok := seenNormal[key]; ok {
			return
		}
		seenNormal[key] = struct{}{}
		route := verifyManifestRouteByPath(path, routes)
		routeName := "default"
		if route != nil && strings.TrimSpace(route.Name) != "" {
			routeName = route.Name
		}
		normalFlows = append(normalFlows, verifyManifestExpectedFlow{
			Name:          name,
			Path:          path,
			Method:        http.MethodGet,
			Expect:        "allow",
			Route:         routeName,
			ExecutionMode: "browser",
			Request:       verifyManifestRouteRequest(path, routing, baseURL),
			Assertions:    verifyManifestRouteAssertionsFromRoute(route),
		})
	}
	addAttack := func(name, path, payloadType, expect string) {
		key := name + "|" + path + "|" + payloadType + "|" + expect
		if _, ok := seenAttack[key]; ok {
			return
		}
		seenAttack[key] = struct{}{}
		route := verifyManifestRouteByPath(path, routes)
		routeName := "default"
		if route != nil && strings.TrimSpace(route.Name) != "" {
			routeName = route.Name
		}
		attacks = append(attacks, verifyManifestAttackExpectation{
			Name:        name,
			Route:       routeName,
			Path:        path,
			Method:      http.MethodGet,
			Carrier:     "browser_navigation",
			PayloadType: payloadType,
			Technique:   payloadType,
			Expect:      expect,
			UseBrowser:  true,
			Request:     verifyManifestRouteRequest(path, routing, baseURL),
			Assertions:  mergeVerifyManifestScenarioAssertions(verifyManifestRouteAssertionsFromRoute(route), verifyManifestExpectedActionAssertions(expect, route)),
		})
	}
	for _, policy := range cfg.PathPolicies {
		if len(policy.PathPrefixes) == 0 {
			continue
		}
		basePath := verifyManifestScenarioPath(policy.PathPrefixes[0])
		baseName := strings.TrimSpace(policy.Name)
		if baseName == "" {
			baseName = strings.Trim(strings.ReplaceAll(basePath, "/", "-"), "-")
			if baseName == "" {
				baseName = "root"
			}
		}
		addNormal(baseName+"-normal", basePath)
		effectiveDryRun := cfg.DryRun
		if policy.DryRun != nil {
			effectiveDryRun = *policy.DryRun
		}
		expect := "challenge"
		if effectiveDryRun {
			expect = "report_only"
		}
		effectiveMode := cfg.Mode
		if strings.TrimSpace(policy.Mode) != "" {
			effectiveMode = policy.Mode
		}
		if effectiveMode == botDefenseModeAlways {
			addAttack(baseName+"-automation-probe", basePath, "bot_like_navigation", expect)
		}
		if policy.TelemetryCookieRequired {
			addAttack(baseName+"-missing-telemetry", basePath, "missing_telemetry_navigation", expect)
		}
	}
	if len(normalFlows) == 0 && len(cfg.PathPrefixes) > 0 {
		basePath := verifyManifestScenarioPath(cfg.PathPrefixes[0])
		addNormal("bot-defense-normal", basePath)
		if cfg.Mode == botDefenseModeAlways {
			expect := "challenge"
			if cfg.DryRun {
				expect = "report_only"
			}
			addAttack("bot-defense-automation-probe", basePath, "bot_like_navigation", expect)
		}
	}
	return normalFlows, attacks
}

func verifyManifestScenarioPath(pathPrefix string) string {
	path := strings.TrimSpace(pathPrefix)
	if path == "" || path == "/" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	if strings.HasSuffix(path, "/") {
		return path + "health"
	}
	return path
}

func currentVerifyManifestRoutes(routing verifyManifestRoutingSummary, bypassRules []verifyManifestBypassRule, cacheRules []verifyManifestCacheRule, rateLimit rateLimitFile, botDefense botDefenseFile, country verifyManifestCountryBlockSummary, ipReputation ipReputationFile, semantic semanticFile, baseURL string) []verifyManifestRoute {
	out := make([]verifyManifestRoute, 0, len(routing.Routes)+1)
	baseHost := verifyManifestHostFromBaseURL(baseURL)
	tls := verifyManifestUsesTLS(baseURL)
	for _, route := range routing.Routes {
		if !route.Enabled {
			continue
		}
		host := ""
		if len(route.Hosts) > 0 {
			host = strings.TrimSpace(route.Hosts[0])
		}
		if host == "" {
			host = baseHost
		}
		pathPrefix := strings.TrimSpace(route.PathValue)
		if pathPrefix == "" {
			pathPrefix = "/"
		}
		if !strings.HasPrefix(pathPrefix, "/") {
			pathPrefix = "/" + pathPrefix
		}
		out = append(out, verifyManifestRoute{
			Name:                route.Name,
			Host:                host,
			MatchType:           strings.TrimSpace(route.PathType),
			MatchValue:          strings.TrimSpace(route.PathValue),
			Upstream:            strings.TrimSpace(route.Upstream),
			CanaryUpstream:      strings.TrimSpace(route.CanaryUpstream),
			CanaryWeightPercent: route.CanaryWeightPercent,
			HashPolicy:          strings.TrimSpace(route.HashPolicy),
			HashKey:             strings.TrimSpace(route.HashKey),
			PathPrefix:          pathPrefix,
			WAFMode:             "block",
		})
	}
	if routing.DefaultRoute != nil {
		out = append(out, verifyManifestRoute{
			Name:       routing.DefaultRoute.Name,
			Host:       baseHost,
			MatchType:  "prefix",
			MatchValue: "/",
			PathPrefix: "/",
			WAFMode:    "block",
		})
	} else if len(routing.Upstreams) > 0 {
		out = append(out, verifyManifestRoute{
			Name:       "default",
			Host:       baseHost,
			MatchType:  "prefix",
			MatchValue: "/",
			PathPrefix: "/",
			WAFMode:    "block",
		})
	}
	for i := range out {
		out[i].BypassModes = currentVerifyManifestRouteBypassModes(out[i], bypassRules)
		out[i].Bypass = len(out[i].BypassModes) > 0
		out[i].Cache = currentVerifyManifestRouteCache(out[i], cacheRules, tls)
		out[i].RateLimit = currentVerifyManifestRouteRateLimit(out[i], rateLimit, tls)
		out[i].BotDefense = currentVerifyManifestRouteBotDefense(out[i], botDefense, tls)
		out[i].Security = currentVerifyManifestRouteSecurity(out[i], country, ipReputation, semantic, tls)
	}
	return out
}

func currentVerifyManifestRouteSecurity(route verifyManifestRoute, country verifyManifestCountryBlockSummary, ipReputation ipReputationFile, semantic semanticFile, tls bool) *verifyManifestRouteSecurity {
	ipCfg, _ := selectVerifyManifestIPReputationScope(ipReputation, route.Host, tls)
	semanticCfg, _ := selectVerifyManifestSemanticScope(semantic, route.Host, tls)
	return &verifyManifestRouteSecurity{
		CountryBlockEnabled:        country.Enabled,
		BlockedCountriesCount:      len(country.BlockedCountries),
		CountryBlockStatusCode:     http.StatusForbidden,
		IPReputationEnabled:        ipCfg.Enabled,
		IPReputationFailOpen:       ipCfg.FailOpen,
		IPReputationBlockStatus:    ipCfg.BlockStatusCode,
		SemanticEnabled:            semanticCfg.Enabled,
		SemanticMode:               strings.TrimSpace(semanticCfg.Mode),
		SemanticChallengeStatus:    http.StatusTooManyRequests,
		SemanticBlockStatus:        http.StatusForbidden,
		SemanticChallengeThreshold: semanticCfg.ChallengeThreshold,
		SemanticBlockThreshold:     semanticCfg.BlockThreshold,
	}
}

func hydrateVerifyManifestRouteHosts(routes []verifyManifestRoute, baseURL string) []verifyManifestRoute {
	host := verifyManifestHostFromBaseURL(baseURL)
	if host == "" {
		return routes
	}
	for i := range routes {
		if strings.TrimSpace(routes[i].Host) == "" {
			routes[i].Host = host
		}
	}
	return routes
}

func resolveVerifyManifestRouteName(path string, routing verifyManifestRoutingSummary) string {
	bestName := ""
	bestScore := -1
	for _, route := range routing.Routes {
		if !route.Enabled {
			continue
		}
		score := verifyManifestRouteMatchScore(path, route.PathType, route.PathValue)
		if score > bestScore {
			bestScore = score
			bestName = route.Name
		}
	}
	if bestName != "" {
		return bestName
	}
	if routing.DefaultRoute != nil && strings.TrimSpace(routing.DefaultRoute.Name) != "" {
		return routing.DefaultRoute.Name
	}
	return "default"
}

func verifyManifestRouteMatchScore(path string, pathType string, pathValue string) int {
	switch strings.TrimSpace(pathType) {
	case "exact":
		if path == strings.TrimSpace(pathValue) {
			return 1_000_000
		}
		return -1
	case "regex":
		pattern := strings.TrimSpace(pathValue)
		if pattern == "" {
			return -1
		}
		re, err := compileProxyRoutePattern(pattern)
		if err != nil || !re.MatchString(path) {
			return -1
		}
		return 500_000 + len(pattern)
	case "", "prefix":
		fallthrough
	default:
		prefix := strings.TrimSpace(pathValue)
		if prefix == "" {
			prefix = "/"
		}
		if strings.HasPrefix(path, prefix) {
			return len(prefix)
		}
		return -1
	}
}

func compileProxyRoutePattern(pattern string) (*regexp.Regexp, error) {
	return regexp.Compile(pattern)
}

func currentVerifyManifestBaseURL(routing verifyManifestRoutingSummary) string {
	scheme := "http"
	if config.ServerTLSEnabled {
		scheme = "https"
	}
	if host := currentVerifyManifestRouteHost(routing); host != "" {
		return scheme + "://" + host
	}
	if len(config.ServerTLSACMEDomains) > 0 && strings.TrimSpace(config.ServerTLSACMEDomains[0]) != "" {
		return scheme + "://" + strings.TrimSpace(config.ServerTLSACMEDomains[0])
	}
	return scheme + "://" + normalizeVerifyManifestListenHostPort(config.ListenAddr, scheme)
}

func currentVerifyManifestRouteHost(routing verifyManifestRoutingSummary) string {
	for _, route := range routing.Routes {
		for _, host := range route.Hosts {
			host = strings.TrimSpace(host)
			if host != "" {
				return host
			}
		}
	}
	return ""
}

func normalizeVerifyManifestListenHostPort(addr string, scheme string) string {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		if scheme == "https" {
			return "127.0.0.1:443"
		}
		return "127.0.0.1:80"
	}
	if strings.HasPrefix(addr, ":") {
		return "127.0.0.1" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	host = strings.TrimSpace(strings.Trim(host, "[]"))
	switch host {
	case "", "0.0.0.0", "::":
		host = "127.0.0.1"
	}
	return net.JoinHostPort(host, port)
}

func verifyManifestChallengeAssertions(expect string, statusCode int) *verifyManifestScenarioAssertions {
	if expect != "challenge" || statusCode == 0 {
		return nil
	}
	return &verifyManifestScenarioAssertions{
		StatusCodes: []int{statusCode},
	}
}

func verifyManifestRouteAssertions(path string, routing verifyManifestRoutingSummary) *verifyManifestScenarioAssertions {
	return verifyManifestRouteAssertionsFromRoute(verifyManifestRouteByPath(path, currentVerifyManifestRoutes(routing, nil, nil, rateLimitFile{}, botDefenseFile{}, verifyManifestCountryBlockSummary{}, ipReputationFile{}, semanticFile{}, "")))
}

func verifyManifestRouteAssertionsFromRoute(route *verifyManifestRoute) *verifyManifestScenarioAssertions {
	if route == nil {
		return nil
	}
	prefixes := verifyManifestRouteFinalURLPrefixes(*route)
	if len(prefixes) == 0 {
		return nil
	}
	return &verifyManifestScenarioAssertions{
		FinalURLPrefixes: prefixes,
	}
}

func verifyManifestExpectedActionAssertions(expect string, route *verifyManifestRoute) *verifyManifestScenarioAssertions {
	if route == nil {
		return nil
	}
	status := 0
	switch expect {
	case "challenge":
		if route.BotDefense != nil && !route.BotDefense.DryRun {
			status = route.BotDefense.ChallengeStatusCode
		}
		if status == 0 && route.Security != nil && route.Security.SemanticEnabled && strings.EqualFold(route.Security.SemanticMode, "challenge") {
			status = route.Security.SemanticChallengeStatus
		}
	case "block":
		if route.BotDefense != nil && route.BotDefense.QuarantineEnabled && !route.BotDefense.DisableQuarantine {
			status = route.BotDefense.QuarantineStatusCode
		}
		if status == 0 && route.Security != nil && route.Security.IPReputationBlockStatus > 0 {
			status = route.Security.IPReputationBlockStatus
		}
		if status == 0 && route.Security != nil && route.Security.CountryBlockEnabled {
			status = route.Security.CountryBlockStatusCode
		}
		if status == 0 && route.Security != nil && route.Security.SemanticEnabled {
			status = route.Security.SemanticBlockStatus
		}
	}
	if status == 0 {
		return nil
	}
	return &verifyManifestScenarioAssertions{StatusCodes: []int{status}}
}

func verifyManifestRouteByPath(path string, routes []verifyManifestRoute) *verifyManifestRoute {
	bestIndex := -1
	bestScore := -1
	for i := range routes {
		score := verifyManifestRouteMatchScore(path, routes[i].MatchType, routes[i].MatchValue)
		if score > bestScore {
			bestScore = score
			bestIndex = i
		}
	}
	if bestIndex >= 0 {
		return &routes[bestIndex]
	}
	return nil
}

func verifyManifestRouteRequest(path string, routing verifyManifestRoutingSummary, baseURL string) *verifyManifestScenarioRequest {
	routeName := resolveVerifyManifestRouteName(path, routing)
	host := currentVerifyManifestRouteHostByName(routeName, routing)
	if host == "" {
		host = verifyManifestHostFromBaseURL(baseURL)
	}
	if host == "" {
		return nil
	}
	return &verifyManifestScenarioRequest{
		Headers: map[string]string{"Host": host},
	}
}

func currentVerifyManifestRouteHostByName(name string, routing verifyManifestRoutingSummary) string {
	if strings.TrimSpace(name) == "" {
		return ""
	}
	for _, route := range routing.Routes {
		if route.Name != name {
			continue
		}
		for _, host := range route.Hosts {
			host = strings.TrimSpace(host)
			if host != "" {
				return host
			}
		}
	}
	return ""
}

func verifyManifestRouteFinalURLPrefixes(route verifyManifestRoute) []string {
	switch strings.TrimSpace(route.MatchType) {
	case "", "prefix", "exact":
		prefix := normalizeVerifyManifestPathPrefix(route.MatchValue)
		if prefix == "" {
			prefix = normalizeVerifyManifestPathPrefix(route.PathPrefix)
		}
		if prefix == "" {
			return nil
		}
		return []string{prefix}
	default:
		return nil
	}
}

func verifyManifestHostFromBaseURL(baseURL string) string {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(u.Host)
}

func mergeVerifyManifestScenarioAssertions(base *verifyManifestScenarioAssertions, extra *verifyManifestScenarioAssertions) *verifyManifestScenarioAssertions {
	if base == nil {
		return extra
	}
	if extra == nil {
		return base
	}
	out := *base
	if len(extra.StatusCodes) > 0 {
		out.StatusCodes = append([]int(nil), extra.StatusCodes...)
	}
	if len(extra.FinalURLPrefixes) > 0 {
		out.FinalURLPrefixes = append([]string(nil), extra.FinalURLPrefixes...)
	}
	if extra.MaxConsoleErrors != nil {
		out.MaxConsoleErrors = extra.MaxConsoleErrors
	}
	if extra.MaxNetworkErrors != nil {
		out.MaxNetworkErrors = extra.MaxNetworkErrors
	}
	return &out
}

func currentVerifyManifestRouteBypassModes(route verifyManifestRoute, rules []verifyManifestBypassRule) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if !verifyManifestRoutePrefixOverlap(route.PathPrefix, rule.Path) {
			continue
		}
		mode := strings.TrimSpace(rule.Mode)
		if mode == "" {
			mode = "bypass"
		}
		if _, ok := seen[mode]; ok {
			continue
		}
		seen[mode] = struct{}{}
		out = append(out, mode)
	}
	return out
}

func currentVerifyManifestRouteCache(route verifyManifestRoute, rules []verifyManifestCacheRule, tls bool) *verifyManifestRouteCache {
	for _, candidate := range policyhost.Candidates(route.Host, tls) {
		if cache := firstVerifyManifestRouteCache(route.PathPrefix, rules, candidate); cache != nil {
			return cache
		}
	}
	return firstVerifyManifestRouteCache(route.PathPrefix, rules, "")
}

func firstVerifyManifestRouteCache(path string, rules []verifyManifestCacheRule, hostScope string) *verifyManifestRouteCache {
	for _, rule := range rules {
		if strings.TrimSpace(rule.HostScope) != strings.TrimSpace(hostScope) {
			continue
		}
		if !verifyManifestRouteMatchesCacheRule(path, rule.MatchType, rule.MatchValue) {
			continue
		}
		return &verifyManifestRouteCache{
			Mode:       rule.Kind,
			MatchType:  rule.MatchType,
			MatchValue: rule.MatchValue,
			TTLSeconds: rule.TTLSeconds,
			Vary:       append([]string(nil), rule.Vary...),
		}
	}
	return nil
}

func currentVerifyManifestRouteRateLimit(route verifyManifestRoute, file rateLimitFile, tls bool) *verifyManifestRouteRateLimit {
	scope, _ := selectVerifyManifestRateLimitScope(file, route.Host, tls)
	summary := buildVerifyManifestRateLimitScopeSummary(scope)
	out := &verifyManifestRouteRateLimit{
		DefaultPolicy: summary.Enabled && summary.DefaultPolicy.Enabled,
	}
	if out.DefaultPolicy {
		out.EffectivePolicies = append(out.EffectivePolicies, verifyManifestRouteRateLimitPolicy{
			Source:            "default",
			Limit:             summary.DefaultPolicy.Limit,
			WindowSeconds:     summary.DefaultPolicy.WindowSeconds,
			Burst:             summary.DefaultPolicy.Burst,
			KeyBy:             summary.DefaultPolicy.KeyBy,
			Status:            summary.DefaultPolicy.Action.Status,
			RetryAfterSeconds: summary.DefaultPolicy.Action.RetryAfterSeconds,
		})
	}
	for _, rule := range summary.Rules {
		if !verifyManifestRouteMatchesCacheRule(route.PathPrefix, rule.MatchType, rule.MatchValue) {
			continue
		}
		if name := strings.TrimSpace(rule.Name); name != "" {
			out.RuleNames = append(out.RuleNames, name)
		}
		if rule.Policy.Enabled {
			out.EffectivePolicies = append(out.EffectivePolicies, verifyManifestRouteRateLimitPolicy{
				Source:            strings.TrimSpace(rule.Name),
				Limit:             rule.Policy.Limit,
				WindowSeconds:     rule.Policy.WindowSeconds,
				Burst:             rule.Policy.Burst,
				KeyBy:             rule.Policy.KeyBy,
				Status:            rule.Policy.Action.Status,
				RetryAfterSeconds: rule.Policy.Action.RetryAfterSeconds,
			})
		}
	}
	if !out.DefaultPolicy && len(out.RuleNames) == 0 && len(out.EffectivePolicies) == 0 {
		return nil
	}
	return out
}

func currentVerifyManifestRouteBotDefense(route verifyManifestRoute, file botDefenseFile, tls bool) *verifyManifestRouteBotDefense {
	cfg, _ := selectVerifyManifestBotDefenseScope(file, route.Host, tls)
	pathPrefixes := normalizePathPrefixes(cfg.PathPrefixes)
	if len(pathPrefixes) == 0 {
		pathPrefixes = []string{"/"}
	}
	matched := false
	for _, prefix := range pathPrefixes {
		if verifyManifestRoutePrefixOverlap(route.PathPrefix, prefix) {
			matched = true
			break
		}
	}
	if !cfg.Enabled || !matched {
		return nil
	}
	out := &verifyManifestRouteBotDefense{
		Enabled:                   true,
		DryRun:                    cfg.DryRun,
		Mode:                      strings.TrimSpace(cfg.Mode),
		ChallengeTTLSeconds:       cfg.ChallengeTTLSeconds,
		ChallengeStatusCode:       cfg.ChallengeStatusCode,
		QuarantineStatusCode:      cfg.Quarantine.StatusCode,
		BehavioralEnabled:         cfg.BehavioralDetection.Enabled,
		BrowserSignalsEnabled:     cfg.BrowserSignals.Enabled,
		DeviceSignalsEnabled:      cfg.DeviceSignals.Enabled,
		InvisibleDeviceCheck:      cfg.DeviceSignals.Enabled && cfg.DeviceSignals.InvisibleHTMLInjection,
		HeaderSignalsEnabled:      cfg.HeaderSignals.Enabled,
		TLSSignalsEnabled:         cfg.TLSSignals.Enabled,
		QuarantineEnabled:         cfg.Quarantine.Enabled,
		ReputationFeedbackEnabled: cfg.Quarantine.Enabled && cfg.Quarantine.ReputationFeedbackSeconds > 0,
	}
	for _, policy := range cfg.PathPolicies {
		matched := false
		for _, prefix := range policy.PathPrefixes {
			if verifyManifestRoutePrefixOverlap(route.PathPrefix, prefix) {
				matched = true
				break
			}
		}
		if !matched {
			continue
		}
		if name := strings.TrimSpace(policy.Name); name != "" {
			out.PathPolicyNames = append(out.PathPolicyNames, name)
		}
		if mode := strings.TrimSpace(policy.Mode); mode != "" {
			out.Mode = mode
		}
		if policy.DryRun != nil {
			out.DryRun = *policy.DryRun
		}
		if policy.TelemetryCookieRequired {
			out.TelemetryCookieRequired = true
		}
		if policy.DisableQuarantine {
			out.DisableQuarantine = true
			out.QuarantineStatusCode = 0
		}
	}
	return out
}

func verifyManifestUsesTLS(baseURL string) bool {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err == nil {
		switch strings.ToLower(strings.TrimSpace(u.Scheme)) {
		case "https":
			return true
		case "http":
			return false
		}
	}
	return config.ServerTLSEnabled
}

func selectVerifyManifestRateLimitScope(file rateLimitFile, host string, tls bool) (rateLimitConfig, string) {
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := file.Hosts[candidate]; ok {
			return scope, candidate
		}
	}
	return file.Default, rateLimitDefaultScope
}

func selectVerifyManifestIPReputationScope(file ipReputationFile, host string, tls bool) (ipReputationConfig, string) {
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := file.Hosts[candidate]; ok {
			return scope, candidate
		}
	}
	return file.Default, ipReputationDefaultScope
}

func selectVerifyManifestSemanticScope(file semanticFile, host string, tls bool) (semanticConfig, string) {
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := file.Hosts[candidate]; ok {
			return scope, candidate
		}
	}
	return file.Default, semanticDefaultScope
}

func selectVerifyManifestBotDefenseScope(file botDefenseFile, host string, tls bool) (botDefenseConfig, string) {
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := file.Hosts[candidate]; ok {
			return scope, candidate
		}
	}
	return file.Default, botDefenseDefaultScope
}

func verifyManifestRoutePrefixOverlap(routePrefix string, candidate string) bool {
	routePrefix = normalizeVerifyManifestPathPrefix(routePrefix)
	candidate = normalizeVerifyManifestPathPrefix(candidate)
	return strings.HasPrefix(candidate, routePrefix) || strings.HasPrefix(routePrefix, candidate)
}

func verifyManifestRouteMatchesCacheRule(routePrefix string, matchType string, matchValue string) bool {
	routePrefix = normalizeVerifyManifestPathPrefix(routePrefix)
	switch strings.TrimSpace(matchType) {
	case "exact", "prefix", "":
		return verifyManifestRoutePrefixOverlap(routePrefix, matchValue)
	case "regex":
		pattern := strings.TrimSpace(matchValue)
		if pattern == "" {
			return false
		}
		re, err := compileProxyRoutePattern(pattern)
		if err != nil {
			return false
		}
		return re.MatchString(routePrefix)
	default:
		return false
	}
}

func normalizeVerifyManifestPathPrefix(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if !strings.HasPrefix(path, "/") {
		return "/" + path
	}
	return path
}

func assignVerifyManifestHashes(manifest *verifyManifest) {
	assignVerifyManifestComponentHashes(manifest)
	assignVerifyManifestHash(manifest)
}

func assignVerifyManifestComponentHashes(manifest *verifyManifest) {
	if manifest == nil {
		return
	}
	manifest.ComponentHashes = verifyManifestComponentHashes{
		WAF:                verifyManifestObjectHash(manifest.WAF),
		Security:           verifyManifestObjectHash(manifest.Security),
		CountryBlock:       verifyManifestObjectHash(manifest.CountryBlock),
		RateLimit:          verifyManifestObjectHash(manifest.RateLimit),
		IPReputation:       verifyManifestObjectHash(manifest.IPReputation),
		Semantic:           verifyManifestObjectHash(manifest.Semantic),
		BotDefense:         verifyManifestObjectHash(manifest.BotDefense),
		Routes:             verifyManifestObjectHash(manifest.Routes),
		Routing:            verifyManifestObjectHash(manifest.Routing),
		BypassRules:        verifyManifestObjectHash(manifest.BypassRules),
		CacheRules:         verifyManifestObjectHash(manifest.CacheRules),
		NormalFlows:        verifyManifestObjectHash(manifest.NormalFlows),
		AttackExpectations: verifyManifestObjectHash(manifest.AttackExpectations),
	}
}

func assignVerifyManifestRouteHashes(routes []verifyManifestRoute) {
	for i := range routes {
		clone := routes[i]
		clone.RouteHash = ""
		routes[i].RouteHash = verifyManifestObjectHash(clone)
	}
}

func assignVerifyManifestScenarioRouteHashes(normalFlows []verifyManifestExpectedFlow, attacks []verifyManifestAttackExpectation, routes []verifyManifestRoute) {
	for i := range normalFlows {
		normalFlows[i].RouteHash = verifyManifestRouteHashByName(normalFlows[i].Route, routes)
	}
	for i := range attacks {
		attacks[i].RouteHash = verifyManifestRouteHashByName(attacks[i].Route, routes)
	}
}

func verifyManifestRouteHashByName(name string, routes []verifyManifestRoute) string {
	for _, route := range routes {
		if route.Name == name {
			return route.RouteHash
		}
	}
	return ""
}

func assignVerifyManifestHash(manifest *verifyManifest) {
	if manifest == nil {
		return
	}
	clone := *manifest
	clone.ConfigHash = ""
	clone.ComponentHashes = verifyManifestComponentHashes{}
	payload, err := json.Marshal(clone)
	if err != nil {
		manifest.ConfigHash = ""
		return
	}
	sum := sha256.Sum256(payload)
	manifest.ConfigHash = hex.EncodeToString(sum[:])
}

func verifyManifestObjectHash(v any) string {
	payload, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

func currentVerifyManifestRouting(cfg ProxyRulesConfig) verifyManifestRoutingSummary {
	routing := verifyManifestRoutingSummary{
		LoadBalancingStrategy: strings.TrimSpace(cfg.LoadBalancingStrategy),
		Upstreams:             make([]verifyManifestUpstreamInfo, 0, len(cfg.Upstreams)),
		Routes:                make([]verifyManifestRouteSummary, 0, len(cfg.Routes)),
	}
	for _, upstream := range cfg.Upstreams {
		routing.Upstreams = append(routing.Upstreams, verifyManifestUpstreamInfo{
			Name:      strings.TrimSpace(upstream.Name),
			URL:       strings.TrimSpace(upstream.URL),
			Weight:    upstream.Weight,
			Enabled:   upstream.Enabled,
			HTTP2Mode: strings.TrimSpace(upstream.HTTP2Mode),
		})
	}
	for _, route := range cfg.Routes {
		routing.Routes = append(routing.Routes, verifyManifestRouteSummary{
			Name:                route.Name,
			Enabled:             route.Enabled == nil || *route.Enabled,
			Hosts:               append([]string(nil), route.Match.Hosts...),
			PathType:            routePathType(route.Match.Path),
			PathValue:           routePathValue(route.Match.Path),
			Upstream:            strings.TrimSpace(route.Action.Upstream),
			CanaryUpstream:      strings.TrimSpace(route.Action.CanaryUpstream),
			CanaryWeightPercent: route.Action.CanaryWeightPct,
			HashPolicy:          strings.TrimSpace(route.Action.HashPolicy),
			HashKey:             strings.TrimSpace(route.Action.HashKey),
		})
	}
	if cfg.DefaultRoute != nil {
		routing.DefaultRoute = &verifyManifestRouteSummary{
			Name:                cfg.DefaultRoute.Name,
			Enabled:             cfg.DefaultRoute.Enabled == nil || *cfg.DefaultRoute.Enabled,
			PathType:            "default",
			PathValue:           "/",
			Upstream:            strings.TrimSpace(cfg.DefaultRoute.Action.Upstream),
			CanaryUpstream:      strings.TrimSpace(cfg.DefaultRoute.Action.CanaryUpstream),
			CanaryWeightPercent: cfg.DefaultRoute.Action.CanaryWeightPct,
			HashPolicy:          strings.TrimSpace(cfg.DefaultRoute.Action.HashPolicy),
			HashKey:             strings.TrimSpace(cfg.DefaultRoute.Action.HashKey),
		}
	}
	return routing
}

func routePathType(path *ProxyRoutePathMatch) string {
	if path == nil {
		return ""
	}
	return strings.TrimSpace(path.Type)
}

func routePathValue(path *ProxyRoutePathMatch) string {
	if path == nil {
		return ""
	}
	return strings.TrimSpace(path.Value)
}

func currentVerifyManifestBypassRules(path string) []verifyManifestBypassRule {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil
	}
	file, err := bypassconf.Parse(string(raw))
	if err != nil {
		return nil
	}
	entries := bypassconf.GetEntries(file)
	out := make([]verifyManifestBypassRule, 0, len(entries))
	for _, entry := range entries {
		mode := "bypass"
		if strings.TrimSpace(entry.ExtraRule) != "" {
			mode = "waf_override"
		}
		out = append(out, verifyManifestBypassRule{
			Path:      entry.Path,
			Mode:      mode,
			ExtraRule: strings.TrimSpace(entry.ExtraRule),
		})
	}
	return out
}

func currentVerifyManifestCacheRules() []verifyManifestCacheRule {
	dto := cacheconf.ToDTO(cacheconf.Get())
	out := make([]verifyManifestCacheRule, 0, len(dto.Default.Rules))
	for _, rule := range dto.Default.Rules {
		out = append(out, verifyManifestCacheRule{
			Kind:       rule.Kind,
			MatchType:  rule.Match.Type,
			MatchValue: rule.Match.Value,
			Methods:    append([]string(nil), rule.Methods...),
			TTLSeconds: rule.TTL,
			Vary:       append([]string(nil), rule.Vary...),
		})
	}
	if len(dto.Hosts) == 0 {
		return out
	}
	keys := make([]string, 0, len(dto.Hosts))
	for host := range dto.Hosts {
		keys = append(keys, host)
	}
	sort.Strings(keys)
	for _, host := range keys {
		scope := dto.Hosts[host]
		for _, rule := range scope.Rules {
			out = append(out, verifyManifestCacheRule{
				HostScope:  host,
				Kind:       rule.Kind,
				MatchType:  rule.Match.Type,
				MatchValue: rule.Match.Value,
				Methods:    append([]string(nil), rule.Methods...),
				TTLSeconds: rule.TTL,
				Vary:       append([]string(nil), rule.Vary...),
			})
		}
	}
	return out
}
