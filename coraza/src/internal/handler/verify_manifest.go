package handler

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
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
	CountryBlockEnabled             bool `json:"country_block_enabled"`
	RateLimitEnabled                bool `json:"rate_limit_enabled"`
	RateLimitRuleCount              int  `json:"rate_limit_rule_count"`
	IPReputationEnabled             bool `json:"ip_reputation_enabled"`
	BotDefenseEnabled               bool `json:"bot_defense_enabled"`
	BotDefenseDryRunEnabled         bool `json:"bot_defense_dry_run_enabled"`
	BotDefensePathPolicyCount       int  `json:"bot_defense_path_policy_count"`
	BotDefensePathPolicyDryRunCount int  `json:"bot_defense_path_policy_dry_run_count"`
	BotDefenseBehavioralEnabled     bool `json:"bot_defense_behavioral_enabled"`
	SemanticEnabled                 bool `json:"semantic_enabled"`
}

type verifyManifestCountryBlockSummary struct {
	Enabled          bool     `json:"enabled"`
	BlockedCountries []string `json:"blocked_countries,omitempty"`
}

type verifyManifestRateLimitSummary struct {
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
}

type verifyManifestSemanticSummary struct {
	Enabled                     bool     `json:"enabled"`
	Mode                        string   `json:"mode,omitempty"`
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
}

type verifyManifestBotDefensePathPolicy struct {
	Name                       string   `json:"name"`
	PathPrefixes               []string `json:"path_prefixes,omitempty"`
	Mode                       string   `json:"mode,omitempty"`
	DryRun                     *bool    `json:"dry_run,omitempty"`
	RiskScoreMultiplierPercent int      `json:"risk_score_multiplier_percent,omitempty"`
	RiskScoreOffset            int      `json:"risk_score_offset,omitempty"`
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

type verifyManifestRoutingSummary struct {
	Routes []verifyManifestRouteSummary `json:"routes"`
}

type verifyManifestRouteSummary struct {
	Name       string   `json:"name"`
	MatchType  string   `json:"match_type"`
	MatchValue string   `json:"match_value"`
	Methods    []string `json:"methods,omitempty"`
	Mode       string   `json:"mode"`
}

type verifyManifestBypassRule struct {
	Path      string `json:"path"`
	Mode      string `json:"mode"`
	ExtraRule string `json:"extra_rule,omitempty"`
}

type verifyManifestCacheRule struct {
	Kind       string   `json:"kind"`
	MatchType  string   `json:"match_type"`
	MatchValue string   `json:"match_value"`
	Methods    []string `json:"methods,omitempty"`
	TTLSeconds int      `json:"ttl_seconds,omitempty"`
	Vary       []string `json:"vary,omitempty"`
}

type verifyManifestRoute struct {
	Name        string                         `json:"name"`
	RouteHash   string                         `json:"route_hash,omitempty"`
	Host        string                         `json:"host,omitempty"`
	RouteMode   string                         `json:"route_mode,omitempty"`
	MatchType   string                         `json:"match_type,omitempty"`
	MatchValue  string                         `json:"match_value,omitempty"`
	Methods     []string                       `json:"methods,omitempty"`
	PathPrefix  string                         `json:"path_prefix"`
	WAFMode     string                         `json:"waf_mode"`
	Bypass      bool                           `json:"bypass,omitempty"`
	BypassModes []string                       `json:"bypass_modes,omitempty"`
	Cache       *verifyManifestRouteCache      `json:"cache,omitempty"`
	RateLimit   *verifyManifestRouteRateLimit  `json:"rate_limit,omitempty"`
	BotDefense  *verifyManifestRouteBotDefense `json:"bot_defense,omitempty"`
	Security    *verifyManifestRouteSecurity   `json:"security,omitempty"`
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
	Enabled             bool     `json:"enabled"`
	DryRun              bool     `json:"dry_run,omitempty"`
	Mode                string   `json:"mode,omitempty"`
	ChallengeTTLSeconds int      `json:"challenge_ttl_seconds,omitempty"`
	ChallengeStatusCode int      `json:"challenge_status_code,omitempty"`
	BehavioralEnabled   bool     `json:"behavioral_enabled,omitempty"`
	PathPolicyNames     []string `json:"path_policy_names,omitempty"`
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
	GeneratedAt                     time.Time
	BaseURL                         string
	APIBasePath                     string
	RuleFiles                       []string
	CRSEnabled                      bool
	CountryBlock                    verifyManifestCountryBlockSummary
	BlockedCountries                []string
	RateLimit                       verifyManifestRateLimitSummary
	RateLimitEnabled                bool
	RateLimitRuleCount              int
	IPReputation                    verifyManifestIPReputationSummary
	IPReputationEnabled             bool
	BotDefenseEnabled               bool
	BotDefenseDryRunEnabled         bool
	BotDefensePathPolicyCount       int
	BotDefensePathPolicyDryRunCount int
	BotDefenseBehavioralEnabled     bool
	BotDefenseConfig                botDefenseConfig
	Semantic                        verifyManifestSemanticSummary
	SemanticEnabled                 bool
	BypassRules                     []verifyManifestBypassRule
	CacheRules                      []verifyManifestCacheRule
}

func GetVerifyManifest(c *gin.Context) {
	blockedCountries := GetBlockedCountries()
	rateLimitCfg := GetRateLimitConfig()
	ipReputationCfg := GetIPReputationConfig()
	ipReputationStatus := IPReputationStatus()
	botDefenseCfg := GetBotDefenseConfig()
	semanticCfg := GetSemanticConfig()
	c.JSON(http.StatusOK, buildVerifyManifestFromState(verifyManifestState{
		GeneratedAt:                     time.Now().UTC(),
		BaseURL:                         strings.TrimSpace(config.AppURL),
		APIBasePath:                     config.APIBasePath,
		RuleFiles:                       configuredRuleFiles(),
		CRSEnabled:                      config.CRSEnable,
		CountryBlock:                    buildVerifyManifestCountryBlockSummary(blockedCountries),
		BlockedCountries:                blockedCountries,
		RateLimit:                       buildVerifyManifestRateLimitSummary(rateLimitCfg),
		RateLimitEnabled:                rateLimitCfg.Enabled,
		RateLimitRuleCount:              len(rateLimitCfg.Rules),
		IPReputation:                    buildVerifyManifestIPReputationSummary(ipReputationCfg, ipReputationStatus),
		IPReputationEnabled:             ipReputationStatus.Enabled,
		BotDefenseEnabled:               botDefenseCfg.Enabled,
		BotDefenseDryRunEnabled:         botDefenseCfg.DryRun,
		BotDefensePathPolicyCount:       len(botDefenseCfg.PathPolicies),
		BotDefensePathPolicyDryRunCount: countBotDefensePathPoliciesDryRun(botDefenseCfg),
		BotDefenseBehavioralEnabled:     botDefenseCfg.BehavioralDetection.Enabled,
		BotDefenseConfig:                botDefenseCfg,
		Semantic:                        buildVerifyManifestSemanticSummary(semanticCfg),
		SemanticEnabled:                 semanticCfg.Enabled,
		BypassRules:                     currentVerifyManifestBypassRules(config.BypassFile),
		CacheRules:                      currentVerifyManifestCacheRules(),
	}))
}

func buildVerifyManifestFromState(state verifyManifestState) verifyManifest {
	state.Semantic = normalizeVerifyManifestSemanticSummary(state.Semantic)
	routes := decorateVerifyManifestRoutes([]verifyManifestRoute{{
		Name:       "default",
		Host:       verifyManifestHostFromBaseURL(state.BaseURL),
		RouteMode:  "block",
		MatchType:  "prefix",
		MatchValue: "/",
		PathPrefix: "/",
		WAFMode:    "block",
	}}, state.BypassRules, state.CacheRules, state.RateLimit, state.BotDefenseConfig, state.CountryBlock, state.IPReputation, state.Semantic)
	normalFlows, attackExpectations := deriveVerifyManifestBotDefenseScenarios(state.BotDefenseConfig, routes, state.BaseURL)
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
			CountryBlockEnabled:             len(state.BlockedCountries) > 0,
			RateLimitEnabled:                state.RateLimitEnabled,
			RateLimitRuleCount:              state.RateLimitRuleCount,
			IPReputationEnabled:             state.IPReputationEnabled,
			BotDefenseEnabled:               state.BotDefenseEnabled,
			BotDefenseDryRunEnabled:         state.BotDefenseDryRunEnabled,
			BotDefensePathPolicyCount:       state.BotDefensePathPolicyCount,
			BotDefensePathPolicyDryRunCount: state.BotDefensePathPolicyDryRunCount,
			BotDefenseBehavioralEnabled:     state.BotDefenseBehavioralEnabled,
			SemanticEnabled:                 state.SemanticEnabled,
		},
		BotDefense: buildVerifyManifestBotDefenseSummary(state.BotDefenseConfig),
		Routes:     routes,
		Routing: verifyManifestRoutingSummary{
			Routes: []verifyManifestRouteSummary{
				{
					Name:       "default",
					MatchType:  "prefix",
					MatchValue: "/",
					Mode:       "block",
				},
			},
		},
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

func buildVerifyManifestBotDefenseSummary(cfg botDefenseConfig) verifyManifestBotDefenseSummary {
	out := verifyManifestBotDefenseSummary{
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
	}
	for _, policy := range cfg.PathPolicies {
		out.PathPolicies = append(out.PathPolicies, verifyManifestBotDefensePathPolicy{
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

func buildVerifyManifestCountryBlockSummary(blocked []string) verifyManifestCountryBlockSummary {
	out := verifyManifestCountryBlockSummary{
		Enabled:          len(blocked) > 0,
		BlockedCountries: append([]string(nil), blocked...),
	}
	return out
}

func buildVerifyManifestRateLimitSummary(cfg rateLimitConfig) verifyManifestRateLimitSummary {
	out := verifyManifestRateLimitSummary{
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

func buildVerifyManifestIPReputationSummary(cfg ipReputationConfig, status ipReputationStatusSnapshot) verifyManifestIPReputationSummary {
	return verifyManifestIPReputationSummary{
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
	}
}

func buildVerifyManifestSemanticSummary(cfg semanticConfig) verifyManifestSemanticSummary {
	return verifyManifestSemanticSummary{
		Enabled:                     cfg.Enabled,
		Mode:                        cfg.Mode,
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

func deriveVerifyManifestBotDefenseScenarios(cfg botDefenseConfig, routes []verifyManifestRoute, baseURL string) ([]verifyManifestExpectedFlow, []verifyManifestAttackExpectation) {
	if !cfg.Enabled {
		return []verifyManifestExpectedFlow{}, []verifyManifestAttackExpectation{}
	}
	normalFlows := make([]verifyManifestExpectedFlow, 0, len(cfg.PathPolicies)+1)
	attacks := make([]verifyManifestAttackExpectation, 0, len(cfg.PathPolicies)+1)
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
			Request:       verifyManifestRouteRequest(path, routes, baseURL),
			Assertions:    verifyManifestRouteAssertions(path, routes),
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
			Request:     verifyManifestRouteRequest(path, routes, baseURL),
			Assertions:  mergeVerifyManifestScenarioAssertions(verifyManifestRouteAssertions(path, routes), verifyManifestExpectedActionAssertions(expect, route)),
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

func resolveVerifyManifestRouteName(path string, routes []verifyManifestRoute) string {
	bestName := "default"
	bestLen := -1
	for _, route := range routes {
		prefix := strings.TrimSpace(route.MatchValue)
		if prefix == "" {
			prefix = strings.TrimSpace(route.PathPrefix)
		}
		if prefix == "" {
			prefix = "/"
		}
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		if len(prefix) > bestLen {
			bestLen = len(prefix)
			bestName = route.Name
		}
	}
	return bestName
}

func verifyManifestChallengeAssertions(expect string, statusCode int) *verifyManifestScenarioAssertions {
	if expect != "challenge" || statusCode == 0 {
		return nil
	}
	return &verifyManifestScenarioAssertions{
		StatusCodes: []int{statusCode},
	}
}

func verifyManifestRouteAssertions(path string, routes []verifyManifestRoute) *verifyManifestScenarioAssertions {
	return verifyManifestRouteAssertionsFromRoute(verifyManifestRouteByPath(path, routes))
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
		if route.Security != nil && route.Security.IPReputationBlockStatus > 0 {
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
	routeName := resolveVerifyManifestRouteName(path, routes)
	for i := range routes {
		if routes[i].Name == routeName {
			return &routes[i]
		}
	}
	return nil
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

func verifyManifestRouteRequest(path string, routes []verifyManifestRoute, baseURL string) *verifyManifestScenarioRequest {
	routeName := resolveVerifyManifestRouteName(path, routes)
	host := ""
	for _, route := range routes {
		if route.Name == routeName && strings.TrimSpace(route.Host) != "" {
			host = strings.TrimSpace(route.Host)
			break
		}
	}
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

func currentVerifyManifestBypassRules(path string) []verifyManifestBypassRule {
	raw, err := os.ReadFile(strings.TrimSpace(path))
	if err != nil {
		return nil
	}
	entries, err := bypassconf.Parse(string(raw))
	if err != nil {
		return nil
	}
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
	out := make([]verifyManifestCacheRule, 0, len(dto))
	for _, rule := range dto {
		out = append(out, verifyManifestCacheRule{
			Kind:       rule.Kind,
			MatchType:  rule.Match.Type,
			MatchValue: rule.Match.Value,
			Methods:    append([]string(nil), rule.Methods...),
			TTLSeconds: rule.TTL,
			Vary:       append([]string(nil), rule.Vary...),
		})
	}
	return out
}

func decorateVerifyManifestRoutes(routes []verifyManifestRoute, bypassRules []verifyManifestBypassRule, cacheRules []verifyManifestCacheRule, rateLimit verifyManifestRateLimitSummary, botDefense botDefenseConfig, country verifyManifestCountryBlockSummary, ipReputation verifyManifestIPReputationSummary, semantic verifyManifestSemanticSummary) []verifyManifestRoute {
	out := make([]verifyManifestRoute, 0, len(routes))
	for _, route := range routes {
		route.BypassModes = currentVerifyManifestRouteBypassModes(route, bypassRules)
		route.Bypass = len(route.BypassModes) > 0
		route.Cache = currentVerifyManifestRouteCache(route, cacheRules)
		route.RateLimit = currentVerifyManifestRouteRateLimit(route, rateLimit)
		route.BotDefense = currentVerifyManifestRouteBotDefense(route, botDefense)
		route.Security = currentVerifyManifestRouteSecurity(country, ipReputation, semantic)
		out = append(out, route)
	}
	return out
}

func currentVerifyManifestRouteSecurity(country verifyManifestCountryBlockSummary, ipReputation verifyManifestIPReputationSummary, semantic verifyManifestSemanticSummary) *verifyManifestRouteSecurity {
	return &verifyManifestRouteSecurity{
		CountryBlockEnabled:        country.Enabled,
		BlockedCountriesCount:      len(country.BlockedCountries),
		CountryBlockStatusCode:     http.StatusForbidden,
		IPReputationEnabled:        ipReputation.Enabled,
		IPReputationFailOpen:       ipReputation.FailOpen,
		IPReputationBlockStatus:    ipReputation.BlockStatusCode,
		SemanticEnabled:            semantic.Enabled,
		SemanticMode:               strings.TrimSpace(semantic.Mode),
		SemanticChallengeStatus:    semantic.ChallengeStatusCode,
		SemanticBlockStatus:        semantic.BlockStatusCode,
		SemanticChallengeThreshold: semantic.ChallengeThreshold,
		SemanticBlockThreshold:     semantic.BlockThreshold,
	}
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

func currentVerifyManifestRouteCache(route verifyManifestRoute, rules []verifyManifestCacheRule) *verifyManifestRouteCache {
	for _, rule := range rules {
		if !verifyManifestRouteMatchesCacheRule(route.PathPrefix, rule.MatchType, rule.MatchValue) {
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

func currentVerifyManifestRouteRateLimit(route verifyManifestRoute, summary verifyManifestRateLimitSummary) *verifyManifestRouteRateLimit {
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

func currentVerifyManifestRouteBotDefense(route verifyManifestRoute, cfg botDefenseConfig) *verifyManifestRouteBotDefense {
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
		Enabled:             true,
		DryRun:              cfg.DryRun,
		Mode:                strings.TrimSpace(cfg.Mode),
		ChallengeTTLSeconds: cfg.ChallengeTTLSeconds,
		ChallengeStatusCode: cfg.ChallengeStatusCode,
		BehavioralEnabled:   cfg.BehavioralDetection.Enabled,
	}
	for _, policy := range cfg.PathPolicies {
		for _, prefix := range policy.PathPrefixes {
			if !verifyManifestRoutePrefixOverlap(route.PathPrefix, prefix) {
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
			break
		}
	}
	return out
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
		re, err := regexp.Compile(pattern)
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
