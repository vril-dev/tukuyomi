package handler

import (
	"testing"
	"time"
)

func TestBuildVerifyManifestFromState(t *testing.T) {
	state := verifyManifestState{
		GeneratedAt:      time.Unix(1700000000, 0).UTC(),
		BaseURL:          "https://example.test",
		APIBasePath:      "/tukuyomi-api",
		RuleFiles:        []string{"rules/custom.conf"},
		CRSEnabled:       true,
		CountryBlock:     verifyManifestCountryBlockSummary{Enabled: true, BlockedCountries: []string{"JP"}},
		BlockedCountries: []string{"JP"},
		RateLimit: verifyManifestRateLimitSummary{
			Enabled: true,
			DefaultPolicy: verifyManifestRateLimitRulePolicy{
				Enabled:       true,
				Limit:         10,
				WindowSeconds: 60,
				Burst:         5,
				KeyBy:         "ip",
			},
			Rules: []verifyManifestRateLimitRule{
				{Name: "login", MatchType: "prefix", MatchValue: "/login"},
				{Name: "search", MatchType: "prefix", MatchValue: "/search"},
			},
		},
		RateLimitEnabled:    true,
		RateLimitRuleCount:  2,
		IPReputation:        verifyManifestIPReputationSummary{Enabled: true, FeedURLs: []string{"https://feed.example.test/ip.txt"}, EffectiveBlockCount: 4},
		IPReputationEnabled: true,
		BotDefenseEnabled:   true,
		Semantic:            verifyManifestSemanticSummary{Enabled: true, Mode: "challenge", BlockThreshold: 9},
		SemanticEnabled:     true,
		BypassRules: []verifyManifestBypassRule{
			{Path: "/healthz", Mode: "bypass"},
		},
		CacheRules: []verifyManifestCacheRule{
			{Kind: "allow", MatchType: "prefix", MatchValue: "/assets", TTLSeconds: 60},
		},
	}

	manifest := buildVerifyManifestFromState(state)
	if manifest.Product != "tukuyomi" {
		t.Fatalf("product=%q", manifest.Product)
	}
	if manifest.WAF.Engine != "coraza" {
		t.Fatalf("waf engine=%q", manifest.WAF.Engine)
	}
	if !manifest.CountryBlock.Enabled || len(manifest.CountryBlock.BlockedCountries) != 1 || manifest.CountryBlock.BlockedCountries[0] != "JP" {
		t.Fatalf("unexpected country block summary: %#v", manifest.CountryBlock)
	}
	if !manifest.RateLimit.Enabled || len(manifest.RateLimit.Rules) != 2 || manifest.RateLimit.Rules[0].Name != "login" {
		t.Fatalf("unexpected rate-limit summary: %#v", manifest.RateLimit)
	}
	if !manifest.IPReputation.Enabled || len(manifest.IPReputation.FeedURLs) != 1 || manifest.IPReputation.EffectiveBlockCount != 4 {
		t.Fatalf("unexpected ip reputation summary: %#v", manifest.IPReputation)
	}
	if !manifest.Semantic.Enabled || manifest.Semantic.Mode != "challenge" || manifest.Semantic.ChallengeStatusCode != 429 || manifest.Semantic.BlockStatusCode != 403 || manifest.Semantic.BlockThreshold != 9 {
		t.Fatalf("unexpected semantic summary: %#v", manifest.Semantic)
	}
	if manifest.ConfigHash == "" {
		t.Fatal("config hash is empty")
	}
	if manifest.ComponentHashes.Routes == "" || manifest.ComponentHashes.RateLimit == "" || manifest.ComponentHashes.BypassRules == "" {
		t.Fatalf("component hashes should be populated: %#v", manifest.ComponentHashes)
	}
	if len(manifest.BypassRules) != 1 || manifest.BypassRules[0].Path != "/healthz" {
		t.Fatalf("unexpected bypass rules: %#v", manifest.BypassRules)
	}
	if len(manifest.CacheRules) != 1 || manifest.CacheRules[0].MatchValue != "/assets" {
		t.Fatalf("unexpected cache rules: %#v", manifest.CacheRules)
	}
	if len(manifest.Routes) != 1 || manifest.Routes[0].Name != "default" || manifest.Routes[0].PathPrefix != "/" {
		t.Fatalf("unexpected routes: %#v", manifest.Routes)
	}
	if manifest.Routes[0].RouteHash == "" {
		t.Fatalf("expected route hash: %#v", manifest.Routes[0])
	}
	if manifest.Routes[0].Host != "example.test" || manifest.Routes[0].RouteMode != "block" || manifest.Routes[0].MatchType != "prefix" || manifest.Routes[0].MatchValue != "/" {
		t.Fatalf("unexpected route match summary: %#v", manifest.Routes[0])
	}
	if !manifest.Routes[0].Bypass || len(manifest.Routes[0].BypassModes) != 1 || manifest.Routes[0].BypassModes[0] != "bypass" {
		t.Fatalf("unexpected route bypass summary: %#v", manifest.Routes[0])
	}
	if manifest.Routes[0].Cache == nil || manifest.Routes[0].Cache.Mode != "allow" || manifest.Routes[0].Cache.MatchValue != "/assets" {
		t.Fatalf("unexpected route cache summary: %#v", manifest.Routes[0].Cache)
	}
	if manifest.Routes[0].Security == nil || !manifest.Routes[0].Security.CountryBlockEnabled || manifest.Routes[0].Security.BlockedCountriesCount != 1 || manifest.Routes[0].Security.CountryBlockStatusCode != 403 || !manifest.Routes[0].Security.IPReputationEnabled || manifest.Routes[0].Security.IPReputationBlockStatus != 0 || !manifest.Routes[0].Security.SemanticEnabled || manifest.Routes[0].Security.SemanticMode != "challenge" || manifest.Routes[0].Security.SemanticChallengeStatus != 429 || manifest.Routes[0].Security.SemanticBlockStatus != 403 || manifest.Routes[0].Security.SemanticChallengeThreshold != 0 || manifest.Routes[0].Security.SemanticBlockThreshold != 9 {
		t.Fatalf("unexpected route security summary: %#v", manifest.Routes[0].Security)
	}
	if manifest.Routes[0].RateLimit == nil || !manifest.Routes[0].RateLimit.DefaultPolicy || len(manifest.Routes[0].RateLimit.RuleNames) != 2 {
		t.Fatalf("unexpected route rate-limit summary: %#v", manifest.Routes[0].RateLimit)
	}
	if len(manifest.Routes[0].RateLimit.EffectivePolicies) != 1 || manifest.Routes[0].RateLimit.EffectivePolicies[0].Source != "default" || manifest.Routes[0].RateLimit.EffectivePolicies[0].Limit != 10 {
		t.Fatalf("unexpected route rate-limit policies: %#v", manifest.Routes[0].RateLimit.EffectivePolicies)
	}
	if manifest.Routes[0].BotDefense != nil {
		t.Fatalf("unexpected route bot-defense summary: %#v", manifest.Routes[0].BotDefense)
	}
	if len(manifest.NormalFlows) != 0 || len(manifest.AttackExpectations) != 0 {
		t.Fatalf("expected empty scaffolding arrays: %#v %#v", manifest.NormalFlows, manifest.AttackExpectations)
	}
}

func TestBuildVerifyManifestFromState_DerivesRicherBotDefenseScenarios(t *testing.T) {
	state := verifyManifestState{
		GeneratedAt: time.Unix(1700000000, 0).UTC(),
		BaseURL:     "https://example.test",
		APIBasePath: "/tukuyomi-api",
		BotDefenseConfig: botDefenseConfig{
			Enabled:              true,
			Mode:                 botDefenseModeAlways,
			ChallengeStatusCode:  429,
			ChallengeTTLSeconds:  900,
			ExemptCIDRs:          []string{"10.0.0.0/8"},
			SuspiciousUserAgents: []string{"curl", "python"},
			BehavioralDetection: botDefenseBehavioralConfig{
				Enabled:             true,
				WindowSeconds:       60,
				BurstThreshold:      8,
				PathFanoutThreshold: 4,
				ScoreThreshold:      1,
				RiskScorePerSignal:  2,
			},
			PathPolicies: []botDefensePathPolicyConfig{
				{
					Name:         "login",
					PathPrefixes: []string{"/login"},
				},
			},
		},
	}

	manifest := buildVerifyManifestFromState(state)
	if manifest.BotDefense.BehavioralDetection == nil || !manifest.BotDefense.BehavioralDetection.Enabled || manifest.BotDefense.BehavioralDetection.WindowSeconds != 60 {
		t.Fatalf("unexpected bot defense behavioral summary: %#v", manifest.BotDefense.BehavioralDetection)
	}
	if manifest.BotDefense.ChallengeTTLSeconds != 900 || len(manifest.BotDefense.ExemptCIDRs) != 1 || len(manifest.BotDefense.SuspiciousUserAgents) != 2 {
		t.Fatalf("unexpected bot defense summary: %#v", manifest.BotDefense)
	}
	if manifest.Routes[0].BotDefense == nil || !manifest.Routes[0].BotDefense.Enabled || manifest.Routes[0].BotDefense.Mode != botDefenseModeAlways || manifest.Routes[0].BotDefense.ChallengeStatusCode != 429 || manifest.Routes[0].BotDefense.ChallengeTTLSeconds != 900 || !manifest.Routes[0].BotDefense.BehavioralEnabled || len(manifest.Routes[0].BotDefense.PathPolicyNames) != 1 || manifest.Routes[0].BotDefense.PathPolicyNames[0] != "login" {
		t.Fatalf("unexpected route bot-defense policy summary: %#v", manifest.Routes[0].BotDefense)
	}
	if len(manifest.NormalFlows) != 1 {
		t.Fatalf("unexpected normal flows: %#v", manifest.NormalFlows)
	}
	flow := manifest.NormalFlows[0]
	if flow.Route != "default" || flow.ExecutionMode != "browser" {
		t.Fatalf("unexpected normal flow metadata: %#v", flow)
	}
	if flow.Assertions == nil || len(flow.Assertions.FinalURLPrefixes) != 1 || flow.Assertions.FinalURLPrefixes[0] != "/" {
		t.Fatalf("unexpected normal flow assertions: %#v", flow.Assertions)
	}
	if flow.RouteHash == "" {
		t.Fatalf("expected normal flow route hash: %#v", flow)
	}
	if flow.Request == nil || flow.Request.Headers["Host"] != "example.test" {
		t.Fatalf("unexpected normal flow request: %#v", flow.Request)
	}
	if len(manifest.AttackExpectations) != 1 {
		t.Fatalf("unexpected attack expectations: %#v", manifest.AttackExpectations)
	}
	attack := manifest.AttackExpectations[0]
	if !attack.UseBrowser || attack.Route != "default" || attack.Technique != "bot_like_navigation" {
		t.Fatalf("unexpected attack metadata: %#v", attack)
	}
	if attack.Assertions == nil || len(attack.Assertions.StatusCodes) != 1 || attack.Assertions.StatusCodes[0] != 429 || len(attack.Assertions.FinalURLPrefixes) != 1 || attack.Assertions.FinalURLPrefixes[0] != "/" {
		t.Fatalf("expected challenge assertions, got %#v", attack.Assertions)
	}
	if attack.RouteHash == "" {
		t.Fatalf("expected attack route hash: %#v", attack)
	}
	if attack.Request == nil || attack.Request.Headers["Host"] != "example.test" {
		t.Fatalf("unexpected attack request: %#v", attack.Request)
	}
}

func TestBuildVerifyManifestFromState_UsesConcretePathForTrailingPrefix(t *testing.T) {
	state := verifyManifestState{
		GeneratedAt: time.Unix(1700000000, 0).UTC(),
		BaseURL:     "https://example.test",
		BotDefenseConfig: botDefenseConfig{
			Enabled:      true,
			PathPrefixes: []string{"/v1/"},
		},
	}

	manifest := buildVerifyManifestFromState(state)
	if len(manifest.NormalFlows) != 1 {
		t.Fatalf("unexpected normal flows: %#v", manifest.NormalFlows)
	}
	if got := manifest.NormalFlows[0].Path; got != "/v1/health" {
		t.Fatalf("NormalFlows[0].Path = %q", got)
	}
}
