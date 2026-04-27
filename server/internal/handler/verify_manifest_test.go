package handler

import (
	"testing"
	"time"
)

func TestBuildVerifyManifestFromState(t *testing.T) {
	rateLimitFile := rateLimitFile{
		Default: rateLimitConfig{
			Enabled: true,
			DefaultPolicy: rateLimitPolicy{
				Enabled:       true,
				Limit:         20,
				WindowSeconds: 60,
				Burst:         10,
				KeyBy:         "ip",
			},
			Rules: []rateLimitRule{
				{Name: "login", MatchType: "prefix", MatchValue: "/login"},
				{Name: "search", MatchType: "prefix", MatchValue: "/search"},
			},
		},
		Hosts: map[string]rateLimitConfig{
			"example.test": {
				Enabled: true,
				DefaultPolicy: rateLimitPolicy{
					Enabled:       true,
					Limit:         5,
					WindowSeconds: 30,
					Burst:         1,
					KeyBy:         "ip",
				},
			},
		},
	}
	ipReputationFile := ipReputationFile{
		Default: ipReputationConfig{
			Enabled:           true,
			FeedURLs:          []string{"https://feed.example.test/bot.txt"},
			RequestTimeoutSec: 5,
		},
		Hosts: map[string]ipReputationConfig{
			"example.test": {
				Enabled:         true,
				FeedURLs:        []string{"https://feed.example.test/app.txt"},
				BlockStatusCode: 451,
				FailOpen:        true,
			},
		},
	}
	botDefenseCfg := botDefenseConfig{
		Enabled:              true,
		DryRun:               false,
		Mode:                 botDefenseModeAlways,
		PathPrefixes:         []string{"/", "/login"},
		ExemptCIDRs:          []string{"10.0.0.0/8"},
		SuspiciousUserAgents: []string{"curl", "python"},
		ChallengeStatusCode:  429,
		ChallengeTTLSeconds:  900,
		BehavioralDetection: botDefenseBehavioralConfig{
			Enabled:             true,
			WindowSeconds:       60,
			BurstThreshold:      8,
			PathFanoutThreshold: 4,
			UAChurnThreshold:    3,
			ScoreThreshold:      1,
			RiskScorePerSignal:  2,
		},
		BrowserSignals: botDefenseBrowserSignalsConfig{
			Enabled:            true,
			JSCookieName:       "__tukuyomi_bot_js",
			ScoreThreshold:     1,
			RiskScorePerSignal: 2,
		},
		DeviceSignals: botDefenseDeviceSignalsConfig{
			Enabled:                    true,
			RequireTimeZone:            true,
			RequirePlatform:            true,
			RequireHardwareConcurrency: true,
			CheckMobileTouch:           true,
			InvisibleHTMLInjection:     true,
			InvisibleMaxBodyBytes:      16384,
			ScoreThreshold:             1,
			RiskScorePerSignal:         2,
		},
		HeaderSignals: botDefenseHeaderSignalsConfig{
			Enabled:               true,
			RequireAcceptLanguage: true,
			ScoreThreshold:        1,
			RiskScorePerSignal:    2,
		},
		TLSSignals: botDefenseTLSSignalsConfig{
			Enabled:            true,
			RequireSNI:         true,
			ScoreThreshold:     1,
			RiskScorePerSignal: 2,
		},
		Quarantine: botDefenseQuarantineConfig{
			Enabled:                   true,
			Threshold:                 10,
			StrikesRequired:           3,
			StrikeWindowSeconds:       300,
			TTLSeconds:                600,
			StatusCode:                429,
			ReputationFeedbackSeconds: 120,
		},
		PathPolicies: []botDefensePathPolicyConfig{
			{
				Name:                    "login",
				PathPrefixes:            []string{"/login"},
				Mode:                    botDefenseModeAlways,
				DryRun:                  boolPtr(true),
				TelemetryCookieRequired: true,
			},
		},
	}
	semanticFile := semanticFile{
		Default: semanticConfig{
			Enabled:            true,
			Mode:               "challenge",
			Provider:           semanticProviderConfig{Enabled: true, Name: semanticProviderNameBuiltinAttackFamily, TimeoutMS: 25},
			ChallengeThreshold: 7,
		},
		Hosts: map[string]semanticConfig{
			"example.test": {
				Enabled:            true,
				Mode:               "block",
				ChallengeThreshold: 6,
				BlockThreshold:     11,
			},
		},
	}
	state := verifyManifestState{
		GeneratedAt:                      time.Unix(1700000000, 0).UTC(),
		BaseURL:                          "https://example.test",
		APIBasePath:                      "/tukuyomi-api",
		RuleFiles:                        []string{"rules/custom.conf"},
		CRSEnabled:                       true,
		CountryBlock:                     verifyManifestCountryBlockSummary{Enabled: true, BlockedCountries: []string{"JP"}},
		BlockedCountries:                 []string{"JP"},
		RateLimit:                        buildVerifyManifestRateLimitSummary(rateLimitFile),
		RateLimitFile:                    rateLimitFile,
		RateLimitEnabled:                 true,
		RateLimitRuleCount:               2,
		IPReputation:                     buildVerifyManifestIPReputationSummary(ipReputationFile, ipReputationStatusSnapshot{DynamicPenaltyCount: 2}, map[string]ipReputationStatusSnapshot{"example.test": {EffectiveBlockCount: 1, BlockStatusCode: 451, FailOpen: true}}),
		IPReputationFile:                 ipReputationFile,
		IPReputationEnabled:              true,
		BotDefenseEnabled:                true,
		BotDefenseDryRunEnabled:          true,
		BotDefensePathPolicyCount:        1,
		BotDefensePathPolicyDryRunCount:  1,
		BotDefenseBehavioralEnabled:      true,
		BotDefenseBrowserSignalsEnabled:  true,
		BotDefenseDeviceSignalsEnabled:   true,
		BotDefenseDeviceInvisibleEnabled: true,
		BotDefenseHeaderSignalsEnabled:   true,
		BotDefenseTLSSignalsEnabled:      true,
		BotDefenseQuarantineEnabled:      true,
		BotDefenseFile:                   botDefenseFile{Default: botDefenseCfg},
		BotDefenseConfig:                 botDefenseCfg,
		Semantic:                         buildVerifyManifestSemanticSummary(semanticFile),
		SemanticFile:                     semanticFile,
		SemanticEnabled:                  true,
		Routing: verifyManifestRoutingSummary{
			LoadBalancingStrategy: "round_robin",
			Upstreams: []verifyManifestUpstreamInfo{
				{Name: "primary", URL: "https://upstream.example.test", Weight: 1, Enabled: true},
			},
			Routes: []verifyManifestRouteSummary{
				{Name: "app", Enabled: true, Hosts: []string{"example.test"}, PathType: "prefix", PathValue: "/app", Upstream: "blue", CanaryUpstream: "green", CanaryWeightPercent: 5, HashPolicy: "header", HashKey: "X-Session-ID"},
			},
		},
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
	if manifest.BaseURL != "https://example.test" {
		t.Fatalf("unexpected base url: %q", manifest.BaseURL)
	}
	if manifest.ConfigHash == "" {
		t.Fatal("config hash is empty")
	}
	if manifest.ComponentHashes.Routes == "" || manifest.ComponentHashes.BotDefense == "" || manifest.ComponentHashes.AttackExpectations == "" {
		t.Fatalf("component hashes should be populated: %#v", manifest.ComponentHashes)
	}
	if !manifest.CountryBlock.Enabled || len(manifest.CountryBlock.BlockedCountries) != 1 || manifest.CountryBlock.BlockedCountries[0] != "JP" {
		t.Fatalf("unexpected country block summary: %#v", manifest.CountryBlock)
	}
	if !manifest.RateLimit.Default.Enabled || len(manifest.RateLimit.Default.Rules) != 2 || manifest.RateLimit.Default.Rules[0].Name != "login" {
		t.Fatalf("unexpected rate-limit summary: %#v", manifest.RateLimit)
	}
	if hostScope := manifest.RateLimit.Hosts["example.test"]; !hostScope.Enabled || hostScope.DefaultPolicy.Limit != 5 {
		t.Fatalf("unexpected host-scoped rate-limit summary: %#v", manifest.RateLimit.Hosts)
	}
	if !manifest.IPReputation.Default.Enabled || len(manifest.IPReputation.Default.FeedURLs) != 1 || manifest.IPReputation.Default.DynamicPenaltyCount != 2 {
		t.Fatalf("unexpected ip reputation summary: %#v", manifest.IPReputation)
	}
	if hostScope := manifest.IPReputation.Hosts["example.test"]; !hostScope.Enabled || hostScope.BlockStatusCode != 451 || !hostScope.FailOpen {
		t.Fatalf("unexpected host-scoped ip reputation summary: %#v", manifest.IPReputation.Hosts)
	}
	if !manifest.Semantic.Default.Enabled || manifest.Semantic.Default.Mode != "challenge" || !manifest.Semantic.Default.ProviderEnabled || manifest.Semantic.Default.ProviderName != semanticProviderNameBuiltinAttackFamily || manifest.Semantic.Default.ProviderTimeoutMS != 25 || manifest.Semantic.Default.ChallengeStatusCode != 429 || manifest.Semantic.Default.BlockStatusCode != 403 || manifest.Semantic.Default.ChallengeThreshold != 7 {
		t.Fatalf("unexpected semantic summary: %#v", manifest.Semantic)
	}
	if hostScope := manifest.Semantic.Hosts["example.test"]; !hostScope.Enabled || hostScope.Mode != "block" || hostScope.BlockThreshold != 11 {
		t.Fatalf("unexpected host-scoped semantic summary: %#v", manifest.Semantic.Hosts)
	}
	if len(manifest.Routing.Upstreams) != 1 || manifest.Routing.Upstreams[0].URL != "https://upstream.example.test" {
		t.Fatalf("unexpected upstreams: %#v", manifest.Routing.Upstreams)
	}
	if len(manifest.Routes) == 0 || manifest.Routes[0].RouteHash == "" {
		t.Fatalf("expected route hash: %#v", manifest.Routes)
	}
	if !manifest.Security.BotDefenseBehavioralEnabled {
		t.Fatalf("expected behavioral bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseBrowserSignalsEnabled {
		t.Fatalf("expected browser-signals bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseDeviceSignalsEnabled {
		t.Fatalf("expected device-signals bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseDeviceInvisibleEnabled {
		t.Fatalf("expected invisible device-check flag to be present: %#v", manifest.Security)
	}
	if manifest.Security.BotDefensePathPolicyCount != 1 {
		t.Fatalf("expected path policy count to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseDryRunEnabled || manifest.Security.BotDefensePathPolicyDryRunCount != 1 {
		t.Fatalf("expected dry-run bot defense flags to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseHeaderSignalsEnabled {
		t.Fatalf("expected header-signals bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseTLSSignalsEnabled {
		t.Fatalf("expected tls-signals bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.Security.BotDefenseQuarantineEnabled {
		t.Fatalf("expected quarantine bot defense flag to be present: %#v", manifest.Security)
	}
	if !manifest.BotDefense.Default.Enabled || manifest.BotDefense.Default.Mode != botDefenseModeAlways {
		t.Fatalf("unexpected bot defense summary: %#v", manifest.BotDefense)
	}
	if manifest.BotDefense.Default.BehavioralDetection == nil || !manifest.BotDefense.Default.BehavioralDetection.Enabled || manifest.BotDefense.Default.BehavioralDetection.WindowSeconds != 60 {
		t.Fatalf("unexpected behavioral summary: %#v", manifest.BotDefense.Default.BehavioralDetection)
	}
	if manifest.BotDefense.Default.BrowserSignals == nil || !manifest.BotDefense.Default.BrowserSignals.Enabled || manifest.BotDefense.Default.BrowserSignals.JSCookieName != "__tukuyomi_bot_js" {
		t.Fatalf("unexpected browser summary: %#v", manifest.BotDefense.Default.BrowserSignals)
	}
	if manifest.BotDefense.Default.DeviceSignals == nil || !manifest.BotDefense.Default.DeviceSignals.Enabled || !manifest.BotDefense.Default.DeviceSignals.InvisibleHTMLInjection {
		t.Fatalf("unexpected device summary: %#v", manifest.BotDefense.Default.DeviceSignals)
	}
	if manifest.BotDefense.Default.HeaderSignals == nil || !manifest.BotDefense.Default.HeaderSignals.Enabled || !manifest.BotDefense.Default.HeaderSignals.RequireAcceptLanguage {
		t.Fatalf("unexpected header summary: %#v", manifest.BotDefense.Default.HeaderSignals)
	}
	if manifest.BotDefense.Default.TLSSignals == nil || !manifest.BotDefense.Default.TLSSignals.Enabled || !manifest.BotDefense.Default.TLSSignals.RequireSNI {
		t.Fatalf("unexpected tls summary: %#v", manifest.BotDefense.Default.TLSSignals)
	}
	if manifest.BotDefense.Default.Quarantine == nil || !manifest.BotDefense.Default.Quarantine.Enabled || manifest.BotDefense.Default.Quarantine.ReputationFeedbackSeconds != 120 {
		t.Fatalf("unexpected quarantine summary: %#v", manifest.BotDefense.Default.Quarantine)
	}
	if manifest.BotDefense.Default.ChallengeTTLSeconds != 900 || len(manifest.BotDefense.Default.ExemptCIDRs) != 1 || len(manifest.BotDefense.Default.SuspiciousUserAgents) != 2 {
		t.Fatalf("unexpected bot defense config summary: %#v", manifest.BotDefense)
	}
	if len(manifest.BotDefense.Default.PathPolicies) != 1 || manifest.BotDefense.Default.PathPolicies[0].DryRun == nil || !*manifest.BotDefense.Default.PathPolicies[0].DryRun {
		t.Fatalf("unexpected bot defense path policy summary: %#v", manifest.BotDefense.Default.PathPolicies)
	}
	if len(manifest.Routing.Routes) != 1 || manifest.Routing.Routes[0].Upstream != "blue" {
		t.Fatalf("unexpected routes: %#v", manifest.Routing.Routes)
	}
	if len(manifest.Routes) != 2 || manifest.Routes[0].Name != "app" || manifest.Routes[0].PathPrefix != "/app" || manifest.Routes[1].Name != "default" {
		t.Fatalf("unexpected canonical routes: %#v", manifest.Routes)
	}
	if manifest.Routes[0].Host != "example.test" || manifest.Routes[0].MatchType != "prefix" || manifest.Routes[0].MatchValue != "/app" || manifest.Routes[0].Upstream != "blue" || manifest.Routes[0].CanaryUpstream != "green" || manifest.Routes[0].CanaryWeightPercent != 5 || manifest.Routes[0].HashPolicy != "header" || manifest.Routes[0].HashKey != "X-Session-ID" {
		t.Fatalf("unexpected app route match summary: %#v", manifest.Routes[0])
	}
	if manifest.Routes[1].Host != "example.test" || manifest.Routes[1].MatchType != "prefix" || manifest.Routes[1].MatchValue != "/" {
		t.Fatalf("unexpected default route match summary: %#v", manifest.Routes[1])
	}
	if manifest.Routes[0].Bypass || manifest.Routes[0].Cache != nil {
		t.Fatalf("unexpected app route decoration: %#v", manifest.Routes[0])
	}
	if manifest.Routes[0].Security == nil || !manifest.Routes[0].Security.CountryBlockEnabled || manifest.Routes[0].Security.BlockedCountriesCount != 1 || manifest.Routes[0].Security.CountryBlockStatusCode != 403 || !manifest.Routes[0].Security.IPReputationEnabled || !manifest.Routes[0].Security.IPReputationFailOpen || manifest.Routes[0].Security.IPReputationBlockStatus != 451 || !manifest.Routes[0].Security.SemanticEnabled || manifest.Routes[0].Security.SemanticMode != "block" || manifest.Routes[0].Security.SemanticChallengeStatus != 429 || manifest.Routes[0].Security.SemanticBlockStatus != 403 || manifest.Routes[0].Security.SemanticChallengeThreshold != 6 || manifest.Routes[0].Security.SemanticBlockThreshold != 11 {
		t.Fatalf("unexpected app route security summary: %#v", manifest.Routes[0].Security)
	}
	if manifest.Routes[0].RateLimit == nil || !manifest.Routes[0].RateLimit.DefaultPolicy || len(manifest.Routes[0].RateLimit.RuleNames) != 0 {
		t.Fatalf("unexpected app route rate-limit summary: %#v", manifest.Routes[0].RateLimit)
	}
	if len(manifest.Routes[0].RateLimit.EffectivePolicies) != 1 || manifest.Routes[0].RateLimit.EffectivePolicies[0].Source != "default" || manifest.Routes[0].RateLimit.EffectivePolicies[0].Limit != 5 || manifest.Routes[0].RateLimit.EffectivePolicies[0].WindowSeconds != 30 {
		t.Fatalf("unexpected app route rate-limit policies: %#v", manifest.Routes[0].RateLimit.EffectivePolicies)
	}
	if manifest.Routes[0].BotDefense == nil || !manifest.Routes[0].BotDefense.Enabled || manifest.Routes[0].BotDefense.Mode != botDefenseModeAlways || manifest.Routes[0].BotDefense.DryRun || manifest.Routes[0].BotDefense.ChallengeStatusCode != 429 || manifest.Routes[0].BotDefense.QuarantineStatusCode != 429 || !manifest.Routes[0].BotDefense.BehavioralEnabled || !manifest.Routes[0].BotDefense.BrowserSignalsEnabled || !manifest.Routes[0].BotDefense.DeviceSignalsEnabled || !manifest.Routes[0].BotDefense.InvisibleDeviceCheck || !manifest.Routes[0].BotDefense.HeaderSignalsEnabled || !manifest.Routes[0].BotDefense.TLSSignalsEnabled || !manifest.Routes[0].BotDefense.QuarantineEnabled || !manifest.Routes[0].BotDefense.ReputationFeedbackEnabled || len(manifest.Routes[0].BotDefense.PathPolicyNames) != 0 || manifest.Routes[0].BotDefense.TelemetryCookieRequired {
		t.Fatalf("unexpected app route bot-defense summary: %#v", manifest.Routes[0].BotDefense)
	}
	if !manifest.Routes[1].Bypass || len(manifest.Routes[1].BypassModes) != 1 || manifest.Routes[1].BypassModes[0] != "bypass" {
		t.Fatalf("unexpected default route bypass summary: %#v", manifest.Routes[1])
	}
	if manifest.Routes[1].Cache == nil || manifest.Routes[1].Cache.Mode != "allow" || manifest.Routes[1].Cache.MatchValue != "/assets" {
		t.Fatalf("unexpected default route cache summary: %#v", manifest.Routes[1].Cache)
	}
	if manifest.Routes[1].RateLimit == nil || !manifest.Routes[1].RateLimit.DefaultPolicy || len(manifest.Routes[1].RateLimit.RuleNames) != 0 {
		t.Fatalf("unexpected default route rate-limit summary: %#v", manifest.Routes[1].RateLimit)
	}
	if len(manifest.Routes[1].RateLimit.EffectivePolicies) != 1 || manifest.Routes[1].RateLimit.EffectivePolicies[0].Source != "default" || manifest.Routes[1].RateLimit.EffectivePolicies[0].Limit != 5 {
		t.Fatalf("unexpected default route rate-limit policies: %#v", manifest.Routes[1].RateLimit.EffectivePolicies)
	}
	if manifest.Routes[1].BotDefense == nil || !manifest.Routes[1].BotDefense.Enabled || manifest.Routes[1].BotDefense.Mode != botDefenseModeAlways || !manifest.Routes[1].BotDefense.DryRun || manifest.Routes[1].BotDefense.ChallengeStatusCode != 429 || manifest.Routes[1].BotDefense.QuarantineStatusCode != 429 || !manifest.Routes[1].BotDefense.BehavioralEnabled || !manifest.Routes[1].BotDefense.BrowserSignalsEnabled || !manifest.Routes[1].BotDefense.DeviceSignalsEnabled || !manifest.Routes[1].BotDefense.InvisibleDeviceCheck || !manifest.Routes[1].BotDefense.HeaderSignalsEnabled || !manifest.Routes[1].BotDefense.TLSSignalsEnabled || !manifest.Routes[1].BotDefense.QuarantineEnabled || !manifest.Routes[1].BotDefense.ReputationFeedbackEnabled || len(manifest.Routes[1].BotDefense.PathPolicyNames) != 1 || manifest.Routes[1].BotDefense.PathPolicyNames[0] != "login" || !manifest.Routes[1].BotDefense.TelemetryCookieRequired {
		t.Fatalf("unexpected default route bot-defense summary: %#v", manifest.Routes[1].BotDefense)
	}
	if len(manifest.NormalFlows) != 1 || manifest.NormalFlows[0].Path != "/login" || manifest.NormalFlows[0].Expect != "allow" {
		t.Fatalf("unexpected normal flows: %#v", manifest.NormalFlows)
	}
	if manifest.NormalFlows[0].Route != "default" || manifest.NormalFlows[0].ExecutionMode != "browser" {
		t.Fatalf("unexpected normal flow metadata: %#v", manifest.NormalFlows[0])
	}
	if manifest.NormalFlows[0].Assertions == nil || len(manifest.NormalFlows[0].Assertions.FinalURLPrefixes) != 1 || manifest.NormalFlows[0].Assertions.FinalURLPrefixes[0] != "/" {
		t.Fatalf("unexpected normal flow assertions: %#v", manifest.NormalFlows[0].Assertions)
	}
	if manifest.NormalFlows[0].RouteHash == "" {
		t.Fatalf("expected normal flow route hash: %#v", manifest.NormalFlows[0])
	}
	if manifest.NormalFlows[0].Request == nil || manifest.NormalFlows[0].Request.Headers["Host"] != "example.test" {
		t.Fatalf("unexpected normal flow request: %#v", manifest.NormalFlows[0].Request)
	}
	if len(manifest.AttackExpectations) != 2 {
		t.Fatalf("unexpected attack expectations: %#v", manifest.AttackExpectations)
	}
	if manifest.AttackExpectations[0].Expect != "report_only" {
		t.Fatalf("unexpected attack expectation: %#v", manifest.AttackExpectations[0])
	}
	if !manifest.AttackExpectations[0].UseBrowser || manifest.AttackExpectations[0].Technique == "" {
		t.Fatalf("unexpected attack metadata: %#v", manifest.AttackExpectations[0])
	}
	if manifest.AttackExpectations[0].Assertions == nil || len(manifest.AttackExpectations[0].Assertions.StatusCodes) != 0 || len(manifest.AttackExpectations[0].Assertions.FinalURLPrefixes) != 1 || manifest.AttackExpectations[0].Assertions.FinalURLPrefixes[0] != "/" {
		t.Fatalf("dry-run attack should only carry route assertions: %#v", manifest.AttackExpectations[0].Assertions)
	}
	if manifest.AttackExpectations[0].Request == nil || manifest.AttackExpectations[0].Request.Headers["Host"] != "example.test" {
		t.Fatalf("unexpected attack request: %#v", manifest.AttackExpectations[0].Request)
	}
	if manifest.AttackExpectations[0].RouteHash == "" {
		t.Fatalf("expected attack route hash: %#v", manifest.AttackExpectations[0])
	}
	if manifest.AttackExpectations[1].Assertions == nil || len(manifest.AttackExpectations[1].Assertions.FinalURLPrefixes) != 1 || manifest.AttackExpectations[1].Assertions.FinalURLPrefixes[0] != "/" {
		t.Fatalf("unexpected telemetry attack assertions: %#v", manifest.AttackExpectations[1].Assertions)
	}
	if manifest.AttackExpectations[1].Request == nil || manifest.AttackExpectations[1].Request.Headers["Host"] != "example.test" {
		t.Fatalf("unexpected telemetry attack request: %#v", manifest.AttackExpectations[1].Request)
	}
	if manifest.AttackExpectations[1].PayloadType != "missing_telemetry_navigation" {
		t.Fatalf("expected telemetry scenario, got %#v", manifest.AttackExpectations[1])
	}
}

func TestCurrentVerifyManifestRouteCache_UsesHostScopedRules(t *testing.T) {
	rules := []verifyManifestCacheRule{
		{
			Kind:       "ALLOW",
			MatchType:  "prefix",
			MatchValue: "/assets/",
			TTLSeconds: 600,
		},
		{
			HostScope:  "admin.example.com",
			Kind:       "DENY",
			MatchType:  "prefix",
			MatchValue: "/assets/",
			TTLSeconds: 60,
		},
	}

	adminRoute := verifyManifestRoute{Host: "admin.example.com", PathPrefix: "/assets/app.js"}
	adminCache := currentVerifyManifestRouteCache(adminRoute, rules, false)
	if adminCache == nil || adminCache.Mode != "DENY" || adminCache.TTLSeconds != 60 {
		t.Fatalf("unexpected admin cache summary: %#v", adminCache)
	}

	siteRoute := verifyManifestRoute{Host: "www.example.com", PathPrefix: "/assets/app.js"}
	siteCache := currentVerifyManifestRouteCache(siteRoute, rules, false)
	if siteCache == nil || siteCache.Mode != "ALLOW" || siteCache.TTLSeconds != 600 {
		t.Fatalf("unexpected site cache summary: %#v", siteCache)
	}
}

func TestBuildVerifyManifestSemanticSummary_IncludesProvider(t *testing.T) {
	summary := buildVerifyManifestSemanticSummary(semanticFile{Default: semanticConfig{
		Enabled:            true,
		Mode:               semanticModeChallenge,
		Provider:           semanticProviderConfig{Enabled: true, Name: semanticProviderNameBuiltinAttackFamily, TimeoutMS: 25},
		ChallengeThreshold: 7,
		BlockThreshold:     9,
		MaxInspectBody:     16384,
	}})

	if !summary.Default.Enabled || summary.Default.Mode != semanticModeChallenge {
		t.Fatalf("unexpected summary: %#v", summary)
	}
	if !summary.Default.ProviderEnabled || summary.Default.ProviderName != semanticProviderNameBuiltinAttackFamily || summary.Default.ProviderTimeoutMS != 25 {
		t.Fatalf("provider summary mismatch: %#v", summary)
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
		Routing: verifyManifestRoutingSummary{
			Upstreams: []verifyManifestUpstreamInfo{
				{Name: "primary", URL: "https://upstream.example.test", Weight: 1, Enabled: true},
			},
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

func boolPtr(v bool) *bool {
	return &v
}
