package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func saveRequestSecurityEventStatsForTest() func() {
	oldPublished := requestSecurityEventsPublishedTotal.Load()
	oldChallengeFailures := requestSecurityBotChallengeFailuresTotal.Load()
	oldChallengePenalties := requestSecurityBotChallengePenaltiesTotal.Load()
	oldRateLimitPromotions := requestSecurityRateLimitPromotionsTotal.Load()
	oldRateLimitPromotionDryRun := requestSecurityRateLimitPromotionDryRunTotal.Load()
	return func() {
		requestSecurityEventsPublishedTotal.Store(oldPublished)
		requestSecurityBotChallengeFailuresTotal.Store(oldChallengeFailures)
		requestSecurityBotChallengePenaltiesTotal.Store(oldChallengePenalties)
		requestSecurityRateLimitPromotionsTotal.Store(oldRateLimitPromotions)
		requestSecurityRateLimitPromotionDryRunTotal.Store(oldRateLimitPromotionDryRun)
	}
}

func TestRequestSecurityEventBusOrdersAndExposesPriorEvents(t *testing.T) {
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	ctx := newRequestSecurityPluginContext("req-events", "10.0.0.1", "JP", time.Unix(1_700_000_000, 0))
	ctx.CountrySource = requestMetadataCountrySourceMMDB
	req := httptest.NewRequest(http.MethodGet, "http://example.test/demo", nil)

	var observedTypes []string
	var observedCounts []int
	ctx.SubscribeSecurityEvents(func(evt requestSecurityEvent) {
		observedTypes = append(observedTypes, evt.EventType)
		observedCounts = append(observedCounts, len(ctx.SecurityEvents()))
	})

	first := ctx.newSecurityEvent(req, "semantic", "semantic", requestSecurityEventTypeSemanticAnomaly, requestSecurityEventActionObserve)
	first = ctx.publishSecurityEvent(first)
	second := ctx.newSecurityEvent(req, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	second = ctx.publishSecurityEvent(second)

	if first.Sequence != 1 || second.Sequence != 2 {
		t.Fatalf("unexpected event sequences: first=%d second=%d", first.Sequence, second.Sequence)
	}
	if len(observedTypes) != 2 {
		t.Fatalf("observed event count=%d want=2", len(observedTypes))
	}
	if observedTypes[0] != requestSecurityEventTypeSemanticAnomaly || observedTypes[1] != requestSecurityEventTypeRateLimited {
		t.Fatalf("unexpected observed event types: %#v", observedTypes)
	}
	if observedCounts[0] != 1 || observedCounts[1] != 2 {
		t.Fatalf("unexpected observed event counts: %#v", observedCounts)
	}
	events := ctx.SecurityEvents()
	if len(events) != 2 {
		t.Fatalf("len(SecurityEvents)=%d want=2", len(events))
	}
	if events[0].EventType != requestSecurityEventTypeSemanticAnomaly || events[1].EventType != requestSecurityEventTypeRateLimited {
		t.Fatalf("unexpected stored events: %#v", events)
	}
	if events[0].CountrySource != requestMetadataCountrySourceMMDB || events[1].CountrySource != requestMetadataCountrySourceMMDB {
		t.Fatalf("unexpected country sources: %#v", events)
	}
}

func TestBotChallengeFailurePublishesFeedbackWithoutPenalizingFirstContact(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreIPReputation := saveIPReputationStateForTest()
	defer restoreIPReputation()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	ipRT, err := ValidateIPReputationRaw(`{
  "enabled": true,
  "block_status_code": 451
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}
	store := ipRT.Default.Store
	if store == nil {
		t.Fatal("expected default ip reputation store")
	}
	ipReputationMu.Lock()
	ipReputationRuntime = &ipRT
	ipReputationStoreRT = store
	ipReputationMu.Unlock()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 300,
  "challenge_status_code": 429,
  "challenge_failure_feedback": {
    "enabled": true,
    "reputation_feedback_seconds": 120
  }
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseChallengeState()

	gin.SetMode(gin.TestMode)
	plugin := newBotDefenseRequestSecurityPlugin()
	now := time.Unix(1_700_010_000, 0).UTC()
	clientIP := "10.0.0.8"
	userAgent := "curl/8.0"

	rec1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(rec1)
	c1.Request = httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	c1.Request.Header.Set("User-Agent", userAgent)
	ctx1 := newRequestSecurityPluginContext("req-bot-1", clientIP, "JP", now)
	if ok := plugin.Handle(newProxyServeContextFromGin(c1), ctx1); ok {
		t.Fatal("first request should issue a bot challenge")
	}
	if ctx1.BotChallengePenaltyApplied {
		t.Fatal("first contact challenge must not apply IP reputation feedback")
	}
	if store.isBlockedAt(clientIP, now) {
		t.Fatal("first contact challenge should not block IP reputation")
	}
	assertEventTypesAbsent(t, ctx1.SecurityEvents(), requestSecurityEventTypeBotChallengeFailed, requestSecurityEventTypeIPReputationFeedback)

	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	c2.Request.Header.Set("User-Agent", userAgent)
	ctx2 := newRequestSecurityPluginContext("req-bot-2", clientIP, "JP", now.Add(5*time.Second))
	if ok := plugin.Handle(newProxyServeContextFromGin(c2), ctx2); ok {
		t.Fatal("failed follow-up should still stop at challenge/quarantine")
	}
	if !ctx2.BotChallengePenaltyApplied {
		t.Fatal("failed follow-up should apply IP reputation feedback")
	}
	if got := int(ctx2.BotChallengePenaltyTTL.Seconds()); got != 120 {
		t.Fatalf("feedback ttl=%d want=120", got)
	}
	if !store.isBlockedAt(clientIP, now.Add(5*time.Second)) {
		t.Fatal("failed follow-up should create a live IP reputation block")
	}
	assertEventTypesPresent(t, ctx2.SecurityEvents(), requestSecurityEventTypeBotChallengeFailed, requestSecurityEventTypeIPReputationFeedback, requestSecurityEventTypeBotChallengeIssued, requestSecurityEventTypeBotChallenge)
}

func TestBotChallengeFailureUsesStoredTelemetryRequirementAcrossFlowChange(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreIPReputation := saveIPReputationStateForTest()
	defer restoreIPReputation()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	ipRT, err := ValidateIPReputationRaw(`{
  "enabled": true,
  "block_status_code": 451
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}
	store := ipRT.Default.Store
	if store == nil {
		t.Fatal("expected default ip reputation store")
	}
	ipReputationMu.Lock()
	ipReputationRuntime = &ipRT
	ipReputationStoreRT = store
	ipReputationMu.Unlock()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 300,
  "challenge_status_code": 429,
  "browser_signals": {
    "enabled": true,
    "js_cookie_name": "__tukuyomi_bot_js",
    "score_threshold": 1,
    "risk_score_per_signal": 2
  },
  "challenge_failure_feedback": {
    "enabled": true,
    "reputation_feedback_seconds": 120
  },
  "path_policies": [
    {
      "name": "login",
      "path_prefixes": ["/login"],
      "telemetry_cookie_required": true
    }
  ]
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseChallengeState()

	gin.SetMode(gin.TestMode)
	plugin := newBotDefenseRequestSecurityPlugin()
	now := time.Unix(1_700_011_000, 0).UTC()
	clientIP := "10.0.0.11"
	userAgent := "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36"

	rec1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(rec1)
	c1.Request = httptest.NewRequest(http.MethodGet, "http://example.test/login", nil)
	c1.Request.Header.Set("User-Agent", userAgent)
	c1.Request.Header.Set("Accept", "text/html")
	ctx1 := newRequestSecurityPluginContext("req-bot-telemetry-1", clientIP, "JP", now)
	if ok := plugin.Handle(newProxyServeContextFromGin(c1), ctx1); ok {
		t.Fatal("first request should issue a bot challenge")
	}
	if ctx1.BotChallengePenaltyApplied {
		t.Fatal("first contact challenge must not apply IP reputation feedback")
	}

	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodGet, "http://example.test/dashboard", nil)
	c2.Request.Header.Set("User-Agent", userAgent)
	c2.Request.Header.Set("Accept", "text/html")
	c2.Request.AddCookie(&http.Cookie{
		Name:  botRT.CookieName,
		Value: issueBotDefenseToken(botRT, clientIP, userAgent, now),
	})
	ctx2 := newRequestSecurityPluginContext("req-bot-telemetry-2", clientIP, "JP", now.Add(5*time.Second))
	if ok := plugin.Handle(newProxyServeContextFromGin(c2), ctx2); ok {
		t.Fatal("follow-up without telemetry cookie should still fail after flow change")
	}
	if !ctx2.BotChallengePenaltyApplied {
		t.Fatal("failed follow-up should apply IP reputation feedback")
	}
	if !store.isBlockedAt(clientIP, now.Add(5*time.Second)) {
		t.Fatal("failed follow-up should create a live IP reputation block")
	}
	assertEventTypesPresent(t, ctx2.SecurityEvents(), requestSecurityEventTypeBotChallengeFailed, requestSecurityEventTypeIPReputationFeedback)
}

func TestBotChallengeFailureAppliesReputationPenaltyToMatchedHostScope(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreIPReputation := saveIPReputationStateForTest()
	defer restoreIPReputation()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	ipRT, err := ValidateIPReputationRaw(`{
  "default": {
    "enabled": false,
    "block_status_code": 451
  },
  "hosts": {
    "secure.example.com": {
      "enabled": true,
      "block_status_code": 452
    }
  }
}`)
	if err != nil {
		t.Fatalf("ValidateIPReputationRaw() unexpected error: %v", err)
	}
	ipReputationMu.Lock()
	ipReputationRuntime = &ipRT
	ipReputationStoreRT = ipRT.Default.Store
	ipReputationMu.Unlock()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "challenge_ttl_seconds": 300,
  "challenge_status_code": 429,
  "challenge_failure_feedback": {
    "enabled": true,
    "reputation_feedback_seconds": 120
  }
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseChallengeState()

	gin.SetMode(gin.TestMode)
	plugin := newBotDefenseRequestSecurityPlugin()
	now := time.Now().UTC()
	clientIP := "10.0.0.19"
	userAgent := "curl/8.0"

	rec1 := httptest.NewRecorder()
	c1, _ := gin.CreateTestContext(rec1)
	c1.Request = httptest.NewRequest(http.MethodGet, "https://secure.example.com/", nil)
	c1.Request.Header.Set("User-Agent", userAgent)
	ctx1 := newRequestSecurityPluginContext("req-bot-scope-1", clientIP, "JP", now)
	ctx1.RequestHost = c1.Request.Host
	ctx1.RequestTLS = true
	if ok := plugin.Handle(newProxyServeContextFromGin(c1), ctx1); ok {
		t.Fatal("first request should issue a bot challenge")
	}

	rec2 := httptest.NewRecorder()
	c2, _ := gin.CreateTestContext(rec2)
	c2.Request = httptest.NewRequest(http.MethodGet, "https://secure.example.com/", nil)
	c2.Request.Header.Set("User-Agent", userAgent)
	ctx2 := newRequestSecurityPluginContext("req-bot-scope-2", clientIP, "JP", now.Add(5*time.Second))
	ctx2.RequestHost = c2.Request.Host
	ctx2.RequestTLS = true
	if ok := plugin.Handle(newProxyServeContextFromGin(c2), ctx2); ok {
		t.Fatal("failed follow-up should still stop at challenge/quarantine")
	}
	if !ctx2.BotChallengePenaltyApplied {
		t.Fatal("failed follow-up should apply IP reputation feedback")
	}

	blocked, status, scope := EvaluateIPReputationForHost("secure.example.com", true, clientIP)
	if !blocked || status != 452 || scope != "secure.example.com" {
		t.Fatalf("host-scoped feedback mismatch: blocked=%v status=%d scope=%q", blocked, status, scope)
	}
	if blocked, _, _ := EvaluateIPReputationForHost("www.example.com", true, clientIP); blocked {
		t.Fatal("bot feedback should not leak into the default scope")
	}

	events := ctx2.SecurityEvents()
	assertEventTypesPresent(t, events, requestSecurityEventTypeBotChallengeFailed, requestSecurityEventTypeIPReputationFeedback)
	foundHostScope := false
	for _, evt := range events {
		if evt.EventType != requestSecurityEventTypeIPReputationFeedback {
			continue
		}
		if scope, _ := evt.Attributes["host_scope"].(string); scope == "secure.example.com" {
			foundHostScope = true
		}
	}
	if !foundHostScope {
		t.Fatal("expected ip reputation feedback event to retain host scope")
	}
}

func TestRateLimitSecurityEventsPromoteToQuarantine(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreRateLimit := saveRateLimitStateForTest()
	defer restoreRateLimit()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 600,
    "status_code": 451
  }
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseQuarantineState()

	rateRT, err := ValidateRateLimitRaw(`{
  "enabled": true,
  "feedback": {
    "enabled": true,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "adaptive_only": false
  },
  "default_policy": {
    "enabled": true,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {"status": 429, "retry_after_seconds": 60}
  },
  "rules": []
}`)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}
	rateLimitMu.Lock()
	rateLimitRuntime = rateRT
	rateLimitMu.Unlock()
	resetRateLimitFeedbackState()

	ip := "10.0.0.9"
	now := time.Unix(1_700_020_000, 0).UTC()
	ctx1 := newRequestSecurityPluginContext("req-rate-1", ip, "JP", now)
	evt1 := ctx1.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt1.Enforced = true
	evt1.Status = 429
	evt1.Attributes = map[string]any{"adaptive": false}
	ctx1.publishSecurityEvent(evt1)
	if ctx1.RateLimitFeedback.Promoted {
		t.Fatal("first rate-limit event should not promote immediately")
	}
	if blocked, _, _ := botDefenseQuarantineStatus(botRT, ip, now); blocked {
		t.Fatal("first rate-limit event should not quarantine the client")
	}

	ctx2 := newRequestSecurityPluginContext("req-rate-2", ip, "JP", now.Add(5*time.Second))
	evt2 := ctx2.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt2.Enforced = true
	evt2.Status = 429
	evt2.Attributes = map[string]any{"adaptive": false}
	ctx2.publishSecurityEvent(evt2)
	if !ctx2.RateLimitFeedback.Promoted || ctx2.RateLimitFeedback.DryRun {
		t.Fatalf("second rate-limit event should promote live quarantine: %+v", ctx2.RateLimitFeedback)
	}
	if ctx2.RateLimitFeedback.Strikes != 2 {
		t.Fatalf("rate-limit strikes=%d want=2", ctx2.RateLimitFeedback.Strikes)
	}
	if blocked, status, _ := botDefenseQuarantineStatus(botRT, ip, now.Add(5*time.Second)); !blocked || status != 451 {
		t.Fatalf("quarantine status after promotion blocked=%v status=%d want blocked=true status=451", blocked, status)
	}
	assertEventTypesPresent(t, ctx2.SecurityEvents(), requestSecurityEventTypeRateLimited, requestSecurityEventTypeRateLimitPromotion)
}

func TestRateLimitSecurityEventsKeepFeedbackStrikesPerHostScope(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreRateLimit := saveRateLimitStateForTest()
	defer restoreRateLimit()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 600,
    "status_code": 451
  }
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseQuarantineState()

	rateRT, err := ValidateRateLimitRaw(`{
  "default": {
    "enabled": true,
    "feedback": {
      "enabled": true,
      "strikes_required": 2,
      "strike_window_seconds": 300,
      "adaptive_only": false
    },
    "default_policy": {
      "enabled": true,
      "limit": 1,
      "window_seconds": 60,
      "burst": 0,
      "key_by": "ip",
      "action": {"status": 429, "retry_after_seconds": 60}
    },
    "rules": []
  },
  "hosts": {
    "one.example.com": {},
    "two.example.com": {}
  }
}`)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}
	rateLimitMu.Lock()
	rateLimitRuntime = rateRT
	rateLimitMu.Unlock()
	resetRateLimitFeedbackState()

	ip := "10.0.0.12"
	now := time.Unix(1_700_021_000, 0).UTC()

	ctx1 := newRequestSecurityPluginContext("req-rate-host-1", ip, "JP", now)
	evt1 := ctx1.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt1.Enforced = true
	evt1.Status = 429
	evt1.Attributes = map[string]any{"adaptive": false, "host_scope": "one.example.com"}
	ctx1.publishSecurityEvent(evt1)
	if ctx1.RateLimitFeedback.Promoted {
		t.Fatalf("first host-scope strike should not promote: %+v", ctx1.RateLimitFeedback)
	}

	ctx2 := newRequestSecurityPluginContext("req-rate-host-2", ip, "JP", now.Add(time.Second))
	evt2 := ctx2.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt2.Enforced = true
	evt2.Status = 429
	evt2.Attributes = map[string]any{"adaptive": false, "host_scope": "two.example.com"}
	ctx2.publishSecurityEvent(evt2)
	if ctx2.RateLimitFeedback.Promoted {
		t.Fatalf("first strike on a different host scope should not promote: %+v", ctx2.RateLimitFeedback)
	}

	ctx3 := newRequestSecurityPluginContext("req-rate-host-3", ip, "JP", now.Add(2*time.Second))
	evt3 := ctx3.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt3.Enforced = true
	evt3.Status = 429
	evt3.Attributes = map[string]any{"adaptive": false, "host_scope": "one.example.com"}
	ctx3.publishSecurityEvent(evt3)
	if !ctx3.RateLimitFeedback.Promoted {
		t.Fatalf("second strike on the same host scope should promote: %+v", ctx3.RateLimitFeedback)
	}
	if ctx3.RateLimitFeedback.HostScope != "one.example.com" {
		t.Fatalf("promotion host scope=%q want one.example.com", ctx3.RateLimitFeedback.HostScope)
	}
	assertEventTypesPresent(t, ctx3.SecurityEvents(), requestSecurityEventTypeRateLimited, requestSecurityEventTypeRateLimitPromotion)
}

func TestRateLimitSecurityEventsDryRunDoesNotQuarantine(t *testing.T) {
	restoreBotDefense := saveBotDefenseStateForTest()
	defer restoreBotDefense()
	restoreRateLimit := saveRateLimitStateForTest()
	defer restoreRateLimit()
	restoreStats := saveRequestSecurityEventStatsForTest()
	defer restoreStats()

	botRT, err := ValidateBotDefenseRaw(`{
  "enabled": true,
  "mode": "always",
  "path_prefixes": ["/"],
  "challenge_secret": "test-bot-defense-secret-12345",
  "quarantine": {
    "enabled": true,
    "threshold": 8,
    "strikes_required": 2,
    "strike_window_seconds": 300,
    "ttl_seconds": 600,
    "status_code": 451
  }
}`)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}
	botDefenseMu.Lock()
	botDefenseRuntime = botRT
	botDefenseMu.Unlock()
	resetBotDefenseQuarantineState()

	rateRT, err := ValidateRateLimitRaw(`{
  "enabled": true,
  "feedback": {
    "enabled": true,
    "strikes_required": 1,
    "strike_window_seconds": 300,
    "adaptive_only": false,
    "dry_run": true
  },
  "default_policy": {
    "enabled": true,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {"status": 429, "retry_after_seconds": 60}
  },
  "rules": []
}`)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}
	rateLimitMu.Lock()
	rateLimitRuntime = rateRT
	rateLimitMu.Unlock()
	resetRateLimitFeedbackState()

	ip := "10.0.0.10"
	now := time.Unix(1_700_030_000, 0).UTC()
	ctx := newRequestSecurityPluginContext("req-rate-dry-run", ip, "JP", now)
	evt := ctx.newSecurityEvent(nil, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
	evt.Enforced = true
	evt.Status = 429
	evt.Attributes = map[string]any{"adaptive": false}
	ctx.publishSecurityEvent(evt)

	if !ctx.RateLimitFeedback.Promoted || !ctx.RateLimitFeedback.DryRun {
		t.Fatalf("dry-run feedback result=%+v want promoted dry-run", ctx.RateLimitFeedback)
	}
	if blocked, _, _ := botDefenseQuarantineStatus(botRT, ip, now); blocked {
		t.Fatal("dry-run rate-limit promotion must not create live quarantine state")
	}
	assertEventTypesPresent(t, ctx.SecurityEvents(), requestSecurityEventTypeRateLimitPromotion)
}

func assertEventTypesPresent(t *testing.T, events []requestSecurityEvent, want ...string) {
	t.Helper()
	got := map[string]bool{}
	for _, evt := range events {
		got[evt.EventType] = true
	}
	for _, eventType := range want {
		if !got[eventType] {
			t.Fatalf("event type %q missing from %#v", eventType, events)
		}
	}
}

func assertEventTypesAbsent(t *testing.T, events []requestSecurityEvent, forbidden ...string) {
	t.Helper()
	for _, evt := range events {
		for _, eventType := range forbidden {
			if evt.EventType == eventType {
				t.Fatalf("unexpected event type %q in %#v", eventType, events)
			}
		}
	}
}
