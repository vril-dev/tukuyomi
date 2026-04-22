package handler

import (
	"strings"
	"sync"
	"time"
)

type botDefenseChallengeFailureFeedbackConfig struct {
	Enabled            bool `json:"enabled"`
	ReputationFeedback int  `json:"reputation_feedback_seconds"`
}

type runtimeBotDefenseChallengeFailureFeedbackConfig struct {
	Enabled            bool
	ReputationFeedback time.Duration
}

type rateLimitFeedbackConfig struct {
	Enabled             bool `json:"enabled"`
	StrikesRequired     int  `json:"strikes_required,omitempty"`
	StrikeWindowSeconds int  `json:"strike_window_seconds,omitempty"`
	AdaptiveOnly        bool `json:"adaptive_only,omitempty"`
	DryRun              bool `json:"dry_run,omitempty"`
}

type runtimeRateLimitFeedbackConfig struct {
	Enabled         bool
	StrikesRequired int
	StrikeWindow    time.Duration
	AdaptiveOnly    bool
	DryRun          bool
}

type botDefenseChallengePendingState struct {
	FlowPolicy        string
	TelemetryRequired bool
	ExpiresAt         time.Time
}

type rateLimitFeedbackState struct {
	Strikes   int
	WindowEnd time.Time
}

var (
	botDefenseChallengeStateMu    sync.Mutex
	botDefenseChallengeStateByKey = map[string]botDefenseChallengePendingState{}
	botDefenseChallengeStateSweep int
	rateLimitFeedbackStateMu      sync.Mutex
	rateLimitFeedbackStateByKey   = map[string]rateLimitFeedbackState{}
	rateLimitFeedbackStateSweep   int
)

func normalizeBotDefenseChallengeFailureFeedbackConfig(cfg botDefenseChallengeFailureFeedbackConfig) botDefenseChallengeFailureFeedbackConfig {
	if !cfg.Enabled {
		return botDefenseChallengeFailureFeedbackConfig{}
	}
	if cfg.ReputationFeedback < 0 {
		cfg.ReputationFeedback = 0
	}
	if cfg.ReputationFeedback == 0 {
		cfg.ReputationFeedback = 300
	}
	return cfg
}

func normalizeRateLimitFeedbackConfig(cfg rateLimitFeedbackConfig) rateLimitFeedbackConfig {
	if !cfg.Enabled {
		return rateLimitFeedbackConfig{}
	}
	if cfg.StrikesRequired <= 0 {
		cfg.StrikesRequired = 3
	}
	if cfg.StrikeWindowSeconds <= 0 {
		cfg.StrikeWindowSeconds = 300
	}
	return cfg
}

func normalizeBotDefenseScopeKey(scopeKey string) string {
	scope := strings.TrimSpace(scopeKey)
	if scope == "" {
		return botDefenseDefaultScope
	}
	return scope
}

func botDefenseScopedStateKey(scopeKey, ip string) string {
	ip = normalizeClientIP(ip)
	if ip == "" {
		return ""
	}
	return normalizeBotDefenseScopeKey(scopeKey) + "|" + ip
}

func botDefenseChallengeStateKey(scopeKey, ip, userAgent string) string {
	base := botDefenseScopedStateKey(scopeKey, ip)
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	if base == "" {
		return ""
	}
	return base + "|" + userAgent
}

func rememberBotDefenseChallengeState(scopeKey, ip, userAgent, flowPolicy string, telemetryRequired bool, now, until time.Time) {
	key := botDefenseChallengeStateKey(scopeKey, ip, userAgent)
	if key == "" || until.IsZero() || !until.After(now) {
		return
	}
	botDefenseChallengeStateMu.Lock()
	defer botDefenseChallengeStateMu.Unlock()
	botDefenseChallengeStateSweep++
	botDefenseChallengeStateByKey[key] = botDefenseChallengePendingState{
		FlowPolicy:        strings.TrimSpace(flowPolicy),
		TelemetryRequired: telemetryRequired,
		ExpiresAt:         until.UTC(),
	}
	if botDefenseChallengeStateSweep%256 == 0 {
		for candidateKey, candidate := range botDefenseChallengeStateByKey {
			if !candidate.ExpiresAt.After(now.UTC()) {
				delete(botDefenseChallengeStateByKey, candidateKey)
			}
		}
	}
}

func currentBotDefenseChallengeState(scopeKey, ip, userAgent string, now time.Time) (botDefenseChallengePendingState, bool) {
	key := botDefenseChallengeStateKey(scopeKey, ip, userAgent)
	if key == "" {
		return botDefenseChallengePendingState{}, false
	}
	botDefenseChallengeStateMu.Lock()
	defer botDefenseChallengeStateMu.Unlock()
	state, ok := botDefenseChallengeStateByKey[key]
	if !ok {
		return botDefenseChallengePendingState{}, false
	}
	if !state.ExpiresAt.After(now.UTC()) {
		delete(botDefenseChallengeStateByKey, key)
		return botDefenseChallengePendingState{}, false
	}
	return state, true
}

func clearBotDefenseChallengeState(scopeKey, ip, userAgent string) {
	key := botDefenseChallengeStateKey(scopeKey, ip, userAgent)
	if key == "" {
		return
	}
	botDefenseChallengeStateMu.Lock()
	defer botDefenseChallengeStateMu.Unlock()
	delete(botDefenseChallengeStateByKey, key)
}

func resetBotDefenseChallengeState() {
	botDefenseChallengeStateMu.Lock()
	defer botDefenseChallengeStateMu.Unlock()
	botDefenseChallengeStateByKey = map[string]botDefenseChallengePendingState{}
	botDefenseChallengeStateSweep = 0
}

func resetRateLimitFeedbackState() {
	rateLimitFeedbackStateMu.Lock()
	defer rateLimitFeedbackStateMu.Unlock()
	rateLimitFeedbackStateByKey = map[string]rateLimitFeedbackState{}
	rateLimitFeedbackStateSweep = 0
}

func rateLimitFeedbackStateKey(ip, hostScope string) string {
	ip = normalizeClientIP(ip)
	if ip == "" {
		return ""
	}
	scope := strings.TrimSpace(hostScope)
	if scope == "" {
		scope = rateLimitDefaultScope
	}
	return scope + "|" + ip
}

func forceBotDefenseQuarantine(rt *runtimeBotDefenseConfig, ip string, now time.Time) bool {
	return forceBotDefenseQuarantineForScope(botDefenseDefaultScope, rt, ip, now)
}

func forceBotDefenseQuarantineForScope(scopeKey string, rt *runtimeBotDefenseConfig, ip string, now time.Time) bool {
	if rt == nil || !rt.Quarantine.Enabled || strings.TrimSpace(ip) == "" {
		return false
	}
	key := botDefenseScopedStateKey(scopeKey, ip)
	if key == "" {
		return false
	}
	botDefenseQuarantineMu.Lock()
	defer botDefenseQuarantineMu.Unlock()
	state := botDefenseQuarantineStateByIP[key]
	alreadyBlocked := !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil)
	state.Strikes = maxInt(state.Strikes, rt.Quarantine.StrikesRequired)
	state.WindowEnd = now.Add(rt.Quarantine.StrikeWindow)
	state.BlockedUntil = now.Add(rt.Quarantine.TTL)
	botDefenseQuarantineStateByIP[key] = state
	return !alreadyBlocked
}

func applyRateLimitFeedbackEvent(now time.Time, ip, hostScope string, adaptive bool) requestSecurityRateLimitFeedbackResult {
	ip = normalizeClientIP(ip)
	key := rateLimitFeedbackStateKey(ip, hostScope)
	rt := currentRateLimitRuntime()
	if rt == nil || key == "" {
		return requestSecurityRateLimitFeedbackResult{}
	}
	scope := selectRateLimitScope(rt, nil)
	if strings.TrimSpace(hostScope) != "" && hostScope != rateLimitDefaultScope {
		if candidate, ok := rt.Hosts[strings.TrimSpace(hostScope)]; ok {
			scope = rateLimitScopeSelection{
				Raw:               candidate.Raw,
				AllowlistPrefixes: candidate.AllowlistPrefixes,
				AllowCountries:    candidate.AllowCountries,
				Rules:             candidate.Rules,
				DefaultPolicy:     candidate.DefaultPolicy,
				Feedback:          candidate.Feedback,
				ScopeKey:          strings.TrimSpace(hostScope),
			}
		}
	}
	if !scope.Feedback.Enabled {
		return requestSecurityRateLimitFeedbackResult{}
	}
	if scope.Feedback.AdaptiveOnly && !adaptive {
		return requestSecurityRateLimitFeedbackResult{}
	}
	botRT := currentBotDefenseRuntime()
	scopeKey := normalizeBotDefenseScopeKey(hostScope)
	scopeRT := selectBotDefenseRuntimeByScopeKey(botRT, scopeKey)
	if scopeRT == nil || !scopeRT.Quarantine.Enabled {
		return requestSecurityRateLimitFeedbackResult{}
	}

	rateLimitFeedbackStateMu.Lock()
	rateLimitFeedbackStateSweep++
	state := rateLimitFeedbackStateByKey[key]
	if state.WindowEnd.IsZero() || now.After(state.WindowEnd) {
		state = rateLimitFeedbackState{
			WindowEnd: now.Add(scope.Feedback.StrikeWindow),
		}
	}
	state.Strikes++
	strikes := state.Strikes
	promoted := strikes >= scope.Feedback.StrikesRequired
	if promoted {
		delete(rateLimitFeedbackStateByKey, key)
	} else {
		rateLimitFeedbackStateByKey[key] = state
	}
	if rateLimitFeedbackStateSweep%512 == 0 {
		for candidateKey, candidate := range rateLimitFeedbackStateByKey {
			if now.After(candidate.WindowEnd) {
				delete(rateLimitFeedbackStateByKey, candidateKey)
			}
		}
	}
	rateLimitFeedbackStateMu.Unlock()

	result := requestSecurityRateLimitFeedbackResult{
		Promoted:  promoted,
		DryRun:    scope.Feedback.DryRun,
		Strikes:   strikes,
		HostScope: scope.ScopeKey,
	}
	if !promoted {
		return result
	}
	if scope.Feedback.DryRun {
		requestSecurityRateLimitPromotionDryRunTotal.Add(1)
		return result
	}
	if forceBotDefenseQuarantineForScope(scopeKey, scopeRT, ip, now.UTC()) {
		requestSecurityRateLimitPromotionsTotal.Add(1)
		if scopeRT.Quarantine.ReputationFeedback > 0 {
			_ = ApplyIPReputationPenaltyForScope(scope.ScopeKey, ip, scopeRT.Quarantine.ReputationFeedback, now.UTC())
		}
	}
	return result
}

func handleRequestSecurityFeedbackEvent(ctx *requestSecurityPluginContext, evt requestSecurityEvent) {
	if ctx == nil {
		return
	}
	switch evt.EventType {
	case requestSecurityEventTypeBotChallengeFailed:
		requestSecurityBotChallengeFailuresTotal.Add(1)
		scopeKey, _ := evt.Attributes["host_scope"].(string)
		scopeRT := selectBotDefenseRuntimeByScopeKey(currentBotDefenseRuntime(), scopeKey)
		if strings.TrimSpace(scopeKey) == "" {
			scopeRT, scopeKey = selectBotDefenseRuntimeForHost(currentBotDefenseRuntime(), ctx.RequestHost, ctx.RequestTLS)
		}
		if scopeRT == nil || !scopeRT.ChallengeFailureFeedback.Enabled || scopeRT.ChallengeFailureFeedback.ReputationFeedback <= 0 || evt.DryRun || !evt.Enforced {
			return
		}
		ipScopeKey := scopeKey
		penaltyApplied := false
		if strings.TrimSpace(ctx.RequestHost) != "" {
			penaltyApplied = ApplyIPReputationPenaltyForHost(ctx.RequestHost, ctx.RequestTLS, evt.ClientIP, scopeRT.ChallengeFailureFeedback.ReputationFeedback, ctx.Now.UTC())
			ipScopeKey = selectIPReputationScope(currentIPReputationRuntime(), ctx.RequestHost, ctx.RequestTLS).ScopeKey
		} else {
			penaltyApplied = ApplyIPReputationPenaltyForScope(scopeKey, evt.ClientIP, scopeRT.ChallengeFailureFeedback.ReputationFeedback, ctx.Now.UTC())
			ipScopeKey = selectIPReputationScopeByKey(currentIPReputationRuntime(), scopeKey).ScopeKey
		}
		if !penaltyApplied {
			return
		}
		ctx.BotChallengePenaltyApplied = true
		ctx.BotChallengePenaltyTTL = scopeRT.ChallengeFailureFeedback.ReputationFeedback
		requestSecurityBotChallengePenaltiesTotal.Add(1)

		derived := ctx.deriveSecurityEvent(evt, requestSecurityEventSourceFeedbackLoop, "ip_reputation", requestSecurityEventTypeIPReputationFeedback, requestSecurityEventActionBlock)
		derived.Enforced = true
		derived.DryRun = false
		if status := IPReputationStatusForHost(ctx.RequestHost, ctx.RequestTLS); status.BlockStatusCode > 0 {
			derived.Status = status.BlockStatusCode
		}
		derived.Attributes = cloneRequestSecurityEventAttributes(derived.Attributes)
		if derived.Attributes == nil {
			derived.Attributes = map[string]any{}
		}
		derived.Attributes["feedback_source"] = requestSecurityEventTypeBotChallengeFailed
		derived.Attributes["host_scope"] = ipScopeKey
		derived.Attributes["bot_host_scope"] = scopeKey
		derived.Attributes["ttl_seconds"] = int(scopeRT.ChallengeFailureFeedback.ReputationFeedback.Seconds())
		published := ctx.publishSecurityEvent(derived)
		emitRequestSecurityFeedbackLog(published)
	case requestSecurityEventTypeRateLimited:
		adaptive, _ := evt.Attributes["adaptive"].(bool)
		hostScope, _ := evt.Attributes["host_scope"].(string)
		result := applyRateLimitFeedbackEvent(ctx.Now.UTC(), evt.ClientIP, hostScope, adaptive)
		if !result.Promoted {
			return
		}
		ctx.RateLimitFeedback = result
		derivedAction := requestSecurityEventActionQuarantine
		if result.DryRun {
			derivedAction = requestSecurityEventActionWouldQuarantine
		}
		derived := ctx.deriveSecurityEvent(evt, requestSecurityEventSourceFeedbackLoop, "rate_limit_feedback", requestSecurityEventTypeRateLimitPromotion, derivedAction)
		derived.Enforced = !result.DryRun
		derived.DryRun = result.DryRun
		if botRT := selectBotDefenseRuntimeByScopeKey(currentBotDefenseRuntime(), result.HostScope); botRT != nil {
			derived.Status = botRT.Quarantine.StatusCode
		}
		derived.Attributes = cloneRequestSecurityEventAttributes(derived.Attributes)
		if derived.Attributes == nil {
			derived.Attributes = map[string]any{}
		}
		derived.Attributes["feedback_source"] = requestSecurityEventTypeRateLimited
		derived.Attributes["strikes"] = result.Strikes
		published := ctx.publishSecurityEvent(derived)
		emitRequestSecurityFeedbackLog(published)
	}
}
