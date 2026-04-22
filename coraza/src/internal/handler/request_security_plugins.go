package handler

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"tukuyomi/internal/observability"
)

type requestSecurityPluginPhase string

const (
	requestSecurityPluginPhasePreWAF  requestSecurityPluginPhase = "pre_waf"
	requestSecurityPluginPhasePostWAF requestSecurityPluginPhase = "post_waf"
)

type requestSecurityPlugin interface {
	Name() string
	Phase() requestSecurityPluginPhase
	Enabled() bool
	Handle(c *proxyServeContext, ctx *requestSecurityPluginContext) bool
}

type requestSecurityPluginContext struct {
	RequestID                  string
	ClientIP                   string
	Country                    string
	CountrySource              string
	RequestHost                string
	RequestTLS                 bool
	Now                        time.Time
	BotSuspicionScore          int
	BotSuspicionSignals        []string
	Semantic                   semanticEvaluation
	AuditTrail                 *securityAuditTrail
	EventBus                   *requestSecurityEventBus
	BotChallengePenaltyApplied bool
	BotChallengePenaltyTTL     time.Duration
	RateLimitFeedback          requestSecurityRateLimitFeedbackResult
}

type requestSecurityPluginFactory func() requestSecurityPlugin

var (
	requestSecurityPluginRegistryMu sync.RWMutex
	requestSecurityPluginFactories  []requestSecurityPluginFactory
)

func init() {
	registerRequestSecurityPlugin(newIPReputationRequestSecurityPlugin)
	registerRequestSecurityPlugin(newBotDefenseRequestSecurityPlugin)
	registerRequestSecurityPlugin(newSemanticRequestSecurityPlugin)
}

func registerRequestSecurityPlugin(factory requestSecurityPluginFactory) {
	if factory == nil {
		return
	}
	requestSecurityPluginRegistryMu.Lock()
	defer requestSecurityPluginRegistryMu.Unlock()
	requestSecurityPluginFactories = append(requestSecurityPluginFactories, factory)
}

func newRequestSecurityPlugins() []requestSecurityPlugin {
	requestSecurityPluginRegistryMu.RLock()
	factories := append([]requestSecurityPluginFactory(nil), requestSecurityPluginFactories...)
	requestSecurityPluginRegistryMu.RUnlock()

	out := make([]requestSecurityPlugin, 0, len(factories))
	for _, factory := range factories {
		if factory == nil {
			continue
		}
		p := factory()
		if p == nil {
			continue
		}
		out = append(out, p)
	}
	return out
}

func newRequestSecurityPluginContext(reqID, clientIP, country string, now time.Time) *requestSecurityPluginContext {
	ctx := &requestSecurityPluginContext{
		RequestID: reqID,
		ClientIP:  clientIP,
		Country:   country,
		Now:       now.UTC(),
		EventBus:  newRequestSecurityEventBus(),
		Semantic: semanticEvaluation{
			Action: semanticActionNone,
		},
	}
	ctx.SubscribeSecurityEvents(func(evt requestSecurityEvent) {
		handleRequestSecurityFeedbackEvent(ctx, evt)
	})
	return ctx
}

func runRequestSecurityPlugins(c *proxyServeContext, phase requestSecurityPluginPhase, plugins []requestSecurityPlugin, ctx *requestSecurityPluginContext) bool {
	for _, p := range plugins {
		if p == nil || p.Phase() != phase || !p.Enabled() {
			continue
		}
		if ok := p.Handle(c, ctx); !ok {
			return false
		}
	}
	return true
}

func (ctx *requestSecurityPluginContext) newEvent(req *http.Request, level, event string) map[string]any {
	evt := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"service":  "coraza",
		"level":    level,
		"event":    event,
		"req_id":   ctx.RequestID,
		"trace_id": observability.TraceIDFromContext(req.Context()),
		"ip":       ctx.ClientIP,
		"country":  ctx.Country,
	}
	if strings.TrimSpace(ctx.CountrySource) != "" {
		evt["country_source"] = ctx.CountrySource
	}
	if req != nil && req.URL != nil {
		evt["path"] = req.URL.Path
	}
	return evt
}

func (ctx *requestSecurityPluginContext) emitEvent(req *http.Request, evt map[string]any) {
	appendProxyRouteLogFields(evt, req)
	emitJSONLogAndAppendEvent(evt)
}

type ipReputationRequestSecurityPlugin struct{}

func newIPReputationRequestSecurityPlugin() requestSecurityPlugin {
	return &ipReputationRequestSecurityPlugin{}
}

func (p *ipReputationRequestSecurityPlugin) Name() string {
	return "ip_reputation"
}

func (p *ipReputationRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *ipReputationRequestSecurityPlugin) Enabled() bool {
	rt := currentIPReputationRuntime()
	return rt != nil && ipReputationEnabled(rt.Raw)
}

func (p *ipReputationRequestSecurityPlugin) Handle(c *proxyServeContext, ctx *requestSecurityPluginContext) bool {
	blocked, statusCode, hostScope := EvaluateIPReputationForRequest(c.Request, ctx.ClientIP)
	if !blocked {
		return true
	}
	if ctx != nil && ctx.AuditTrail != nil {
		ctx.AuditTrail.recordIPReputation(statusCode)
		ctx.AuditTrail.setTerminal("ip_reputation", "ip_reputation", "blocked", statusCode)
	}
	securityEvt := ctx.newSecurityEvent(c.Request, p.Name(), "ip_reputation", requestSecurityEventTypeIPReputation, requestSecurityEventActionBlock)
	securityEvt.Enforced = true
	securityEvt.Status = statusCode
	securityEvt.Attributes = map[string]any{
		"host_scope": hostScope,
	}
	ctx.publishSecurityEvent(securityEvt)
	evt := ctx.newEvent(c.Request, "WARN", "ip_reputation")
	evt["status"] = statusCode
	evt["host_scope"] = hostScope
	ctx.emitEvent(c.Request, evt)
	c.AbortWithStatus(statusCode)
	return false
}

type botDefenseRequestSecurityPlugin struct{}

func newBotDefenseRequestSecurityPlugin() requestSecurityPlugin {
	return &botDefenseRequestSecurityPlugin{}
}

func (p *botDefenseRequestSecurityPlugin) Name() string {
	return "bot_defense"
}

func (p *botDefenseRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *botDefenseRequestSecurityPlugin) Enabled() bool {
	rt := currentBotDefenseRuntime()
	return rt != nil && botDefenseEnabled(rt.File)
}

func (p *botDefenseRequestSecurityPlugin) Handle(c *proxyServeContext, ctx *requestSecurityPluginContext) bool {
	botDecision := EvaluateBotDefense(c.Request, ctx.ClientIP, ctx.Now)
	ctx.BotSuspicionScore = botDecision.RiskScore
	ctx.BotSuspicionSignals = append(ctx.BotSuspicionSignals[:0], botDecision.Signals...)
	sourceEvent := "bot_defense_observe"
	if botDecision.Action == botDefenseActionQuarantine {
		sourceEvent = "bot_quarantine"
	} else if botDecision.Action == botDefenseActionChallenge {
		sourceEvent = "bot_challenge"
	}
	if botDecision.DryRun && botDecision.Action == botDefenseActionQuarantine {
		sourceEvent = "bot_quarantine_dry_run"
	} else if botDecision.DryRun && botDecision.Action == botDefenseActionChallenge {
		sourceEvent = "bot_challenge_dry_run"
	}
	if botDecision.ChallengeOutcome == botDefenseChallengeOutcomeFailed {
		sourceEvent = requestSecurityEventTypeBotChallengeFailed
	}

	if botDecision.ChallengeOutcome != "" {
		outcomeType := requestSecurityEventTypeBotChallengePassed
		if botDecision.ChallengeOutcome == botDefenseChallengeOutcomeFailed {
			outcomeType = requestSecurityEventTypeBotChallengeFailed
		}
		outcomeEvt := ctx.newSecurityEvent(c.Request, p.Name(), "bot_defense", outcomeType, requestSecurityEventActionObserve)
		outcomeEvt.Enforced = !botDecision.DryRun
		outcomeEvt.DryRun = botDecision.DryRun
		outcomeEvt.RiskScore = botDecision.RiskScore
		outcomeEvt.Attributes = map[string]any{
			"mode":                      botDecision.Mode,
			"host_scope":                botDecision.HostScope,
			"flow_policy":               botDecision.FlowPolicy,
			"telemetry_cookie_required": botDecision.TelemetryCookieRequired,
		}
		if botDecision.ChallengeFailureReason != "" {
			outcomeEvt.Attributes["failure_reason"] = botDecision.ChallengeFailureReason
		}
		if len(botDecision.Signals) > 0 {
			outcomeEvt.Attributes["signals"] = append([]string(nil), botDecision.Signals...)
		}
		ctx.publishSecurityEvent(outcomeEvt)
	}

	if botDecision.Action == botDefenseActionChallenge && !botDecision.DryRun {
		rememberBotDefenseChallengeState(
			botDecision.HostScope,
			ctx.ClientIP,
			c.Request.UserAgent(),
			botDecision.FlowPolicy,
			botDecision.TelemetryCookieRequired,
			ctx.Now.UTC(),
			ctx.Now.UTC().Add(time.Duration(botDecision.TTLSeconds)*time.Second),
		)
		issuedEvt := ctx.newSecurityEvent(c.Request, p.Name(), "bot_defense", requestSecurityEventTypeBotChallengeIssued, requestSecurityEventActionChallenge)
		issuedEvt.Enforced = true
		issuedEvt.Status = botDecision.Status
		issuedEvt.RiskScore = botDecision.RiskScore
		issuedEvt.Attributes = map[string]any{
			"mode":                      botDecision.Mode,
			"host_scope":                botDecision.HostScope,
			"flow_policy":               botDecision.FlowPolicy,
			"ttl_seconds":               botDecision.TTLSeconds,
			"telemetry_cookie_required": botDecision.TelemetryCookieRequired,
		}
		if len(botDecision.Signals) > 0 {
			issuedEvt.Attributes["signals"] = append([]string(nil), botDecision.Signals...)
		}
		ctx.publishSecurityEvent(issuedEvt)
	} else if botDecision.ChallengeOutcome != "" || botDecision.Action == botDefenseActionQuarantine {
		clearBotDefenseChallengeState(botDecision.HostScope, ctx.ClientIP, c.Request.UserAgent())
	}

	if botDecision.Action != "" || botDecision.RiskScore > 0 {
		securityEvt := ctx.newSecurityEvent(c.Request, p.Name(), "bot_defense", requestSecurityEventTypeBotDefenseObserve, requestSecurityEventActionObserve)
		switch {
		case botDecision.Action == botDefenseActionQuarantine && botDecision.DryRun:
			securityEvt.EventType = requestSecurityEventTypeBotQuarantineDryRun
			securityEvt.Action = requestSecurityEventActionWouldQuarantine
		case botDecision.Action == botDefenseActionQuarantine:
			securityEvt.EventType = requestSecurityEventTypeBotQuarantine
			securityEvt.Action = requestSecurityEventActionQuarantine
			securityEvt.Enforced = true
		case botDecision.Action == botDefenseActionChallenge && botDecision.DryRun:
			securityEvt.EventType = requestSecurityEventTypeBotChallengeDryRun
			securityEvt.Action = requestSecurityEventActionWouldChallenge
		case botDecision.Action == botDefenseActionChallenge:
			securityEvt.EventType = requestSecurityEventTypeBotChallenge
			securityEvt.Action = requestSecurityEventActionChallenge
			securityEvt.Enforced = true
		}
		securityEvt.DryRun = botDecision.DryRun
		securityEvt.Status = botDecision.Status
		securityEvt.RiskScore = botDecision.RiskScore
		securityEvt.Attributes = map[string]any{
			"mode":                      botDecision.Mode,
			"host_scope":                botDecision.HostScope,
			"flow_policy":               botDecision.FlowPolicy,
			"telemetry_cookie_required": botDecision.TelemetryCookieRequired,
		}
		if botDecision.ChallengeOutcome != "" {
			securityEvt.Attributes["challenge_outcome"] = botDecision.ChallengeOutcome
		}
		if botDecision.ChallengeFailureReason != "" {
			securityEvt.Attributes["challenge_failure_reason"] = botDecision.ChallengeFailureReason
		}
		if len(botDecision.Signals) > 0 {
			securityEvt.Attributes["signals"] = append([]string(nil), botDecision.Signals...)
		}
		if botDecision.Action == botDefenseActionChallenge {
			securityEvt.Attributes["ttl_seconds"] = botDecision.TTLSeconds
		}
		ctx.publishSecurityEvent(securityEvt)
	}
	if botDecision.Action != "" || botDecision.RiskScore > 0 {
		recordBotDefenseDecision(c.Request, ctx, botDecision)
		if ctx != nil && ctx.AuditTrail != nil {
			ctx.AuditTrail.recordBotDefense(botDecision, sourceEvent, ctx.BotChallengePenaltyApplied, ctx.BotChallengePenaltyTTL)
		}
	}
	if botDecision.DryRun && botDecision.Action != "" {
		eventName := "bot_challenge_dry_run"
		if botDecision.Action == botDefenseActionQuarantine {
			eventName = "bot_quarantine_dry_run"
		}
		evt := ctx.newEvent(c.Request, "WARN", eventName)
		evt["status"] = botDecision.Status
		evt["mode"] = botDecision.Mode
		evt["action"] = botDecision.Action
		evt["risk_score"] = botDecision.RiskScore
		evt["dry_run"] = true
		evt["host_scope"] = botDecision.HostScope
		if botDecision.FlowPolicy != "" {
			evt["flow_policy"] = botDecision.FlowPolicy
		}
		if botDecision.ChallengeOutcome != "" {
			evt["challenge_outcome"] = botDecision.ChallengeOutcome
		}
		if botDecision.ChallengeFailureReason != "" {
			evt["challenge_failure_reason"] = botDecision.ChallengeFailureReason
		}
		if ctx.BotChallengePenaltyApplied {
			evt["ip_reputation_feedback_applied"] = true
			evt["ip_reputation_feedback_ttl_seconds"] = int(ctx.BotChallengePenaltyTTL.Seconds())
		}
		if len(botDecision.Signals) > 0 {
			evt["signals"] = strings.Join(botDecision.Signals, ",")
		}
		ctx.emitEvent(c.Request, evt)
		c.Header("X-Tukuyomi-Bot-Dry-Run", botDecision.Action)
		return true
	}
	if botDecision.Allowed {
		return true
	}
	eventName := "bot_challenge"
	if botDecision.Action == botDefenseActionQuarantine {
		eventName = "bot_quarantine"
	}
	if ctx != nil && ctx.AuditTrail != nil {
		ctx.AuditTrail.setTerminal("bot_defense", eventName, botDefenseEffectiveAction(botDecision), botDecision.Status)
	}
	evt := ctx.newEvent(c.Request, "WARN", eventName)
	evt["status"] = botDecision.Status
	evt["mode"] = botDecision.Mode
	evt["action"] = botDecision.Action
	evt["risk_score"] = botDecision.RiskScore
	evt["host_scope"] = botDecision.HostScope
	if botDecision.FlowPolicy != "" {
		evt["flow_policy"] = botDecision.FlowPolicy
	}
	if botDecision.ChallengeOutcome != "" {
		evt["challenge_outcome"] = botDecision.ChallengeOutcome
	}
	if botDecision.ChallengeFailureReason != "" {
		evt["challenge_failure_reason"] = botDecision.ChallengeFailureReason
	}
	if ctx.BotChallengePenaltyApplied {
		evt["ip_reputation_feedback_applied"] = true
		evt["ip_reputation_feedback_ttl_seconds"] = int(ctx.BotChallengePenaltyTTL.Seconds())
	}
	if len(botDecision.Signals) > 0 {
		evt["signals"] = strings.Join(botDecision.Signals, ",")
	}
	ctx.emitEvent(c.Request, evt)
	if botDecision.Action == botDefenseActionQuarantine {
		c.AbortWithStatus(botDecision.Status)
		return false
	}
	WriteBotDefenseChallenge(c.Writer, c.Request, botDecision)
	c.Abort()
	return false
}

type semanticRequestSecurityPlugin struct{}

func newSemanticRequestSecurityPlugin() requestSecurityPlugin {
	return &semanticRequestSecurityPlugin{}
}

func (p *semanticRequestSecurityPlugin) Name() string {
	return "semantic"
}

func (p *semanticRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return requestSecurityPluginPhasePreWAF
}

func (p *semanticRequestSecurityPlugin) Enabled() bool {
	rt := currentSemanticRuntime()
	return rt != nil && semanticEnabled(rt.File)
}

func (p *semanticRequestSecurityPlugin) Handle(c *proxyServeContext, ctx *requestSecurityPluginContext) bool {
	eval := EvaluateSemanticWithRequestID(c.Request, ctx.ClientIP, ctx.RequestID, ctx.Now)
	ctx.Semantic = eval
	if ctx != nil && ctx.AuditTrail != nil && (eval.Score > 0 || eval.Action != semanticActionNone) {
		ctx.AuditTrail.recordSemantic(eval)
	}
	if eval.Score > 0 {
		c.Header("X-Tukuyomi-Semantic-Score", strconv.Itoa(eval.Score))
	}
	if eval.Action == semanticActionNone {
		return true
	}

	evt := ctx.newEvent(c.Request, "WARN", "semantic_anomaly")
	evt["action"] = eval.Action
	evt["host_scope"] = eval.HostScope
	evt["score"] = eval.Score
	evt["base_score"] = eval.BaseScore
	evt["stateful_score"] = eval.StatefulScore
	evt["provider_score"] = eval.ProviderScore
	evt["reasons"] = strings.Join(eval.Reasons, ",")
	evt["reason_list"] = append([]string(nil), eval.Reasons...)
	evt["score_breakdown"] = semanticSignalLogObjects(eval.Signals)
	evt["base_reason_list"] = append([]string(nil), eval.BaseReasons...)
	evt["stateful_reason_list"] = append([]string(nil), eval.StatefulReasons...)
	evt["provider_reason_list"] = append([]string(nil), eval.ProviderReasons...)
	evt["base_score_breakdown"] = semanticSignalLogObjects(eval.BaseSignals)
	evt["stateful_score_breakdown"] = semanticSignalLogObjects(eval.StatefulSignals)
	evt["provider_score_breakdown"] = semanticSignalLogObjects(eval.ProviderSignals)
	if eval.Telemetry != nil {
		if eval.Telemetry.Context.ActorKey != "" {
			evt["actor_key"] = eval.Telemetry.Context.ActorKey
		}
		if eval.Telemetry.Context.PathClass != "" {
			evt["path_class"] = eval.Telemetry.Context.PathClass
		}
		if eval.Telemetry.Context.TargetClass != "" {
			evt["target_class"] = eval.Telemetry.Context.TargetClass
		}
		if eval.Telemetry.Context.SurfaceClass != "" {
			evt["surface_class"] = eval.Telemetry.Context.SurfaceClass
		}
		evt["semantic_context"] = eval.Telemetry.Context
		evt["semantic_fingerprints"] = eval.Telemetry.Fingerprints
		if len(eval.Telemetry.FeatureBuckets) > 0 {
			evt["semantic_feature_buckets"] = append([]string(nil), eval.Telemetry.FeatureBuckets...)
		}
	}
	if eval.StatefulSnapshot != nil {
		evt["semantic_stateful_history"] = eval.StatefulSnapshot
	}
	if eval.ProviderResult != nil {
		evt["provider_name"] = eval.ProviderResult.Name
		evt["provider_attack_family"] = eval.ProviderResult.AttackFamily
		evt["provider_confidence"] = eval.ProviderResult.Confidence
	}

	securityEvt := ctx.newSecurityEvent(c.Request, p.Name(), "semantic", requestSecurityEventTypeSemanticAnomaly, requestSecurityEventActionAllowWithFindings)
	securityEvt.RiskScore = eval.Score
	securityEvt.Attributes = map[string]any{
		"host_scope":     eval.HostScope,
		"score":          eval.Score,
		"base_score":     eval.BaseScore,
		"stateful_score": eval.StatefulScore,
		"provider_score": eval.ProviderScore,
		"reasons":        append([]string(nil), eval.Reasons...),
	}
	switch eval.Action {
	case semanticActionLogOnly:
		securityEvt.Action = requestSecurityEventActionObserve
	case semanticActionChallenge:
		securityEvt.Action = requestSecurityEventActionChallenge
	case semanticActionBlock:
		securityEvt.Action = requestSecurityEventActionBlock
	}

	switch eval.Action {
	case semanticActionChallenge:
		if !HasValidSemanticChallengeCookie(c.Request, ctx.ClientIP, ctx.Now) {
			statusCode := http.StatusTooManyRequests
			if selection := selectSemanticScope(currentSemanticRuntime(), c.Request); selection.Runtime != nil {
				statusCode = selection.Runtime.challengeStatusCode
			}
			if ctx != nil && ctx.AuditTrail != nil {
				ctx.AuditTrail.setTerminal("semantic", "semantic_anomaly", "challenge", statusCode)
			}
			securityEvt.Enforced = true
			securityEvt.Status = statusCode
			ctx.publishSecurityEvent(securityEvt)
			evt["status"] = statusCode
			ctx.emitEvent(c.Request, evt)
			WriteSemanticChallenge(c.Writer, c.Request, ctx.ClientIP)
			c.Abort()
			return false
		}
		securityEvt.Action = requestSecurityEventActionAllowWithFindings
	case semanticActionBlock:
		if ctx != nil && ctx.AuditTrail != nil {
			ctx.AuditTrail.setTerminal("semantic", "semantic_anomaly", "blocked", http.StatusForbidden)
		}
		securityEvt.Enforced = true
		securityEvt.Status = http.StatusForbidden
		ctx.publishSecurityEvent(securityEvt)
		evt["status"] = http.StatusForbidden
		ctx.emitEvent(c.Request, evt)
		c.AbortWithStatus(http.StatusForbidden)
		return false
	}
	ctx.publishSecurityEvent(securityEvt)
	ctx.emitEvent(c.Request, evt)
	return true
}

func requestSecurityRiskScore(ctx *requestSecurityPluginContext) int {
	if ctx == nil {
		return 0
	}
	return ctx.Semantic.Score + ctx.BotSuspicionScore
}
