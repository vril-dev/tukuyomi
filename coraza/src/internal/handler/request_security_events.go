package handler

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"tukuyomi/internal/observability"
)

const (
	requestSecurityEventSourceFeedbackLoop = "feedback_loop"

	requestSecurityEventTypeIPReputation         = "ip_reputation"
	requestSecurityEventTypeBotDefenseObserve    = "bot_defense_observe"
	requestSecurityEventTypeBotChallenge         = "bot_challenge"
	requestSecurityEventTypeBotChallengeDryRun   = "bot_challenge_dry_run"
	requestSecurityEventTypeBotQuarantine        = "bot_quarantine"
	requestSecurityEventTypeBotQuarantineDryRun  = "bot_quarantine_dry_run"
	requestSecurityEventTypeBotChallengeIssued   = "bot_challenge_issued"
	requestSecurityEventTypeBotChallengePassed   = "bot_challenge_passed"
	requestSecurityEventTypeBotChallengeFailed   = "bot_challenge_failed"
	requestSecurityEventTypeIPReputationFeedback = "ip_reputation_feedback_applied"
	requestSecurityEventTypeSemanticAnomaly      = "semantic_anomaly"
	requestSecurityEventTypeRateLimited          = "rate_limited"
	requestSecurityEventTypeRateLimitPromotion   = "rate_limit_quarantine_promoted"
	requestSecurityEventTypeWAFBlock             = "waf_block"
	requestSecurityEventActionAllow              = "allow"
	requestSecurityEventActionObserve            = "observe"
	requestSecurityEventActionBlock              = "block"
	requestSecurityEventActionChallenge          = "challenge"
	requestSecurityEventActionQuarantine         = "quarantine"
	requestSecurityEventActionAllowWithFindings  = "allow_with_findings"
	requestSecurityEventActionWouldChallenge     = "would_challenge"
	requestSecurityEventActionWouldQuarantine    = "would_quarantine"
)

type requestSecurityEvent struct {
	Sequence      int            `json:"sequence"`
	EventID       string         `json:"event_id"`
	TS            string         `json:"ts"`
	ReqID         string         `json:"req_id"`
	TraceID       string         `json:"trace_id,omitempty"`
	ClientIP      string         `json:"client_ip,omitempty"`
	Country       string         `json:"country,omitempty"`
	CountrySource string         `json:"country_source,omitempty"`
	Path          string         `json:"path,omitempty"`
	Phase         string         `json:"phase,omitempty"`
	SourcePlugin  string         `json:"source_plugin,omitempty"`
	Family        string         `json:"family,omitempty"`
	EventType     string         `json:"event_type,omitempty"`
	Action        string         `json:"action,omitempty"`
	Enforced      bool           `json:"enforced"`
	DryRun        bool           `json:"dry_run,omitempty"`
	RiskScore     int            `json:"risk_score,omitempty"`
	Status        int            `json:"status,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type requestSecurityEventObserver func(requestSecurityEvent)

type requestSecurityEventBus struct {
	mu        sync.RWMutex
	events    []requestSecurityEvent
	observers []requestSecurityEventObserver
}

type requestSecurityEventStatsSnapshot struct {
	PublishedTotal                uint64 `json:"published_total"`
	BotChallengeFailuresTotal     uint64 `json:"bot_challenge_failures_total"`
	BotChallengePenaltiesTotal    uint64 `json:"bot_challenge_penalties_total"`
	RateLimitPromotionsTotal      uint64 `json:"rate_limit_promotions_total"`
	RateLimitPromotionDryRunTotal uint64 `json:"rate_limit_promotion_dry_run_total"`
}

type requestSecurityRateLimitFeedbackResult struct {
	Promoted  bool
	DryRun    bool
	Strikes   int
	HostScope string
}

var (
	requestSecurityEventsPublishedTotal          atomic.Uint64
	requestSecurityBotChallengeFailuresTotal     atomic.Uint64
	requestSecurityBotChallengePenaltiesTotal    atomic.Uint64
	requestSecurityRateLimitPromotionsTotal      atomic.Uint64
	requestSecurityRateLimitPromotionDryRunTotal atomic.Uint64
)

func newRequestSecurityEventBus() *requestSecurityEventBus {
	return &requestSecurityEventBus{}
}

func cloneRequestSecurityEventAttributes(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneRequestSecurityEvent(in requestSecurityEvent) requestSecurityEvent {
	in.Attributes = cloneRequestSecurityEventAttributes(in.Attributes)
	return in
}

func (b *requestSecurityEventBus) Publish(evt requestSecurityEvent) requestSecurityEvent {
	if b == nil {
		return evt
	}
	b.mu.Lock()
	evt = cloneRequestSecurityEvent(evt)
	evt.Sequence = len(b.events) + 1
	if strings.TrimSpace(evt.EventID) == "" {
		evt.EventID = fmt.Sprintf("%s-sec-%d-%d", strings.TrimSpace(evt.ReqID), evt.Sequence, time.Now().UTC().UnixNano())
	}
	b.events = append(b.events, evt)
	observers := append([]requestSecurityEventObserver(nil), b.observers...)
	b.mu.Unlock()

	requestSecurityEventsPublishedTotal.Add(1)
	for _, observer := range observers {
		if observer != nil {
			observer(cloneRequestSecurityEvent(evt))
		}
	}
	return evt
}

func (b *requestSecurityEventBus) Events() []requestSecurityEvent {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]requestSecurityEvent, 0, len(b.events))
	for _, evt := range b.events {
		out = append(out, cloneRequestSecurityEvent(evt))
	}
	return out
}

func (b *requestSecurityEventBus) Subscribe(observer requestSecurityEventObserver) {
	if b == nil || observer == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observers = append(b.observers, observer)
}

func RequestSecurityEventStatsSnapshot() requestSecurityEventStatsSnapshot {
	return requestSecurityEventStatsSnapshot{
		PublishedTotal:                requestSecurityEventsPublishedTotal.Load(),
		BotChallengeFailuresTotal:     requestSecurityBotChallengeFailuresTotal.Load(),
		BotChallengePenaltiesTotal:    requestSecurityBotChallengePenaltiesTotal.Load(),
		RateLimitPromotionsTotal:      requestSecurityRateLimitPromotionsTotal.Load(),
		RateLimitPromotionDryRunTotal: requestSecurityRateLimitPromotionDryRunTotal.Load(),
	}
}

func (ctx *requestSecurityPluginContext) SubscribeSecurityEvents(observer requestSecurityEventObserver) {
	if ctx == nil {
		return
	}
	ctx.EventBus.Subscribe(observer)
}

func (ctx *requestSecurityPluginContext) SecurityEvents() []requestSecurityEvent {
	if ctx == nil {
		return nil
	}
	return ctx.EventBus.Events()
}

func (ctx *requestSecurityPluginContext) newSecurityEvent(req *http.Request, sourcePlugin, family, eventType, action string) requestSecurityEvent {
	traceCtx := context.Background()
	if req != nil {
		traceCtx = req.Context()
	}
	evt := requestSecurityEvent{
		TS:            time.Now().UTC().Format(time.RFC3339Nano),
		ReqID:         strings.TrimSpace(ctx.RequestID),
		TraceID:       observability.TraceIDFromContext(traceCtx),
		ClientIP:      strings.TrimSpace(ctx.ClientIP),
		Country:       strings.TrimSpace(ctx.Country),
		CountrySource: strings.TrimSpace(ctx.CountrySource),
		Phase:         string(requestSecurityPluginPhasePreWAF),
		SourcePlugin:  strings.TrimSpace(sourcePlugin),
		Family:        strings.TrimSpace(family),
		EventType:     strings.TrimSpace(eventType),
		Action:        strings.TrimSpace(action),
	}
	if req != nil && req.URL != nil {
		evt.Path = req.URL.Path
	}
	return evt
}

func (ctx *requestSecurityPluginContext) deriveSecurityEvent(base requestSecurityEvent, sourcePlugin, family, eventType, action string) requestSecurityEvent {
	evt := cloneRequestSecurityEvent(base)
	evt.EventID = ""
	evt.SourcePlugin = strings.TrimSpace(sourcePlugin)
	evt.Family = strings.TrimSpace(family)
	evt.EventType = strings.TrimSpace(eventType)
	evt.Action = strings.TrimSpace(action)
	evt.Attributes = cloneRequestSecurityEventAttributes(evt.Attributes)
	evt.TS = time.Now().UTC().Format(time.RFC3339Nano)
	return evt
}

func (ctx *requestSecurityPluginContext) publishSecurityEvent(evt requestSecurityEvent) requestSecurityEvent {
	if ctx == nil {
		return evt
	}
	return ctx.EventBus.Publish(evt)
}

func emitRequestSecurityFeedbackLog(evt requestSecurityEvent) {
	logLevel := "INFO"
	if evt.Enforced && !evt.DryRun {
		logLevel = "WARN"
	}
	payload := map[string]any{
		"ts":             evt.TS,
		"service":        "coraza",
		"level":          logLevel,
		"event":          evt.EventType,
		"req_id":         evt.ReqID,
		"trace_id":       evt.TraceID,
		"ip":             evt.ClientIP,
		"country":        evt.Country,
		"country_source": evt.CountrySource,
		"path":           evt.Path,
		"source_plugin":  evt.SourcePlugin,
		"family":         evt.Family,
		"action":         evt.Action,
		"enforced":       evt.Enforced,
		"dry_run":        evt.DryRun,
	}
	if evt.RiskScore > 0 {
		payload["risk_score"] = evt.RiskScore
	}
	if evt.Status > 0 {
		payload["status"] = evt.Status
	}
	if len(evt.Attributes) > 0 {
		payload["attributes"] = evt.Attributes
	}
	emitJSONLogAndAppendEvent(payload)
}
