package requestsecurityevents

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	SourceFeedbackLoop = "feedback_loop"

	TypeIPReputation         = "ip_reputation"
	TypeBotDefenseObserve    = "bot_defense_observe"
	TypeBotChallenge         = "bot_challenge"
	TypeBotChallengeDryRun   = "bot_challenge_dry_run"
	TypeBotQuarantine        = "bot_quarantine"
	TypeBotQuarantineDryRun  = "bot_quarantine_dry_run"
	TypeBotChallengeIssued   = "bot_challenge_issued"
	TypeBotChallengePassed   = "bot_challenge_passed"
	TypeBotChallengeFailed   = "bot_challenge_failed"
	TypeIPReputationFeedback = "ip_reputation_feedback_applied"
	TypeSemanticAnomaly      = "semantic_anomaly"
	TypeRateLimited          = "rate_limited"
	TypeRateLimitPromotion   = "rate_limit_quarantine_promoted"
	TypeWAFBlock             = "waf_block"

	ActionAllow             = "allow"
	ActionObserve           = "observe"
	ActionBlock             = "block"
	ActionChallenge         = "challenge"
	ActionQuarantine        = "quarantine"
	ActionAllowWithFindings = "allow_with_findings"
	ActionWouldChallenge    = "would_challenge"
	ActionWouldQuarantine   = "would_quarantine"
)

type Event struct {
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

type Observer func(Event)

type Bus struct {
	mu        sync.RWMutex
	stats     *Stats
	events    []Event
	observers []Observer
}

type StatsSnapshot struct {
	PublishedTotal                uint64 `json:"published_total"`
	BotChallengeFailuresTotal     uint64 `json:"bot_challenge_failures_total"`
	BotChallengePenaltiesTotal    uint64 `json:"bot_challenge_penalties_total"`
	RateLimitPromotionsTotal      uint64 `json:"rate_limit_promotions_total"`
	RateLimitPromotionDryRunTotal uint64 `json:"rate_limit_promotion_dry_run_total"`
}

type RateLimitFeedbackResult struct {
	Promoted  bool
	DryRun    bool
	Strikes   int
	HostScope string
}

type Stats struct {
	publishedTotal                atomic.Uint64
	botChallengeFailuresTotal     atomic.Uint64
	botChallengePenaltiesTotal    atomic.Uint64
	rateLimitPromotionsTotal      atomic.Uint64
	rateLimitPromotionDryRunTotal atomic.Uint64
}

func NewStats() *Stats {
	return &Stats{}
}

func NewBus(stats *Stats) *Bus {
	return &Bus{stats: stats}
}

func CloneAttributes(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]any, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func CloneEvent(in Event) Event {
	in.Attributes = CloneAttributes(in.Attributes)
	return in
}

func (b *Bus) Publish(evt Event) Event {
	if b == nil {
		return evt
	}
	b.mu.Lock()
	evt = CloneEvent(evt)
	evt.Sequence = len(b.events) + 1
	if strings.TrimSpace(evt.EventID) == "" {
		evt.EventID = fmt.Sprintf("%s-sec-%d-%d", strings.TrimSpace(evt.ReqID), evt.Sequence, time.Now().UTC().UnixNano())
	}
	b.events = append(b.events, evt)
	observers := append([]Observer(nil), b.observers...)
	b.mu.Unlock()

	if b.stats != nil {
		b.stats.publishedTotal.Add(1)
	}
	for _, observer := range observers {
		if observer != nil {
			observer(CloneEvent(evt))
		}
	}
	return evt
}

func (b *Bus) Events() []Event {
	if b == nil {
		return nil
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	out := make([]Event, 0, len(b.events))
	for _, evt := range b.events {
		out = append(out, CloneEvent(evt))
	}
	return out
}

func (b *Bus) Subscribe(observer Observer) {
	if b == nil || observer == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	b.observers = append(b.observers, observer)
}

func (s *Stats) Snapshot() StatsSnapshot {
	if s == nil {
		return StatsSnapshot{}
	}
	return StatsSnapshot{
		PublishedTotal:                s.publishedTotal.Load(),
		BotChallengeFailuresTotal:     s.botChallengeFailuresTotal.Load(),
		BotChallengePenaltiesTotal:    s.botChallengePenaltiesTotal.Load(),
		RateLimitPromotionsTotal:      s.rateLimitPromotionsTotal.Load(),
		RateLimitPromotionDryRunTotal: s.rateLimitPromotionDryRunTotal.Load(),
	}
}

func (s *Stats) Restore(snapshot StatsSnapshot) {
	if s == nil {
		return
	}
	s.publishedTotal.Store(snapshot.PublishedTotal)
	s.botChallengeFailuresTotal.Store(snapshot.BotChallengeFailuresTotal)
	s.botChallengePenaltiesTotal.Store(snapshot.BotChallengePenaltiesTotal)
	s.rateLimitPromotionsTotal.Store(snapshot.RateLimitPromotionsTotal)
	s.rateLimitPromotionDryRunTotal.Store(snapshot.RateLimitPromotionDryRunTotal)
}

func (s *Stats) AddBotChallengeFailure() {
	if s != nil {
		s.botChallengeFailuresTotal.Add(1)
	}
}

func (s *Stats) AddBotChallengePenalty() {
	if s != nil {
		s.botChallengePenaltiesTotal.Add(1)
	}
}

func (s *Stats) AddRateLimitPromotion() {
	if s != nil {
		s.rateLimitPromotionsTotal.Add(1)
	}
}

func (s *Stats) AddRateLimitPromotionDryRun() {
	if s != nil {
		s.rateLimitPromotionDryRunTotal.Add(1)
	}
}
