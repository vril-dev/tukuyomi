package handler

import (
	"strings"
	"sync"
	"time"
)

const (
	defaultTemporalWindowSeconds       = 10
	defaultTemporalMaxEntriesPerIP     = 128
	defaultTemporalBurstThreshold      = 20
	defaultTemporalBurstScore          = 2
	defaultTemporalPathFanoutThreshold = 8
	defaultTemporalPathFanoutScore     = 2
	defaultTemporalUAChurnThreshold    = 4
	defaultTemporalUAChurnScore        = 1
)

type semanticSignal struct {
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

type temporalRiskStore struct {
	mu              sync.Mutex
	window          time.Duration
	maxEntriesPerIP int
	byIP            map[string][]temporalObservation
}

type temporalObservation struct {
	at   time.Time
	path string
	ua   string
}

type temporalRiskSnapshot struct {
	RequestCount       int
	DistinctPaths      int
	DistinctUserAgents int
}

func newTemporalRiskStore(cfg semanticConfig) *temporalRiskStore {
	window := cfg.TemporalWindowSeconds
	if window <= 0 {
		window = defaultTemporalWindowSeconds
	}
	maxEntries := cfg.TemporalMaxEntriesPerIP
	if maxEntries <= 0 {
		maxEntries = defaultTemporalMaxEntriesPerIP
	}
	return &temporalRiskStore{
		window:          time.Duration(window) * time.Second,
		maxEntriesPerIP: maxEntries,
		byIP:            make(map[string][]temporalObservation, 1024),
	}
}

func (s *temporalRiskStore) Observe(ipStr, path, userAgent string, now time.Time) temporalRiskSnapshot {
	if s == nil {
		return temporalRiskSnapshot{}
	}
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return temporalRiskSnapshot{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.window)
	existing := s.byIP[ipStr]
	kept := existing[:0]
	for _, obs := range existing {
		if !obs.at.Before(cutoff) {
			kept = append(kept, obs)
		}
	}
	kept = append(kept, temporalObservation{
		at:   now,
		path: normalizeTemporalPath(path),
		ua:   normalizeTemporalUserAgent(userAgent),
	})
	if s.maxEntriesPerIP > 0 && len(kept) > s.maxEntriesPerIP {
		kept = kept[len(kept)-s.maxEntriesPerIP:]
	}
	s.byIP[ipStr] = kept

	paths := make(map[string]struct{}, len(kept))
	uas := make(map[string]struct{}, len(kept))
	for _, obs := range kept {
		paths[obs.path] = struct{}{}
		if obs.ua != "" {
			uas[obs.ua] = struct{}{}
		}
	}
	return temporalRiskSnapshot{
		RequestCount:       len(kept),
		DistinctPaths:      len(paths),
		DistinctUserAgents: len(uas),
	}
}

func inspectSemanticTemporalRisk(rt *runtimeSemanticConfig, cfg semanticConfig, clientIP, path, userAgent string, now time.Time, score *int, signals *[]semanticSignal) {
	if rt == nil || rt.temporal == nil {
		return
	}
	snap := rt.temporal.Observe(clientIP, path, userAgent, now)
	if snap.RequestCount >= cfg.TemporalBurstThreshold {
		appendSemanticSignal(signals, score, "temporal:ip_burst", cfg.TemporalBurstScore)
	}
	if snap.DistinctPaths >= cfg.TemporalPathFanoutThreshold {
		appendSemanticSignal(signals, score, "temporal:ip_path_fanout", cfg.TemporalPathFanoutScore)
	}
	if snap.DistinctUserAgents >= cfg.TemporalUAChurnThreshold {
		appendSemanticSignal(signals, score, "temporal:ip_ua_churn", cfg.TemporalUAChurnScore)
	}
}

func normalizeTemporalPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return "/"
	}
	if len(path) > 256 {
		return path[:256]
	}
	return path
}

func normalizeTemporalUserAgent(userAgent string) string {
	userAgent = strings.ToLower(strings.TrimSpace(userAgent))
	if len(userAgent) > 192 {
		return userAgent[:192]
	}
	return userAgent
}
