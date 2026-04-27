package semanticrisk

import (
	"strings"
	"sync"
	"time"
)

const (
	DefaultTemporalWindowSeconds       = 10
	DefaultTemporalMaxEntriesPerIP     = 128
	DefaultTemporalBurstThreshold      = 20
	DefaultTemporalBurstScore          = 2
	DefaultTemporalPathFanoutThreshold = 8
	DefaultTemporalPathFanoutScore     = 2
	DefaultTemporalUAChurnThreshold    = 4
	DefaultTemporalUAChurnScore        = 1
)

type Signal struct {
	Reason string `json:"reason"`
	Score  int    `json:"score"`
}

type TemporalConfig struct {
	WindowSeconds   int
	MaxEntriesPerIP int
}

type TemporalThresholds struct {
	BurstThreshold      int
	BurstScore          int
	PathFanoutThreshold int
	PathFanoutScore     int
	UAChurnThreshold    int
	UAChurnScore        int
}

type TemporalStore struct {
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

type TemporalSnapshot struct {
	RequestCount       int
	DistinctPaths      int
	DistinctUserAgents int
}

func NewTemporalStore(cfg TemporalConfig) *TemporalStore {
	window := cfg.WindowSeconds
	if window <= 0 {
		window = DefaultTemporalWindowSeconds
	}
	maxEntries := cfg.MaxEntriesPerIP
	if maxEntries <= 0 {
		maxEntries = DefaultTemporalMaxEntriesPerIP
	}
	return &TemporalStore{
		window:          time.Duration(window) * time.Second,
		maxEntriesPerIP: maxEntries,
		byIP:            make(map[string][]temporalObservation, 1024),
	}
}

func (s *TemporalStore) Observe(ipStr, path, userAgent string, now time.Time) TemporalSnapshot {
	if s == nil {
		return TemporalSnapshot{}
	}
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return TemporalSnapshot{}
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
	return TemporalSnapshot{
		RequestCount:       len(kept),
		DistinctPaths:      len(paths),
		DistinctUserAgents: len(uas),
	}
}

func EvaluateTemporal(snap TemporalSnapshot, cfg TemporalThresholds) []Signal {
	out := make([]Signal, 0, 3)
	if snap.RequestCount >= cfg.BurstThreshold {
		out = append(out, Signal{Reason: "temporal:ip_burst", Score: cfg.BurstScore})
	}
	if snap.DistinctPaths >= cfg.PathFanoutThreshold {
		out = append(out, Signal{Reason: "temporal:ip_path_fanout", Score: cfg.PathFanoutScore})
	}
	if snap.DistinctUserAgents >= cfg.UAChurnThreshold {
		out = append(out, Signal{Reason: "temporal:ip_ua_churn", Score: cfg.UAChurnScore})
	}
	return out
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
