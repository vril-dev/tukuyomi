package semanticrisk

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	StatefulSensitiveAfterSuspiciousThreshold = 2
	StatefulAdminAfterSuspiciousScore         = 3
	StatefulSensitiveAfterSuspiciousScore     = 2
	StatefulSurfaceShiftThreshold             = 3
	StatefulSurfaceShiftScore                 = 1
	StatefulSensitivityShiftMinHistory        = 3
	StatefulSensitivityShiftScore             = 1
)

type HistoryObservation struct {
	At           time.Time
	PathClass    string
	TargetClass  string
	SurfaceClass string
	BaseScore    int
}

type HistorySnapshot struct {
	PriorRequests           int      `json:"prior_requests"`
	PriorSuspiciousRequests int      `json:"prior_suspicious_requests"`
	DistinctPathClasses     int      `json:"distinct_path_classes"`
	DistinctTargetClasses   int      `json:"distinct_target_classes"`
	DistinctSurfaceClasses  int      `json:"distinct_surface_classes"`
	MaxSeenTargetClass      string   `json:"max_seen_target_class,omitempty"`
	SeenSurfaceClasses      []string `json:"seen_surface_classes,omitempty"`
	SeenTargetClasses       []string `json:"seen_target_classes,omitempty"`
}

type HistoryStore struct {
	mu               sync.Mutex
	window           time.Duration
	maxEntriesPerKey int
	byKey            map[string][]HistoryObservation
}

func NewHistoryStore(cfg TemporalConfig) *HistoryStore {
	window := cfg.WindowSeconds
	if window <= 0 {
		window = DefaultTemporalWindowSeconds
	}
	maxEntries := cfg.MaxEntriesPerIP
	if maxEntries <= 0 {
		maxEntries = DefaultTemporalMaxEntriesPerIP
	}
	return &HistoryStore{
		window:           time.Duration(window) * time.Second,
		maxEntriesPerKey: maxEntries,
		byKey:            make(map[string][]HistoryObservation, 1024),
	}
}

func (s *HistoryStore) Observe(key string, obs HistoryObservation, now time.Time) HistorySnapshot {
	if s == nil {
		return HistorySnapshot{}
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return HistorySnapshot{}
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	cutoff := now.Add(-s.window)
	existing := s.byKey[key]
	kept := existing[:0]
	for _, item := range existing {
		if !item.At.Before(cutoff) {
			kept = append(kept, item)
		}
	}

	snapshot := historySnapshotFromObservations(kept)

	kept = append(kept, obs)
	if s.maxEntriesPerKey > 0 && len(kept) > s.maxEntriesPerKey {
		kept = kept[len(kept)-s.maxEntriesPerKey:]
	}
	s.byKey[key] = kept

	return snapshot
}

func EvaluateStateful(snapshot HistorySnapshot, currentTargetClass string, currentSurfaceClass string, baseScore int) []Signal {
	if snapshot.PriorRequests == 0 {
		return nil
	}

	out := make([]Signal, 0, 3)
	currentRank := targetClassRank(currentTargetClass)
	seenRank := targetClassRank(snapshot.MaxSeenTargetClass)

	if currentTargetClass == "admin_management" && snapshot.PriorSuspiciousRequests >= StatefulSensitiveAfterSuspiciousThreshold {
		out = append(out, Signal{Reason: "stateful:admin_after_suspicious_activity", Score: StatefulAdminAfterSuspiciousScore})
	} else if currentRank >= targetClassRank("account_security") &&
		snapshot.PriorSuspiciousRequests >= StatefulSensitiveAfterSuspiciousThreshold {
		out = append(out, Signal{Reason: "stateful:sensitive_path_after_suspicious_activity", Score: StatefulSensitiveAfterSuspiciousScore})
	}

	if snapshot.PriorRequests >= StatefulSensitivityShiftMinHistory &&
		currentRank >= targetClassRank("account_security") &&
		seenRank >= 0 &&
		currentRank > seenRank {
		out = append(out, Signal{Reason: "stateful:sudden_target_sensitivity_shift", Score: StatefulSensitivityShiftScore})
	}

	if snapshot.PriorRequests >= StatefulSurfaceShiftThreshold &&
		currentSurfaceClass != "" &&
		snapshot.DistinctSurfaceClasses >= 2 &&
		baseScore > 0 &&
		!stringListContains(snapshot.SeenSurfaceClasses, currentSurfaceClass) {
		out = append(out, Signal{Reason: "stateful:rapid_surface_shift", Score: StatefulSurfaceShiftScore})
	}

	return out
}

func historySnapshotFromObservations(observations []HistoryObservation) HistorySnapshot {
	if len(observations) == 0 {
		return HistorySnapshot{}
	}
	pathClasses := make(map[string]struct{}, len(observations))
	targetClasses := make(map[string]struct{}, len(observations))
	surfaceClasses := make(map[string]struct{}, len(observations))

	snapshot := HistorySnapshot{
		PriorRequests: len(observations),
	}
	maxRank := -1
	for _, obs := range observations {
		if obs.BaseScore > 0 {
			snapshot.PriorSuspiciousRequests++
		}
		if obs.PathClass != "" {
			pathClasses[obs.PathClass] = struct{}{}
		}
		if obs.TargetClass != "" {
			targetClasses[obs.TargetClass] = struct{}{}
			if rank := targetClassRank(obs.TargetClass); rank > maxRank {
				maxRank = rank
				snapshot.MaxSeenTargetClass = obs.TargetClass
			}
		}
		if obs.SurfaceClass != "" {
			surfaceClasses[obs.SurfaceClass] = struct{}{}
		}
	}
	snapshot.DistinctPathClasses = len(pathClasses)
	snapshot.DistinctTargetClasses = len(targetClasses)
	snapshot.DistinctSurfaceClasses = len(surfaceClasses)
	snapshot.SeenSurfaceClasses = sortedSetKeys(surfaceClasses)
	snapshot.SeenTargetClasses = sortedSetKeys(targetClasses)
	return snapshot
}

func targetClassRank(class string) int {
	switch strings.TrimSpace(class) {
	case "public_static":
		return 0
	case "authenticated_app":
		return 1
	case "write_action":
		return 2
	case "account_security":
		return 3
	case "admin_management":
		return 4
	default:
		return -1
	}
}

func sortedSetKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return uniqueStrings(out)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := values[:0]
	var last string
	for _, value := range values {
		if value == "" {
			continue
		}
		if len(out) > 0 && value == last {
			continue
		}
		out = append(out, value)
		last = value
	}
	return out
}

func stringListContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
