package handler

import (
	"sort"
	"strings"
	"sync"
	"time"
)

const (
	statefulSensitiveAfterSuspiciousThreshold = 2
	statefulAdminAfterSuspiciousScore         = 3
	statefulSensitiveAfterSuspiciousScore     = 2
	statefulSurfaceShiftThreshold             = 3
	statefulSurfaceShiftScore                 = 1
	statefulSensitivityShiftMinHistory        = 3
	statefulSensitivityShiftScore             = 1
)

type semanticHistoryObservation struct {
	at           time.Time
	pathClass    string
	targetClass  string
	surfaceClass string
	baseScore    int
}

type semanticHistorySnapshot struct {
	PriorRequests           int      `json:"prior_requests"`
	PriorSuspiciousRequests int      `json:"prior_suspicious_requests"`
	DistinctPathClasses     int      `json:"distinct_path_classes"`
	DistinctTargetClasses   int      `json:"distinct_target_classes"`
	DistinctSurfaceClasses  int      `json:"distinct_surface_classes"`
	MaxSeenTargetClass      string   `json:"max_seen_target_class,omitempty"`
	SeenSurfaceClasses      []string `json:"seen_surface_classes,omitempty"`
	SeenTargetClasses       []string `json:"seen_target_classes,omitempty"`
}

type semanticHistoryStore struct {
	mu               sync.Mutex
	window           time.Duration
	maxEntriesPerKey int
	byKey            map[string][]semanticHistoryObservation
}

func newSemanticHistoryStore(cfg semanticConfig) *semanticHistoryStore {
	window := cfg.TemporalWindowSeconds
	if window <= 0 {
		window = defaultTemporalWindowSeconds
	}
	maxEntries := cfg.TemporalMaxEntriesPerIP
	if maxEntries <= 0 {
		maxEntries = defaultTemporalMaxEntriesPerIP
	}
	return &semanticHistoryStore{
		window:           time.Duration(window) * time.Second,
		maxEntriesPerKey: maxEntries,
		byKey:            make(map[string][]semanticHistoryObservation, 1024),
	}
}

func (s *semanticHistoryStore) Observe(key string, obs semanticHistoryObservation, now time.Time) semanticHistorySnapshot {
	if s == nil {
		return semanticHistorySnapshot{}
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return semanticHistorySnapshot{}
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
		if !item.at.Before(cutoff) {
			kept = append(kept, item)
		}
	}

	snapshot := semanticHistorySnapshotFromObservations(kept)

	kept = append(kept, obs)
	if s.maxEntriesPerKey > 0 && len(kept) > s.maxEntriesPerKey {
		kept = kept[len(kept)-s.maxEntriesPerKey:]
	}
	s.byKey[key] = kept

	return snapshot
}

func semanticHistorySnapshotFromObservations(observations []semanticHistoryObservation) semanticHistorySnapshot {
	if len(observations) == 0 {
		return semanticHistorySnapshot{}
	}
	pathClasses := make(map[string]struct{}, len(observations))
	targetClasses := make(map[string]struct{}, len(observations))
	surfaceClasses := make(map[string]struct{}, len(observations))

	snapshot := semanticHistorySnapshot{
		PriorRequests: len(observations),
	}
	maxRank := -1
	for _, obs := range observations {
		if obs.baseScore > 0 {
			snapshot.PriorSuspiciousRequests++
		}
		if obs.pathClass != "" {
			pathClasses[obs.pathClass] = struct{}{}
		}
		if obs.targetClass != "" {
			targetClasses[obs.targetClass] = struct{}{}
			if rank := semanticTargetClassRank(obs.targetClass); rank > maxRank {
				maxRank = rank
				snapshot.MaxSeenTargetClass = obs.targetClass
			}
		}
		if obs.surfaceClass != "" {
			surfaceClasses[obs.surfaceClass] = struct{}{}
		}
	}
	snapshot.DistinctPathClasses = len(pathClasses)
	snapshot.DistinctTargetClasses = len(targetClasses)
	snapshot.DistinctSurfaceClasses = len(surfaceClasses)
	snapshot.SeenSurfaceClasses = semanticSortedSetKeys(surfaceClasses)
	snapshot.SeenTargetClasses = semanticSortedSetKeys(targetClasses)
	return snapshot
}

func inspectSemanticStatefulRisk(
	rt *runtimeSemanticScope,
	telemetry *semanticTelemetry,
	baseScore int,
	now time.Time,
	score *int,
	signals *[]semanticSignal,
) *semanticHistorySnapshot {
	if rt == nil || rt.history == nil || telemetry == nil {
		return nil
	}
	key := strings.TrimSpace(telemetry.Context.ActorKey)
	if key == "" {
		return nil
	}
	currentTargetClass := telemetry.Context.TargetClass
	currentSurfaceClass := telemetry.Context.SurfaceClass
	snapshot := rt.history.Observe(key, semanticHistoryObservation{
		at:           now.UTC(),
		pathClass:    telemetry.Context.PathClass,
		targetClass:  currentTargetClass,
		surfaceClass: currentSurfaceClass,
		baseScore:    baseScore,
	}, now.UTC())

	if snapshot.PriorRequests == 0 {
		return &snapshot
	}

	currentRank := semanticTargetClassRank(currentTargetClass)
	seenRank := semanticTargetClassRank(snapshot.MaxSeenTargetClass)

	if currentTargetClass == "admin_management" && snapshot.PriorSuspiciousRequests >= statefulSensitiveAfterSuspiciousThreshold {
		appendSemanticSignal(signals, score, "stateful:admin_after_suspicious_activity", statefulAdminAfterSuspiciousScore)
	} else if currentRank >= semanticTargetClassRank("account_security") &&
		snapshot.PriorSuspiciousRequests >= statefulSensitiveAfterSuspiciousThreshold {
		appendSemanticSignal(signals, score, "stateful:sensitive_path_after_suspicious_activity", statefulSensitiveAfterSuspiciousScore)
	}

	if snapshot.PriorRequests >= statefulSensitivityShiftMinHistory &&
		currentRank >= semanticTargetClassRank("account_security") &&
		seenRank >= 0 &&
		currentRank > seenRank {
		appendSemanticSignal(signals, score, "stateful:sudden_target_sensitivity_shift", statefulSensitivityShiftScore)
	}

	if snapshot.PriorRequests >= statefulSurfaceShiftThreshold &&
		currentSurfaceClass != "" &&
		snapshot.DistinctSurfaceClasses >= 2 &&
		baseScore > 0 &&
		!semanticStringListContains(snapshot.SeenSurfaceClasses, currentSurfaceClass) {
		appendSemanticSignal(signals, score, "stateful:rapid_surface_shift", statefulSurfaceShiftScore)
	}

	return &snapshot
}

func semanticTargetClassRank(class string) int {
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

func semanticSortedSetKeys(values map[string]struct{}) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return unique(out)
}

func semanticStringListContains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
