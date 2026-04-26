package semanticrisk

import (
	"testing"
	"time"
)

func TestHistoryStoreObserveReturnsPriorSnapshot(t *testing.T) {
	store := NewHistoryStore(TemporalConfig{
		WindowSeconds:   30,
		MaxEntriesPerIP: 10,
	})
	now := time.Unix(1000, 0).UTC()

	first := store.Observe("actor", HistoryObservation{
		At:           now,
		PathClass:    "browse",
		TargetClass:  "public_static",
		SurfaceClass: "web",
		BaseScore:    2,
	}, now)
	if first.PriorRequests != 0 {
		t.Fatalf("first prior_requests=%d want 0", first.PriorRequests)
	}

	second := store.Observe("actor", HistoryObservation{
		At:           now.Add(time.Second),
		PathClass:    "login",
		TargetClass:  "authenticated_app",
		SurfaceClass: "api",
		BaseScore:    0,
	}, now.Add(time.Second))
	if second.PriorRequests != 1 {
		t.Fatalf("second prior_requests=%d want 1", second.PriorRequests)
	}
	if second.PriorSuspiciousRequests != 1 {
		t.Fatalf("prior_suspicious=%d want 1", second.PriorSuspiciousRequests)
	}
	if second.MaxSeenTargetClass != "public_static" {
		t.Fatalf("max_seen_target_class=%q want public_static", second.MaxSeenTargetClass)
	}
}

func TestEvaluateStatefulAdminAfterSuspiciousActivity(t *testing.T) {
	signals := EvaluateStateful(HistorySnapshot{
		PriorRequests:           3,
		PriorSuspiciousRequests: StatefulSensitiveAfterSuspiciousThreshold,
		DistinctSurfaceClasses:  2,
		MaxSeenTargetClass:      "authenticated_app",
		SeenSurfaceClasses:      []string{"api", "web"},
	}, "admin_management", "admin", 3)

	if len(signals) == 0 {
		t.Fatal("expected stateful signals")
	}
	if signals[0].Reason != "stateful:admin_after_suspicious_activity" {
		t.Fatalf("first reason=%q want admin signal", signals[0].Reason)
	}
}

func TestEvaluateStatefulSurfaceShift(t *testing.T) {
	signals := EvaluateStateful(HistorySnapshot{
		PriorRequests:          StatefulSurfaceShiftThreshold,
		DistinctSurfaceClasses: 2,
		SeenSurfaceClasses:     []string{"api", "web"},
	}, "write_action", "admin", 1)

	found := false
	for _, signal := range signals {
		if signal.Reason == "stateful:rapid_surface_shift" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("rapid_surface_shift missing: %#v", signals)
	}
}
