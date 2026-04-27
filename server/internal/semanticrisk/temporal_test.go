package semanticrisk

import (
	"testing"
	"time"
)

func TestTemporalStoreObserveTracksCounts(t *testing.T) {
	store := NewTemporalStore(TemporalConfig{
		WindowSeconds:   10,
		MaxEntriesPerIP: 10,
	})
	now := time.Unix(1000, 0).UTC()

	store.Observe("192.0.2.1", "/a", "Agent-A", now)
	store.Observe("192.0.2.1", "/b", "Agent-B", now.Add(time.Second))
	snap := store.Observe("192.0.2.1", "/b", "Agent-B", now.Add(2*time.Second))

	if snap.RequestCount != 3 {
		t.Fatalf("request_count=%d want 3", snap.RequestCount)
	}
	if snap.DistinctPaths != 2 {
		t.Fatalf("distinct_paths=%d want 2", snap.DistinctPaths)
	}
	if snap.DistinctUserAgents != 2 {
		t.Fatalf("distinct_user_agents=%d want 2", snap.DistinctUserAgents)
	}
}

func TestTemporalStorePrunesWindowAndCapsEntries(t *testing.T) {
	store := NewTemporalStore(TemporalConfig{
		WindowSeconds:   2,
		MaxEntriesPerIP: 2,
	})
	now := time.Unix(1000, 0).UTC()

	store.Observe("192.0.2.1", "/old", "Agent-A", now)
	store.Observe("192.0.2.1", "/a", "Agent-A", now.Add(3*time.Second))
	store.Observe("192.0.2.1", "/b", "Agent-B", now.Add(4*time.Second))
	snap := store.Observe("192.0.2.1", "/c", "Agent-C", now.Add(5*time.Second))

	if snap.RequestCount != 2 {
		t.Fatalf("request_count=%d want capped/pruned 2", snap.RequestCount)
	}
	if snap.DistinctPaths != 2 {
		t.Fatalf("distinct_paths=%d want 2", snap.DistinctPaths)
	}
}

func TestEvaluateTemporal(t *testing.T) {
	signals := EvaluateTemporal(TemporalSnapshot{
		RequestCount:       5,
		DistinctPaths:      4,
		DistinctUserAgents: 3,
	}, TemporalThresholds{
		BurstThreshold:      5,
		BurstScore:          2,
		PathFanoutThreshold: 4,
		PathFanoutScore:     3,
		UAChurnThreshold:    3,
		UAChurnScore:        1,
	})

	if len(signals) != 3 {
		t.Fatalf("signals=%d want 3", len(signals))
	}
	if signals[0].Reason != "temporal:ip_burst" || signals[0].Score != 2 {
		t.Fatalf("unexpected first signal: %#v", signals[0])
	}
}
