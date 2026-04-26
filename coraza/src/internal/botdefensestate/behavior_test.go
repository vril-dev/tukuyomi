package botdefensestate

import (
	"slices"
	"testing"
	"time"
)

func TestBehaviorTracksScopedSignals(t *testing.T) {
	ResetBehavior()
	t.Cleanup(ResetBehavior)

	cfg := BehaviorConfig{
		Enabled:                true,
		WindowSeconds:          60,
		BurstThreshold:         10,
		PathFanoutThreshold:    2,
		UAChurnThreshold:       2,
		MissingCookieThreshold: 2,
		ScoreThreshold:         2,
		RiskScorePerSignal:     3,
	}
	now := time.Unix(1_700_000_000, 0).UTC()

	_ = ObserveBehavior("one.example", cfg, "10.0.0.1", "/a", "Agent/A", false, now)
	snapshot := ObserveBehavior("one.example", cfg, "10.0.0.1", "/b", "Agent/B", false, now.Add(time.Second))
	score, signals := EvaluateBehavior(cfg, snapshot)
	if score != 9 {
		t.Fatalf("score=%d want=9 signals=%v", score, signals)
	}
	for _, want := range []string{"path_fanout:2", "ua_churn:2", "missing_cookie:2"} {
		if !slices.Contains(signals, want) {
			t.Fatalf("signal %q missing from %v", want, signals)
		}
	}

	isolated := ObserveBehavior("two.example", cfg, "10.0.0.1", "/a", "Agent/A", false, now.Add(2*time.Second))
	if isolated.PathFanout != 1 || isolated.UAChurn != 1 || isolated.MissingCookieCount != 1 {
		t.Fatalf("scoped state leaked: %#v", isolated)
	}
}

func TestBehaviorSnapshotRestoreClones(t *testing.T) {
	ResetBehavior()
	t.Cleanup(ResetBehavior)

	cfg := BehaviorConfig{Enabled: true, WindowSeconds: 60}
	now := time.Unix(1_700_000_100, 0).UTC()
	ObserveBehavior("", cfg, "10.0.0.2", "/a", "Agent/A", false, now)

	snapshot := SnapshotBehaviorStore()
	state := snapshot.StateByIP["default|10.0.0.2"]
	state.Paths["/mutated"] = struct{}{}
	snapshot.StateByIP["default|10.0.0.2"] = state
	RestoreBehaviorStore(snapshot)

	restored := SnapshotBehaviorStore()
	if _, ok := restored.StateByIP["default|10.0.0.2"].Paths["/mutated"]; !ok {
		t.Fatal("restore should use the provided snapshot")
	}
	state = restored.StateByIP["default|10.0.0.2"]
	state.Paths["/later"] = struct{}{}
	restored.StateByIP["default|10.0.0.2"] = state
	fresh := SnapshotBehaviorStore()
	if _, ok := fresh.StateByIP["default|10.0.0.2"].Paths["/later"]; ok {
		t.Fatal("snapshot mutation escaped into store")
	}
}
