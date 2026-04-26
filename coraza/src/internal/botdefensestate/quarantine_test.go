package botdefensestate

import (
	"testing"
	"time"
)

func TestQuarantineEscalatesByScope(t *testing.T) {
	ResetQuarantine()
	t.Cleanup(ResetQuarantine)

	cfg := QuarantineConfig{
		Enabled:         true,
		Threshold:       8,
		StrikesRequired: 2,
		StrikeWindow:    5 * time.Minute,
		TTL:             10 * time.Minute,
		StatusCode:      451,
	}
	now := time.Unix(1_700_001_000, 0).UTC()

	if MaybeEscalateQuarantine("one.example", cfg, "10.0.0.3", 7, now) {
		t.Fatal("risk below threshold should not quarantine")
	}
	if MaybeEscalateQuarantine("one.example", cfg, "10.0.0.3", 8, now) {
		t.Fatal("first strike should not quarantine")
	}
	if blocked, _, _ := QuarantineStatus("two.example", cfg, "10.0.0.3", now.Add(time.Second)); blocked {
		t.Fatal("second scope should not inherit strikes")
	}
	if !MaybeEscalateQuarantine("one.example", cfg, "10.0.0.3", 8, now.Add(2*time.Second)) {
		t.Fatal("second strike should quarantine")
	}
	if blocked, status, _ := QuarantineStatus("one.example", cfg, "10.0.0.3", now.Add(3*time.Second)); !blocked || status != 451 {
		t.Fatalf("status blocked=%v status=%d want true 451", blocked, status)
	}
}

func TestForceQuarantineReportsNewBlockOnly(t *testing.T) {
	ResetQuarantine()
	t.Cleanup(ResetQuarantine)

	cfg := QuarantineConfig{
		Enabled:         true,
		StrikesRequired: 2,
		StrikeWindow:    time.Minute,
		TTL:             time.Minute,
		StatusCode:      403,
	}
	now := time.Unix(1_700_001_100, 0).UTC()
	if !ForceQuarantine("", cfg, "10.0.0.4", now) {
		t.Fatal("first force should create a new quarantine")
	}
	if ForceQuarantine("", cfg, "10.0.0.4", now.Add(time.Second)) {
		t.Fatal("second force inside ttl should report existing block")
	}
	snapshot := SnapshotQuarantineStore()
	if len(snapshot.StateByIP) != 1 {
		t.Fatalf("snapshot entries=%d want=1", len(snapshot.StateByIP))
	}
	ResetQuarantine()
	if blocked, _, _ := QuarantineStatus("", cfg, "10.0.0.4", now.Add(2*time.Second)); blocked {
		t.Fatal("reset should clear quarantine")
	}
	RestoreQuarantineStore(snapshot)
	if blocked, _, _ := QuarantineStatus("", cfg, "10.0.0.4", now.Add(2*time.Second)); !blocked {
		t.Fatal("restore should restore quarantine")
	}
}
