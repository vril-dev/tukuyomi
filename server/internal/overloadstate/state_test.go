package overloadstate

import (
	"testing"

	"tukuyomi/internal/middleware"
)

func TestSnapshotProvider(t *testing.T) {
	defer SetProvider(nil)

	SetProvider(func() map[string]middleware.ConcurrencyGuardSnapshot {
		return map[string]middleware.ConcurrencyGuardSnapshot{
			"proxy": {Name: "proxy", Enabled: true, Limit: 12},
		}
	})

	if got := Snapshot("proxy"); !got.Enabled || got.Limit != 12 {
		t.Fatalf("proxy snapshot=%+v", got)
	}
	if got := Snapshot("missing"); got.Enabled || got.Name != "missing" {
		t.Fatalf("missing snapshot=%+v", got)
	}
}
