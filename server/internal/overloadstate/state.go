package overloadstate

import (
	"sync"

	"tukuyomi/internal/middleware"
)

var snapshots struct {
	mu sync.RWMutex
	fn func() map[string]middleware.ConcurrencyGuardSnapshot
}

func SetProvider(fn func() map[string]middleware.ConcurrencyGuardSnapshot) {
	snapshots.mu.Lock()
	defer snapshots.mu.Unlock()
	snapshots.fn = fn
}

func Snapshot(scope string) middleware.ConcurrencyGuardSnapshot {
	snapshots.mu.RLock()
	fn := snapshots.fn
	snapshots.mu.RUnlock()

	if fn == nil {
		return middleware.DisabledConcurrencyGuardSnapshot(scope, 0, 0, 0)
	}
	all := fn()
	if snapshot, ok := all[scope]; ok {
		return snapshot
	}
	return middleware.DisabledConcurrencyGuardSnapshot(scope, 0, 0, 0)
}
