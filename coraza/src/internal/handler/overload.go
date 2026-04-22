package handler

import (
	"sync"

	"tukuyomi/internal/middleware"
)

var overloadSnapshotsState struct {
	mu sync.RWMutex
	fn func() map[string]middleware.ConcurrencyGuardSnapshot
}

func SetOverloadSnapshotProvider(fn func() map[string]middleware.ConcurrencyGuardSnapshot) {
	overloadSnapshotsState.mu.Lock()
	defer overloadSnapshotsState.mu.Unlock()

	overloadSnapshotsState.fn = fn
}

func overloadSnapshot(scope string) middleware.ConcurrencyGuardSnapshot {
	overloadSnapshotsState.mu.RLock()
	fn := overloadSnapshotsState.fn
	overloadSnapshotsState.mu.RUnlock()

	if fn == nil {
		return middleware.DisabledConcurrencyGuardSnapshot(scope, 0, 0, 0)
	}
	snapshots := fn()
	if snapshot, ok := snapshots[scope]; ok {
		return snapshot
	}
	return middleware.DisabledConcurrencyGuardSnapshot(scope, 0, 0, 0)
}
