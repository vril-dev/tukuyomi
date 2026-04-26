package botdefensestate

import (
	"sync"
	"time"
)

type QuarantineConfig struct {
	Enabled         bool
	Threshold       int
	StrikesRequired int
	StrikeWindow    time.Duration
	TTL             time.Duration
	StatusCode      int
}

type QuarantineState struct {
	Strikes      int
	WindowEnd    time.Time
	BlockedUntil time.Time
}

type QuarantineStoreSnapshot struct {
	StateByIP map[string]QuarantineState
	Sweep     int
}

var (
	quarantineMu        sync.Mutex
	quarantineStateByIP = map[string]QuarantineState{}
	quarantineSweep     int
)

func ResetQuarantine() {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	quarantineStateByIP = map[string]QuarantineState{}
	quarantineSweep = 0
}

func QuarantineStatus(scopeKey string, cfg QuarantineConfig, ip string, now time.Time) (bool, int, time.Time) {
	key := stateKey(scopeKey, ip)
	if !cfg.Enabled || key == "" {
		return false, 0, time.Time{}
	}
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	state, ok := quarantineStateByIP[key]
	if !ok {
		return false, 0, time.Time{}
	}
	if !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil) {
		return true, cfg.StatusCode, state.BlockedUntil
	}
	if !state.BlockedUntil.IsZero() && !now.Before(state.BlockedUntil) {
		delete(quarantineStateByIP, key)
	}
	return false, 0, time.Time{}
}

func MaybeEscalateQuarantine(scopeKey string, cfg QuarantineConfig, ip string, riskScore int, now time.Time) bool {
	key := stateKey(scopeKey, ip)
	if !cfg.Enabled || key == "" || riskScore < cfg.Threshold {
		return false
	}
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	quarantineSweep++
	state := quarantineStateByIP[key]
	if state.WindowEnd.IsZero() || now.After(state.WindowEnd) {
		state = QuarantineState{
			WindowEnd: now.Add(cfg.StrikeWindow),
		}
	}
	state.Strikes++
	if state.Strikes >= cfg.StrikesRequired {
		state.BlockedUntil = now.Add(cfg.TTL)
	}
	quarantineStateByIP[key] = state
	sweepExpiredQuarantine(now)
	return !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil)
}

func ForceQuarantine(scopeKey string, cfg QuarantineConfig, ip string, now time.Time) bool {
	key := stateKey(scopeKey, ip)
	if !cfg.Enabled || key == "" {
		return false
	}
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	state := quarantineStateByIP[key]
	alreadyBlocked := !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil)
	if state.Strikes < cfg.StrikesRequired {
		state.Strikes = cfg.StrikesRequired
	}
	state.WindowEnd = now.Add(cfg.StrikeWindow)
	state.BlockedUntil = now.Add(cfg.TTL)
	quarantineStateByIP[key] = state
	return !alreadyBlocked
}

func SnapshotQuarantineStore() QuarantineStoreSnapshot {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	return QuarantineStoreSnapshot{
		StateByIP: cloneQuarantineStateByIP(quarantineStateByIP),
		Sweep:     quarantineSweep,
	}
}

func RestoreQuarantineStore(snapshot QuarantineStoreSnapshot) {
	quarantineMu.Lock()
	defer quarantineMu.Unlock()
	quarantineStateByIP = cloneQuarantineStateByIP(snapshot.StateByIP)
	quarantineSweep = snapshot.Sweep
}

func sweepExpiredQuarantine(now time.Time) {
	if quarantineSweep%1024 != 0 {
		return
	}
	for key, candidate := range quarantineStateByIP {
		if !candidate.BlockedUntil.IsZero() && now.After(candidate.BlockedUntil) && now.After(candidate.WindowEnd) {
			delete(quarantineStateByIP, key)
			continue
		}
		if candidate.BlockedUntil.IsZero() && now.After(candidate.WindowEnd) {
			delete(quarantineStateByIP, key)
		}
	}
}

func cloneQuarantineStateByIP(in map[string]QuarantineState) map[string]QuarantineState {
	out := make(map[string]QuarantineState, len(in))
	for key, state := range in {
		out[key] = state
	}
	return out
}
