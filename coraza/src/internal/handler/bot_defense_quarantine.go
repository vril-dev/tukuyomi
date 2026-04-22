package handler

import (
	"sync"
	"time"
)

var (
	botDefenseQuarantineMu        sync.Mutex
	botDefenseQuarantineStateByIP = map[string]botDefenseQuarantineState{}
	botDefenseQuarantineSweep     int
)

func resetBotDefenseQuarantineState() {
	botDefenseQuarantineMu.Lock()
	defer botDefenseQuarantineMu.Unlock()
	botDefenseQuarantineStateByIP = map[string]botDefenseQuarantineState{}
	botDefenseQuarantineSweep = 0
}

func botDefenseQuarantineStatus(rt *runtimeBotDefenseConfig, ip string, now time.Time) (bool, int, time.Time) {
	return botDefenseQuarantineStatusForScope(botDefenseDefaultScope, rt, ip, now)
}

func botDefenseQuarantineStatusForScope(scopeKey string, rt *runtimeBotDefenseConfig, ip string, now time.Time) (bool, int, time.Time) {
	key := botDefenseScopedStateKey(scopeKey, ip)
	if rt == nil || !rt.Quarantine.Enabled || key == "" {
		return false, 0, time.Time{}
	}
	botDefenseQuarantineMu.Lock()
	defer botDefenseQuarantineMu.Unlock()
	state, ok := botDefenseQuarantineStateByIP[key]
	if !ok {
		return false, 0, time.Time{}
	}
	if !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil) {
		return true, rt.Quarantine.StatusCode, state.BlockedUntil
	}
	if !state.BlockedUntil.IsZero() && !now.Before(state.BlockedUntil) {
		delete(botDefenseQuarantineStateByIP, key)
	}
	return false, 0, time.Time{}
}

func maybeEscalateBotDefenseQuarantine(rt *runtimeBotDefenseConfig, ip string, riskScore int, now time.Time) bool {
	return maybeEscalateBotDefenseQuarantineForScope(botDefenseDefaultScope, rt, ip, riskScore, now)
}

func maybeEscalateBotDefenseQuarantineForScope(scopeKey string, rt *runtimeBotDefenseConfig, ip string, riskScore int, now time.Time) bool {
	key := botDefenseScopedStateKey(scopeKey, ip)
	if rt == nil || !rt.Quarantine.Enabled || key == "" || riskScore < rt.Quarantine.Threshold {
		return false
	}
	botDefenseQuarantineMu.Lock()
	defer botDefenseQuarantineMu.Unlock()
	botDefenseQuarantineSweep++
	state := botDefenseQuarantineStateByIP[key]
	if state.WindowEnd.IsZero() || now.After(state.WindowEnd) {
		state = botDefenseQuarantineState{
			WindowEnd: now.Add(rt.Quarantine.StrikeWindow),
		}
	}
	state.Strikes++
	if state.Strikes >= rt.Quarantine.StrikesRequired {
		state.BlockedUntil = now.Add(rt.Quarantine.TTL)
	}
	botDefenseQuarantineStateByIP[key] = state
	if botDefenseQuarantineSweep%1024 == 0 {
		for key, candidate := range botDefenseQuarantineStateByIP {
			if !candidate.BlockedUntil.IsZero() && now.After(candidate.BlockedUntil) && now.After(candidate.WindowEnd) {
				delete(botDefenseQuarantineStateByIP, key)
				continue
			}
			if candidate.BlockedUntil.IsZero() && now.After(candidate.WindowEnd) {
				delete(botDefenseQuarantineStateByIP, key)
			}
		}
	}
	return !state.BlockedUntil.IsZero() && now.Before(state.BlockedUntil)
}
