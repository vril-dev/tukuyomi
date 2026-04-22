package handler

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

var (
	botDefenseBehaviorMu        sync.Mutex
	botDefenseBehaviorStateByIP = map[string]botDefenseBehaviorState{}
	botDefenseBehaviorSweep     int
)

func resetBotDefenseBehaviorState() {
	botDefenseBehaviorMu.Lock()
	defer botDefenseBehaviorMu.Unlock()
	botDefenseBehaviorStateByIP = map[string]botDefenseBehaviorState{}
	botDefenseBehaviorSweep = 0
}

func observeBotDefenseBehavior(rt *runtimeBotDefenseConfig, clientIP, reqPath, userAgent string, hasValidCookie bool, now time.Time) botDefenseBehaviorSnapshot {
	return observeBotDefenseBehaviorForScope(botDefenseDefaultScope, rt, clientIP, reqPath, userAgent, hasValidCookie, now)
}

func observeBotDefenseBehaviorForScope(scopeKey string, rt *runtimeBotDefenseConfig, clientIP, reqPath, userAgent string, hasValidCookie bool, now time.Time) botDefenseBehaviorSnapshot {
	if rt == nil || !rt.Behavioral.Enabled {
		return botDefenseBehaviorSnapshot{}
	}
	key := botDefenseScopedStateKey(scopeKey, clientIP)
	if key == "" {
		return botDefenseBehaviorSnapshot{}
	}
	if reqPath == "" {
		reqPath = "/"
	}
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	windowID := now.Unix() / int64(rt.Behavioral.WindowSeconds)

	botDefenseBehaviorMu.Lock()
	defer botDefenseBehaviorMu.Unlock()

	botDefenseBehaviorSweep++
	state := botDefenseBehaviorStateByIP[key]
	if state.WindowID != windowID {
		state = botDefenseBehaviorState{
			WindowID:   windowID,
			Paths:      map[string]struct{}{},
			UserAgents: map[string]struct{}{},
		}
	}
	if state.Paths == nil {
		state.Paths = map[string]struct{}{}
	}
	if state.UserAgents == nil {
		state.UserAgents = map[string]struct{}{}
	}
	state.RequestCount++
	state.Paths[reqPath] = struct{}{}
	if ua != "" {
		state.UserAgents[ua] = struct{}{}
	}
	if !hasValidCookie {
		state.MissingCookieCount++
	}
	state.Updated = now
	botDefenseBehaviorStateByIP[key] = state

	if botDefenseBehaviorSweep%1024 == 0 {
		cutoff := now.Add(-2 * time.Duration(rt.Behavioral.WindowSeconds) * time.Second)
		for key, candidate := range botDefenseBehaviorStateByIP {
			if candidate.Updated.Before(cutoff) {
				delete(botDefenseBehaviorStateByIP, key)
			}
		}
	}

	return botDefenseBehaviorSnapshot{
		RequestCount:       state.RequestCount,
		PathFanout:         len(state.Paths),
		UAChurn:            len(state.UserAgents),
		MissingCookieCount: state.MissingCookieCount,
	}
}

func evaluateBotDefenseBehavior(rt *runtimeBotDefenseConfig, snapshot botDefenseBehaviorSnapshot) (int, []string) {
	if rt == nil || !rt.Behavioral.Enabled {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if snapshot.RequestCount >= rt.Behavioral.BurstThreshold {
		signals = append(signals, fmt.Sprintf("burst:%d", snapshot.RequestCount))
	}
	if snapshot.PathFanout >= rt.Behavioral.PathFanoutThreshold {
		signals = append(signals, fmt.Sprintf("path_fanout:%d", snapshot.PathFanout))
	}
	if snapshot.UAChurn >= rt.Behavioral.UAChurnThreshold {
		signals = append(signals, fmt.Sprintf("ua_churn:%d", snapshot.UAChurn))
	}
	if snapshot.MissingCookieCount >= rt.Behavioral.MissingCookieThreshold {
		signals = append(signals, fmt.Sprintf("missing_cookie:%d", snapshot.MissingCookieCount))
	}
	if len(signals) < rt.Behavioral.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * rt.Behavioral.RiskScorePerSignal, signals
}
