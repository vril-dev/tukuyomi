package botdefensestate

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

const defaultScope = "default"

type BehaviorConfig struct {
	Enabled                bool
	WindowSeconds          int
	BurstThreshold         int
	PathFanoutThreshold    int
	UAChurnThreshold       int
	MissingCookieThreshold int
	ScoreThreshold         int
	RiskScorePerSignal     int
}

type BehaviorSnapshot struct {
	RequestCount       int
	PathFanout         int
	UAChurn            int
	MissingCookieCount int
}

type BehaviorState struct {
	WindowID           int64
	RequestCount       int
	MissingCookieCount int
	Paths              map[string]struct{}
	UserAgents         map[string]struct{}
	Updated            time.Time
}

type BehaviorStoreSnapshot struct {
	StateByIP map[string]BehaviorState
	Sweep     int
}

var (
	behaviorMu        sync.Mutex
	behaviorStateByIP = map[string]BehaviorState{}
	behaviorSweep     int
)

func ResetBehavior() {
	behaviorMu.Lock()
	defer behaviorMu.Unlock()
	behaviorStateByIP = map[string]BehaviorState{}
	behaviorSweep = 0
}

func ObserveBehavior(scopeKey string, cfg BehaviorConfig, clientIP, reqPath, userAgent string, hasValidCookie bool, now time.Time) BehaviorSnapshot {
	if !cfg.Enabled {
		return BehaviorSnapshot{}
	}
	key := stateKey(scopeKey, clientIP)
	if key == "" || cfg.WindowSeconds <= 0 {
		return BehaviorSnapshot{}
	}
	if reqPath == "" {
		reqPath = "/"
	}
	ua := strings.ToLower(strings.TrimSpace(userAgent))
	windowID := now.Unix() / int64(cfg.WindowSeconds)

	behaviorMu.Lock()
	defer behaviorMu.Unlock()

	behaviorSweep++
	state := behaviorStateByIP[key]
	if state.WindowID != windowID {
		state = BehaviorState{
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
	behaviorStateByIP[key] = state

	if behaviorSweep%1024 == 0 {
		cutoff := now.Add(-2 * time.Duration(cfg.WindowSeconds) * time.Second)
		for key, candidate := range behaviorStateByIP {
			if candidate.Updated.Before(cutoff) {
				delete(behaviorStateByIP, key)
			}
		}
	}

	return BehaviorSnapshot{
		RequestCount:       state.RequestCount,
		PathFanout:         len(state.Paths),
		UAChurn:            len(state.UserAgents),
		MissingCookieCount: state.MissingCookieCount,
	}
}

func EvaluateBehavior(cfg BehaviorConfig, snapshot BehaviorSnapshot) (int, []string) {
	if !cfg.Enabled {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if snapshot.RequestCount >= cfg.BurstThreshold {
		signals = append(signals, fmt.Sprintf("burst:%d", snapshot.RequestCount))
	}
	if snapshot.PathFanout >= cfg.PathFanoutThreshold {
		signals = append(signals, fmt.Sprintf("path_fanout:%d", snapshot.PathFanout))
	}
	if snapshot.UAChurn >= cfg.UAChurnThreshold {
		signals = append(signals, fmt.Sprintf("ua_churn:%d", snapshot.UAChurn))
	}
	if snapshot.MissingCookieCount >= cfg.MissingCookieThreshold {
		signals = append(signals, fmt.Sprintf("missing_cookie:%d", snapshot.MissingCookieCount))
	}
	if len(signals) < cfg.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * cfg.RiskScorePerSignal, signals
}

func SnapshotBehaviorStore() BehaviorStoreSnapshot {
	behaviorMu.Lock()
	defer behaviorMu.Unlock()
	return BehaviorStoreSnapshot{
		StateByIP: cloneBehaviorStateByIP(behaviorStateByIP),
		Sweep:     behaviorSweep,
	}
}

func RestoreBehaviorStore(snapshot BehaviorStoreSnapshot) {
	behaviorMu.Lock()
	defer behaviorMu.Unlock()
	behaviorStateByIP = cloneBehaviorStateByIP(snapshot.StateByIP)
	behaviorSweep = snapshot.Sweep
}

func stateKey(scopeKey, ip string) string {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return ""
	}
	scope := strings.TrimSpace(scopeKey)
	if scope == "" {
		scope = defaultScope
	}
	return scope + "|" + ip
}

func cloneBehaviorStateByIP(in map[string]BehaviorState) map[string]BehaviorState {
	out := make(map[string]BehaviorState, len(in))
	for key, state := range in {
		if state.Paths != nil {
			paths := make(map[string]struct{}, len(state.Paths))
			for path := range state.Paths {
				paths[path] = struct{}{}
			}
			state.Paths = paths
		}
		if state.UserAgents != nil {
			userAgents := make(map[string]struct{}, len(state.UserAgents))
			for userAgent := range state.UserAgents {
				userAgents[userAgent] = struct{}{}
			}
			state.UserAgents = userAgents
		}
		out[key] = state
	}
	return out
}
