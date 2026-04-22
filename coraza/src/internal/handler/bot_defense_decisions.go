package handler

import (
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
)

const botDefenseDecisionHistoryLimit = 100

type botDefenseDecisionRecord struct {
	Timestamp  string   `json:"timestamp"`
	RequestID  string   `json:"request_id,omitempty"`
	ClientIP   string   `json:"client_ip,omitempty"`
	Country    string   `json:"country,omitempty"`
	Method     string   `json:"method,omitempty"`
	Path       string   `json:"path,omitempty"`
	UserAgent  string   `json:"user_agent,omitempty"`
	HostScope  string   `json:"host_scope,omitempty"`
	FlowPolicy string   `json:"flow_policy,omitempty"`
	Action     string   `json:"action"`
	DryRun     bool     `json:"dry_run,omitempty"`
	Status     int      `json:"status,omitempty"`
	Mode       string   `json:"mode,omitempty"`
	RiskScore  int      `json:"risk_score"`
	Signals    []string `json:"signals,omitempty"`
}

var (
	botDefenseDecisionMu      sync.Mutex
	botDefenseDecisionHistory []botDefenseDecisionRecord
)

func recordBotDefenseDecision(req *http.Request, ctx *requestSecurityPluginContext, decision botDefenseDecision) {
	record := botDefenseDecisionRecord{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Action:     decision.Action,
		DryRun:     decision.DryRun,
		Status:     decision.Status,
		Mode:       decision.Mode,
		HostScope:  decision.HostScope,
		FlowPolicy: decision.FlowPolicy,
		RiskScore:  decision.RiskScore,
		Signals:    append([]string(nil), decision.Signals...),
	}
	if record.Action == "" {
		record.Action = "allow"
	}
	if ctx != nil {
		record.RequestID = ctx.RequestID
		record.ClientIP = ctx.ClientIP
		record.Country = ctx.Country
	}
	if req != nil {
		record.Method = req.Method
		if req.URL != nil {
			record.Path = req.URL.Path
		}
		record.UserAgent = req.UserAgent()
	}

	botDefenseDecisionMu.Lock()
	defer botDefenseDecisionMu.Unlock()
	botDefenseDecisionHistory = append(botDefenseDecisionHistory, record)
	if len(botDefenseDecisionHistory) > botDefenseDecisionHistoryLimit {
		botDefenseDecisionHistory = append([]botDefenseDecisionRecord(nil), botDefenseDecisionHistory[len(botDefenseDecisionHistory)-botDefenseDecisionHistoryLimit:]...)
	}
}

func recentBotDefenseDecisions(limit int) []botDefenseDecisionRecord {
	if limit <= 0 {
		limit = 20
	}
	if limit > botDefenseDecisionHistoryLimit {
		limit = botDefenseDecisionHistoryLimit
	}
	botDefenseDecisionMu.Lock()
	defer botDefenseDecisionMu.Unlock()
	if len(botDefenseDecisionHistory) == 0 {
		return nil
	}
	start := len(botDefenseDecisionHistory) - limit
	if start < 0 {
		start = 0
	}
	src := botDefenseDecisionHistory[start:]
	out := make([]botDefenseDecisionRecord, 0, len(src))
	for i := len(src) - 1; i >= 0; i-- {
		out = append(out, cloneBotDefenseDecisionRecord(src[i]))
	}
	return out
}

func latestBotDefenseDecision() (botDefenseDecisionRecord, bool) {
	botDefenseDecisionMu.Lock()
	defer botDefenseDecisionMu.Unlock()
	if len(botDefenseDecisionHistory) == 0 {
		return botDefenseDecisionRecord{}, false
	}
	return cloneBotDefenseDecisionRecord(botDefenseDecisionHistory[len(botDefenseDecisionHistory)-1]), true
}

func cloneBotDefenseDecisionRecord(in botDefenseDecisionRecord) botDefenseDecisionRecord {
	in.Signals = append([]string(nil), in.Signals...)
	return in
}

func resetBotDefenseDecisionHistory() {
	botDefenseDecisionMu.Lock()
	defer botDefenseDecisionMu.Unlock()
	botDefenseDecisionHistory = nil
}

func GetBotDefenseDecisions(c *gin.Context) {
	limit := 20
	if raw := strings.TrimSpace(c.Query("limit")); raw != "" {
		if v, err := strconv.Atoi(raw); err == nil {
			limit = v
		}
	}
	items := recentBotDefenseDecisions(limit)
	c.JSON(http.StatusOK, gin.H{
		"items": items,
		"count": len(items),
	})
}
