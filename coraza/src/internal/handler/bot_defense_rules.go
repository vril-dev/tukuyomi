package handler

import (
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/botdecisions"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/runtimefiles"
)

const botDefenseConfigBlobKey = "bot_defense_rules"

type botDefenseDecisionRecord = botdecisions.Record

var botDefenseDecisionHistory = botdecisions.NewHistory(botdecisions.DefaultLimit)

func GetBotDefenseRules(c *gin.Context) {
	path := GetBotDefensePath()
	raw, _ := os.ReadFile(path)
	savedAt := runtimefiles.FileSavedAt(path)
	dbRaw, rec, found, ok := loadPolicyJSONConfigForAdmin(c, botDefensePolicyJSONDomain.adminRead())
	if !ok {
		return
	}
	if found {
		rt, parseErr := ValidateBotDefenseRaw(string(dbRaw))
		if parseErr != nil {
			respondConfigBlobDBError(c, "bot-defense db rows parse failed", parseErr)
			return
		}
		savedAt = configVersionSavedAt(rec)
		c.JSON(http.StatusOK, gin.H{
			"etag":                      rec.ETag,
			"raw":                       string(dbRaw),
			"enabled":                   rt.Raw.Enabled,
			"dry_run":                   rt.Raw.DryRun,
			"mode":                      rt.Raw.Mode,
			"path_prefixes":             rt.Raw.PathPrefixes,
			"path_policy_count":         len(rt.Raw.PathPolicies),
			"path_policy_dry_run_count": countBotDefensePathPoliciesDryRun(rt.Raw),
			"behavioral_enabled":        rt.Raw.BehavioralDetection.Enabled,
			"browser_signals_enabled":   rt.Raw.BrowserSignals.Enabled,
			"device_signals_enabled":    rt.Raw.DeviceSignals.Enabled,
			"device_invisible_enabled":  rt.Raw.DeviceSignals.InvisibleHTMLInjection,
			"header_signals_enabled":    rt.Raw.HeaderSignals.Enabled,
			"tls_signals_enabled":       rt.Raw.TLSSignals.Enabled,
			"quarantine_enabled":        rt.Raw.Quarantine.Enabled,
			"saved_at":                  savedAt,
		})
		return
	}
	cfg := GetBotDefenseConfig()

	c.JSON(http.StatusOK, gin.H{
		"etag":                      bypassconf.ComputeETag(raw),
		"raw":                       string(raw),
		"enabled":                   cfg.Enabled,
		"dry_run":                   cfg.DryRun,
		"mode":                      cfg.Mode,
		"path_prefixes":             cfg.PathPrefixes,
		"path_policy_count":         len(cfg.PathPolicies),
		"path_policy_dry_run_count": countBotDefensePathPoliciesDryRun(cfg),
		"behavioral_enabled":        cfg.BehavioralDetection.Enabled,
		"browser_signals_enabled":   cfg.BrowserSignals.Enabled,
		"device_signals_enabled":    cfg.DeviceSignals.Enabled,
		"device_invisible_enabled":  cfg.DeviceSignals.InvisibleHTMLInjection,
		"header_signals_enabled":    cfg.HeaderSignals.Enabled,
		"tls_signals_enabled":       cfg.TLSSignals.Enabled,
		"quarantine_enabled":        cfg.Quarantine.Enabled,
		"saved_at":                  savedAt,
	})
}

func recordBotDefenseDecision(req *http.Request, ctx *requestSecurityPluginContext, decision botDefenseDecision) {
	record := botdecisions.Record{
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
	botDefenseDecisionHistory.Add(record)
}

func recentBotDefenseDecisions(limit int) []botdecisions.Record {
	return botDefenseDecisionHistory.Recent(limit)
}

func latestBotDefenseDecision() (botdecisions.Record, bool) {
	return botDefenseDecisionHistory.Latest()
}

func resetBotDefenseDecisionHistory() {
	botDefenseDecisionHistory.Reset()
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

func ValidateBotDefenseRules(c *gin.Context) {
	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateBotDefenseRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":                        true,
		"messages":                  []string{},
		"enabled":                   rt.Raw.Enabled,
		"dry_run":                   rt.Raw.DryRun,
		"mode":                      rt.Raw.Mode,
		"path_prefixes":             rt.Raw.PathPrefixes,
		"path_policy_count":         len(rt.Raw.PathPolicies),
		"path_policy_dry_run_count": countBotDefensePathPoliciesDryRun(rt.Raw),
		"behavioral_enabled":        rt.Raw.BehavioralDetection.Enabled,
		"browser_signals_enabled":   rt.Raw.BrowserSignals.Enabled,
		"device_signals_enabled":    rt.Raw.DeviceSignals.Enabled,
		"device_invisible_enabled":  rt.Raw.DeviceSignals.InvisibleHTMLInjection,
		"header_signals_enabled":    rt.Raw.HeaderSignals.Enabled,
		"tls_signals_enabled":       rt.Raw.TLSSignals.Enabled,
		"quarantine_enabled":        rt.Raw.Quarantine.Enabled,
	})
}

func PutBotDefenseRules(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}

	in, ok := bindRawPolicyPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateBotDefenseRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}

	normalizedRaw, err := normalizeBotDefensePolicyRaw(in.Raw)
	if err != nil {
		respondPolicyValidationError(c, err)
		return
	}
	rec, ok := writePolicyJSONConfigUpdate(c, store, botDefensePolicyJSONDomain.update(normalizedRaw))
	if !ok {
		return
	}
	if err := applyBotDefensePolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":                        true,
		"etag":                      rec.ETag,
		"enabled":                   rt.Raw.Enabled,
		"dry_run":                   rt.Raw.DryRun,
		"mode":                      rt.Raw.Mode,
		"path_prefixes":             rt.Raw.PathPrefixes,
		"path_policy_count":         len(rt.Raw.PathPolicies),
		"path_policy_dry_run_count": countBotDefensePathPoliciesDryRun(rt.Raw),
		"behavioral_enabled":        rt.Raw.BehavioralDetection.Enabled,
		"browser_signals_enabled":   rt.Raw.BrowserSignals.Enabled,
		"device_signals_enabled":    rt.Raw.DeviceSignals.Enabled,
		"device_invisible_enabled":  rt.Raw.DeviceSignals.InvisibleHTMLInjection,
		"header_signals_enabled":    rt.Raw.HeaderSignals.Enabled,
		"tls_signals_enabled":       rt.Raw.TLSSignals.Enabled,
		"quarantine_enabled":        rt.Raw.Quarantine.Enabled,
		"saved_at":                  rec.ActivatedAt.Format(time.RFC3339Nano),
	})
}

func SyncBotDefenseStorage() error {
	return syncPolicyJSONConfigStorage(botDefensePolicyJSONDomain.sync(applyBotDefensePolicyRaw))
}
