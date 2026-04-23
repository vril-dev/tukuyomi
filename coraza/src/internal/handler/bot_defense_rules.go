package handler

import (
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const botDefenseConfigBlobKey = "bot_defense_rules"

type botDefensePutBody struct {
	Raw string `json:"raw"`
}

func bindBotDefensePutBody(c *gin.Context) (botDefensePutBody, bool) {
	var in botDefensePutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return botDefensePutBody{}, false
	}

	return in, true
}

func GetBotDefenseRules(c *gin.Context) {
	path := GetBotDefensePath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(botDefenseConfigBlobKey), normalizeBotDefensePolicyRaw, "bot defense rules")
		if err != nil {
			respondConfigBlobDBError(c, "bot-defense db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateBotDefenseRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "bot-defense db rows parse failed", parseErr)
				return
			} else {
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
		}
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

func ValidateBotDefenseRules(c *gin.Context) {
	in, ok := bindBotDefensePutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateBotDefenseRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
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
	path := GetBotDefensePath()
	store := getLogsStatsStore()

	in, ok := bindBotDefensePutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateBotDefenseRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	normalizedRaw, err := normalizeBotDefensePolicyRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if store != nil {
		spec := mustPolicyJSONSpec(botDefenseConfigBlobKey)
		currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeBotDefensePolicyRaw, "bot defense rules")
		if err != nil {
			respondConfigBlobDBError(c, "bot-defense db seed failed", err)
			return
		}
		expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
		rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "bot defense rules update", 0)
		if err != nil {
			if errors.Is(err, errConfigVersionConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, botDefenseConfigBlobKey)})
				return
			}
			respondConfigBlobDBError(c, "bot-defense db update failed", err)
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
		return
	}

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := ReloadBotDefense(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadBotDefense()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))

	c.JSON(http.StatusOK, gin.H{
		"ok":                        true,
		"etag":                      newETag,
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
		"saved_at":                  now.Format(time.RFC3339Nano),
	})
}

func SyncBotDefenseStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(botDefenseConfigBlobKey), normalizeBotDefensePolicyRaw, "bot defense rules")
	if err != nil || !found {
		return err
	}
	return applyBotDefensePolicyRaw(raw)
}
