package handler

import (
	"net/http"
	"os"
	"strings"
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
		dbRaw, dbETag, found, err := store.GetConfigBlob(botDefenseConfigBlobKey)
		if err != nil {
			respondConfigBlobDBError(c, "bot-defense db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateBotDefenseRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "bot-defense db blob parse failed", parseErr)
				return
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				savedAt = configBlobSavedAt(store, botDefenseConfigBlobKey)
				c.JSON(http.StatusOK, gin.H{
					"etag":                      dbETag,
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
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(botDefenseConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				respondConfigBlobDBError(c, "bot-defense db seed failed", err)
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
	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(botDefenseConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ValidateBotDefenseRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				respondConfigBlobDBError(c, "bot-defense db blob parse failed for conflict check", parseErr)
				return
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindBotDefensePutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateBotDefenseRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
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
	if store != nil {
		if err := store.UpsertConfigBlob(botDefenseConfigBlobKey, []byte(in.Raw), newETag, now); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadBotDefense()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "bot-defense db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

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
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: botDefenseConfigBlobKey,
		Path:      GetBotDefensePath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateBotDefenseRaw(raw)
			return err
		},
		Reload:           ReloadBotDefense,
		SkipWriteIfEqual: true,
	})
}
