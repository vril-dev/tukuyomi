package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

func StatusHandler(c *gin.Context) {
	semantic := GetSemanticConfig()
	semanticStats := GetSemanticStats()
	notificationStatus := GetNotificationStatus()
	ipReputationStatus := IPReputationStatus()
	botDefenseCfg := GetBotDefenseConfig()
	botDefenseLatest, botDefenseLatestOK := latestBotDefenseDecision()
	responseCache := GetResponseCacheStatus()
	logOutput := GetLogOutputStatus()
	dbTotalRows := 0
	dbWAFBlockRows := 0
	dbSizeBytes := int64(0)
	dbLastIngestOffset := int64(0)
	dbLastIngestModTime := ""
	dbLastSyncScannedLines := 0
	dbStatusError := ""
	botDefenseRecentDecision := map[string]any{}
	if botDefenseLatestOK {
		botDefenseRecentDecision = map[string]any{
			"timestamp":   botDefenseLatest.Timestamp,
			"action":      botDefenseLatest.Action,
			"dry_run":     botDefenseLatest.DryRun,
			"status":      botDefenseLatest.Status,
			"flow_policy": botDefenseLatest.FlowPolicy,
			"risk_score":  botDefenseLatest.RiskScore,
			"signals":     append([]string(nil), botDefenseLatest.Signals...),
			"path":        botDefenseLatest.Path,
			"request_id":  botDefenseLatest.RequestID,
		}
	}

	if store := getLogsStatsStore(); store != nil {
		if wafPath, ok := logFiles["waf"]; ok {
			snapshot, err := store.StatusSnapshot(resolveLogPath("waf", wafPath))
			if err != nil {
				dbStatusError = err.Error()
			} else {
				dbTotalRows = snapshot.TotalRows
				dbWAFBlockRows = snapshot.WAFBlockRows
				dbSizeBytes = snapshot.DBSizeBytes
				dbLastIngestOffset = snapshot.LastIngestOffset
				dbLastIngestModTime = snapshot.LastIngestModTime
				dbLastSyncScannedLines = snapshot.LastSyncScannedLines
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"status":                                "running",
		"rules_file":                            config.RulesFile,
		"bypass_file":                           config.BypassFile,
		"country_block_file":                    config.CountryBlockFile,
		"country_header_names":                  config.CountryHeaderNames,
		"country_source_requires_trusted_proxy": true,
		"blocked_countries":                     GetBlockedCountries(),
		"rate_limit_file":                       config.RateLimitFile,
		"rate_limit_enabled":                    GetRateLimitConfig().Enabled,
		"rate_limit_rule_count":                 len(GetRateLimitConfig().Rules),
		"notification_file":                     config.NotificationFile,
		"notification_enabled":                  notificationStatus.Enabled,
		"notification_sink_count":               notificationStatus.SinkCount,
		"notification_enabled_sinks":            notificationStatus.EnabledSinkCount,
		"notification_active_alerts":            notificationStatus.ActiveAlerts,
		"notification_sent_total":               notificationStatus.Sent,
		"notification_failed_total":             notificationStatus.Failed,
		"notification_last_error":               notificationStatus.LastDispatchErr,
		"ip_reputation_enabled":                 ipReputationStatus.Enabled,
		"ip_reputation_feed_urls":               ipReputationStatus.FeedURLs,
		"ip_reputation_last_refresh_at":         ipReputationStatus.LastRefreshAt,
		"ip_reputation_last_refresh_error":      ipReputationStatus.LastRefreshError,
		"ip_reputation_effective_allow_count":   ipReputationStatus.EffectiveAllowCount,
		"ip_reputation_effective_block_count":   ipReputationStatus.EffectiveBlockCount,
		"ip_reputation_feed_allow_count":        ipReputationStatus.FeedAllowCount,
		"ip_reputation_feed_block_count":        ipReputationStatus.FeedBlockCount,
		"ip_reputation_block_status_code":       ipReputationStatus.BlockStatusCode,
		"ip_reputation_fail_open":               ipReputationStatus.FailOpen,
		"bot_defense_file":                      config.BotDefenseFile,
		"bot_defense_enabled":                   botDefenseCfg.Enabled,
		"bot_defense_dry_run":                   botDefenseCfg.DryRun,
		"bot_defense_mode":                      botDefenseCfg.Mode,
		"bot_defense_paths":                     botDefenseCfg.PathPrefixes,
		"bot_defense_path_policy_count":         len(botDefenseCfg.PathPolicies),
		"bot_defense_behavioral_enabled":        botDefenseCfg.BehavioralDetection.Enabled,
		"bot_defense_recent_decision":           botDefenseRecentDecision,
		"semantic_file":                         config.SemanticFile,
		"semantic_enabled":                      semantic.Enabled,
		"semantic_mode":                         semantic.Mode,
		"semantic_log_threshold":                semantic.LogThreshold,
		"semantic_challenge_threshold":          semantic.ChallengeThreshold,
		"semantic_block_threshold":              semantic.BlockThreshold,
		"semantic_max_inspect_body":             semantic.MaxInspectBody,
		"semantic_exempt_path_prefixes":         semantic.ExemptPathPrefixes,
		"semantic_inspected_requests":           semanticStats.InspectedRequests,
		"semantic_scored_requests":              semanticStats.ScoredRequests,
		"semantic_log_only_actions":             semanticStats.LogOnlyActions,
		"semantic_challenge_actions":            semanticStats.ChallengeActions,
		"semantic_block_actions":                semanticStats.BlockActions,
		"log_file":                              config.LogFile,
		"log_output_file":                       logOutput.Path,
		"log_output_provider":                   logOutput.Provider,
		"log_output_waf_mode":                   logOutput.WAF.Mode,
		"log_output_waf_file_path":              logOutput.WAF.FilePath,
		"log_output_interesting_mode":           logOutput.Interesting.Mode,
		"log_output_interesting_file_path":      logOutput.Interesting.FilePath,
		"log_output_access_error_mode":          logOutput.AccessError.Mode,
		"log_output_access_error_file_path":     logOutput.AccessError.FilePath,
		"log_output_stdout_streams":             logOutput.StdoutStreams,
		"log_output_file_streams":               logOutput.FileStreams,
		"log_output_local_read_compatible":      logOutput.LocalReadCompatible,
		"strict_mode":                           config.StrictOverride,
		"api_base":                              config.APIBasePath,
		"ui_base":                               config.UIBasePath,
		"trusted_proxy_cidrs":                   config.TrustedProxyCIDRs,
		"trusted_proxy_count":                   len(config.TrustedProxyCIDRs),
		"forward_internal_response_headers":     config.ForwardInternalResponseHeaders,
		"response_cache_mode":                   responseCache.Mode,
		"response_cache_enabled":                responseCache.Enabled,
		"response_cache_max_entries":            responseCache.MaxEntries,
		"response_cache_max_body_bytes":         responseCache.MaxBodyBytes,
		"response_cache_entry_count":            responseCache.EntryCount,
		"response_cache_inflight_keys":          responseCache.InflightKeys,
		"response_cache_hits":                   responseCache.Hits,
		"response_cache_misses":                 responseCache.Misses,
		"response_cache_stores":                 responseCache.Stores,
		"response_cache_bypasses":               responseCache.Bypasses,
		"response_cache_evictions":              responseCache.Evictions,
		"response_cache_coalesced_waits":        responseCache.CoalescedWaits,
		"crs_enabled":                           config.CRSEnable,
		"crs_setup_file":                        config.CRSSetupFile,
		"crs_rules_dir":                         config.CRSRulesDir,
		"crs_disabled_file":                     config.CRSDisabledFile,
		"storage_backend":                       config.StorageBackend,
		"db_enabled":                            config.DBEnabled,
		"db_driver":                             config.DBDriver,
		"db_dsn_configured":                     strings.TrimSpace(config.DBDSN) != "",
		"db_path":                               config.DBPath,
		"db_retention_days":                     config.DBRetentionDays,
		"db_sync_interval_sec":                  int(config.DBSyncInterval / time.Second),
		"db_sync_loop_enabled":                  config.DBEnabled && config.DBSyncInterval > 0,
		"db_total_rows":                         dbTotalRows,
		"db_waf_block_rows":                     dbWAFBlockRows,
		"db_size_bytes":                         dbSizeBytes,
		"db_last_ingest_offset":                 dbLastIngestOffset,
		"db_last_ingest_mod_time":               dbLastIngestModTime,
		"db_last_sync_scanned_lines":            dbLastSyncScannedLines,
		"db_status_error":                       dbStatusError,
		"allow_insecure_defaults":               config.AllowInsecureDefaults,
	})
}

func RulesHandler(c *gin.Context) {
	files := configuredRuleFiles()
	result := make(map[string]string)
	out := make([]gin.H, 0, len(files))

	for _, path := range files {
		content, err := os.ReadFile(path)
		if store := getLogsStatsStore(); store != nil {
			key := ruleFileConfigBlobKey(path)
			dbRaw, dbETag, found, dbErr := store.GetConfigBlob(key)
			if dbErr != nil {
				log.Printf("[RULES][DB][WARN] get config blob failed (path=%s): %v", path, dbErr)
			} else if found {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
					if err := store.UpsertConfigBlob(key, dbRaw, dbETag, time.Now().UTC()); err != nil {
						log.Printf("[RULES][DB][WARN] normalize etag failed (path=%s): %v", path, err)
					}
				}
				result[path] = string(dbRaw)
				out = append(out, gin.H{
					"path": path,
					"raw":  string(dbRaw),
					"etag": dbETag,
				})
				continue
			} else if err == nil && len(content) > 0 {
				if err := store.UpsertConfigBlob(key, content, bypassconf.ComputeETag(content), time.Now().UTC()); err != nil {
					log.Printf("[RULES][DB][WARN] seed config blob failed (path=%s): %v", path, err)
				}
			}
		}
		if err != nil {
			result[path] = "[読込失敗] " + err.Error()
			out = append(out, gin.H{
				"path":  path,
				"raw":   "",
				"etag":  "",
				"error": err.Error(),
			})
			continue
		}
		result[path] = string(content)
		out = append(out, gin.H{
			"path": path,
			"raw":  string(content),
			"etag": bypassconf.ComputeETag(content),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": result,
		"files": out,
	})
}

type rulesPutBody struct {
	Path string `json:"path"`
	Raw  string `json:"raw"`
}

func ValidateRules(c *gin.Context) {
	var in rulesPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	target, err := ensureEditableRulePath(in.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := waf.ValidateWithRuleOverride(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutRules(c *gin.Context) {
	var in rulesPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	target, err := ensureEditableRulePath(in.Path)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	store := getLogsStatsStore()
	curRaw, hadFile, err := readFileMaybe(target)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		key := ruleFileConfigBlobKey(target)
		dbRaw, dbETag, found, getErr := store.GetConfigBlob(key)
		if getErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": getErr.Error()})
			return
		}
		if found {
			curRaw = dbRaw
			if strings.TrimSpace(dbETag) == "" {
				dbETag = bypassconf.ComputeETag(dbRaw)
			}
			curETag = dbETag
		}
	}

	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := waf.ValidateWithRuleOverride(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bypassconf.AtomicWriteWithBackup(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := waf.ReloadBaseWAF(); err != nil {
		_ = rollbackRuleFile(target, hadFile, curRaw)
		_ = waf.ReloadBaseWAF()
		c.JSON(http.StatusInternalServerError, gin.H{
			"error": fmt.Sprintf("reload failed and rollback applied: %v", err),
		})
		return
	}

	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		key := ruleFileConfigBlobKey(target)
		if err := store.UpsertConfigBlob(key, []byte(in.Raw), newETag, time.Now().UTC()); err != nil {
			rollbackErr := rollbackRuleFile(target, hadFile, curRaw)
			_ = waf.ReloadBaseWAF()
			msg := fmt.Sprintf("db sync failed and rollback applied: %v", err)
			if rollbackErr != nil {
				msg = fmt.Sprintf("%s (rollback error: %v)", msg, rollbackErr)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          newETag,
		"hot_reloaded":  true,
		"reloaded_file": target,
	})
}

func configuredRuleFiles() []string {
	parts := strings.Split(config.RulesFile, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		if _, ok := seen[p]; ok {
			continue
		}
		seen[p] = struct{}{}
		out = append(out, p)
	}
	return out
}

func ensureEditableRulePath(path string) (string, error) {
	target := filepath.Clean(strings.TrimSpace(path))
	if target == "" {
		return "", fmt.Errorf("path is empty")
	}
	for _, p := range configuredRuleFiles() {
		if filepath.Clean(p) == target {
			return p, nil
		}
	}
	return "", fmt.Errorf("path is not editable: %s", path)
}

func ruleFileConfigBlobKey(path string) string {
	cleaned := filepath.Clean(strings.TrimSpace(path))
	sum := sha256.Sum256([]byte(cleaned))
	return "rule_file_sha256:" + hex.EncodeToString(sum[:])
}

func SyncRuleFilesStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}

	changed := false
	for _, path := range configuredRuleFiles() {
		if strings.TrimSpace(path) == "" {
			continue
		}

		fileRaw, hadFile, err := readFileMaybe(path)
		if err != nil {
			return err
		}
		key := ruleFileConfigBlobKey(path)
		dbRaw, dbETag, found, err := store.GetConfigBlob(key)
		if err != nil {
			return err
		}

		if found {
			if !hadFile || !bytes.Equal(fileRaw, dbRaw) {
				if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
					return err
				}
				if err := bypassconf.AtomicWriteWithBackup(path, dbRaw); err != nil {
					return err
				}
				changed = true
			}
			if strings.TrimSpace(dbETag) == "" {
				dbETag = bypassconf.ComputeETag(dbRaw)
				if err := store.UpsertConfigBlob(key, dbRaw, dbETag, time.Now().UTC()); err != nil {
					return err
				}
			}
			continue
		}

		if !hadFile || len(fileRaw) == 0 {
			continue
		}
		if err := store.UpsertConfigBlob(key, fileRaw, bypassconf.ComputeETag(fileRaw), time.Now().UTC()); err != nil {
			return err
		}
	}

	if changed && waf.GetBaseWAF() != nil {
		if err := waf.ReloadBaseWAF(); err != nil {
			return fmt.Errorf("reload base waf after rule sync: %w", err)
		}
	}
	return nil
}

func rollbackRuleFile(path string, hadFile bool, raw []byte) error {
	if hadFile {
		return bypassconf.AtomicWriteWithBackup(path, raw)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
