package handler

import (
	"fmt"
	"net/http"
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
	semanticFile := GetSemanticFile()
	semanticStats := GetSemanticStats()
	notificationStatus := GetNotificationStatus()
	ipReputationStatus := IPReputationStatus()
	latestBotDecision, hasLatestBotDecision := latestBotDefenseDecision()
	adminRateStats := AdminRateLimitStatsSnapshot()
	requestSecurityEventStats := RequestSecurityEventStatsSnapshot()
	globalOverload := overloadSnapshot("global")
	proxyOverload := overloadSnapshot("proxy")
	serverTLSStatus := ServerTLSRuntimeStatusSnapshot()
	serverHTTP3Status := ServerHTTP3RuntimeStatusSnapshot()
	securityAuditStatus := SecurityAuditStatusSnapshot()
	_, _, responseCacheCfg, responseCacheStats := ResponseCacheSnapshot()
	_, proxyETag, proxyCfg, proxyHealth, proxyRollbackDepth := ProxyRulesSnapshot()
	proxyCompressionStatus := proxyResponseCompressionStatusSnapshot()
	siteStatuses := SiteStatusSnapshot()
	requestCountryStatus := RequestCountryRuntimeStatusSnapshot()
	_, _, phpRuntimeInventory, phpRuntimeRollbackDepth := PHPRuntimeInventorySnapshot()
	_, _, vhostCfg, vhostRollbackDepth := VhostConfigSnapshot()
	vhostRuntimeStatus := VhostRuntimeStatusSnapshot()
	phpRuntimeMaterialized := PHPRuntimeMaterializationSnapshot()
	phpRuntimeProcesses := PHPRuntimeProcessSnapshot()
	adminListenerEnabled := strings.TrimSpace(config.AdminListenAddr) != ""
	listenerMode := "single"
	if adminListenerEnabled {
		listenerMode = "split"
	}
	botDefenseCfg := GetBotDefenseConfig()
	botDefenseFile := GetBotDefenseFile()
	botDefenseSummary := summarizeBotDefenseFile(botDefenseFile)
	rateLimitCfg := GetRateLimitConfig()
	dbTotalRows := 0
	dbWAFBlockRows := 0
	dbSizeBytes := int64(0)
	dbLastIngestOffset := int64(0)
	dbLastIngestModTime := ""
	dbLastSyncScannedLines := 0
	dbStatusError := ""

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
		"status":                                              "running",
		"rules_file":                                          config.RulesFile,
		"bypass_file":                                         config.BypassFile,
		"country_block_file":                                  config.CountryBlockFile,
		"blocked_countries":                                   GetBlockedCountries(),
		"rate_limit_file":                                     config.RateLimitFile,
		"rate_limit_enabled":                                  rateLimitEnabled(rateLimitCfg),
		"rate_limit_rule_count":                               rateLimitRuleCount(rateLimitCfg),
		"rate_limit_feedback_enabled":                         rateLimitCfg.Default.Feedback.Enabled,
		"rate_limit_feedback_strikes_required":                rateLimitCfg.Default.Feedback.StrikesRequired,
		"rate_limit_feedback_strike_window_seconds":           rateLimitCfg.Default.Feedback.StrikeWindowSeconds,
		"rate_limit_feedback_adaptive_only":                   rateLimitCfg.Default.Feedback.AdaptiveOnly,
		"rate_limit_feedback_dry_run":                         rateLimitCfg.Default.Feedback.DryRun,
		"notification_file":                                   config.NotificationFile,
		"notification_enabled":                                notificationStatus.Enabled,
		"notification_sink_count":                             notificationStatus.SinkCount,
		"notification_enabled_sinks":                          notificationStatus.EnabledSinkCount,
		"notification_active_alerts":                          notificationStatus.ActiveAlerts,
		"notification_sent_total":                             notificationStatus.Sent,
		"notification_failed_total":                           notificationStatus.Failed,
		"notification_last_error":                             notificationStatus.LastDispatchErr,
		"ip_reputation_enabled":                               ipReputationStatus.Enabled,
		"ip_reputation_feed_urls":                             ipReputationStatus.FeedURLs,
		"ip_reputation_last_refresh_at":                       ipReputationStatus.LastRefreshAt,
		"ip_reputation_last_refresh_error":                    ipReputationStatus.LastRefreshError,
		"ip_reputation_effective_allow_count":                 ipReputationStatus.EffectiveAllowCount,
		"ip_reputation_effective_block_count":                 ipReputationStatus.EffectiveBlockCount,
		"ip_reputation_feed_allow_count":                      ipReputationStatus.FeedAllowCount,
		"ip_reputation_feed_block_count":                      ipReputationStatus.FeedBlockCount,
		"ip_reputation_dynamic_penalty_count":                 ipReputationStatus.DynamicPenaltyCount,
		"ip_reputation_block_status_code":                     ipReputationStatus.BlockStatusCode,
		"ip_reputation_fail_open":                             ipReputationStatus.FailOpen,
		"bot_defense_file":                                    config.BotDefenseFile,
		"bot_defense_enabled":                                 botDefenseSummary.Enabled,
		"bot_defense_dry_run_enabled":                         botDefenseSummary.DryRunEnabled,
		"bot_defense_mode":                                    botDefenseCfg.Mode,
		"bot_defense_paths":                                   botDefenseCfg.PathPrefixes,
		"bot_defense_host_scope_count":                        botDefenseSummary.HostScopeCount,
		"bot_defense_path_policy_count":                       botDefenseSummary.PathPolicyCount,
		"bot_defense_path_policy_dry_run_count":               botDefenseSummary.PathPolicyDryRunCount,
		"bot_defense_behavioral_enabled":                      botDefenseSummary.BehavioralEnabled,
		"bot_defense_browser_signals_enabled":                 botDefenseSummary.BrowserSignalsEnabled,
		"bot_defense_device_signals_enabled":                  botDefenseSummary.DeviceSignalsEnabled,
		"bot_defense_device_invisible_enabled":                botDefenseSummary.DeviceInvisibleEnabled,
		"bot_defense_header_signals_enabled":                  botDefenseSummary.HeaderSignalsEnabled,
		"bot_defense_tls_signals_enabled":                     botDefenseSummary.TLSSignalsEnabled,
		"bot_defense_quarantine_enabled":                      botDefenseSummary.QuarantineEnabled,
		"bot_defense_quarantine_threshold":                    botDefenseCfg.Quarantine.Threshold,
		"bot_defense_quarantine_strikes_required":             botDefenseCfg.Quarantine.StrikesRequired,
		"bot_defense_quarantine_ttl_seconds":                  botDefenseCfg.Quarantine.TTLSeconds,
		"bot_defense_challenge_failure_feedback_enabled":      botDefenseSummary.ChallengeFailureFeedbackOn,
		"bot_defense_challenge_failure_feedback_seconds":      botDefenseCfg.ChallengeFailureFeedback.ReputationFeedback,
		"bot_defense_recent_decision_count":                   len(recentBotDefenseDecisions(10)),
		"bot_defense_last_action":                             latestBotDecision.Action,
		"bot_defense_last_dry_run":                            latestBotDecision.DryRun,
		"bot_defense_last_flow_policy":                        latestBotDecision.FlowPolicy,
		"bot_defense_last_risk_score":                         latestBotDecision.RiskScore,
		"bot_defense_last_signals":                            latestBotDecision.Signals,
		"bot_defense_last_decision_at":                        latestBotDecision.Timestamp,
		"bot_defense_has_recent_decisions":                    hasLatestBotDecision,
		"request_security_events_published_total":             requestSecurityEventStats.PublishedTotal,
		"request_security_bot_challenge_failures_total":       requestSecurityEventStats.BotChallengeFailuresTotal,
		"request_security_bot_challenge_penalties_total":      requestSecurityEventStats.BotChallengePenaltiesTotal,
		"request_security_rate_limit_promotions_total":        requestSecurityEventStats.RateLimitPromotionsTotal,
		"request_security_rate_limit_promotion_dry_run_total": requestSecurityEventStats.RateLimitPromotionDryRunTotal,
		"semantic_file":                                       config.SemanticFile,
		"semantic_enabled":                                    semanticEnabled(semanticFile),
		"semantic_mode":                                       semantic.Mode,
		"semantic_log_threshold":                              semantic.LogThreshold,
		"semantic_challenge_threshold":                        semantic.ChallengeThreshold,
		"semantic_block_threshold":                            semantic.BlockThreshold,
		"semantic_max_inspect_body":                           semantic.MaxInspectBody,
		"semantic_exempt_path_prefixes":                       semantic.ExemptPathPrefixes,
		"semantic_inspected_requests":                         semanticStats.InspectedRequests,
		"semantic_scored_requests":                            semanticStats.ScoredRequests,
		"semantic_log_only_actions":                           semanticStats.LogOnlyActions,
		"semantic_challenge_actions":                          semanticStats.ChallengeActions,
		"semantic_block_actions":                              semanticStats.BlockActions,
		"log_file":                                            config.LogFile,
		"strict_mode":                                         config.StrictOverride,
		"api_base":                                            config.APIBasePath,
		"ui_path":                                             config.UIBasePath,
		"site_config_file":                                    config.SiteConfigFile,
		"site_config_storage":                                 siteConfigStorageLabel(),
		"site_count":                                          len(siteStatuses),
		"site_enabled_count":                                  countEnabledSiteStatuses(siteStatuses),
		"sites":                                               siteStatuses,
		"php_runtime_inventory_file":                          config.PHPRuntimeInventoryFile,
		"php_runtime_count":                                   len(phpRuntimeInventory.Runtimes),
		"php_runtime_rollback_depth":                          phpRuntimeRollbackDepth,
		"php_runtime_materialized_count":                      len(phpRuntimeMaterialized),
		"php_runtime_materialized":                            phpRuntimeMaterialized,
		"php_runtime_process_count":                           len(phpRuntimeProcesses),
		"php_runtime_processes":                               phpRuntimeProcesses,
		"vhost_config_file":                                   config.VhostConfigFile,
		"vhost_count":                                         len(vhostCfg.Vhosts),
		"vhost_static_count":                                  countVhostsByMode(vhostCfg, "static"),
		"vhost_php_fpm_count":                                 countVhostsByMode(vhostCfg, "php-fpm"),
		"vhost_rollback_depth":                                vhostRollbackDepth,
		"vhost_degraded":                                      vhostRuntimeStatus.Degraded,
		"vhost_last_error":                                    vhostRuntimeStatus.LastError,
		"scheduled_task_config_storage":                       scheduledTaskConfigStorageLabel(currentScheduledTaskConfigPath()),
		"upstream_runtime_storage":                            upstreamRuntimeStorageLabel(),
		"security_audit":                                      securityAuditStatus,
		"security_audit_enabled":                              securityAuditStatus.Enabled,
		"security_audit_capture_mode":                         securityAuditStatus.CaptureMode,
		"security_audit_capture_headers":                      securityAuditStatus.CaptureHeaders,
		"security_audit_capture_body":                         securityAuditStatus.CaptureBody,
		"security_audit_max_body_bytes":                       securityAuditStatus.MaxBodyBytes,
		"security_audit_file":                                 securityAuditStatus.File,
		"security_audit_blob_dir":                             securityAuditStatus.BlobDir,
		"security_audit_encryption_key_id":                    securityAuditStatus.EncryptionKeyID,
		"security_audit_hmac_key_id":                          securityAuditStatus.HMACKeyID,
		"security_audit_records_total":                        securityAuditStatus.RecordsTotal,
		"security_audit_captures_total":                       securityAuditStatus.CapturesTotal,
		"security_audit_verify_failures_total":                securityAuditStatus.VerifyFailuresTotal,
		"security_audit_last_verify_at":                       securityAuditStatus.LastVerifyAt,
		"security_audit_last_verify_ok":                       securityAuditStatus.LastVerifyOK,
		"security_audit_last_verify_error":                    securityAuditStatus.LastVerifyError,
		"security_audit_last_integrity_sequence":              securityAuditStatus.LastIntegritySequence,
		"security_audit_last_integrity_hash":                  securityAuditStatus.LastIntegrityHash,
		"security_audit_last_capture_error":                   securityAuditStatus.LastCaptureError,
		"security_audit_last_write_error":                     securityAuditStatus.LastWriteError,
		"security_audit_last_verification_anchored":           securityAuditStatus.LastVerificationAnchor,
		"admin_external_mode":                                 config.AdminExternalMode,
		"admin_read_only":                                     config.AdminReadOnly,
		"admin_trusted_cidrs":                                 config.AdminTrustedCIDRs,
		"admin_trust_forwarded_for":                           config.AdminTrustForwardedFor,
		"admin_rate_limit_enabled":                            config.AdminRateLimitEnabled,
		"admin_rate_limit_rps":                                config.AdminRateLimitRPS,
		"admin_rate_limit_burst":                              config.AdminRateLimitBurst,
		"admin_rate_limit_status_code":                        config.AdminRateLimitStatusCode,
		"admin_rate_limit_retry_after_seconds":                config.AdminRateLimitRetryAfter,
		"admin_rate_limit_requests_total":                     adminRateStats.Requests,
		"admin_rate_limit_allowed_total":                      adminRateStats.Allowed,
		"admin_rate_limit_blocked_total":                      adminRateStats.Blocked,
		"listener_mode":                                       listenerMode,
		"listen_addr":                                         config.ListenAddr,
		"public_listener_addr":                                config.ListenAddr,
		"public_listener_tls_enabled":                         config.ServerTLSEnabled,
		"public_listener_proxy_protocol_enabled":              config.ServerProxyProtocolEnabled,
		"public_listener_proxy_protocol_trusted_cidrs":        config.ServerProxyProtocolTrustedCIDRs,
		"admin_listener_enabled":                              adminListenerEnabled,
		"admin_listener_addr":                                 config.AdminListenAddr,
		"admin_listener_transport":                            "http",
		"admin_listener_builtin_tls":                          false,
		"admin_listener_proxy_protocol_enabled":               config.AdminProxyProtocolEnabled,
		"admin_listener_proxy_protocol_trusted_cidrs":         config.AdminProxyProtocolTrustedCIDRs,
		"request_country_configured_mode":                     requestCountryStatus.ConfiguredMode,
		"request_country_effective_mode":                      requestCountryStatus.EffectiveMode,
		"request_country_managed_path":                        requestCountryStatus.ManagedPath,
		"request_country_loaded":                              requestCountryStatus.Loaded,
		"request_country_db_size_bytes":                       requestCountryStatus.DBSizeBytes,
		"request_country_db_mod_time":                         requestCountryStatus.DBModTime,
		"request_country_last_error":                          requestCountryStatus.LastError,
		"server_read_timeout_sec":                             int(config.ServerReadTimeout / time.Second),
		"server_read_header_timeout_sec":                      int(config.ServerReadHeaderTimeout / time.Second),
		"server_write_timeout_sec":                            int(config.ServerWriteTimeout / time.Second),
		"server_idle_timeout_sec":                             int(config.ServerIdleTimeout / time.Second),
		"server_max_header_bytes":                             config.ServerMaxHeaderBytes,
		"server_max_concurrent_requests":                      config.ServerMaxConcurrentReqs,
		"server_max_queued_requests":                          globalOverload.QueueCapacity,
		"server_queued_request_timeout_ms":                    globalOverload.QueueTimeoutMS,
		"server_max_concurrent_proxy_requests":                config.ServerMaxConcurrentProxy,
		"server_max_queued_proxy_requests":                    proxyOverload.QueueCapacity,
		"server_queued_proxy_request_timeout_ms":              proxyOverload.QueueTimeoutMS,
		"server_overload_global":                              globalOverload,
		"server_overload_proxy":                               proxyOverload,
		"server_tls_enabled":                                  config.ServerTLSEnabled,
		"server_tls_source":                                   serverTLSStatus.Source,
		"server_tls_cert_file":                                config.ServerTLSCertFile,
		"server_tls_key_configured":                           strings.TrimSpace(config.ServerTLSKeyFile) != "",
		"server_tls_min_version":                              config.ServerTLSMinVersion,
		"server_tls_redirect_http":                            config.ServerTLSRedirectHTTP,
		"server_tls_http_redirect_addr":                       config.ServerTLSHTTPRedirectAddr,
		"server_tls_cert_not_after":                           serverTLSStatus.CertNotAfter,
		"server_tls_last_error":                               serverTLSStatus.LastError,
		"server_tls_acme_enabled":                             config.ServerTLSACMEEnabled,
		"server_tls_acme_domains":                             config.ServerTLSACMEDomains,
		"server_tls_acme_staging":                             config.ServerTLSACMEStaging,
		"server_tls_acme_success_total":                       serverTLSStatus.ACMESuccessTotal,
		"server_tls_acme_failure_total":                       serverTLSStatus.ACMEFailureTotal,
		"server_http3_enabled":                                config.ServerHTTP3Enabled,
		"server_http3_advertised":                             serverHTTP3Status.Advertised,
		"server_http3_alt_svc_max_age_sec":                    config.ServerHTTP3AltSvcMaxAgeSec,
		"server_http3_alt_svc":                                serverHTTP3Status.AltSvc,
		"server_http3_last_error":                             serverHTTP3Status.LastError,
		"runtime_gomaxprocs":                                  config.RuntimeGOMAXPROCS,
		"runtime_memory_limit_mb":                             config.RuntimeMemoryLimitMB,
		"proxy_config_file":                                   config.ProxyConfigFile,
		"proxy_engine_mode":                                   normalizeProxyEngineMode(config.ProxyEngineMode),
		"waf_engine_mode":                                     normalizeSettingsWAFEngineMode(config.WAFEngineMode),
		"proxy_etag":                                          proxyETag,
		"proxy_dial_timeout":                                  proxyCfg.DialTimeout,
		"proxy_response_header_timeout":                       proxyCfg.ResponseHeaderTimeout,
		"proxy_idle_conn_timeout":                             proxyCfg.IdleConnTimeout,
		"proxy_upstream_keepalive_sec":                        proxyCfg.UpstreamKeepAliveSec,
		"proxy_max_idle_conns":                                proxyCfg.MaxIdleConns,
		"proxy_max_idle_conns_per_host":                       proxyCfg.MaxIdleConnsPerHost,
		"proxy_max_conns_per_host":                            proxyCfg.MaxConnsPerHost,
		"proxy_force_http2":                                   proxyCfg.ForceHTTP2,
		"proxy_h2c_upstream":                                  proxyCfg.H2CUpstream,
		"proxy_upstream_http2_mode":                           proxyUpstreamHTTP2Mode(proxyCfg),
		"proxy_disable_compression":                           proxyCfg.DisableCompression,
		"proxy_response_compression_enabled":                  proxyCfg.ResponseCompression.Enabled,
		"proxy_response_compression_algorithms":               proxyCfg.ResponseCompression.Algorithms,
		"proxy_response_compression_min_bytes":                proxyCfg.ResponseCompression.MinBytes,
		"proxy_response_compression_mime_types":               proxyCfg.ResponseCompression.MIMETypes,
		"proxy_response_compression_compressed_total":         proxyCompressionStatus.CompressedTotal,
		"proxy_response_compression_compressed_by_algorithm":  proxyCompressionStatus.CompressedByAlgorithm,
		"proxy_response_compression_bytes_in_total":           proxyCompressionStatus.CompressedBytesIn,
		"proxy_response_compression_bytes_out_total":          proxyCompressionStatus.CompressedBytesOut,
		"proxy_response_compression_skipped_client_total":     proxyCompressionStatus.SkippedClientTotal,
		"proxy_response_compression_skipped_encoded_total":    proxyCompressionStatus.SkippedEncodedTotal,
		"proxy_response_compression_skipped_bodyless_total":   proxyCompressionStatus.SkippedBodylessTotal,
		"proxy_response_compression_skipped_small_total":      proxyCompressionStatus.SkippedSmallTotal,
		"proxy_response_compression_skipped_mime_total":       proxyCompressionStatus.SkippedMimeTotal,
		"proxy_response_compression_skipped_transform_total":  proxyCompressionStatus.SkippedTransformTotal,
		"proxy_response_compression_skipped_upgrade_total":    proxyCompressionStatus.SkippedUpgradeTotal,
		"proxy_expect_continue_timeout":                       proxyCfg.ExpectContinueTimeout,
		"proxy_tls_insecure_skip_verify":                      proxyCfg.TLSInsecureSkipVerify,
		"proxy_tls_client_cert":                               proxyCfg.TLSClientCert,
		"proxy_tls_client_key":                                proxyCfg.TLSClientKey,
		"proxy_retry_attempts":                                proxyCfg.RetryAttempts,
		"proxy_retry_backoff_ms":                              proxyCfg.RetryBackoffMS,
		"proxy_retry_per_try_timeout_ms":                      proxyCfg.RetryPerTryTimeoutMS,
		"proxy_retry_status_codes":                            proxyCfg.RetryStatusCodes,
		"proxy_retry_methods":                                 proxyCfg.RetryMethods,
		"proxy_passive_health_enabled":                        proxyCfg.PassiveHealthEnabled,
		"proxy_passive_failure_threshold":                     proxyCfg.PassiveFailureThreshold,
		"proxy_passive_unhealthy_status_codes":                proxyCfg.PassiveUnhealthyStatusCodes,
		"proxy_circuit_breaker_enabled":                       proxyCfg.CircuitBreakerEnabled,
		"proxy_circuit_breaker_open_sec":                      proxyCfg.CircuitBreakerOpenSec,
		"proxy_circuit_breaker_half_open_requests":            proxyCfg.CircuitBreakerHalfOpenRequests,
		"proxy_buffer_request_body":                           proxyCfg.BufferRequestBody,
		"proxy_max_response_buffer_bytes":                     proxyCfg.MaxResponseBufferBytes,
		"proxy_flush_interval_ms":                             proxyCfg.FlushIntervalMS,
		"proxy_health_check_path":                             proxyCfg.HealthCheckPath,
		"proxy_health_check_interval_sec":                     proxyCfg.HealthCheckInterval,
		"proxy_health_check_timeout_sec":                      proxyCfg.HealthCheckTimeout,
		"proxy_error_html_file":                               proxyCfg.ErrorHTMLFile,
		"proxy_error_redirect_url":                            proxyCfg.ErrorRedirectURL,
		"proxy_rollback_depth":                                proxyRollbackDepth,
		"upstream_health_enabled":                             proxyHealth.Enabled,
		"upstream_health_status":                              proxyHealth.Status,
		"upstream_health_strategy":                            proxyHealth.Strategy,
		"upstream_health_endpoint":                            proxyHealth.Endpoint,
		"upstream_health_checked_at":                          proxyHealth.CheckedAt,
		"upstream_health_last_success_at":                     proxyHealth.LastSuccessAt,
		"upstream_health_last_failure_at":                     proxyHealth.LastFailureAt,
		"upstream_health_consecutive_failures":                proxyHealth.ConsecutiveFailures,
		"upstream_health_last_error":                          proxyHealth.LastError,
		"upstream_health_last_status_code":                    proxyHealth.LastStatusCode,
		"upstream_health_last_latency_ms":                     proxyHealth.LastLatencyMS,
		"upstream_health_active_backends":                     proxyHealth.ActiveBackends,
		"upstream_health_healthy_backends":                    proxyHealth.HealthyBackends,
		"upstream_health_backends":                            proxyHealth.Backends,
		"proxy_upstreams":                                     proxyCfg.Upstreams,
		"proxy_load_balancing_strategy":                       proxyCfg.LoadBalancingStrategy,
		"cache_store_enabled":                                 responseCacheCfg.Enabled,
		"cache_store_dir":                                     responseCacheCfg.StoreDir,
		"cache_max_bytes":                                     responseCacheCfg.MaxBytes,
		"cache_memory_enabled":                                responseCacheCfg.MemoryEnabled,
		"cache_memory_max_bytes":                              responseCacheCfg.MemoryMaxBytes,
		"cache_memory_max_entries":                            responseCacheCfg.MemoryMaxEntries,
		"cache_size_bytes":                                    responseCacheStats.SizeBytes,
		"cache_entry_count":                                   responseCacheStats.EntryCount,
		"cache_hits_total":                                    responseCacheStats.Hits,
		"cache_misses_total":                                  responseCacheStats.Misses,
		"cache_stores_total":                                  responseCacheStats.Stores,
		"cache_evictions_total":                               responseCacheStats.Evictions,
		"cache_clears_total":                                  responseCacheStats.Clears,
		"cache_memory_size_bytes":                             responseCacheStats.MemorySizeBytes,
		"cache_memory_entry_count":                            responseCacheStats.MemoryEntryCount,
		"cache_memory_hits_total":                             responseCacheStats.MemoryHits,
		"cache_memory_misses_total":                           responseCacheStats.MemoryMisses,
		"cache_memory_stores_total":                           responseCacheStats.MemoryStores,
		"cache_memory_evictions_total":                        responseCacheStats.MemoryEvictions,
		"crs_enabled":                                         config.CRSEnable,
		"crs_setup_file":                                      config.CRSSetupFile,
		"crs_rules_dir":                                       config.CRSRulesDir,
		"crs_disabled_file":                                   config.CRSDisabledFile,
		"db_driver":                                           config.DBDriver,
		"db_dsn_configured":                                   strings.TrimSpace(config.DBDSN) != "",
		"db_path":                                             config.DBPath,
		"db_retention_days":                                   config.DBRetentionDays,
		"db_sync_interval_sec":                                int(config.DBSyncInterval / time.Second),
		"db_sync_loop_enabled":                                config.DBSyncInterval > 0,
		"db_total_rows":                                       dbTotalRows,
		"db_waf_block_rows":                                   dbWAFBlockRows,
		"db_size_bytes":                                       dbSizeBytes,
		"db_last_ingest_offset":                               dbLastIngestOffset,
		"db_last_ingest_mod_time":                             dbLastIngestModTime,
		"db_last_sync_scanned_lines":                          dbLastSyncScannedLines,
		"db_status_error":                                     dbStatusError,
		"allow_insecure_defaults":                             config.AllowInsecureDefaults,
	})
}

func RulesHandler(c *gin.Context) {
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	assets, assetRec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		respondConfigBlobDBError(c, "rules db read failed", err)
		return
	}
	if !found {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "active waf rule assets missing in db; run make crs-install before editing rule assets"})
		return
	}

	editable := editableWAFRuleAssets(assets)
	result := make(map[string]string, len(editable))
	out := make([]gin.H, 0, len(editable))
	for i, asset := range editable {
		etag := strings.TrimSpace(asset.ETag)
		if etag == "" {
			etag = bypassconf.ComputeETag(asset.Raw)
		}
		if asset.Kind == wafRuleAssetKindBase {
			result[asset.Path] = string(asset.Raw)
		}
		out = append(out, gin.H{
			"path":     asset.Path,
			"kind":     asset.Kind,
			"position": i,
			"raw":      string(asset.Raw),
			"etag":     etag,
			"usage":    wafRuleAssetUsageLabel(asset.Kind),
			"saved_at": wafRuleAssetSavedAt(assetRec, asset.Path),
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"rules": result,
		"files": out,
	})
}

type rulesPutBody struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
	Raw  string `json:"raw"`
}

func ValidateRules(c *gin.Context) {
	var in rulesPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	kind, target, err := normalizeRulesRequestTarget(in.Path, in.Kind)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := validateRuleAssetRaw(kind, target, []byte(in.Raw)); err != nil {
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

	kind, target, err := normalizeRulesRequestTarget(in.Path, in.Kind)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if _, err := requireConfigDBStore(); err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	curRaw, curETag, domainETag, _, err := loadEditableWAFRuleAssetForKind(target, kind)
	existed := err == nil
	if err != nil && !strings.Contains(err.Error(), "not found") {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := validateRuleAssetRaw(kind, target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	rec, asset, err := writeWAFRuleAssetUpdateForKind(target, kind, []byte(in.Raw), domainETag, ruleAssetWriteReason(kind))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	hotReloaded := false
	if kind == wafRuleAssetKindBase {
		if err := waf.ReloadBaseWAF(); err != nil {
			if existed {
				_, _, _ = writeWAFRuleAssetUpdateForKind(target, kind, curRaw, rec.ETag, "base rule rollback after reload failure")
			} else {
				_, _ = deleteWAFRuleAssetForKind(target, kind, rec.ETag, "base rule create rollback after reload failure")
			}
			_ = waf.ReloadBaseWAF()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": fmt.Sprintf("reload failed and rollback applied: %v", err),
			})
			return
		}
		hotReloaded = true
	} else if kind == wafRuleAssetKindBypassExtra {
		waf.InvalidateOverrideWAF(target)
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          asset.ETag,
		"kind":          kind,
		"path":          target,
		"hot_reloaded":  hotReloaded,
		"reloaded_file": target,
		"saved_at":      configVersionSavedAt(rec),
	})
}

type rulesDeleteQuery struct {
	Path string `form:"path"`
	Kind string `form:"kind"`
}

func DeleteRuleAsset(c *gin.Context) {
	var in rulesDeleteQuery
	if err := c.ShouldBindQuery(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	kind, target, err := normalizeRulesRequestTarget(in.Path, in.Kind)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if kind == wafRuleAssetKindBypassExtra {
		if inUseBy, inUse := managedOverrideRuleInUse(target); inUse {
			c.JSON(http.StatusConflict, gin.H{
				"error":  "rule asset is still referenced by bypass rules",
				"path":   target,
				"in_use": inUseBy,
			})
			return
		}
	}
	curRaw, _, domainETag, _, err := loadEditableWAFRuleAssetForKind(target, kind)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	rec, err := deleteWAFRuleAssetForKind(target, kind, domainETag, ruleAssetDeleteReason(kind))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if kind == wafRuleAssetKindBase {
		if err := waf.ReloadBaseWAF(); err != nil {
			_, _, _ = writeWAFRuleAssetUpdateForKind(target, kind, curRaw, rec.ETag, "base rule delete rollback after reload failure")
			_ = waf.ReloadBaseWAF()
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("reload failed and rollback applied: %v", err)})
			return
		}
	} else {
		waf.InvalidateOverrideWAF(target)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "path": target, "kind": kind, "deleted": true, "saved_at": configVersionSavedAt(rec)})
}

type rulesOrderBody struct {
	Files  []rulesOrderItem `json:"files"`
	Assets []rulesOrderItem `json:"assets"`
}

type rulesOrderItem struct {
	Path string `json:"path"`
	Kind string `json:"kind"`
}

func PutRuleAssetOrder(c *gin.Context) {
	var in rulesOrderBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	order := in.Assets
	if len(order) == 0 {
		order = in.Files
	}
	if len(order) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "rule asset order is empty"})
		return
	}
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	current, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !found {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "active waf rule assets missing in db; run make crs-install before editing rule assets"})
		return
	}
	previous := editableWAFRuleAssets(current)
	nextOrder := make([]wafRuleAssetVersion, 0, len(order))
	for _, item := range order {
		kind, target, err := normalizeRulesRequestTarget(item.Path, item.Kind)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		nextOrder = append(nextOrder, wafRuleAssetVersion{Path: target, Kind: kind})
	}
	nextRec, nextAssets, err := reorderEditableWAFRuleAssets(nextOrder, rec.ETag, "rule asset order update")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		_, _, _ = reorderEditableWAFRuleAssets(previous, nextRec.ETag, "rule asset order rollback after reload failure")
		_ = waf.ReloadBaseWAF()
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("reload failed and rollback applied: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":           true,
		"files":        ruleAssetResponseFiles(nextAssets, nextRec),
		"hot_reloaded": true,
		"saved_at":     configVersionSavedAt(nextRec),
	})
}

func configuredRuleFiles() []string {
	parts := strings.Split(config.RulesFile, ",")
	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, p := range parts {
		p = config.NormalizeBaseRuleAssetPath(p)
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
	target := config.NormalizeBaseRuleAssetPath(path)
	if target == "" {
		return "", fmt.Errorf("path is empty")
	}
	for _, p := range configuredRuleFiles() {
		if config.NormalizeBaseRuleAssetPath(p) == target {
			return p, nil
		}
	}
	return "", fmt.Errorf("path is not editable: %s", path)
}

func normalizeRulesRequestTarget(path string, kind string) (string, string, error) {
	normalizedKind, err := normalizeEditableWAFRuleAssetKind(kind)
	if err != nil {
		return "", "", err
	}
	target, err := normalizeWAFRuleAssetPathForKind(path, normalizedKind)
	if err != nil {
		return "", "", err
	}
	if normalizedKind == wafRuleAssetKindBase && isUnsafeLogicalRuleAssetPath(target) {
		return "", "", fmt.Errorf("base rule asset path must stay within the rule asset namespace: %s", path)
	}
	return normalizedKind, target, nil
}

func isUnsafeLogicalRuleAssetPath(path string) bool {
	path = filepath.ToSlash(filepath.Clean(strings.TrimSpace(path)))
	return filepath.IsAbs(path) || path == ".." || strings.HasPrefix(path, "../")
}

func validateRuleAssetRaw(kind string, target string, raw []byte) error {
	switch kind {
	case wafRuleAssetKindBase:
		return waf.ValidateWithRuleOverride(target, raw)
	case wafRuleAssetKindBypassExtra:
		return waf.ValidateStandaloneRule(target, raw)
	default:
		return fmt.Errorf("unsupported editable rule asset kind: %s", kind)
	}
}

func wafRuleAssetUsageLabel(kind string) string {
	switch kind {
	case wafRuleAssetKindBypassExtra:
		return "Bypass Rules extra_rule"
	default:
		return "Base WAF rule set"
	}
}

func ruleAssetWriteReason(kind string) string {
	if kind == wafRuleAssetKindBypassExtra {
		return "bypass extra rule update"
	}
	return "base rule update"
}

func ruleAssetDeleteReason(kind string) string {
	if kind == wafRuleAssetKindBypassExtra {
		return "bypass extra rule delete"
	}
	return "base rule delete"
}

func ruleAssetResponseFiles(assets []wafRuleAssetVersion, rec configVersionRecord) []gin.H {
	editable := editableWAFRuleAssets(assets)
	out := make([]gin.H, 0, len(editable))
	for i, asset := range editable {
		etag := strings.TrimSpace(asset.ETag)
		if etag == "" {
			etag = bypassconf.ComputeETag(asset.Raw)
		}
		out = append(out, gin.H{
			"path":     asset.Path,
			"kind":     asset.Kind,
			"position": i,
			"raw":      string(asset.Raw),
			"etag":     etag,
			"usage":    wafRuleAssetUsageLabel(asset.Kind),
			"saved_at": wafRuleAssetSavedAt(rec, asset.Path),
		})
	}
	return out
}
