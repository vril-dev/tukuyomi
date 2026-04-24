package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	appConfigBlobKey        = "app_config"
	proxyRulesConfigBlobKey = "proxy_rules"
)

func SyncAppConfigStorage() error {
	_, _, cfg, err := loadAppConfigStorage(true)
	if err != nil {
		return err
	}
	return config.ApplyAppConfigFile(cfg)
}

func ImportStartupConfigStorage() error {
	if err := ImportWAFRuleAssetsStorage(); err != nil {
		return err
	}
	if err := importProxyRulesStorage(); err != nil {
		return err
	}
	if err := importSiteConfigStorage(); err != nil {
		return err
	}
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		return err
	}
	if err := importVhostConfigStorage(); err != nil {
		return err
	}
	if err := importScheduledTaskConfigStorage(); err != nil {
		return err
	}
	if err := importUpstreamRuntimeConfigStorage(); err != nil {
		return err
	}
	if err := importPolicyConfigStorage(); err != nil {
		return err
	}
	if err := importResponseCacheConfigStorage(); err != nil {
		return err
	}
	if err := importRequestCountryStorage(); err != nil {
		return err
	}
	if err := importAppConfigStorage(); err != nil {
		return err
	}
	return nil
}

func loadAppConfigStorage(seedIfMissing bool) (string, string, config.AppConfigFile, error) {
	_, bootstrapCfg, err := loadBootstrapAppConfig()
	if err != nil {
		return "", "", config.AppConfigFile{}, err
	}
	store := getLogsStatsStore()
	if store == nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("db store is not initialized")
	}

	cfg, rec, found, err := store.loadActiveAppConfig(bootstrapCfg)
	if err != nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("read normalized app_config from db: %w", err)
	}
	if found {
		raw, err := config.MarshalAppConfigFile(cfg)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
		return raw, rec.ETag, cfg, nil
	}

	if dbRaw, _, legacyFound, err := store.GetConfigBlob(appConfigBlobKey); err != nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("read legacy app_config db blob: %w", err)
	} else if legacyFound {
		candidate, err := config.DecodeAppConfigRaw(dbRaw)
		if err != nil {
			return "", "", config.AppConfigFile{}, fmt.Errorf("decode legacy app_config db blob: %w", err)
		}
		candidate, _, err = appConfigBlobRawFromCandidate(candidate, bootstrapCfg)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
		if err := ValidateRequestCountryRuntimeConfig(candidate); err != nil {
			return "", "", config.AppConfigFile{}, fmt.Errorf("validate legacy app_config request_metadata country mode: %w", err)
		}
		rec, cfg, err := store.writeAppConfigVersion("", candidate, bootstrapCfg, configVersionSourceImport, "", "legacy app config import", 0)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
		_ = store.DeleteConfigBlob(appConfigBlobKey)
		raw, err := config.MarshalAppConfigFile(cfg)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
		return raw, rec.ETag, cfg, nil
	}

	cfg, normalizedRaw, err := appConfigBlobRawFromCandidate(bootstrapCfg, bootstrapCfg)
	if err != nil {
		return "", "", config.AppConfigFile{}, err
	}
	etag := bypassconf.ComputeETag([]byte(normalizedRaw))
	if seedIfMissing {
		if err := ValidateRequestCountryRuntimeConfig(cfg); err != nil {
			return "", "", config.AppConfigFile{}, fmt.Errorf("validate app_config request_metadata country mode: %w", err)
		}
		rec, seededCfg, err := store.writeAppConfigVersion("", cfg, bootstrapCfg, configVersionSourceImport, "", "app config bootstrap import", 0)
		if err != nil {
			return "", "", config.AppConfigFile{}, fmt.Errorf("seed normalized app_config db: %w", err)
		}
		cfg = seededCfg
		etag = rec.ETag
		normalizedRaw, err = config.MarshalAppConfigFile(cfg)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
	}
	return normalizedRaw, etag, cfg, nil
}

func importAppConfigStorage() error {
	_, bootstrapCfg, err := loadBootstrapAppConfig()
	if err != nil {
		return err
	}
	if _, _, err := appConfigBlobRawFromCandidate(bootstrapCfg, bootstrapCfg); err != nil {
		return err
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if err := ValidateRequestCountryRuntimeConfig(bootstrapCfg); err != nil {
		return fmt.Errorf("validate app_config request_metadata country mode: %w", err)
	}
	if _, _, err := store.writeAppConfigVersion("", bootstrapCfg, bootstrapCfg, configVersionSourceImport, "", "app config seed import", 0); err != nil {
		return fmt.Errorf("import normalized app_config: %w", err)
	}
	_ = store.DeleteConfigBlob(appConfigBlobKey)
	return nil
}

func importProxyRulesStorage() error {
	raw, hadFile, err := readFileMaybe(config.ProxyConfigFile)
	if err != nil {
		return fmt.Errorf("read proxy seed file: %w", err)
	}
	rawText := startupProxySeedRaw(config.ProxyConfigFile, raw, hadFile)
	prepared, err := prepareProxyRulesRaw(rawText)
	if err != nil {
		return fmt.Errorf("validate proxy seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeProxyConfigVersion("", prepared.cfg, configVersionSourceImport, "", "proxy seed import", 0); err != nil {
		return fmt.Errorf("import normalized proxy config: %w", err)
	}
	_ = store.DeleteConfigBlob(proxyRulesConfigBlobKey)
	return nil
}

func hasStartupSeedPathSuffix(path string, suffix string) bool {
	path = strings.ToLower(filepath.ToSlash(strings.TrimSpace(path)))
	suffix = strings.ToLower(filepath.ToSlash(strings.TrimSpace(suffix)))
	if path == suffix {
		return true
	}
	return strings.HasSuffix(path, "/"+suffix)
}

func importSiteConfigStorage() error {
	path := strings.TrimSpace(config.SiteConfigFile)
	if path == "" {
		path = "conf/sites.json"
	}
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read sites seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultSiteConfigRaw
	}
	prepared, err := prepareSiteConfigRaw(rawText)
	if err != nil {
		return fmt.Errorf("validate sites seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeSiteConfigVersion("", prepared.cfg, configVersionSourceImport, "", "sites seed import", 0); err != nil {
		return fmt.Errorf("import normalized sites config: %w", err)
	}
	_ = store.DeleteConfigBlob(siteConfigBlobKey)
	return nil
}

func importVhostConfigStorage() error {
	path := strings.TrimSpace(config.VhostConfigFile)
	if path == "" {
		path = "data/php-fpm/vhosts.json"
	}
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read vhost seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultVhostConfigRaw
	}
	prepared, err := prepareVhostConfigRawWithInventory(rawText, currentPHPRuntimeInventoryConfig())
	if err != nil {
		return fmt.Errorf("validate vhost seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeVhostConfigVersion("", prepared.cfg, configVersionSourceImport, "", "vhost seed import", 0); err != nil {
		return fmt.Errorf("import normalized vhost config: %w", err)
	}
	return nil
}

func importPHPRuntimeInventoryStorage() error {
	path := strings.TrimSpace(config.PHPRuntimeInventoryFile)
	if path == "" {
		path = "data/php-fpm/inventory.json"
	}
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read php runtime inventory seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultPHPRuntimeInventoryRaw
	}
	prepared, err := preparePHPRuntimeInventoryRaw(rawText, path)
	if err != nil {
		return fmt.Errorf("validate php runtime inventory seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writePHPRuntimeInventoryPreparedConfigVersion("", prepared, configVersionSourceImport, "", "php runtime inventory seed import", 0); err != nil {
		return fmt.Errorf("import normalized php runtime inventory config: %w", err)
	}
	return nil
}

func importScheduledTaskConfigStorage() error {
	path := strings.TrimSpace(config.ScheduledTaskConfigFile)
	if path == "" {
		path = defaultScheduledTaskConfigPath
	}
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read scheduled tasks seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultScheduledTaskConfigRaw
	}
	prepared, err := prepareScheduledTaskConfigRaw(rawText, currentPHPRuntimeInventoryConfig())
	if err != nil {
		return fmt.Errorf("validate scheduled tasks seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeScheduledTaskConfigVersion("", prepared.cfg, configVersionSourceImport, "", "scheduled tasks seed import", 0); err != nil {
		return fmt.Errorf("import normalized scheduled tasks config: %w", err)
	}
	_ = store.DeleteConfigBlob(scheduledTaskConfigBlobKey)
	return nil
}

func importUpstreamRuntimeConfigStorage() error {
	path := managedUpstreamRuntimePath()
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read upstream runtime seed file: %w", err)
	}
	parsed, err := ParseUpstreamRuntimeRaw(string(raw))
	if err != nil {
		return fmt.Errorf("validate upstream runtime seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, _, err := store.writeUpstreamRuntimeConfigVersion("", parsed, configuredManagedBackendKeys(currentProxyConfig()), configVersionSourceImport, "", "upstream runtime seed import", 0); err != nil {
		return fmt.Errorf("import normalized upstream runtime config: %w", err)
	}
	_ = store.DeleteConfigBlob(upstreamRuntimeConfigBlobKey)
	return nil
}

func importPolicyConfigStorage() error {
	imports := []struct {
		domain    string
		path      string
		normalize func(string) ([]byte, error)
		reason    string
	}{
		{domain: cacheConfigBlobKey, path: config.ResolveReadablePolicyPath(configuredCacheRulesPath(), configuredLegacyCacheRulesPath()), normalize: normalizeCacheRulesPolicyRaw, reason: "cache rules seed import"},
		{domain: bypassConfigBlobKey, path: config.BypassFile, normalize: normalizeBypassPolicyRaw, reason: "bypass rules seed import"},
		{domain: countryBlockConfigBlobKey, path: config.CountryBlockFile, normalize: normalizeCountryBlockPolicyRaw, reason: "country block seed import"},
		{domain: rateLimitConfigBlobKey, path: config.RateLimitFile, normalize: normalizeRateLimitPolicyRaw, reason: "rate limit seed import"},
		{domain: botDefenseConfigBlobKey, path: config.BotDefenseFile, normalize: normalizeBotDefensePolicyRaw, reason: "bot defense seed import"},
		{domain: semanticConfigBlobKey, path: config.SemanticFile, normalize: normalizeSemanticPolicyRaw, reason: "semantic seed import"},
		{domain: notificationConfigBlobKey, path: config.NotificationFile, normalize: normalizeNotificationPolicyRaw, reason: "notification seed import"},
		{domain: ipReputationConfigBlobKey, path: config.IPReputationFile, normalize: normalizeIPReputationPolicyRaw, reason: "ip reputation seed import"},
	}
	for _, item := range imports {
		if err := importPolicyJSONStorage(item.domain, item.path, item.normalize, item.reason); err != nil {
			return err
		}
	}
	if err := importCRSDisabledStorage(); err != nil {
		return err
	}
	if err := importManagedOverrideRulesStorage(); err != nil {
		return err
	}
	return nil
}

func importPolicyJSONStorage(domain string, path string, normalize func(string) ([]byte, error), reason string) error {
	raw, hadFile, err := readFileMaybe(path)
	if err != nil {
		return fmt.Errorf("read %s seed file: %w", domain, err)
	}
	rawText, err := startupPolicySeedRaw(domain, raw, hadFile)
	if err != nil {
		return fmt.Errorf("build %s startup seed: %w", domain, err)
	}
	if strings.TrimSpace(rawText) == "" {
		return nil
	}
	normalized, err := normalize(rawText)
	if err != nil {
		return fmt.Errorf("validate %s seed file: %w", domain, err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	spec := mustPolicyJSONSpec(domain)
	if _, err := store.writePolicyJSONConfigVersion("", spec, normalized, configVersionSourceImport, "", reason, 0); err != nil {
		return fmt.Errorf("import normalized %s: %w", domain, err)
	}
	_ = store.DeleteConfigBlob(domain)
	return nil
}

func importCRSDisabledStorage() error {
	raw, _, err := readFileMaybe(config.CRSDisabledFile)
	if err != nil {
		return fmt.Errorf("read crs disabled seed file: %w", err)
	}
	names := crsDisabledNamesFromRaw(raw)
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeCRSDisabledConfigVersion("", names, configVersionSourceImport, "", "crs disabled seed import", 0); err != nil {
		return fmt.Errorf("import normalized crs disabled: %w", err)
	}
	_ = store.DeleteConfigBlob(crsDisabledConfigBlobKey)
	return nil
}

func importManagedOverrideRulesStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	_, _, _, err := loadRuntimeManagedOverrideRules(store)
	return err
}

func importResponseCacheConfigStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	prepared, err := defaultPreparedResponseCacheConfig()
	if err != nil {
		return fmt.Errorf("prepare default response cache config: %w", err)
	}
	if _, _, err := store.writeResponseCacheConfigVersion("", prepared.cfg, configVersionSourceImport, "", "response cache seed import", 0); err != nil {
		return fmt.Errorf("import normalized response cache config: %w", err)
	}
	_ = store.DeleteConfigBlob(responseCacheConfigBlobKey)
	return nil
}

func loadBootstrapAppConfig() ([]byte, config.AppConfigFile, error) {
	path := currentSettingsConfigPath()
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return nil, config.AppConfigFile{}, fmt.Errorf("read bootstrap config.json: %w", err)
	}
	cfg, err := config.LoadAppConfigFile(path)
	if err != nil {
		return nil, config.AppConfigFile{}, fmt.Errorf("load bootstrap config.json: %w", err)
	}
	applyEffectiveBootstrapDBConnection(&cfg)
	return raw, cfg, nil
}

func applyEffectiveBootstrapDBConnection(cfg *config.AppConfigFile) {
	if cfg == nil {
		return
	}
	if driver := strings.ToLower(strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_DRIVER"))); driver != "" {
		cfg.Storage.DBDriver = driver
	}
	if dsn := os.Getenv("WAF_STORAGE_DB_DSN"); strings.TrimSpace(dsn) != "" {
		cfg.Storage.DBDSN = dsn
	}
	if path := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_PATH")); path != "" {
		cfg.Storage.DBPath = path
	}
}

func appConfigBlobRawFromCandidate(candidate config.AppConfigFile, bootstrap config.AppConfigFile) (config.AppConfigFile, string, error) {
	preserveBootstrapDBConnection(&candidate, bootstrap)
	normalized, err := config.NormalizeAndValidateAppConfigFile(candidate)
	if err != nil {
		return config.AppConfigFile{}, "", err
	}
	raw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		return config.AppConfigFile{}, "", err
	}
	return normalized, raw, nil
}

func preserveBootstrapDBConnection(cfg *config.AppConfigFile, bootstrap config.AppConfigFile) {
	if cfg == nil {
		return
	}
	cfg.Storage.Backend = ""
	cfg.Storage.DBDriver = bootstrap.Storage.DBDriver
	cfg.Storage.DBDSN = bootstrap.Storage.DBDSN
	cfg.Storage.DBPath = bootstrap.Storage.DBPath
}

func marshalAppConfigBlob(cfg config.AppConfigFile) (string, error) {
	raw, err := config.MarshalAppConfigFile(cfg)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return "", err
	}
	if storage, ok := obj["storage"].(map[string]any); ok {
		delete(storage, "backend")
		delete(storage, "db_driver")
		delete(storage, "db_dsn")
		delete(storage, "db_path")
	}
	body, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}
