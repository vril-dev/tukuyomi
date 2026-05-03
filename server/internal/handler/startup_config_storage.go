package handler

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/configbundle"
	"tukuyomi/internal/edgeconfigsnapshot"
	"tukuyomi/internal/storagesync"
)

const (
	appConfigBlobKey               = "app_config"
	proxyRulesConfigBlobKey        = "proxy_rules"
	startupSeedConfDefaultDir      = "seeds/conf"
	startupSeedConfDirEnv          = "WAF_DB_IMPORT_SEED_CONF_DIR"
	startupSeedBundleFileEnv       = "WAF_DB_IMPORT_SEED_BUNDLE_FILE"
	startupProxySeedName           = "proxy.json"
	startupSitesSeedName           = "sites.json"
	startupPHPRuntimeSeedName      = "php-runtime-inventory.json"
	startupPSGIRuntimeSeedName     = "psgi-runtime-inventory.json"
	startupVhostsSeedName          = "vhosts.json"
	startupScheduledTasksSeedName  = "scheduled-tasks.json"
	startupUpstreamRuntimeSeedName = "upstream-runtime.json"
	startupCRSDisabledSeedName     = "crs-disabled.conf"
	startupResponseCacheSeedName   = "cache-store.json"
)

var storageSyncRunner = storagesync.NewRunner([]storagesync.Task{
	{Name: "sites", Run: SyncSiteStorage},
	{Name: "scheduled-tasks", Run: SyncScheduledTaskStorage},
	{Name: "upstream-runtime", Run: SyncUpstreamRuntimeStorage},
	{Name: "rules", Run: SyncRuleFilesStorage},
	{Name: "override-rules", Run: SyncManagedOverrideRulesStorage},
	{Name: "crs-disabled", Run: SyncCRSDisabledStorage},
	{Name: "bypass", Run: SyncBypassStorage},
	{Name: "country-block", Run: SyncCountryBlockStorage},
	{Name: "rate-limit", Run: SyncRateLimitStorage},
	{Name: "notifications", Run: SyncNotificationStorage},
	{Name: "bot-defense", Run: SyncBotDefenseStorage},
	{Name: "semantic", Run: SyncSemanticStorage},
	{Name: "cache-rules", Run: SyncCacheRulesStorage},
	{Name: "cache-store", Run: SyncResponseCacheStoreStorage},
})

func DBStorageActive() bool {
	return getLogsStatsStore() != nil
}

func SyncAllStorageFromDB() error {
	return storageSyncRunner.Sync()
}

func StartStorageSyncLoop(interval time.Duration) {
	storagesync.StartLoop(interval, SyncAllStorageFromDB, func(err error) {
		log.Printf("[DB][SYNC][WARN] periodic sync failed: %v", err)
	})
}

func SyncAppConfigStorage() error {
	_, _, cfg, err := loadAppConfigStorage(true)
	if err != nil {
		return err
	}
	return config.ApplyAppConfigFile(cfg)
}

func ImportStartupConfigStorage() error {
	if err := importAdminUsersSeedStorage(); err != nil {
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
	if err := importPSGIRuntimeInventoryStorage(); err != nil {
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

func importRequestCountryStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
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
	raw, hadFile, err := readStartupSeedFile(config.ProxyConfigFile, startupProxySeedName)
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
	raw, _, err := readStartupSeedFile(path, startupSitesSeedName)
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
	raw, _, err := readStartupSeedFile(path, startupVhostsSeedName)
	if err != nil {
		return fmt.Errorf("read Runtime Apps seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultVhostConfigRaw
	}
	prepared, err := prepareVhostConfigRawWithInventories(rawText, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
	if err != nil {
		return fmt.Errorf("validate Runtime Apps seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writeVhostConfigVersion("", prepared.cfg, configVersionSourceImport, "", "Runtime Apps seed import", 0); err != nil {
		return fmt.Errorf("import normalized Runtime Apps config: %w", err)
	}
	return nil
}

func importPHPRuntimeInventoryStorage() error {
	path := strings.TrimSpace(config.PHPRuntimeInventoryFile)
	if path == "" {
		path = "data/php-fpm/inventory.json"
	}
	raw, _, err := readStartupSeedFile(path, startupPHPRuntimeSeedName)
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

func importPSGIRuntimeInventoryStorage() error {
	path := strings.TrimSpace(config.PSGIRuntimeInventoryFile)
	if path == "" {
		path = "data/psgi/inventory.json"
	}
	raw, _, err := readStartupSeedFile(path, startupPSGIRuntimeSeedName)
	if err != nil {
		return fmt.Errorf("read psgi runtime inventory seed file: %w", err)
	}
	rawText := string(raw)
	if strings.TrimSpace(rawText) == "" {
		rawText = defaultPSGIRuntimeInventoryRaw
	}
	prepared, err := preparePSGIRuntimeInventoryRaw(rawText, path)
	if err != nil {
		return fmt.Errorf("validate psgi runtime inventory seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, err := store.writePSGIRuntimeInventoryPreparedConfigVersion("", prepared, configVersionSourceImport, "", "psgi runtime inventory seed import", 0); err != nil {
		return fmt.Errorf("import normalized psgi runtime inventory config: %w", err)
	}
	return nil
}

func importScheduledTaskConfigStorage() error {
	path := strings.TrimSpace(config.ScheduledTaskConfigFile)
	if path == "" {
		path = defaultScheduledTaskConfigPath
	}
	raw, _, err := readStartupSeedFile(path, startupScheduledTasksSeedName)
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
	raw, _, err := readStartupSeedFile(path, startupUpstreamRuntimeSeedName)
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
	raw, hadFile, err := readStartupSeedFile(path, startupPolicySeedName(domain))
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
	raw, _, err := readStartupSeedFile(config.CRSDisabledFile, startupCRSDisabledSeedName)
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
	rules, _, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil || !found {
		return err
	}
	return migrateManagedOverrideRulesToWAFRuleAssets(store, rules)
}

func importResponseCacheConfigStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	raw, _, err := readStartupSeedFile(config.CacheStoreFile, startupResponseCacheSeedName)
	if err != nil {
		return fmt.Errorf("read response cache seed file: %w", err)
	}
	var prepared preparedResponseCacheConfig
	if strings.TrimSpace(string(raw)) == "" {
		prepared, err = defaultPreparedResponseCacheConfig()
		if err != nil {
			return fmt.Errorf("prepare default response cache config: %w", err)
		}
	} else {
		prepared, err = prepareResponseCacheRaw(string(raw))
		if err != nil {
			return fmt.Errorf("validate response cache seed file: %w", err)
		}
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

func startupSeedConfDir() string {
	if raw, ok := os.LookupEnv(startupSeedConfDirEnv); ok {
		return strings.TrimSpace(raw)
	}
	return startupSeedConfDefaultDir
}

func startupSeedBundlePath() (string, bool) {
	if raw, ok := os.LookupEnv(startupSeedBundleFileEnv); ok {
		return strings.TrimSpace(raw), true
	}
	seedDir := startupSeedConfDir()
	if seedDir == "" {
		return "", false
	}
	return filepath.Join(seedDir, configbundle.DefaultName), false
}

func readStartupSeedFile(primaryPath string, seedName string) ([]byte, bool, error) {
	primaryPath = strings.TrimSpace(primaryPath)
	if primaryPath != "" {
		raw, hadFile, err := readFileMaybe(primaryPath)
		if err != nil {
			return nil, false, err
		}
		if hadFile && strings.TrimSpace(string(raw)) != "" {
			return raw, true, nil
		}
		seedRaw, seedFound, err := readStartupSeedConfFile(seedName)
		if err != nil || seedFound {
			return seedRaw, seedFound, err
		}
		return raw, hadFile, nil
	}
	return readStartupSeedConfFile(seedName)
}

func readStartupSeedConfFile(seedName string) ([]byte, bool, error) {
	seedName = filepath.Clean(strings.TrimSpace(seedName))
	if seedName == "." || seedName == "" {
		return []byte{}, false, nil
	}
	if seedName == ".." || filepath.IsAbs(seedName) || strings.HasPrefix(filepath.ToSlash(seedName), "../") {
		return nil, false, fmt.Errorf("invalid bundled seed name %q", seedName)
	}
	if raw, found, err := readStartupSeedBundleSeed(seedName); err != nil || found {
		return raw, found, err
	}
	seedDir := startupSeedConfDir()
	if seedDir == "" {
		return []byte{}, false, nil
	}
	raw, hadFile, err := readFileMaybe(filepath.Join(seedDir, seedName))
	if err != nil {
		return nil, false, err
	}
	if hadFile && strings.TrimSpace(string(raw)) != "" {
		return raw, true, nil
	}
	return []byte{}, false, nil
}

func readStartupSeedBundleSeed(seedName string) ([]byte, bool, error) {
	if _, ok := configbundle.DomainForLegacySeed(seedName); !ok {
		return nil, false, nil
	}
	path, explicit := startupSeedBundlePath()
	if path == "" {
		return nil, false, nil
	}
	raw, hadFile, err := readFileMaybe(path)
	if err != nil {
		return nil, false, err
	}
	if !hadFile {
		if explicit {
			return nil, false, fmt.Errorf("configured seed bundle file not found: %s", path)
		}
		return nil, false, nil
	}
	if strings.TrimSpace(string(raw)) == "" {
		return nil, false, nil
	}
	bundle, err := configbundle.Decode(raw)
	if err != nil {
		return nil, false, err
	}
	return bundle.LegacySeedRaw(seedName)
}

func BuildRuntimeConfigBundleExport() ([]byte, error) {
	store := getLogsStatsStore()
	if store == nil {
		return nil, errConfigDBStoreRequired
	}
	bundle := configbundle.New("gateway-status-export", time.Now().UTC())

	appRaw, _, _, err := loadAppConfigStorage(false)
	if err != nil {
		return nil, fmt.Errorf("read app config: %w", err)
	}
	redactedApp, _, err := edgeconfigsnapshot.RedactAppConfigRaw(appRaw)
	if err != nil {
		return nil, fmt.Errorf("redact app config: %w", err)
	}
	if err := configbundle.SetBootstrapAppConfigRaw(&bundle, redactedApp); err != nil {
		return nil, err
	}

	proxyCfg, _, found, err := store.loadActiveProxyConfig()
	if err != nil {
		return nil, fmt.Errorf("read proxy config: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active proxy config missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainProxy, []byte(mustJSON(proxyCfg))); err != nil {
		return nil, err
	}
	siteCfg, _, found, err := store.loadActiveSiteConfig()
	if err != nil {
		return nil, fmt.Errorf("read sites config: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active sites config missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainSites, []byte(mustJSON(siteCfg))); err != nil {
		return nil, err
	}
	phpRuntime, _, found, err := store.loadActivePHPRuntimeInventoryPreparedConfig(currentPHPRuntimeInventoryPath())
	if err != nil {
		return nil, fmt.Errorf("read php runtime inventory: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active php runtime inventory missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainPHPRuntimeInventory, []byte(mustJSON(phpRuntime.cfg))); err != nil {
		return nil, err
	}
	psgiRuntime, _, found, err := store.loadActivePSGIRuntimeInventoryPreparedConfig(currentPSGIRuntimeInventoryPath())
	if err != nil {
		return nil, fmt.Errorf("read psgi runtime inventory: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active psgi runtime inventory missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainPSGIRuntimeInventory, []byte(mustJSON(psgiRuntime.cfg))); err != nil {
		return nil, err
	}
	vhostCfg, _, found, err := store.loadActiveVhostConfig()
	if err != nil {
		return nil, fmt.Errorf("read Runtime Apps config: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active Runtime Apps config missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainRuntimeApps, []byte(mustJSON(vhostCfg))); err != nil {
		return nil, err
	}
	scheduledCfg, _, found, err := store.loadActiveScheduledTaskConfig()
	if err != nil {
		return nil, fmt.Errorf("read scheduled tasks config: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active scheduled tasks config missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainScheduledTasks, []byte(mustJSON(scheduledCfg))); err != nil {
		return nil, err
	}
	upstreamCfg, _, found, err := store.loadActiveUpstreamRuntimeConfig(configuredManagedBackendKeys(proxyCfg))
	if err != nil {
		return nil, fmt.Errorf("read upstream runtime: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active upstream runtime config missing in db; run make db-import before exporting config bundle")
	}
	upstreamRaw, err := MarshalUpstreamRuntimeJSON(upstreamCfg)
	if err != nil {
		return nil, fmt.Errorf("marshal upstream runtime: %w", err)
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainUpstreamRuntime, upstreamRaw); err != nil {
		return nil, err
	}
	responseCacheCfg, _, found, err := store.loadActiveResponseCacheConfig()
	if err != nil {
		return nil, fmt.Errorf("read response cache config: %w", err)
	}
	if !found {
		return nil, fmt.Errorf("active response cache config missing in db; run make db-import before exporting config bundle")
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainCacheStore, []byte(mustJSON(responseCacheCfg))); err != nil {
		return nil, err
	}

	for _, item := range []struct {
		storeDomain  string
		bundleDomain string
	}{
		{cacheConfigBlobKey, configbundle.DomainCacheRules},
		{bypassConfigBlobKey, configbundle.DomainWAFBypass},
		{countryBlockConfigBlobKey, configbundle.DomainCountryBlock},
		{rateLimitConfigBlobKey, configbundle.DomainRateLimit},
		{botDefenseConfigBlobKey, configbundle.DomainBotDefense},
		{semanticConfigBlobKey, configbundle.DomainSemantic},
		{notificationConfigBlobKey, configbundle.DomainNotifications},
		{ipReputationConfigBlobKey, configbundle.DomainIPReputation},
	} {
		raw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(item.storeDomain))
		if err != nil {
			return nil, fmt.Errorf("read %s config: %w", item.storeDomain, err)
		}
		if !found {
			return nil, fmt.Errorf("active %s config missing in db; run make db-import before exporting config bundle", item.storeDomain)
		}
		if err := addRuntimeConfigBundleDomain(&bundle, item.bundleDomain, raw); err != nil {
			return nil, err
		}
	}

	names, _, found, err := store.loadActiveCRSDisabledConfig()
	if err != nil {
		return nil, fmt.Errorf("read crs disabled config: %w", err)
	}
	if !found {
		names = nil
	}
	crsRaw, err := json.Marshal(names)
	if err != nil {
		return nil, err
	}
	if err := addRuntimeConfigBundleDomain(&bundle, configbundle.DomainCRSDisabled, crsRaw); err != nil {
		return nil, err
	}

	return configbundle.Marshal(bundle)
}

func addRuntimeConfigBundleDomain(bundle *configbundle.Bundle, domain string, raw []byte) error {
	raw = redactRuntimeConfigBundleDomain(domain, raw)
	if err := configbundle.SetDomainRaw(bundle, domain, raw); err != nil {
		return fmt.Errorf("add config bundle domain %s: %w", domain, err)
	}
	return nil
}

func redactRuntimeConfigBundleDomain(domain string, raw []byte) []byte {
	if strings.TrimSpace(domain) != configbundle.DomainProxy || len(raw) == 0 || !json.Valid(raw) {
		return raw
	}
	var obj any
	if err := json.Unmarshal(raw, &obj); err != nil {
		return raw
	}
	redactNamedJSONFields(obj, map[string]struct{}{
		"hash_key":       {},
		"tls_client_key": {},
		"client_key":     {},
	})
	out, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return raw
	}
	return append(out, '\n')
}

func redactNamedJSONFields(v any, names map[string]struct{}) {
	switch obj := v.(type) {
	case map[string]any:
		for key, value := range obj {
			if _, ok := names[key]; ok {
				if text, ok := value.(string); ok && strings.TrimSpace(text) != "" {
					obj[key] = "[redacted]"
					continue
				}
			}
			redactNamedJSONFields(value, names)
		}
	case []any:
		for _, item := range obj {
			redactNamedJSONFields(item, names)
		}
	}
}

func startupPolicySeedName(domain string) string {
	switch domain {
	case cacheConfigBlobKey:
		return "cache-rules.json"
	case bypassConfigBlobKey:
		return "waf-bypass.json"
	case countryBlockConfigBlobKey:
		return "country-block.json"
	case rateLimitConfigBlobKey:
		return "rate-limit.json"
	case botDefenseConfigBlobKey:
		return "bot-defense.json"
	case semanticConfigBlobKey:
		return "semantic.json"
	case notificationConfigBlobKey:
		return "notifications.json"
	case ipReputationConfigBlobKey:
		return "ip-reputation.json"
	default:
		return ""
	}
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
