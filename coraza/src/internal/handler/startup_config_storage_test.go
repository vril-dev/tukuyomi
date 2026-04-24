package handler

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"tukuyomi/internal/config"
)

func TestImportStartupConfigStorageKeepsDBWAFRuleAssetsWithoutSeedFiles(t *testing.T) {
	restore := saveStartupConfigForTest()
	defer restore()

	tmp := t.TempDir()
	confDir := filepath.Join(tmp, "conf")
	dbPath := filepath.Join(tmp, "db", "tukuyomi.db")
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		t.Fatalf("mkdir db dir: %v", err)
	}
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("mkdir conf dir: %v", err)
	}
	configPath := filepath.Join(confDir, "config.json")
	configRaw := fmt.Sprintf(`{
  "storage": {
    "db_driver": "sqlite",
    "db_path": %q,
    "db_dsn": "",
    "db_retention_days": 30,
    "db_sync_interval_sec": 0
  }
}
`, dbPath)
	if err := os.WriteFile(configPath, []byte(configRaw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	missingRoot := filepath.Join(tmp, "missing")
	config.ConfigFile = configPath
	config.ProxyConfigFile = filepath.Join(missingRoot, "conf", "proxy.json")
	config.SiteConfigFile = filepath.Join(missingRoot, "sites.json")
	config.PHPRuntimeInventoryFile = filepath.Join(missingRoot, "inventory.json")
	config.VhostConfigFile = filepath.Join(missingRoot, "vhosts.json")
	config.ScheduledTaskConfigFile = filepath.Join(missingRoot, "scheduled-tasks.json")
	config.UpstreamRuntimeFile = filepath.Join(missingRoot, "upstream-runtime.json")
	config.CacheRulesFile = filepath.Join(missingRoot, "cache-rules.json")
	config.BypassFile = filepath.Join(missingRoot, "waf-bypass.json")
	config.CountryBlockFile = filepath.Join(missingRoot, "country-block.json")
	config.RateLimitFile = filepath.Join(missingRoot, "rate-limit.json")
	config.BotDefenseFile = filepath.Join(missingRoot, "bot-defense.json")
	config.SemanticFile = filepath.Join(missingRoot, "semantic.json")
	config.NotificationFile = filepath.Join(missingRoot, "notifications.json")
	config.IPReputationFile = filepath.Join(missingRoot, "ip-reputation.json")
	config.CRSDisabledFile = filepath.Join(missingRoot, "crs-disabled.conf")
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false

	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	const wafRaw = "SecRuleEngine On\n"
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: config.DefaultBaseRuleAssetPath,
		Kind: wafRuleAssetKindBase,
		Raw:  []byte(wafRaw),
	}}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("seed waf assets: %v", err)
	}

	if err := ImportStartupConfigStorage(); err != nil {
		t.Fatalf("import startup config storage: %v", err)
	}

	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("load waf rule assets found=%v err=%v", found, err)
	}
	got, ok := wafRuleAssetMap(assets)[config.DefaultBaseRuleAssetPath]
	if !ok {
		t.Fatalf("base waf rule asset missing after startup import: %v", assets)
	}
	if string(got.Raw) != wafRaw {
		t.Fatalf("base waf rule asset raw changed: %q", string(got.Raw))
	}
}

func saveStartupConfigForTest() func() {
	oldConfigFile := config.ConfigFile
	oldProxy := config.ProxyConfigFile
	oldSites := config.SiteConfigFile
	oldInventory := config.PHPRuntimeInventoryFile
	oldVhost := config.VhostConfigFile
	oldScheduled := config.ScheduledTaskConfigFile
	oldUpstream := config.UpstreamRuntimeFile
	oldCacheRules := config.CacheRulesFile
	oldBypass := config.BypassFile
	oldCountryBlock := config.CountryBlockFile
	oldRateLimit := config.RateLimitFile
	oldBotDefense := config.BotDefenseFile
	oldSemantic := config.SemanticFile
	oldNotification := config.NotificationFile
	oldIPReputation := config.IPReputationFile
	oldRules := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldCRSSetup := config.CRSSetupFile
	oldCRSRulesDir := config.CRSRulesDir
	oldCRSDisabled := config.CRSDisabledFile
	oldDBDriver := config.DBDriver
	oldDBPath := config.DBPath
	oldDBDSN := config.DBDSN
	oldDBRetention := config.DBRetentionDays
	return func() {
		config.ConfigFile = oldConfigFile
		config.ProxyConfigFile = oldProxy
		config.SiteConfigFile = oldSites
		config.PHPRuntimeInventoryFile = oldInventory
		config.VhostConfigFile = oldVhost
		config.ScheduledTaskConfigFile = oldScheduled
		config.UpstreamRuntimeFile = oldUpstream
		config.CacheRulesFile = oldCacheRules
		config.BypassFile = oldBypass
		config.CountryBlockFile = oldCountryBlock
		config.RateLimitFile = oldRateLimit
		config.BotDefenseFile = oldBotDefense
		config.SemanticFile = oldSemantic
		config.NotificationFile = oldNotification
		config.IPReputationFile = oldIPReputation
		config.RulesFile = oldRules
		config.CRSEnable = oldCRSEnable
		config.CRSSetupFile = oldCRSSetup
		config.CRSRulesDir = oldCRSRulesDir
		config.CRSDisabledFile = oldCRSDisabled
		config.DBDriver = oldDBDriver
		config.DBPath = oldDBPath
		config.DBDSN = oldDBDSN
		config.DBRetentionDays = oldDBRetention
	}
}
