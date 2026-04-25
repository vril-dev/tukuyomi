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
	t.Setenv(startupSeedConfDirEnv, "")

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

func TestReadStartupSeedFileFallsBackToSeedConf(t *testing.T) {
	tmp := t.TempDir()
	seedDir := filepath.Join(tmp, "seeds", "conf")
	if err := os.MkdirAll(seedDir, 0o755); err != nil {
		t.Fatalf("mkdir seed dir: %v", err)
	}
	seedRaw := []byte(`{"source":"seed"}` + "\n")
	if err := os.WriteFile(filepath.Join(seedDir, startupProxySeedName), seedRaw, 0o600); err != nil {
		t.Fatalf("write seed: %v", err)
	}
	t.Setenv(startupSeedConfDirEnv, seedDir)

	raw, found, err := readStartupSeedFile(filepath.Join(tmp, "missing", "proxy.json"), startupProxySeedName)
	if err != nil {
		t.Fatalf("read fallback seed: %v", err)
	}
	if !found || string(raw) != string(seedRaw) {
		t.Fatalf("fallback seed mismatch found=%v raw=%q", found, string(raw))
	}

	primaryPath := filepath.Join(tmp, "conf", "proxy.json")
	if err := os.MkdirAll(filepath.Dir(primaryPath), 0o755); err != nil {
		t.Fatalf("mkdir primary dir: %v", err)
	}
	primaryRaw := []byte(`{"source":"primary"}` + "\n")
	if err := os.WriteFile(primaryPath, primaryRaw, 0o600); err != nil {
		t.Fatalf("write primary: %v", err)
	}
	raw, found, err = readStartupSeedFile(primaryPath, startupProxySeedName)
	if err != nil {
		t.Fatalf("read primary seed: %v", err)
	}
	if !found || string(raw) != string(primaryRaw) {
		t.Fatalf("primary seed mismatch found=%v raw=%q", found, string(raw))
	}
}

func TestBundledStartupSeedConfFilesValidate(t *testing.T) {
	root := repoRootForStartupSeedTest(t)
	seedDir := filepath.Join(root, "seeds", "conf")
	readSeed := func(name string) string {
		t.Helper()
		raw, err := os.ReadFile(filepath.Join(seedDir, name))
		if err != nil {
			t.Fatalf("read bundled seed %s: %v", name, err)
		}
		return string(raw)
	}

	if _, err := prepareProxyRulesRaw(readSeed(startupProxySeedName)); err != nil {
		t.Fatalf("validate proxy seed: %v", err)
	}
	if _, err := prepareSiteConfigRaw(readSeed(startupSitesSeedName)); err != nil {
		t.Fatalf("validate sites seed: %v", err)
	}
	inventory, err := preparePHPRuntimeInventoryRaw(readSeed(startupPHPRuntimeSeedName), filepath.Join(seedDir, startupPHPRuntimeSeedName))
	if err != nil {
		t.Fatalf("validate php runtime inventory seed: %v", err)
	}
	if _, err := prepareVhostConfigRawWithInventory(readSeed(startupVhostsSeedName), inventory.cfg); err != nil {
		t.Fatalf("validate vhosts seed: %v", err)
	}
	if _, err := prepareScheduledTaskConfigRaw(readSeed(startupScheduledTasksSeedName), inventory.cfg); err != nil {
		t.Fatalf("validate scheduled tasks seed: %v", err)
	}
	if _, err := ParseUpstreamRuntimeRaw(readSeed(startupUpstreamRuntimeSeedName)); err != nil {
		t.Fatalf("validate upstream runtime seed: %v", err)
	}
	policySeeds := []struct {
		name      string
		normalize func(string) ([]byte, error)
	}{
		{"cache-rules.json", normalizeCacheRulesPolicyRaw},
		{"waf-bypass.json", normalizeBypassPolicyRaw},
		{"country-block.json", normalizeCountryBlockPolicyRaw},
		{"rate-limit.json", normalizeRateLimitPolicyRaw},
		{"bot-defense.json", normalizeBotDefensePolicyRaw},
		{"semantic.json", normalizeSemanticPolicyRaw},
		{"notifications.json", normalizeNotificationPolicyRaw},
		{"ip-reputation.json", normalizeIPReputationPolicyRaw},
	}
	for _, seed := range policySeeds {
		if _, err := seed.normalize(readSeed(seed.name)); err != nil {
			t.Fatalf("validate policy seed %s: %v", seed.name, err)
		}
	}
	if _, err := prepareResponseCacheRaw(readSeed(startupResponseCacheSeedName)); err != nil {
		t.Fatalf("validate response cache seed: %v", err)
	}
	_ = crsDisabledNamesFromRaw([]byte(readSeed(startupCRSDisabledSeedName)))
}

func repoRootForStartupSeedTest(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for i := 0; i < 8; i++ {
		if _, err := os.Stat(filepath.Join(dir, "seeds", "conf", startupProxySeedName)); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatalf("repository root with seeds/conf/%s not found", startupProxySeedName)
	return ""
}

func saveStartupConfigForTest() func() {
	oldConfigFile := config.ConfigFile
	oldProxy := config.ProxyConfigFile
	oldSites := config.SiteConfigFile
	oldInventory := config.PHPRuntimeInventoryFile
	oldVhost := config.VhostConfigFile
	oldScheduled := config.ScheduledTaskConfigFile
	oldUpstream := config.UpstreamRuntimeFile
	oldCacheStore := config.CacheStoreFile
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
		config.CacheStoreFile = oldCacheStore
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
