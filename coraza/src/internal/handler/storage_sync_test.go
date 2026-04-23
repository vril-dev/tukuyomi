package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

func TestImportPolicyJSONStorage_SeedsBypassDBFromFile(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	bypassPath := filepath.Join(tmp, "waf.bypass")
	fileRaw := "/healthz\n"
	if err := os.WriteFile(bypassPath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write bypass file: %v", err)
	}
	config.BypassFile = bypassPath

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := importPolicyJSONStorage(bypassConfigBlobKey, config.BypassFile, normalizeBypassPolicyRaw, "bypass rules seed import"); err != nil {
		t.Fatalf("import bypass storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(bypassConfigBlobKey))
	if err != nil || !found {
		t.Fatalf("expected bypass normalized rows to be seeded found=%v err=%v", found, err)
	}
	if _, err := bypassconf.Parse(string(gotRaw)); err != nil {
		t.Fatalf("seeded bypass rows invalid: %v", err)
	}
	if _, _, found, err := store.GetConfigBlob(bypassConfigBlobKey); err != nil || found {
		t.Fatalf("legacy bypass blob found=%v err=%v", found, err)
	}
}

func TestSyncBypassStorage_ImportsLegacyBlobAndAppliesRuntime(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	bypassPath := filepath.Join(tmp, "waf.bypass")
	fileRaw := "/old\n"
	if err := os.WriteFile(bypassPath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write bypass file: %v", err)
	}
	config.BypassFile = bypassPath
	if err := bypassconf.Init(bypassPath, ""); err != nil {
		t.Fatalf("init bypass loader: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
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
	dbRaw := "/api/\n"
	if err := store.UpsertConfigBlob(bypassConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncBypassStorage(); err != nil {
		t.Fatalf("sync bypass storage: %v", err)
	}

	match := bypassconf.Match("example.com", "/api/test", false)
	if match.Action != bypassconf.ACTION_BYPASS {
		t.Fatalf("bypass runtime not reloaded from legacy blob: action=%v", match.Action)
	}
	if _, _, found, err := store.GetConfigBlob(bypassConfigBlobKey); err != nil || found {
		t.Fatalf("legacy bypass blob found=%v err=%v", found, err)
	}
}

func TestImportCRSDisabledStorage_SeedsDBFromFile(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.CRSEnable = false
	config.CRSDisabledFile = filepath.Join(tmp, "crs-disabled.conf")
	fileRaw := "# disabled list\nREQUEST-913-SCANNER-DETECTION.conf\n"
	if err := os.WriteFile(config.CRSDisabledFile, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write crs-disabled file: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := importCRSDisabledStorage(); err != nil {
		t.Fatalf("import crs-disabled storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	names, _, found, err := store.loadActiveCRSDisabledConfig()
	if err != nil || !found {
		t.Fatalf("expected crs-disabled normalized rows to be seeded found=%v err=%v", found, err)
	}
	if len(names) != 1 || names[0] != "REQUEST-913-SCANNER-DETECTION.conf" {
		t.Fatalf("seeded crs-disabled names=%v", names)
	}
	if _, _, found, err := store.GetConfigBlob(crsDisabledConfigBlobKey); err != nil || found {
		t.Fatalf("legacy crs-disabled blob found=%v err=%v", found, err)
	}
}

func TestSyncCRSDisabledStorage_ImportsLegacyBlobWithoutRestoringFile(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.CRSEnable = false
	config.CRSDisabledFile = filepath.Join(tmp, "crs-disabled.conf")
	if err := os.WriteFile(config.CRSDisabledFile, []byte("REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n"), 0o644); err != nil {
		t.Fatalf("write crs-disabled file: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
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
	dbRaw := "# from db\nREQUEST-913-SCANNER-DETECTION.conf\n"
	if err := store.UpsertConfigBlob(crsDisabledConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncCRSDisabledStorage(); err != nil {
		t.Fatalf("sync crs-disabled storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(config.CRSDisabledFile)
	if err != nil {
		t.Fatalf("read crs-disabled file: %v", err)
	}
	if string(gotFileRaw) != "REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n" {
		t.Fatalf("crs-disabled file should not be restored from DB, got=%q", string(gotFileRaw))
	}
	if _, _, found, err := store.GetConfigBlob(crsDisabledConfigBlobKey); err != nil || found {
		t.Fatalf("legacy crs-disabled blob found=%v err=%v", found, err)
	}
}

func TestDBRuntimePolicySyncDoesNotCreateSeedFiles(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()
	restoreCountry := saveCountryBlockStateForTest()
	defer restoreCountry()
	restoreRate := saveRateLimitStateForTest()
	defer restoreRate()
	restoreBot := saveBotDefenseStateForTest()
	defer restoreBot()
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	restoreIP := saveIPReputationStateForTest()
	defer restoreIP()

	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "tukuyomi.db")
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

	writePolicy := func(domain string, raw string, normalize func(string) ([]byte, error)) {
		t.Helper()
		normalized, err := normalize(raw)
		if err != nil {
			t.Fatalf("normalize %s: %v", domain, err)
		}
		if _, err := store.writePolicyJSONConfigVersion("", mustPolicyJSONSpec(domain), normalized, configVersionSourceImport, "", "test import", 0); err != nil {
			t.Fatalf("write %s: %v", domain, err)
		}
	}

	config.BypassFile = filepath.Join(tmp, "missing", "waf-bypass.json")
	config.CRSDisabledFile = filepath.Join(tmp, "missing", "crs-disabled.conf")
	config.CRSEnable = false
	countryPath := filepath.Join(tmp, "missing", "country-block.json")
	ratePath := filepath.Join(tmp, "missing", "rate-limit.json")
	botPath := filepath.Join(tmp, "missing", "bot-defense.json")
	semanticPath := filepath.Join(tmp, "missing", "semantic.json")
	notifyPath := filepath.Join(tmp, "missing", "notifications.json")
	ipPath := filepath.Join(tmp, "missing", "ip-reputation.json")

	writePolicy(bypassConfigBlobKey, `{"default":{"entries":[{"path":"/db-only"}]}}`, normalizeBypassPolicyRaw)
	writePolicy(cacheConfigBlobKey, `{"default":{"rules":[]}}`, normalizeCacheRulesPolicyRaw)
	writePolicy(countryBlockConfigBlobKey, `{"default":{"blocked_countries":["JP"]}}`, normalizeCountryBlockPolicyRaw)
	writePolicy(rateLimitConfigBlobKey, rateLimitRawForTest(33), normalizeRateLimitPolicyRaw)
	writePolicy(botDefenseConfigBlobKey, `{
  "enabled": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "suspicious_user_agents": ["curl"],
  "challenge_cookie_name": "__bot_ok",
  "challenge_secret": "test-secret-12345",
  "challenge_ttl_seconds": 1800,
  "challenge_status_code": 429
}`, normalizeBotDefensePolicyRaw)
	writePolicy(semanticConfigBlobKey, `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": ["/healthz"],
  "log_threshold": 2,
  "challenge_threshold": 4,
  "block_threshold": 8,
  "max_inspect_body": 8192
}`, normalizeSemanticPolicyRaw)
	writePolicy(notificationConfigBlobKey, `{"enabled":false,"sinks":[]}`, normalizeNotificationPolicyRaw)
	writePolicy(ipReputationConfigBlobKey, `{"enabled":false}`, normalizeIPReputationPolicyRaw)
	if _, err := store.writeCRSDisabledConfigVersion("", []string{"REQUEST-913-SCANNER-DETECTION.conf"}, configVersionSourceImport, "", "test crs import", 0); err != nil {
		t.Fatalf("write crs disabled: %v", err)
	}

	if err := SyncBypassStorage(); err != nil {
		t.Fatalf("sync bypass: %v", err)
	}
	if err := SyncCacheRulesStorage(); err != nil {
		t.Fatalf("sync cache rules: %v", err)
	}
	if err := InitCountryBlock(countryPath, ""); err != nil {
		t.Fatalf("init country block: %v", err)
	}
	if err := InitRateLimit(ratePath); err != nil {
		t.Fatalf("init rate limit: %v", err)
	}
	if err := InitBotDefense(botPath); err != nil {
		t.Fatalf("init bot defense: %v", err)
	}
	if err := InitSemantic(semanticPath); err != nil {
		t.Fatalf("init semantic: %v", err)
	}
	if err := InitNotifications(notifyPath); err != nil {
		t.Fatalf("init notifications: %v", err)
	}
	if err := InitIPReputation(ipPath); err != nil {
		t.Fatalf("init ip reputation: %v", err)
	}
	if err := SyncCRSDisabledStorage(); err != nil {
		t.Fatalf("sync crs disabled: %v", err)
	}

	for _, path := range []string{
		config.BypassFile,
		config.CRSDisabledFile,
		countryPath,
		ratePath,
		botPath,
		semanticPath,
		notifyPath,
		ipPath,
	} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("seed file should not be created: %s stat=%v", path, err)
		}
	}
	match := bypassconf.Match("example.com", "/db-only", false)
	if match.Action != bypassconf.ACTION_BYPASS {
		t.Fatalf("bypass was not applied from DB: %+v", match)
	}
}

func saveBypassAndCRSConfigForTest() func() {
	oldBypass := config.BypassFile
	oldCRSEnable := config.CRSEnable
	oldCRSDisabled := config.CRSDisabledFile

	return func() {
		config.BypassFile = oldBypass
		config.CRSEnable = oldCRSEnable
		config.CRSDisabledFile = oldCRSDisabled
	}
}
