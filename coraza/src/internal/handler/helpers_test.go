package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tukuyomi/internal/config"
)

func TestEnsureEditableRulePath(t *testing.T) {
	restore := saveRuleConfig()
	defer restore()

	config.CRSEnable = false
	config.RulesFile = "rules/a.conf, rules/b.conf"

	path, err := ensureEditableRulePath("rules/a.conf")
	if err != nil {
		t.Fatalf("ensureEditableRulePath returned error: %v", err)
	}
	if path != "rules/a.conf" {
		t.Fatalf("path=%q want=%q", path, "rules/a.conf")
	}

	if _, err := ensureEditableRulePath("rules/c.conf"); err == nil {
		t.Fatal("ensureEditableRulePath should reject paths outside configured rules")
	}
}

func TestValidateRaw_StrictOverride(t *testing.T) {
	restore := saveRuleConfig()
	defer restore()

	config.StrictOverride = false
	if _, err := validateRaw("/foo rules/missing.conf\n"); err != nil {
		t.Fatalf("validateRaw should allow missing extra rule when strict=false: %v", err)
	}

	config.StrictOverride = true
	if _, err := validateRaw("/foo rules/missing.conf\n"); err == nil {
		t.Fatal("validateRaw should fail when strict=true and extra rule is missing")
	}
}

func TestReadFileMaybeAndRollback(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "crs-disabled.conf")

	b, had, err := readFileMaybe(path)
	if err != nil {
		t.Fatalf("readFileMaybe missing file error: %v", err)
	}
	if had {
		t.Fatal("readFileMaybe should report hadFile=false for missing file")
	}
	if len(b) != 0 {
		t.Fatalf("readFileMaybe missing file bytes=%d want=0", len(b))
	}

	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := rollbackCRSDisabledFile(path, true, []byte("prev\n")); err != nil {
		t.Fatalf("rollbackCRSDisabledFile(hadFile=true): %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rolled back file: %v", err)
	}
	if string(after) != "prev\n" {
		t.Fatalf("rollback content=%q want=%q", string(after), "prev\n")
	}

	if err := os.WriteFile(path, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := rollbackCRSDisabledFile(path, false, nil); err != nil {
		t.Fatalf("rollbackCRSDisabledFile(hadFile=false): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should be removed on rollback when hadFile=false, err=%v", err)
	}
}

func saveRuleConfig() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldCRSSetup := config.CRSSetupFile
	oldCRSRulesDir := config.CRSRulesDir
	oldCRSDisabled := config.CRSDisabledFile
	oldStrict := config.StrictOverride
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.CRSSetupFile = oldCRSSetup
		config.CRSRulesDir = oldCRSRulesDir
		config.CRSDisabledFile = oldCRSDisabled
		config.StrictOverride = oldStrict
	}
}

func newUpstreamHealthMonitorForTest(t *testing.T, cfg ProxyRulesConfig) *upstreamHealthMonitor {
	t.Helper()
	oldPath := config.UpstreamRuntimeFile
	if strings.TrimSpace(config.UpstreamRuntimeFile) == "" {
		config.UpstreamRuntimeFile = filepath.Join(t.TempDir(), "conf", "upstream-runtime.json")
		t.Cleanup(func() {
			config.UpstreamRuntimeFile = oldPath
		})
	}
	tracker, err := newUpstreamHealthMonitor(cfg)
	if err != nil {
		t.Fatalf("newUpstreamHealthMonitor: %v", err)
	}
	return tracker
}

func initConfigDBStoreForTest(t *testing.T) *wafEventStore {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "tukuyomi.db")
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
	return store
}

func importProxyRuntimeDBForTest(t *testing.T, raw string) ProxyRulesConfig {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	prepared, err := prepareProxyRulesRaw(raw)
	if err != nil {
		t.Fatalf("prepare proxy rules: %v", err)
	}
	if _, err := store.writeProxyConfigVersion("", prepared.cfg, configVersionSourceImport, "", "test proxy import", 0); err != nil {
		t.Fatalf("write proxy config: %v", err)
	}
	seedUpstreamRuntimeDBForTest(t, prepared.cfg)
	return prepared.cfg
}

func importCountryBlockDBForTest(t *testing.T, raw string) countryBlockFile {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	normalized, err := normalizeCountryBlockPolicyRaw(raw)
	if err != nil {
		t.Fatalf("normalize country block rules: %v", err)
	}
	file, err := ParseCountryBlockRaw(string(normalized))
	if err != nil {
		t.Fatalf("parse normalized country block rules: %v", err)
	}
	if _, err := store.writePolicyJSONConfigVersion("", mustPolicyJSONSpec(countryBlockConfigBlobKey), normalized, configVersionSourceImport, "", "test country block import", 0); err != nil {
		t.Fatalf("write country block rules: %v", err)
	}
	return file
}

func importSiteRuntimeDBForTest(t *testing.T, raw string) SiteConfigFile {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	prepared, err := prepareSiteConfigRaw(raw)
	if err != nil {
		t.Fatalf("prepare site config: %v", err)
	}
	if _, err := store.writeSiteConfigVersion("", prepared.cfg, configVersionSourceImport, "", "test sites import", 0); err != nil {
		t.Fatalf("write site config: %v", err)
	}
	return prepared.cfg
}

func importPHPRuntimeInventoryDBForTest(t *testing.T, raw string, inventoryPath string) PHPRuntimeInventoryFile {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	prepared, err := preparePHPRuntimeInventoryRaw(raw, inventoryPath)
	if err != nil {
		t.Fatalf("prepare php runtime inventory: %v", err)
	}
	if _, err := store.writePHPRuntimeInventoryConfigVersion("", prepared.cfg, configVersionSourceImport, "", "test php runtime inventory import", 0); err != nil {
		t.Fatalf("write php runtime inventory config: %v", err)
	}
	return prepared.cfg
}

func importVhostRuntimeDBForTest(t *testing.T, raw string, inventory PHPRuntimeInventoryFile) VhostConfigFile {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	prepared, err := prepareVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("prepare vhost config: %v", err)
	}
	if _, err := store.writeVhostConfigVersion("", prepared.cfg, configVersionSourceImport, "", "test vhost import", 0); err != nil {
		t.Fatalf("write vhost config: %v", err)
	}
	return prepared.cfg
}

func seedUpstreamRuntimeDBForTest(t *testing.T, cfg ProxyRulesConfig) {
	t.Helper()
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	if _, _, err := store.writeUpstreamRuntimeConfigVersion("", upstreamRuntimeFile{}, configuredManagedBackendKeys(cfg), configVersionSourceImport, "", "test upstream runtime import", 0); err != nil {
		t.Fatalf("write upstream runtime config: %v", err)
	}
}
