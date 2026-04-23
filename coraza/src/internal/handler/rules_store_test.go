package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

func TestImportWAFRuleAssetsStorage_SeedsDBRuleAssetsFromFile(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "rules", "tukuyomi.conf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	fileRaw := "SecRuleEngine On\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	config.RulesFile = rulePath
	config.CRSEnable = false

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := ImportWAFRuleAssetsStorage(); err != nil {
		t.Fatalf("import waf rule assets: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("expected active waf rule assets found=%v err=%v", found, err)
	}
	got, ok := wafRuleAssetMap(assets)[normalizeWAFRuleAssetPath(rulePath)]
	if !ok {
		t.Fatalf("expected rule asset for %s: %v", rulePath, assets)
	}
	if strings.TrimSpace(string(got.Raw)) != strings.TrimSpace(fileRaw) {
		t.Fatalf("seeded asset mismatch:\n got=%s\nwant=%s", string(got.Raw), fileRaw)
	}
	if _, _, found, err := store.GetConfigBlob(ruleFileConfigBlobKey(rulePath)); err != nil || found {
		t.Fatalf("legacy rule blob found=%v err=%v", found, err)
	}
}

func TestSyncRuleFilesStorage_DoesNotRestoreFileAndWAFLoadsDBAsset(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "rules", "tukuyomi.conf")
	if err := os.MkdirAll(filepath.Dir(rulePath), 0o755); err != nil {
		t.Fatalf("mkdir rules dir: %v", err)
	}
	fileRaw := "SecRuleEngine DetectionOnly\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	config.RulesFile = rulePath
	config.CRSEnable = false

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
	dbRaw := "SecRuleEngine On\n"
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: normalizeWAFRuleAssetPath(rulePath),
		Kind: wafRuleAssetKindBase,
		Raw:  []byte(dbRaw),
	}}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}
	if err := os.Remove(rulePath); err != nil {
		t.Fatalf("remove rule file: %v", err)
	}

	if err := SyncRuleFilesStorage(); err != nil {
		t.Fatalf("sync rule files storage: %v", err)
	}

	if _, err := os.Stat(rulePath); !os.IsNotExist(err) {
		t.Fatalf("rule file should not be restored from DB, stat err=%v", err)
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		t.Fatalf("reload waf from DB rule asset: %v", err)
	}
}

func TestSyncRuleFilesStorage_WAFLoadsCRSAssetsAndDataFromDBWithoutFiles(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulesRoot := filepath.Join(tmp, "rules")
	rulePath := filepath.Join(rulesRoot, "tukuyomi.conf")
	crsSetup := filepath.Join(rulesRoot, "crs", "crs-setup.conf")
	crsRulesDir := filepath.Join(rulesRoot, "crs", "rules")
	crsRule := filepath.Join(crsRulesDir, "REQUEST-901-INITIALIZATION.conf")
	crsData := filepath.Join(crsRulesDir, "agents.data")
	for _, dir := range []string{filepath.Dir(rulePath), filepath.Dir(crsSetup), crsRulesDir, filepath.Join(tmp, "conf")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	if err := os.WriteFile(rulePath, []byte("SecRuleEngine On\n"), 0o644); err != nil {
		t.Fatalf("write base rule: %v", err)
	}
	if err := os.WriteFile(crsSetup, []byte("SecRequestBodyAccess On\n"), 0o644); err != nil {
		t.Fatalf("write crs setup: %v", err)
	}
	if err := os.WriteFile(crsRule, []byte(`SecRule REQUEST_HEADERS:User-Agent "@pmFromFile agents.data" "id:100101,phase:1,deny,status:403,log,msg:'blocked test agent'"
`), 0o644); err != nil {
		t.Fatalf("write crs rule: %v", err)
	}
	if err := os.WriteFile(crsData, []byte("blocked-agent\n"), 0o644); err != nil {
		t.Fatalf("write crs data: %v", err)
	}

	config.RulesFile = rulePath
	config.CRSEnable = true
	config.CRSSetupFile = crsSetup
	config.CRSRulesDir = crsRulesDir
	config.CRSDisabledFile = filepath.Join(tmp, "conf", "crs-disabled.conf")

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := ImportWAFRuleAssetsStorage(); err != nil {
		t.Fatalf("import waf rule assets: %v", err)
	}
	if err := os.RemoveAll(rulesRoot); err != nil {
		t.Fatalf("remove rules root: %v", err)
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		t.Fatalf("reload waf from DB CRS assets: %v", err)
	}
}

func saveRulesFileConfigForTest() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldCRSSetup := config.CRSSetupFile
	oldCRSRulesDir := config.CRSRulesDir
	oldCRSDisabled := config.CRSDisabledFile
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.CRSSetupFile = oldCRSSetup
		config.CRSRulesDir = oldCRSRulesDir
		config.CRSDisabledFile = oldCRSDisabled
	}
}
