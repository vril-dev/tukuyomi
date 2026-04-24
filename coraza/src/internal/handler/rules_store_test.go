package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

func TestImportWAFRuleAssetsStorage_SeedsDBRuleAssetsFromFile(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "tukuyomi.conf")
	fileRaw := "SecRuleEngine On\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", tmp)
	config.RulesFile = config.DefaultBaseRuleAssetPath
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
	got, ok := wafRuleAssetMap(assets)[config.DefaultBaseRuleAssetPath]
	if !ok {
		t.Fatalf("expected rule asset for %s: %v", config.DefaultBaseRuleAssetPath, assets)
	}
	if strings.TrimSpace(string(got.Raw)) != strings.TrimSpace(fileRaw) {
		t.Fatalf("seeded asset mismatch:\n got=%s\nwant=%s", string(got.Raw), fileRaw)
	}
}

func TestSyncRuleFilesStorage_DoesNotRestoreFileAndWAFLoadsDBAsset(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	rulePath := filepath.Join(tmp, "tukuyomi.conf")
	fileRaw := "SecRuleEngine DetectionOnly\n"
	if err := os.WriteFile(rulePath, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rule file: %v", err)
	}
	t.Setenv("WAF_RULE_ASSET_FS_ROOT", tmp)
	config.RulesFile = config.DefaultBaseRuleAssetPath
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
		Path: config.DefaultBaseRuleAssetPath,
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
	stageRoot := filepath.Join(tmp, "stage")
	rulePath := filepath.Join(stageRoot, "tukuyomi.conf")
	crsSetup := filepath.Join(stageRoot, "rules", "crs", "crs-setup.conf")
	crsRulesDir := filepath.Join(stageRoot, "rules", "crs", "rules")
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

	t.Setenv("WAF_RULE_ASSET_FS_ROOT", stageRoot)
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = true
	config.CRSSetupFile = "rules/crs/crs-setup.conf"
	config.CRSRulesDir = "rules/crs/rules"
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
	if err := os.RemoveAll(stageRoot); err != nil {
		t.Fatalf("remove staged rule assets: %v", err)
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		t.Fatalf("reload waf from DB CRS assets: %v", err)
	}
}

func TestRulesHandlerReturnsCanonicalDBAssetPath(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	config.RulesFile = config.DefaultBaseRuleAssetPath
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
	raw := []byte("SecRuleEngine On\n")
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: config.DefaultBaseRuleAssetPath,
		Kind: wafRuleAssetKindBase,
		Raw:  raw,
	}}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/rules", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	RulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "rules/tukuyomi.conf") {
		t.Fatalf("response contains legacy rule asset path: %s", rec.Body.String())
	}
	var out struct {
		Rules map[string]string `json:"rules"`
		Files []struct {
			Path string `json:"path"`
			Raw  string `json:"raw"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if got := out.Rules[config.DefaultBaseRuleAssetPath]; got != string(raw) {
		t.Fatalf("rules[%q]=%q want=%q", config.DefaultBaseRuleAssetPath, got, string(raw))
	}
	if len(out.Files) != 1 {
		t.Fatalf("files len=%d want=1", len(out.Files))
	}
	if out.Files[0].Path != config.DefaultBaseRuleAssetPath {
		t.Fatalf("file path=%q want=%q", out.Files[0].Path, config.DefaultBaseRuleAssetPath)
	}
}

func TestPrepareInitialRuleFilesUsesDBBaseAssetOrder(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.RulesFile = "a.conf,b.conf"
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
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: "b.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n")},
		{Path: "a.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRequestBodyAccess On\n")},
	}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	files, err := waf.PrepareInitialRuleFiles()
	if err != nil {
		t.Fatalf("prepare initial rule files: %v", err)
	}
	want := []string{"b.conf", "a.conf"}
	if strings.Join(files, ",") != strings.Join(want, ",") {
		t.Fatalf("files=%v want=%v", files, want)
	}
}

func TestRulesHandlerReturnsBypassExtraRuleAssets(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := managedOverrideRulePath("orders-preview.conf")

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
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n")},
		{Path: target, Kind: wafRuleAssetKindBypassExtra, Raw: []byte("SecRuleEngine On\n")},
	}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/rules", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	RulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Files []struct {
			Path string `json:"path"`
			Kind string `json:"kind"`
		} `json:"files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if len(out.Files) != 2 {
		t.Fatalf("files len=%d want=2 body=%s", len(out.Files), rec.Body.String())
	}
	if out.Files[1].Path != filepath.ToSlash(target) || out.Files[1].Kind != wafRuleAssetKindBypassExtra {
		t.Fatalf("extra asset=%+v want path=%q kind=%q", out.Files[1], filepath.ToSlash(target), wafRuleAssetKindBypassExtra)
	}
}

func TestPutRulesCreatesBypassExtraRuleAsset(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = false
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := managedOverrideRulePath("orders-preview.conf")

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
		waf.InvalidateOverrideWAF(target)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: config.DefaultBaseRuleAssetPath,
		Kind: wafRuleAssetKindBase,
		Raw:  []byte("SecRuleEngine On\n"),
	}}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	body := rulesPutBody{
		Path: "orders-preview.conf",
		Kind: wafRuleAssetKindBypassExtra,
		Raw:  standaloneOverrideRuleSample,
	}
	payload, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/rules", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	PutRules(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("extra rule file should not be materialized, stat err=%v", err)
	}
	if _, err := waf.GetWAFForExtraRule(target); err != nil {
		t.Fatalf("load DB-backed extra rule: %v", err)
	}
}

func saveRulesFileConfigForTest() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldCRSSetup := config.CRSSetupFile
	oldCRSRulesDir := config.CRSRulesDir
	oldCRSDisabled := config.CRSDisabledFile
	oldOverrideRulesDir := config.OverrideRulesDir
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.CRSSetupFile = oldCRSSetup
		config.CRSRulesDir = oldCRSRulesDir
		config.CRSDisabledFile = oldCRSDisabled
		config.OverrideRulesDir = oldOverrideRulesDir
	}
}
