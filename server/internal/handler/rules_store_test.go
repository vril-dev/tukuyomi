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

	"tukuyomi/internal/bypassconf"
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
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/rules?runtime=1", nil)
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
	oldBypass := bypassconf.GetFile()
	bypassconf.SetFile(bypassconf.File{Default: bypassconf.Scope{Entries: []bypassconf.Entry{{
		Path:      "/api/orders/preview",
		ExtraRule: "orders-preview.conf",
	}}}})
	t.Cleanup(func() {
		bypassconf.SetFile(oldBypass)
	})

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
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/rules?runtime=1", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	RulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		Files []struct {
			Path           string   `json:"path"`
			Kind           string   `json:"kind"`
			Position       int      `json:"position"`
			OrderGroup     string   `json:"order_group"`
			GroupPosition  int      `json:"group_position"`
			RuntimeLoaded  bool     `json:"runtime_loaded"`
			Advanced       bool     `json:"advanced"`
			ReferenceCount int      `json:"reference_count"`
			ReferencedBy   []string `json:"referenced_by"`
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
	if out.Files[0].OrderGroup != "base_load_order" || !out.Files[0].RuntimeLoaded || out.Files[0].Advanced {
		t.Fatalf("base metadata=%+v", out.Files[0])
	}
	if out.Files[0].Position != 0 || out.Files[0].GroupPosition != 0 || out.Files[1].Position != 1 || out.Files[1].GroupPosition != 0 {
		t.Fatalf("positions=%+v", out.Files)
	}
	if out.Files[1].OrderGroup != "bypass_snippet" || out.Files[1].RuntimeLoaded || !out.Files[1].Advanced {
		t.Fatalf("bypass metadata=%+v", out.Files[1])
	}
	if out.Files[1].ReferenceCount != 1 || len(out.Files[1].ReferencedBy) != 1 || out.Files[1].ReferencedBy[0] != "/api/orders/preview" {
		t.Fatalf("bypass references=%+v", out.Files[1])
	}
}

func TestRulesHandlerReturnsRuntimeCRSAndBaseLoadOrder(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	config.RulesFile = config.DefaultBaseRuleAssetPath
	config.CRSEnable = true
	config.CRSSetupFile = "rules/crs/crs-setup.conf"
	config.CRSRulesDir = "rules/crs/rules"
	disabledName := "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"
	disabledPath := "rules/crs/rules/" + disabledName

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
		{Path: "disabled-base.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRequestBodyAccess On\n"), Disabled: true},
		{Path: disabledPath, Kind: wafRuleAssetKindCRSAsset, Raw: []byte("SecRule REQUEST_URI @rx test \"id:920000,phase:1,pass\"\n")},
		{Path: config.CRSSetupFile, Kind: wafRuleAssetKindCRSSetup, Raw: []byte("SecRequestBodyAccess On\n")},
		{Path: "rules/crs/rules/REQUEST-901-INITIALIZATION.conf", Kind: wafRuleAssetKindCRSAsset, Raw: []byte("SecRule REQUEST_URI @rx test \"id:901000,phase:1,pass\"\n")},
		{Path: "rules/crs/rules/README.md", Kind: wafRuleAssetKindCRSAsset, Raw: []byte("# CRS docs\n")},
		{Path: "rules/crs/rules/agents.data", Kind: wafRuleAssetKindCRSAsset, Raw: []byte("blocked-agent\n")},
		{Path: "rules/crs/rules/REQUEST-999-EXAMPLE.conf.example", Kind: wafRuleAssetKindCRSAsset, Raw: []byte("# example\n")},
	}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}
	if _, err := store.writeCRSDisabledConfigVersion("", []string{disabledName}, configVersionSourceImport, "", "test crs disabled import", 0); err != nil {
		t.Fatalf("write crs disabled: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/rules?runtime=1", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	RulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out struct {
		RuntimeFiles []struct {
			Path          string `json:"path"`
			Kind          string `json:"kind"`
			OrderGroup    string `json:"order_group"`
			Position      int    `json:"position"`
			GroupPosition int    `json:"group_position"`
			Enabled       bool   `json:"enabled"`
			RuntimeLoaded bool   `json:"runtime_loaded"`
			Editable      bool   `json:"editable"`
			Toggleable    bool   `json:"toggleable"`
		} `json:"runtime_files"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode rules response: %v", err)
	}
	if len(out.RuntimeFiles) != 5 {
		t.Fatalf("runtime files len=%d want=5 body=%s", len(out.RuntimeFiles), rec.Body.String())
	}
	for _, f := range out.RuntimeFiles {
		if strings.HasSuffix(f.Path, ".md") || strings.HasSuffix(f.Path, ".data") || strings.HasSuffix(f.Path, ".conf.example") {
			t.Fatalf("runtime files include non-runtime CRS asset: %+v", out.RuntimeFiles)
		}
	}
	want := []struct {
		path          string
		kind          string
		enabled       bool
		runtimeLoaded bool
		editable      bool
		toggleable    bool
	}{
		{config.CRSSetupFile, wafRuleAssetKindCRSSetup, true, true, false, false},
		{"rules/crs/rules/REQUEST-901-INITIALIZATION.conf", wafRuleAssetKindCRSAsset, true, true, false, true},
		{disabledPath, wafRuleAssetKindCRSAsset, false, false, false, true},
		{config.DefaultBaseRuleAssetPath, wafRuleAssetKindBase, true, true, true, true},
		{"disabled-base.conf", wafRuleAssetKindBase, false, false, true, true},
	}
	for i, expected := range want {
		got := out.RuntimeFiles[i]
		if got.Path != expected.path || got.Kind != expected.kind || got.Enabled != expected.enabled || got.RuntimeLoaded != expected.runtimeLoaded || got.Editable != expected.editable || got.Toggleable != expected.toggleable {
			t.Fatalf("runtime file[%d]=+%v want=%+v", i, got, expected)
		}
		if got.Position != i {
			t.Fatalf("runtime file[%d] position=%d", i, got.Position)
		}
	}
	if out.RuntimeFiles[0].OrderGroup != "coraza_load_order" || out.RuntimeFiles[1].GroupPosition != 1 || out.RuntimeFiles[3].OrderGroup != "base_load_order" {
		t.Fatalf("runtime grouping=%+v", out.RuntimeFiles)
	}
}

func TestPutRulesCreatesBaseRuleDisabledByDefault(t *testing.T) {
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
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: config.DefaultBaseRuleAssetPath,
		Kind: wafRuleAssetKindBase,
		Raw:  []byte("SecRuleEngine On\n"),
	}}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	body := rulesPutBody{
		Path: "custom.conf",
		Kind: wafRuleAssetKindBase,
		Raw:  "SecRequestBodyAccess On\n",
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
	var out struct {
		Enabled bool `json:"enabled"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode put response: %v", err)
	}
	if out.Enabled {
		t.Fatalf("new base rule should default disabled, response=%s", rec.Body.String())
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("load active waf rule assets found=%v err=%v", found, err)
	}
	asset, ok := wafRuleAssetByPath(assets, "custom.conf")
	if !ok {
		t.Fatalf("custom.conf not found in assets: %+v", assets)
	}
	if !asset.Disabled {
		t.Fatalf("custom.conf should be disabled by default: %+v", asset)
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
	if _, err := waf.GetEngineForExtraRule(target); err != nil {
		t.Fatalf("load DB-backed extra rule: %v", err)
	}
}

func TestPutRuleAssetOrderReordersBaseOnlyAndPreservesBypassExtra(t *testing.T) {
	restore := saveRulesFileConfigForTest()
	defer restore()

	gin.SetMode(gin.TestMode)
	tmp := t.TempDir()
	config.RulesFile = "a.conf,b.conf"
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
		{Path: "a.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n")},
		{Path: target, Kind: wafRuleAssetKindBypassExtra, Raw: []byte("SecRuleEngine On\n")},
		{Path: "b.conf", Kind: wafRuleAssetKindBase, Raw: []byte("SecRequestBodyAccess On\n")},
	}, configVersionSourceImport, "", "test waf asset import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	body := rulesOrderBody{Assets: []rulesOrderItem{
		{Path: "b.conf", Kind: wafRuleAssetKindBase},
		{Path: "a.conf", Kind: wafRuleAssetKindBase},
	}}
	payload, _ := json.Marshal(body)
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/rules:order", strings.NewReader(string(payload)))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	PutRuleAssetOrder(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("load active waf rule assets found=%v err=%v", found, err)
	}
	if len(assets) != 3 {
		t.Fatalf("assets len=%d want=3: %+v", len(assets), assets)
	}
	if assets[0].Path != "b.conf" || assets[1].Path != "a.conf" || assets[2].Path != filepath.ToSlash(target) {
		t.Fatalf("asset order=%+v", assets)
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
