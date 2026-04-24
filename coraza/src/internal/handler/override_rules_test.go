package handler

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

const standaloneOverrideRuleSample = `SecRuleEngine On

SecRule ARGS:q "@rx (?i)(<script|union([[:space:]]+all)?[[:space:]]+select|benchmark\s*\(|sleep\s*\()" \
  "id:100001,phase:2,deny,status:403,log,msg:'suspicious search query'"
`

func TestValidateManagedOverrideRuleAcceptsStandaloneRule(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	body := overrideRuleBody{
		Name: "orders-preview.conf",
		Raw:  standaloneOverrideRuleSample,
	}
	payload, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/override-rules:validate", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	ValidateManagedOverrideRule(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutManagedOverrideRuleRoundTrip(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	body := overrideRuleBody{
		Name: "orders-preview.conf",
		Raw: `SecRuleEngine On

SecRule REQUEST_URI "@streq /api/orders/preview" "id:100001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
`,
	}
	raw, _ := json.Marshal(body)

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	seedBaseWAFRuleAssetsForTest(t, store)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/override-rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	PutManagedOverrideRule(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	target := filepath.Join(config.OverrideRulesDir, body.Name)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("override file should not be written, stat err=%v", err)
	}

	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("load waf rule assets from db found=%v err=%v", found, err)
	}
	gotRule, ok := wafRuleAssetMap(assets)[filepath.ToSlash(target)]
	if !ok {
		t.Fatalf("%s not found in DB rule assets: %v", body.Name, assets)
	}
	if strings.TrimSpace(string(gotRule.Raw)) != strings.TrimSpace(body.Raw) {
		t.Fatalf("saved override mismatch:\n got=%s\nwant=%s", string(gotRule.Raw), body.Raw)
	}
}

func TestPutManagedOverrideRuleRequiresDBStore(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveOverrideRulesConfigForTest()
	defer restore()
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")

	body := overrideRuleBody{
		Name: "orders-preview.conf",
		Raw: `SecRuleEngine On

SecRule REQUEST_URI "@streq /api/orders/preview" "id:100001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
`,
	}
	raw, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/override-rules", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	PutManagedOverrideRule(c)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	target := filepath.Join(config.OverrideRulesDir, body.Name)
	if _, err := os.Stat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("override file should not be written without DB store, stat err=%v", err)
	}
}

func TestDeleteManagedOverrideRuleRejectsInUse(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := filepath.Join(config.OverrideRulesDir, "orders-preview.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}
	if err := os.WriteFile(target, []byte("SecRuleEngine On\n"), 0o644); err != nil {
		t.Fatalf("write override file: %v", err)
	}

	bypassPath := filepath.Join(tmp, "conf", "waf-bypass.json")
	bypassRaw := `{"entries":[{"path":"/api/orders/preview","extra_rule":"` + target + `"}]}`
	if err := os.MkdirAll(filepath.Dir(bypassPath), 0o755); err != nil {
		t.Fatalf("mkdir bypass dir: %v", err)
	}
	if err := os.WriteFile(bypassPath, []byte(bypassRaw), 0o644); err != nil {
		t.Fatalf("write bypass file: %v", err)
	}
	if err := bypassconf.Init(bypassPath, ""); err != nil {
		t.Fatalf("init bypass loader: %v", err)
	}

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodDelete, "/tukuyomi-api/override-rules?name=orders-preview.conf", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	DeleteManagedOverrideRule(c)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestImportManagedOverrideRulesStorageIgnoresFileSeed(t *testing.T) {
	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := filepath.Join(config.OverrideRulesDir, "orders-preview.conf")
	fileRaw := []byte(`SecRuleEngine On

SecRule REQUEST_URI "@streq /api/orders/preview" "id:100001,phase:1,pass,nolog"
`)
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}
	if err := os.WriteFile(target, fileRaw, 0o644); err != nil {
		t.Fatalf("write override file: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := importManagedOverrideRulesStorage(); err != nil {
		t.Fatalf("import override storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	if rules, _, found, err := store.loadActiveManagedOverrideRules(); err != nil || found || len(rules) != 0 {
		t.Fatalf("filesystem override seed should not be imported found=%v rules=%v err=%v", found, rules, err)
	}
	if _, _, found, err := store.GetConfigBlob(overrideRuleConfigBlobKey("orders-preview.conf")); err != nil || found {
		t.Fatalf("legacy override blob found=%v err=%v", found, err)
	}
}

func TestSyncManagedOverrideRulesStorageImportsLegacyBlobWithoutRestoringFile(t *testing.T) {
	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := filepath.Join(config.OverrideRulesDir, "orders-preview.conf")
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		t.Fatalf("mkdir override dir: %v", err)
	}
	if err := os.WriteFile(target, []byte("SecRuleEngine On\n"), 0o644); err != nil {
		t.Fatalf("write override file: %v", err)
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
	seedBaseWAFRuleAssetsForTest(t, store)
	dbRaw := []byte(`SecRuleEngine On

SecRule REQUEST_URI "@streq /api/orders/preview" "id:100001,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
`)
	if err := store.UpsertConfigBlob(
		overrideRuleConfigBlobKey("orders-preview.conf"),
		dbRaw,
		bypassconf.ComputeETag(dbRaw),
		time.Now().UTC(),
	); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncManagedOverrideRulesStorage(); err != nil {
		t.Fatalf("sync override storage: %v", err)
	}

	if got, err := os.ReadFile(target); err != nil || strings.TrimSpace(string(got)) != "SecRuleEngine On" {
		t.Fatalf("existing file should not be restored from db blob got=%q err=%v", string(got), err)
	}
	rules, _, found, err := store.loadActiveManagedOverrideRules()
	if err != nil || !found {
		t.Fatalf("load active override rules found=%v err=%v", found, err)
	}
	gotRule, ok := managedOverrideRuleMap(rules)["orders-preview.conf"]
	if !ok {
		t.Fatalf("orders-preview.conf not found in DB rules: %v", rules)
	}
	if strings.TrimSpace(string(gotRule.Raw)) != strings.TrimSpace(string(dbRaw)) {
		t.Fatalf("db rule mismatch:\n got=%s\nwant=%s", string(gotRule.Raw), string(dbRaw))
	}
	if _, _, found, err := store.GetConfigBlob(overrideRuleConfigBlobKey("orders-preview.conf")); err != nil || found {
		t.Fatalf("legacy override blob found=%v err=%v", found, err)
	}
	assets, _, found, err := store.loadActiveWAFRuleAssets()
	if err != nil || !found {
		t.Fatalf("load active waf rule assets found=%v err=%v", found, err)
	}
	gotAsset, ok := wafRuleAssetMap(assets)[filepath.ToSlash(target)]
	if !ok || gotAsset.Kind != wafRuleAssetKindBypassExtra {
		t.Fatalf("migrated bypass extra rule asset not found: %v", assets)
	}
}

func TestGetEngineForExtraRuleLoadsManagedOverrideFromDBWithoutFile(t *testing.T) {
	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")
	target := filepath.Join(config.OverrideRulesDir, "orders-preview.conf")

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
		waf.InvalidateOverrideWAF(target)
	})

	store := getLogsStatsStore()
	dbRaw := []byte(`SecRuleEngine On

SecRule REQUEST_URI "@streq /api/orders/preview" "id:100001,phase:1,pass,nolog"
`)
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{
		{Path: config.DefaultBaseRuleAssetPath, Kind: wafRuleAssetKindBase, Raw: []byte("SecRuleEngine On\n")},
		{Path: target, Kind: wafRuleAssetKindBypassExtra, Raw: dbRaw},
	}, configVersionSourceImport, "", "test waf rule assets import", 0); err != nil {
		t.Fatalf("write waf rule assets: %v", err)
	}

	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("override file should not exist before WAF load, stat err=%v", err)
	}
	if _, err := waf.GetEngineForExtraRule(target); err != nil {
		t.Fatalf("load extra rule from DB: %v", err)
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		t.Fatalf("override file should not be materialized by WAF load, stat err=%v", err)
	}
}

func saveOverrideRulesConfigForTest() func() {
	oldOverrideRulesDir := config.OverrideRulesDir
	oldBypassFile := config.BypassFile
	oldStrict := config.StrictOverride

	return func() {
		config.OverrideRulesDir = oldOverrideRulesDir
		config.BypassFile = oldBypassFile
		config.StrictOverride = oldStrict
	}
}

func seedBaseWAFRuleAssetsForTest(t *testing.T, store *wafEventStore) {
	t.Helper()
	if _, _, err := store.writeWAFRuleAssetsVersion("", []wafRuleAssetVersion{{
		Path: config.DefaultBaseRuleAssetPath,
		Kind: wafRuleAssetKindBase,
		Raw:  []byte("SecRuleEngine On\n"),
	}}, configVersionSourceImport, "", "test base waf asset import", 0); err != nil {
		t.Fatalf("write base waf rule asset: %v", err)
	}
}
