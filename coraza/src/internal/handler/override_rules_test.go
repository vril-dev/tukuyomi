package handler

import (
	"bytes"
	"encoding/json"
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
)

func TestValidateManagedOverrideRuleAcceptsBundledSample(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := saveOverrideRulesConfigForTest()
	defer restore()

	tmp := t.TempDir()
	config.OverrideRulesDir = filepath.Join(tmp, "conf", "rules")

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "data", "conf", "rules", "search-endpoint.conf"))
	if err != nil {
		t.Fatalf("read bundled sample: %v", err)
	}
	body := overrideRuleBody{
		Name: "search-endpoint.conf",
		Raw:  string(raw),
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

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	target := filepath.Join(config.OverrideRulesDir, body.Name)
	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read override file: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(body.Raw) {
		t.Fatalf("saved override mismatch:\n got=%s\nwant=%s", string(got), body.Raw)
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

func TestSyncManagedOverrideRulesStorageSeedsDBFromFileWhenMissingBlob(t *testing.T) {
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
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
	})

	if err := SyncManagedOverrideRulesStorage(); err != nil {
		t.Fatalf("sync override storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(overrideRuleConfigBlobKey("orders-preview.conf"))
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected override config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(string(fileRaw)) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), string(fileRaw))
	}
}

func TestSyncManagedOverrideRulesStorageRestoresFileFromDB(t *testing.T) {
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
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
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

	got, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read restored override file: %v", err)
	}
	if strings.TrimSpace(string(got)) != strings.TrimSpace(string(dbRaw)) {
		t.Fatalf("restored file mismatch:\n got=%s\nwant=%s", string(got), string(dbRaw))
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
