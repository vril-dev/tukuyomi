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
)

func TestVhostConfigNormalizesLegacyOverrideFileNameAway(t *testing.T) {
	raw := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9440,
      "document_root": "/srv/docs/public",
      "override_file_name": "../.htaccess",
      "try_files": ["$uri"],
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`

	cfg, err := ValidateVhostConfigRawWithInventory(raw, PHPRuntimeInventoryFile{})
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventory: %v", err)
	}
	if len(cfg.Vhosts) != 1 {
		t.Fatalf("vhost count=%d want=1", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].OverrideFileName != "" {
		t.Fatalf("override_file_name=%q want empty", cfg.Vhosts[0].OverrideFileName)
	}

	prepared, err := prepareVhostConfigRawWithInventory(raw, PHPRuntimeInventoryFile{})
	if err != nil {
		t.Fatalf("prepareVhostConfigRawWithInventory: %v", err)
	}
	if strings.Contains(prepared.raw, "override_file_name") || strings.Contains(prepared.raw, ".htaccess") {
		t.Fatalf("normalized raw retained override data: %s", prepared.raw)
	}
}

func TestServeProxyIgnoresHtaccessLikeNginx(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	docroot := filepath.Join(tmp, "site", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("nginx-style index"), 0o600); err != nil {
		t.Fatalf("WriteFile(index.html): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".htaccess"), []byte("RewriteRule ^legacy$ /index.html [L]\nRewriteRule ^ - [L]\nRequire all denied\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.htaccess): %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9441,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "override_file_name": ".htaccess",
      "try_files": ["$uri"],
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "docs", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "docs-static"},
		},
	}))
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	rec := serveNoHtaccessDocsRequest(t, "/index.html")
	if rec.Code != http.StatusOK {
		t.Fatalf("index status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "nginx-style index") {
		t.Fatalf("unexpected index body=%q", rec.Body.String())
	}

	rec = serveNoHtaccessDocsRequest(t, "/legacy")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("legacy status=%d want=404 body=%s", rec.Code, rec.Body.String())
	}

	_, _, cfg, _ := VhostConfigSnapshot()
	if len(cfg.Vhosts) != 1 {
		t.Fatalf("active vhost count=%d want=1", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].OverrideFileName != "" {
		t.Fatalf("active override_file_name=%q want empty", cfg.Vhosts[0].OverrideFileName)
	}
}

func TestGetRuntimeAppsOmitsOverrideReports(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	docroot := filepath.Join(tmp, "site", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".htaccess"), []byte("RewriteRule ^ - [L]\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.htaccess): %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "127.0.0.1",
      "listen_port": 9442,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "override_file_name": ".htaccess",
      "try_files": ["$uri"],
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(vhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	ctx.Request = httptest.NewRequest(http.MethodGet, "/runtime-apps", nil)
	GetRuntimeApps(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetRuntimeApps status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp map[string]json.RawMessage
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	if _, ok := resp["override_reports"]; ok {
		t.Fatalf("override_reports should be absent: %s", rec.Body.String())
	}
	if raw, ok := resp["raw"]; ok && strings.Contains(string(raw), "override_file_name") {
		t.Fatalf("raw retained override_file_name: %s", raw)
	}
}

func TestInitVhostRuntimeDegradesOnInvalidStoredConfig(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	vhostPath := filepath.Join(tmp, "vhosts.json")
	raw := `{
  "vhosts": [
    {
      "name": "broken",
      "mode": "static",
      "hostname": "broken.example.com",
      "listen_port": 0,
      "document_root": "/srv/broken/public",
      "generated_target": "broken-static",
      "linked_upstream_name": "broken"
    }
  ]
}`
	if err := os.WriteFile(vhostPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}

	err := InitVhostRuntime(vhostPath, 2)
	if err == nil {
		t.Fatalf("InitVhostRuntime succeeded, want startup config error")
	}
	if !IsVhostStartupConfigError(err) {
		t.Fatalf("error type=%T value=%v, want vhost startup config error", err, err)
	}
	status := VhostRuntimeStatusSnapshot()
	if !status.Degraded || !strings.Contains(status.LastError, "listen_port") {
		t.Fatalf("unexpected runtime status: %+v", status)
	}
	_, _, cfg, _ := VhostConfigSnapshot()
	if len(cfg.Vhosts) != 0 {
		t.Fatalf("active vhost count=%d want=0", len(cfg.Vhosts))
	}
}

func serveNoHtaccessDocsRequest(t *testing.T, requestPath string) *httptest.ResponseRecorder {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com"+requestPath, nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	return rec
}
