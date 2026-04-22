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
	"golang.org/x/crypto/bcrypt"
)

func TestValidateVhostConfigRawWithInventoryDetailedImportsHtaccessSubset(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	docroot := filepath.Join(tmp, "site", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte("preview-pass"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatalf("GenerateFromPassword: %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".users"), []byte("alice:"+string(hash)+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.users): %v", err)
	}
	overrideBody := strings.Join([]string{
		"RewriteEngine On",
		"RewriteRule ^legacy$ /index.html [R=301,QSA,L]",
		"AuthType Basic",
		`AuthName "Members Area"`,
		"AuthUserFile .users",
		"Require user alice",
		"Require ip 127.0.0.1",
		"Require all denied",
		"UnsupportedDirective on",
	}, "\n")
	if err := os.WriteFile(filepath.Join(docroot, ".customrules"), []byte(overrideBody), 0o600); err != nil {
		t.Fatalf("WriteFile(.customrules): %v", err)
	}

	raw := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9440,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "override_file_name": ".customrules",
      "generated_target": "docs-static",
      "linked_upstream_name": "docs"
    }
  ]
}`
	cfg, reports, err := ValidateVhostConfigRawWithInventoryDetailed(raw, PHPRuntimeInventoryFile{})
	if err != nil {
		t.Fatalf("ValidateVhostConfigRawWithInventoryDetailed: %v", err)
	}
	if len(cfg.Vhosts) != 1 {
		t.Fatalf("vhost count=%d want=1", len(cfg.Vhosts))
	}
	vhost := cfg.Vhosts[0]
	if len(vhost.RewriteRules) != 1 {
		t.Fatalf("rewrite rule count=%d want=1", len(vhost.RewriteRules))
	}
	if len(vhost.AccessRules) != 3 {
		t.Fatalf("access rule count=%d want=3", len(vhost.AccessRules))
	}
	report, ok := reports["docs-static"]
	if !ok {
		t.Fatalf("missing override report: %+v", reports)
	}
	if !report.Found || report.OverrideFileName != ".customrules" {
		t.Fatalf("unexpected report: %+v", report)
	}
	if report.ImportedRewriteRules != 1 || report.ImportedAccessRules != 3 || !report.ImportedBasicAuth {
		t.Fatalf("unexpected import counts: %+v", report)
	}
	if len(report.Messages) == 0 || !strings.Contains(strings.Join(report.Messages, "\n"), "UnsupportedDirective") {
		t.Fatalf("expected unsupported directive warning, got %+v", report.Messages)
	}
}

func TestServeProxyAppliesImportedHtaccessRewrite(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(docroot, "index.html"), []byte("imported rewrite ok"), 0o600); err != nil {
		t.Fatalf("WriteFile(index.html): %v", err)
	}
	if err := os.WriteFile(filepath.Join(docroot, ".htaccess"), []byte("RewriteEngine On\nRewriteRule ^legacy$ /index.html [L]\n"), 0o600); err != nil {
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
      "hostname": "docs.example.com",
      "listen_port": 9441,
      "document_root": "` + filepath.ToSlash(docroot) + `",
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
		Routes: []ProxyRoute{
			{
				Name:     "docs",
				Priority: 10,
				Enabled:  boolPtrHT(true),
				Match: ProxyRouteMatch{
					Hosts: []string{"docs.example.com"},
				},
				Action: ProxyRouteAction{Upstream: "docs"},
			},
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

	req := httptest.NewRequest(http.MethodGet, "http://docs.example.com/legacy", nil)
	decision, err := resolveProxyRouteDecision(req, currentProxyConfig(), proxyRuntimeHealth())
	if err != nil {
		t.Fatalf("resolveProxyRouteDecision: %v", err)
	}
	req = req.WithContext(withProxyRouteDecision(req.Context(), decision))
	rec := httptest.NewRecorder()
	ServeProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "imported rewrite ok") {
		t.Fatalf("unexpected body=%q", rec.Body.String())
	}
}

func TestGetVhostsIncludesOverrideReports(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(docroot, ".rules"), []byte("RewriteRule ^legacy$ /index.html [L]\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(.rules): %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	vhosts := `{
  "vhosts": [
    {
      "name": "docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9442,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "override_file_name": ".rules",
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
	ctx.Request = httptest.NewRequest(http.MethodGet, "/vhosts", nil)
	GetVhosts(ctx)
	if rec.Code != http.StatusOK {
		t.Fatalf("GetVhosts status=%d body=%s", rec.Code, rec.Body.String())
	}
	var resp struct {
		OverrideReports map[string]VhostOverrideImportReport `json:"override_reports"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}
	report, ok := resp.OverrideReports["docs-static"]
	if !ok || !report.Found || report.OverrideFileName != ".rules" {
		t.Fatalf("unexpected override reports: %+v", resp.OverrideReports)
	}
}

func boolPtrHT(v bool) *bool {
	return &v
}
