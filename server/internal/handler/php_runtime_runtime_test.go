package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestValidateVhostConfigRawRequiresKnownRuntime(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "generated_target": "app-php",
      "runtime_id": "missing",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err == nil {
		t.Fatal("expected missing runtime validation error")
	} else if !strings.Contains(err.Error(), `references unknown runtime "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVhostConfigRawAcceptsKnownRuntimeWithoutSupportToggle(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "generated_target": "app-php",
      "runtime_id": "php82",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateVhostConfigRawGeneratesHiddenTargetWhenOmitted(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "linked_upstream_name": "app"
    },
    {
      "name": "app php",
      "mode": "php-fpm",
      "hostname": "app-php.example.com",
      "listen_port": 9082,
      "document_root": "apps/app-php/public",
      "runtime_id": "php82",
      "linked_upstream_name": "app-upstream"
    }
  ]
}`
	cfg, err := ValidateVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Vhosts) != 2 {
		t.Fatalf("vhost count=%d want=2", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].GeneratedTarget != "app-php" {
		t.Fatalf("first generated_target=%q want app-php", cfg.Vhosts[0].GeneratedTarget)
	}
	if cfg.Vhosts[1].GeneratedTarget != "app-php-2" {
		t.Fatalf("second generated_target=%q want app-php-2", cfg.Vhosts[1].GeneratedTarget)
	}
}

func TestValidateVhostConfigRawAllowsOmittedLinkedUpstreamName(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php"
    }
  ]
}`
	cfg, err := ValidateVhostConfigRawWithInventory(raw, inventory)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Vhosts[0].LinkedUpstreamName != "" {
		t.Fatalf("linked_upstream_name=%q want empty", cfg.Vhosts[0].LinkedUpstreamName)
	}
}

func TestValidateVhostConfigRawRejectsDuplicateLinkedUpstreamNames(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	inventory := PHPRuntimeInventoryFile{
		Runtimes: []PHPRuntimeRecord{
			{
				RuntimeID:  "php82",
				BinaryPath: "data/php-fpm/binaries/php82/php-fpm",
				Modules:    []string{"mbstring", "redis"},
				Source:     "bundled",
			},
		},
	}
	raw := `{
  "vhosts": [
    {
      "name": "app1",
      "mode": "php-fpm",
      "hostname": "app1.example.com",
      "listen_port": 9081,
      "document_root": "apps/app1/public",
      "runtime_id": "php82",
      "generated_target": "app1-php",
      "linked_upstream_name": "app"
    },
    {
      "name": "app2",
      "mode": "php-fpm",
      "hostname": "app2.example.com",
      "listen_port": 9082,
      "document_root": "apps/app2/public",
      "runtime_id": "php82",
      "generated_target": "app2-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, err := ValidateVhostConfigRawWithInventory(raw, inventory); err == nil || !strings.Contains(err.Error(), `duplicates "app"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPHPRuntimeInventoryListsOnlyBuiltArtifacts(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if runtime.RuntimeID != "php83" {
		t.Fatalf("runtime_id=%q want=php83", runtime.RuntimeID)
	}
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.CLIBinaryPath, filepath.ToSlash(filepath.Join(filepath.Dir(runtime.BinaryPath), "php")); got != want {
		t.Fatalf("cli_binary_path=%q want=%q", got, want)
	}
	if got, want := runtime.Modules, []string{"mbstring", "fileinfo", "redis"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if got, want := runtime.DefaultDisabledModules, []string{}; !slices.Equal(got, want) {
		t.Fatalf("default_disabled_modules=%v want=%v", got, want)
	}
}

func TestApplyPHPRuntimeInventoryRawDoesNotDeadlockOnMaterializationRefresh(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, defaultPHPRuntimeInventoryRaw, inventoryPath)
	importVhostRuntimeDBForTest(t, defaultVhostConfigRaw, inventoryCfg)
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	_, etag, _, _ := PHPRuntimeInventorySnapshot()
	nextInventory := "{}"

	done := make(chan error, 1)
	go func() {
		_, _, err := ApplyPHPRuntimeInventoryRaw(etag, nextInventory)
		done <- err
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ApplyPHPRuntimeInventoryRaw: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("ApplyPHPRuntimeInventoryRaw timed out; possible self-deadlock while refreshing materialization")
	}
}

func TestApplyAndRollbackVhostConfigRaw(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "marketing-app-upstream", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
			{Name: "static-docs-upstream", URL: "http://127.0.0.1:8082", Weight: 1, Enabled: true},
			{Name: "primary", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
	}))
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, defaultPHPRuntimeInventoryRaw, inventoryPath)
	importVhostRuntimeDBForTest(t, defaultVhostConfigRaw, inventoryCfg)
	importProxyRuntimeDBForTest(t, proxyRaw)
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	_, etag, _, _ := VhostConfigSnapshot()
	nextVhosts := `{
  "vhosts": [
    {
      "name": "marketing app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "linked_upstream_name": "marketing-app-upstream"
    },
    {
      "name": "static docs",
      "mode": "static",
      "hostname": "docs.example.com",
      "listen_port": 9082,
      "document_root": "apps/docs/public",
      "linked_upstream_name": "static-docs-upstream"
    }
  ]
}`
	newETag, cfg, err := ApplyVhostConfigRaw(etag, nextVhosts)
	if err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}
	if newETag == "" || newETag == etag {
		t.Fatalf("unexpected etag transition old=%q new=%q", etag, newETag)
	}
	if len(cfg.Vhosts) != 2 {
		t.Fatalf("vhost count=%d want=2", len(cfg.Vhosts))
	}
	if cfg.Vhosts[0].GeneratedTarget != "marketing-app" {
		t.Fatalf("generated_target=%q want=%q", cfg.Vhosts[0].GeneratedTarget, "marketing-app")
	}
	if cfg.Vhosts[1].RuntimeID != "" {
		t.Fatalf("static runtime_id=%q want empty", cfg.Vhosts[1].RuntimeID)
	}

	rolledETag, rolledCfg, restored, err := RollbackVhostConfig()
	if err != nil {
		t.Fatalf("RollbackVhostConfig: %v", err)
	}
	if rolledETag == "" {
		t.Fatal("rollback etag should not be empty")
	}
	if restored.ETag != etag {
		t.Fatalf("restored etag=%q want=%q", restored.ETag, etag)
	}
	if len(rolledCfg.Vhosts) != 0 {
		t.Fatalf("vhost count after rollback=%d want=0", len(rolledCfg.Vhosts))
	}
}

func TestGetPHPRuntimesAndVhostsHandlers(t *testing.T) {
	gin.SetMode(gin.TestMode)

	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	docroot := filepath.Join(tmp, "apps", "app", "public")
	if err := os.MkdirAll(docroot, 0o755); err != nil {
		t.Fatalf("MkdirAll(docroot): %v", err)
	}

	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    },
    {
      "name": "static",
      "mode": "static",
      "hostname": "static.example.com",
      "listen_port": 9082,
      "document_root": "` + filepath.ToSlash(docroot) + `",
      "generated_target": "app-static",
      "linked_upstream_name": "static"
    }
  ]
}`
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	runtimeRec := httptest.NewRecorder()
	runtimeCtx, _ := gin.CreateTestContext(runtimeRec)
	runtimeCtx.Request = httptest.NewRequest(http.MethodGet, "/php-runtimes", nil)
	GetPHPRuntimes(runtimeCtx)
	if runtimeRec.Code != http.StatusOK {
		t.Fatalf("GetPHPRuntimes status=%d body=%s", runtimeRec.Code, runtimeRec.Body.String())
	}
	var runtimeResp struct {
		ETag         string                         `json:"etag"`
		Raw          string                         `json:"raw"`
		Runtimes     PHPRuntimeInventoryFile        `json:"runtimes"`
		Materialized []PHPRuntimeMaterializedStatus `json:"materialized"`
	}
	if err := json.Unmarshal(runtimeRec.Body.Bytes(), &runtimeResp); err != nil {
		t.Fatalf("runtime response json: %v", err)
	}
	if runtimeResp.ETag == "" || runtimeResp.Raw == "" {
		t.Fatalf("runtime response missing etag/raw: %s", runtimeRec.Body.String())
	}
	if len(runtimeResp.Runtimes.Runtimes) != 1 || runtimeResp.Runtimes.Runtimes[0].RuntimeID != "php82" {
		t.Fatalf("runtime listing mismatch: %+v", runtimeResp.Runtimes)
	}
	if !slices.Contains(runtimeResp.Runtimes.Runtimes[0].Modules, "redis") {
		t.Fatalf("modules=%v want redis", runtimeResp.Runtimes.Runtimes[0].Modules)
	}
	if len(runtimeResp.Runtimes.Runtimes[0].DefaultDisabledModules) != 0 {
		t.Fatalf("default_disabled_modules=%v want empty", runtimeResp.Runtimes.Runtimes[0].DefaultDisabledModules)
	}
	if len(runtimeResp.Materialized) != 1 || runtimeResp.Materialized[0].RuntimeID != "php82" {
		t.Fatalf("materialized runtime mismatch: %+v", runtimeResp.Materialized)
	}

	vhostRec := httptest.NewRecorder()
	vhostCtx, _ := gin.CreateTestContext(vhostRec)
	vhostCtx.Request = httptest.NewRequest(http.MethodGet, "/vhosts", nil)
	GetVhosts(vhostCtx)
	if vhostRec.Code != http.StatusOK {
		t.Fatalf("GetVhosts status=%d body=%s", vhostRec.Code, vhostRec.Body.String())
	}
	var vhostResp struct {
		ETag   string          `json:"etag"`
		Raw    string          `json:"raw"`
		Vhosts VhostConfigFile `json:"vhosts"`
	}
	if err := json.Unmarshal(vhostRec.Body.Bytes(), &vhostResp); err != nil {
		t.Fatalf("vhost response json: %v", err)
	}
	if vhostResp.ETag == "" || vhostResp.Raw == "" {
		t.Fatalf("vhost response missing etag/raw: %s", vhostRec.Body.String())
	}
	if len(vhostResp.Vhosts.Vhosts) != 2 {
		t.Fatalf("vhost count=%d want=2", len(vhostResp.Vhosts.Vhosts))
	}
}

func TestValidatePHPRuntimeInventoryRawIgnoresLegacyPHPSupportFlag(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	cfg, err := ValidatePHPRuntimeInventoryRaw(`{
  "php_enabled": true
}`)
	if err != nil {
		t.Fatalf("ValidatePHPRuntimeInventoryRaw: %v", err)
	}
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0", len(cfg.Runtimes))
	}
}

func TestDefaultPHPRuntimeInventoryStartsEmptyUntilRuntimeIsBuilt(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	prepared, err := preparePHPRuntimeInventoryRaw(defaultPHPRuntimeInventoryRaw, inventoryPath)
	if err != nil {
		t.Fatalf("preparePHPRuntimeInventoryRaw(default): %v", err)
	}
	if len(prepared.cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0", len(prepared.cfg.Runtimes))
	}
}

func TestValidatePHPRuntimeInventoryRawLoadsBuiltArtifactModulesAndDefaults(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(defaultVhostConfigRaw), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis", "fileinfo"},
	})
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if err := InitVhostRuntime(vhostPath, 2); err != nil {
		t.Fatalf("InitVhostRuntime: %v", err)
	}

	cfg, err := ValidatePHPRuntimeInventoryRaw("{}")
	if err != nil {
		t.Fatalf("ValidatePHPRuntimeInventoryRaw: %v", err)
	}
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.Modules, []string{"mbstring", "redis", "fileinfo"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if got, want := runtime.DefaultDisabledModules, []string{}; !slices.Equal(got, want) {
		t.Fatalf("default_disabled_modules=%v want=%v", got, want)
	}
}

func TestPHPRuntimeInventoryDBLoadsWithoutInventoryOrManifestJSON(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	binaryPath := writeTestPHPRuntimeArtifact(t, inventoryPath, "php83", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.3",
		Version:     "PHP 8.3.21 (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})
	explicitInventory := mustJSON(PHPRuntimeInventoryFile{Runtimes: []PHPRuntimeRecord{{
		RuntimeID:              "php83",
		DisplayName:            "PHP 8.3",
		DetectedVersion:        "PHP 8.3.21 (fpm-fcgi)",
		BinaryPath:             filepath.ToSlash(binaryPath),
		CLIBinaryPath:          filepath.ToSlash(filepath.Join(filepath.Dir(binaryPath), "php")),
		Modules:                []string{"mbstring", "fileinfo", "redis"},
		DefaultDisabledModules: []string{},
		Source:                 "bundled",
	}}})
	if err := os.WriteFile(inventoryPath, []byte(explicitInventory), 0o600); err != nil {
		t.Fatalf("write explicit inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}

	runtimeDir := filepath.Dir(binaryPath)
	for _, path := range []string{
		inventoryPath,
		filepath.Join(runtimeDir, "runtime.json"),
		filepath.Join(runtimeDir, "modules.json"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			t.Fatalf("remove %s: %v", path, err)
		}
	}

	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	raw, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if strings.Contains(raw, "runtime.json") || strings.Contains(raw, "modules.json") {
		t.Fatalf("raw inventory should not reference deleted manifest paths: %s", raw)
	}
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1", len(cfg.Runtimes))
	}
	runtime := cfg.Runtimes[0]
	if runtime.RuntimeID != "php83" {
		t.Fatalf("runtime_id=%q want php83", runtime.RuntimeID)
	}
	if !runtime.Available {
		t.Fatalf("runtime available=%v want=true (%s)", runtime.Available, runtime.AvailabilityMessage)
	}
	if got, want := runtime.Modules, []string{"mbstring", "fileinfo", "redis"}; !slices.Equal(got, want) {
		t.Fatalf("modules=%v want=%v", got, want)
	}
	if _, err := os.Stat(inventoryPath); !os.IsNotExist(err) {
		t.Fatalf("inventory json should not be recreated, stat err=%v", err)
	}
}

func TestPHPRuntimeInventoryDBAutoDiscoveryReflectsBuiltArtifactsAfterStartup(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count before build=%d want=0", len(cfg.Runtimes))
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ = PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count after build=%d want=1", len(cfg.Runtimes))
	}
	if got := cfg.Runtimes[0].RuntimeID; got != "php85" {
		t.Fatalf("runtime_id=%q want php85", got)
	}
	if !cfg.Runtimes[0].Available {
		t.Fatalf("runtime available=%v want=true (%s)", cfg.Runtimes[0].Available, cfg.Runtimes[0].AvailabilityMessage)
	}
}

func TestPHPRuntimeInventoryDBExplicitEmptyDoesNotAutoDiscover(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(`{"runtimes":[]}`), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 0 {
		t.Fatalf("runtime count=%d want=0 for explicit empty inventory", len(cfg.Runtimes))
	}
}

func TestPHPRuntimeInventoryDBLegacyImportWithoutStateAutoDiscovers(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	if _, err := store.exec(`DELETE FROM php_runtime_inventory_state`); err != nil {
		t.Fatalf("delete php runtime inventory state: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}

	writeTestPHPRuntimeArtifact(t, inventoryPath, "php85", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.5",
		Version:     "PHP 8.5.0-dev (fpm-fcgi)",
		Modules:     []string{"mbstring", "fileinfo", "redis"},
	})

	_, _, cfg, _ := PHPRuntimeInventorySnapshot()
	if len(cfg.Runtimes) != 1 {
		t.Fatalf("runtime count=%d want=1 for legacy import without inventory state", len(cfg.Runtimes))
	}
	if got := cfg.Runtimes[0].RuntimeID; got != "php85" {
		t.Fatalf("runtime_id=%q want php85", got)
	}
}

func TestInitPHPRuntimeInventoryRuntimeDoesNotDeleteMaterializedRuntimesBeforeVhostsLoad(t *testing.T) {
	restore := resetPHPFoundationRuntimesForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "data", "php-fpm", "inventory.json")
	if err := os.MkdirAll(filepath.Dir(inventoryPath), 0o755); err != nil {
		t.Fatalf("mkdir inventory dir: %v", err)
	}
	if err := os.WriteFile(inventoryPath, []byte(defaultPHPRuntimeInventoryRaw), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	runtimeDir := filepath.Join(filepath.Dir(inventoryPath), "runtime", "php85")
	sentinel := filepath.Join(runtimeDir, "php-fpm.conf")
	if err := os.MkdirAll(runtimeDir, 0o755); err != nil {
		t.Fatalf("mkdir runtime dir: %v", err)
	}
	if err := os.WriteFile(sentinel, []byte("[global]\n"), 0o600); err != nil {
		t.Fatalf("write sentinel runtime config: %v", err)
	}

	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	oldInventoryPath := config.PHPRuntimeInventoryFile
	config.PHPRuntimeInventoryFile = inventoryPath
	t.Cleanup(func() {
		config.PHPRuntimeInventoryFile = oldInventoryPath
	})
	if err := importPHPRuntimeInventoryStorage(); err != nil {
		t.Fatalf("import php runtime inventory: %v", err)
	}
	if err := InitPHPRuntimeInventoryRuntime(inventoryPath, 2); err != nil {
		t.Fatalf("InitPHPRuntimeInventoryRuntime: %v", err)
	}
	if _, err := os.Stat(sentinel); err != nil {
		t.Fatalf("materialized runtime config should remain until vhost runtime owns refresh: %v", err)
	}
}

func resetPHPFoundationRuntimesForTest(t *testing.T) func() {
	t.Helper()

	phpRuntimeInventoryMu.Lock()
	prevInventory := phpRuntimeInventoryRt
	phpRuntimeInventoryRt = nil
	phpRuntimeInventoryMu.Unlock()

	vhostRuntimeMu.Lock()
	prevVhost := vhostRt
	vhostRt = nil
	vhostRuntimeMu.Unlock()

	proxyRuntimeMu.Lock()
	prevProxy := proxyRt
	proxyRt = nil
	proxyRuntimeMu.Unlock()

	siteRuntimeMu.Lock()
	prevSite := siteRt
	siteRt = nil
	siteRuntimeMu.Unlock()

	phpRuntimeSupervisorMu.Lock()
	prevSupervisor := phpRuntimeSupervisorRt
	phpRuntimeSupervisorRt = nil
	phpRuntimeSupervisorMu.Unlock()

	phpRuntimeMaterializationMu.Lock()
	prevMaterialized := phpRuntimeMaterialized
	phpRuntimeMaterialized = nil
	phpRuntimeMaterializationMu.Unlock()

	scheduledTaskRuntimeMu.Lock()
	prevScheduledTasks := scheduledTaskRt
	scheduledTaskRt = nil
	scheduledTaskRuntimeMu.Unlock()

	return func() {
		phpRuntimeInventoryMu.Lock()
		phpRuntimeInventoryRt = prevInventory
		phpRuntimeInventoryMu.Unlock()

		vhostRuntimeMu.Lock()
		vhostRt = prevVhost
		vhostRuntimeMu.Unlock()

		proxyRuntimeMu.Lock()
		proxyRt = prevProxy
		proxyRuntimeMu.Unlock()

		siteRuntimeMu.Lock()
		siteRt = prevSite
		siteRuntimeMu.Unlock()

		phpRuntimeSupervisorMu.Lock()
		currentSupervisor := phpRuntimeSupervisorRt
		phpRuntimeSupervisorRt = prevSupervisor
		phpRuntimeSupervisorMu.Unlock()
		if currentSupervisor != nil {
			_ = currentSupervisor.shutdown()
		}

		phpRuntimeMaterializationMu.Lock()
		phpRuntimeMaterialized = prevMaterialized
		phpRuntimeMaterializationMu.Unlock()

		scheduledTaskRuntimeMu.Lock()
		scheduledTaskRt = prevScheduledTasks
		scheduledTaskRuntimeMu.Unlock()
	}
}
