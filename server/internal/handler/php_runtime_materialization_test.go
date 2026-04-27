package handler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrepareProxyRulesRawWithSitesAndVhostsAddsGeneratedPHPTargets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	raw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "app"},
		},
	}))

	prepared, err := prepareProxyRulesRawWithSitesAndVhosts(raw, SiteConfigFile{}, VhostConfigFile{
		Vhosts: []VhostConfig{
			{
				Name:               "app",
				Mode:               "php-fpm",
				Hostname:           "app.example.com",
				ListenPort:         9081,
				DocumentRoot:       "apps/app/public",
				RuntimeID:          "php82",
				GeneratedTarget:    "app-php",
				LinkedUpstreamName: "app",
			},
		},
	})
	if err != nil {
		t.Fatalf("prepareProxyRulesRawWithSitesAndVhosts: %v", err)
	}

	upstream, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app-php")
	if !ok {
		t.Fatal("generated vhost upstream not found in effective config")
	}
	if upstream.URL != "fcgi://app.example.com:9081" {
		t.Fatalf("generated upstream url=%q want=%q", upstream.URL, "fcgi://app.example.com:9081")
	}
	if upstream.GeneratedKind != proxyUpstreamGeneratedKindVhostTarget {
		t.Fatalf("generated target kind=%q want=%q", upstream.GeneratedKind, proxyUpstreamGeneratedKindVhostTarget)
	}
	if upstream.ProviderClass != proxyUpstreamProviderClassVhostManaged {
		t.Fatalf("generated target provider_class=%q want=%q", upstream.ProviderClass, proxyUpstreamProviderClassVhostManaged)
	}
	if upstream.ManagedByVhost != "app" {
		t.Fatalf("generated target managed_by_vhost=%q want=app", upstream.ManagedByVhost)
	}
	configured, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app")
	if !ok {
		t.Fatal("configured upstream not found in effective config")
	}
	if configured.URL != "http://127.0.0.1:8080" {
		t.Fatalf("configured upstream url=%q want=%q", configured.URL, "http://127.0.0.1:8080")
	}
	if configured.GeneratedKind != "" {
		t.Fatalf("configured upstream generated kind=%q want empty", configured.GeneratedKind)
	}
	if configured.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("configured upstream provider_class=%q want=%q", configured.ProviderClass, proxyUpstreamProviderClassDirect)
	}
	if _, ok := findProxyRouteByName(prepared.effectiveCfg.Routes, "vhost:app"); ok {
		t.Fatal("vhost runtime listener must not synthesize a Host-header route")
	}
	if prepared.target == nil {
		t.Fatal("prepared target should not be nil")
	}
	if prepared.target.String() != "http://127.0.0.1:8080" {
		t.Fatalf("prepared target=%q want=%q", prepared.target.String(), "http://127.0.0.1:8080")
	}
}

func TestPrepareProxyRulesRawWithSitesAndVhostsAllowsVhostWithoutConfiguredLinkedUpstream(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	raw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{}))

	prepared, err := prepareProxyRulesRawWithSitesAndVhosts(raw, SiteConfigFile{}, VhostConfigFile{
		Vhosts: []VhostConfig{
			{
				Name:               "app",
				Mode:               "php-fpm",
				Hostname:           "app.example.com",
				ListenPort:         9081,
				DocumentRoot:       "apps/app/public",
				RuntimeID:          "php82",
				GeneratedTarget:    "app-php",
				LinkedUpstreamName: "app",
			},
		},
	})
	if err != nil {
		t.Fatalf("prepareProxyRulesRawWithSitesAndVhosts: %v", err)
	}
	if _, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app"); ok {
		t.Fatal("linked_upstream_name should not synthesize or require a configured upstream")
	}
	if upstream, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app-php"); !ok {
		t.Fatal("generated vhost upstream not found")
	} else if upstream.URL != "fcgi://app.example.com:9081" {
		t.Fatalf("generated upstream url=%q want fcgi://app.example.com:9081", upstream.URL)
	}
	if _, ok := findProxyRouteByName(prepared.effectiveCfg.Routes, "vhost:app"); ok {
		t.Fatal("vhost runtime listener must not synthesize a Host-header route")
	}
}

func TestPrepareProxyRulesRawWithSitesAndVhostsKeepsConfiguredUpstreamDirect(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	raw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
	}))

	prepared, err := prepareProxyRulesRawWithSitesAndVhosts(raw, SiteConfigFile{}, VhostConfigFile{
		Vhosts: []VhostConfig{
			{
				Name:               "app",
				Mode:               "php-fpm",
				Hostname:           "app.example.com",
				ListenPort:         9081,
				DocumentRoot:       "apps/app/public",
				RuntimeID:          "php82",
				GeneratedTarget:    "app-php",
				LinkedUpstreamName: "app",
			},
		},
	})
	if err != nil {
		t.Fatalf("prepareProxyRulesRawWithSitesAndVhosts: %v", err)
	}
	upstreamCount := 0
	for _, upstream := range prepared.effectiveCfg.Upstreams {
		if upstream.Name == "app" {
			upstreamCount++
		}
	}
	if upstreamCount != 1 {
		t.Fatalf("configured upstream count=%d want=1", upstreamCount)
	}
	upstream, ok := findProxyUpstreamByName(prepared.effectiveCfg.Upstreams, "app")
	if !ok {
		t.Fatal("configured upstream missing")
	}
	if upstream.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("configured upstream provider_class=%q want=%q", upstream.ProviderClass, proxyUpstreamProviderClassDirect)
	}
	if upstream.ManagedByVhost != "" {
		t.Fatalf("configured upstream managed_by_vhost=%q want empty", upstream.ManagedByVhost)
	}
	if upstream.URL != "http://127.0.0.1:8080" {
		t.Fatalf("configured upstream url=%q want=%q", upstream.URL, "http://127.0.0.1:8080")
	}
}

func TestApplyAndRollbackVhostConfigRawMaterializesRuntimeFiles(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
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
			{Name: "app", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
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
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, _, err := ApplyVhostConfigRaw(etag, nextVhosts); err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}

	snapshot := PHPRuntimeMaterializationSnapshot()
	if len(snapshot) != 1 {
		t.Fatalf("materialized runtime count=%d want=1", len(snapshot))
	}
	runtimeDir := filepath.Join(tmp, "runtime", "php82")
	configPath := filepath.Join(runtimeDir, "php-fpm.conf")
	poolPath := filepath.Join(runtimeDir, "pools", "app-php.conf")
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("stat php-fpm.conf: %v", err)
	}
	if _, err := os.Stat(poolPath); err != nil {
		t.Fatalf("stat pool file: %v", err)
	}
	configBody, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read php-fpm.conf: %v", err)
	}
	poolBody, err := os.ReadFile(poolPath)
	if err != nil {
		t.Fatalf("read pool file: %v", err)
	}
	expectedInclude := filepath.Join(runtimeDir, "pools", "*.conf")
	if !strings.Contains(string(configBody), "include = "+expectedInclude) {
		t.Fatalf("php-fpm.conf missing absolute include path: %s", string(configBody))
	}
	if !strings.Contains(string(poolBody), "listen = app.example.com:9081") {
		t.Fatalf("pool file missing listen directive: %s", string(poolBody))
	}
	expectedDocroot, err := filepath.Abs("apps/app/public")
	if err != nil {
		t.Fatalf("filepath.Abs(docroot): %v", err)
	}
	if !strings.Contains(string(poolBody), "chdir = "+expectedDocroot) {
		t.Fatalf("pool file missing absolute chdir: %s", string(poolBody))
	}
	if _, _, _, err := RollbackVhostConfig(); err != nil {
		t.Fatalf("RollbackVhostConfig: %v", err)
	}
	if _, err := os.Stat(runtimeDir); !os.IsNotExist(err) {
		t.Fatalf("runtime dir should be removed after rollback, err=%v", err)
	}
	if len(PHPRuntimeMaterializationSnapshot()) != 0 {
		t.Fatal("materialization snapshot should be empty after rollback")
	}
}

func TestRefreshPHPRuntimeMaterializationDoesNotCreateDefaultRuntimeDirForEmptyVhosts(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	t.Chdir(t.TempDir())

	if err := refreshPHPRuntimeMaterializationWithConfig(PHPRuntimeInventoryFile{}, VhostConfigFile{}); err != nil {
		t.Fatalf("refreshPHPRuntimeMaterializationWithConfig: %v", err)
	}
	if _, err := os.Stat(filepath.Join("data", "php-fpm", "runtime")); !os.IsNotExist(err) {
		t.Fatalf("empty vhost materialization should not create default runtime dir, stat err=%v", err)
	}
	if snapshot := PHPRuntimeMaterializationSnapshot(); len(snapshot) != 0 {
		t.Fatalf("materialized runtime count=%d want 0", len(snapshot))
	}
}

func TestApplyVhostConfigRawRefreshesProxyGeneratedTargets(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "app"},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, initialInventory, inventoryPath)
	importVhostRuntimeDBForTest(t, initialVhosts, inventoryCfg)
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

	cfg := currentProxyConfig()
	upstream, ok := findProxyUpstreamByName(cfg.Upstreams, "app-php")
	if !ok {
		t.Fatal("generated vhost upstream missing from current proxy config")
	}
	if upstream.URL != "fcgi://app.example.com:9081" {
		t.Fatalf("upstream url=%q want=%q", upstream.URL, "fcgi://app.example.com:9081")
	}

	_, etag, _, _ := VhostConfigSnapshot()
	updatedVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9082,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	if _, _, err := ApplyVhostConfigRaw(etag, updatedVhosts); err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}

	cfg = currentProxyConfig()
	upstream, ok = findProxyUpstreamByName(cfg.Upstreams, "app-php")
	if !ok {
		t.Fatal("generated vhost upstream missing from current proxy config after refresh")
	}
	if upstream.URL != "fcgi://app.example.com:9082" {
		t.Fatalf("refreshed upstream url=%q want=%q", upstream.URL, "fcgi://app.example.com:9082")
	}
}

func TestApplyVhostConfigRawIgnoresLinkedUpstreamRenameForRouting(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "app"},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, initialInventory, inventoryPath)
	importVhostRuntimeDBForTest(t, initialVhosts, inventoryCfg)
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
	updatedVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app-next"
    }
  ]
}`
	if _, _, err := ApplyVhostConfigRaw(etag, updatedVhosts); err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}
	cfg := currentProxyConfig()
	upstream, ok := findProxyUpstreamByName(cfg.Upstreams, "app")
	if !ok {
		t.Fatal("configured upstream app missing")
	}
	if upstream.URL != "http://127.0.0.1:8080" || upstream.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("configured upstream app changed unexpectedly: %#v", upstream)
	}
	if _, ok := findProxyRouteByName(cfg.Routes, "vhost:app"); ok {
		t.Fatal("vhost runtime listener must not synthesize a Host-header route")
	}
}

func TestApplyVhostConfigRawKeepsAlternateConfiguredUpstreamDirect(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
			{Name: "app-next", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
			{Name: "primary", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "primary"},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, initialInventory, inventoryPath)
	importVhostRuntimeDBForTest(t, initialVhosts, inventoryCfg)
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
	updatedVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app-next"
    }
  ]
}`
	if _, _, err := ApplyVhostConfigRaw(etag, updatedVhosts); err != nil {
		t.Fatalf("ApplyVhostConfigRaw: %v", err)
	}

	cfg := currentProxyConfig()
	prev, ok := findProxyUpstreamByName(cfg.Upstreams, "app")
	if !ok {
		t.Fatal("previous configured upstream missing after relink")
	}
	if prev.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("previous upstream provider_class=%q want=%q", prev.ProviderClass, proxyUpstreamProviderClassDirect)
	}
	if prev.URL != "http://127.0.0.1:8080" {
		t.Fatalf("previous upstream url=%q want=%q", prev.URL, "http://127.0.0.1:8080")
	}
	next, ok := findProxyUpstreamByName(cfg.Upstreams, "app-next")
	if !ok {
		t.Fatal("alternate configured upstream missing")
	}
	if next.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("provider_class=%q want=%q", next.ProviderClass, proxyUpstreamProviderClassDirect)
	}
	if next.ManagedByVhost != "" {
		t.Fatalf("managed_by_vhost=%q want empty", next.ManagedByVhost)
	}
}

func TestApplyVhostConfigRawRestoresConfiguredUpstreamWhenDeletingVhost(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "app"},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
	}
	writeTestPHPRuntimeArtifact(t, inventoryPath, "php82", testPHPRuntimeArtifactOptions{
		DisplayName: "PHP 8.2",
		Version:     "PHP 8.2.99 (fpm-fcgi)",
		Modules:     []string{"mbstring", "redis"},
	})
	initConfigDBStoreForTest(t)
	inventoryCfg := importPHPRuntimeInventoryDBForTest(t, initialInventory, inventoryPath)
	importVhostRuntimeDBForTest(t, initialVhosts, inventoryCfg)
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
	if _, _, err := ApplyVhostConfigRaw(etag, `{"vhosts":[]}`); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	cfg := currentProxyConfig()
	upstream, ok := findProxyUpstreamByName(cfg.Upstreams, "app")
	if !ok {
		t.Fatal("configured upstream missing after deleting vhost")
	}
	if upstream.ProviderClass != proxyUpstreamProviderClassDirect {
		t.Fatalf("provider_class=%q want=%q", upstream.ProviderClass, proxyUpstreamProviderClassDirect)
	}
	if upstream.URL != "http://127.0.0.1:8080" {
		t.Fatalf("url=%q want=%q", upstream.URL, "http://127.0.0.1:8080")
	}
}

func TestValidateProxyRulesRawAllowsDeletingDirectUpstreamReferencedOnlyByLegacyLinkedName(t *testing.T) {
	restore := resetPHPProxyFoundationForTest(t)
	defer restore()

	tmp := t.TempDir()
	inventoryPath := filepath.Join(tmp, "inventory.json")
	vhostPath := filepath.Join(tmp, "vhosts.json")
	proxyPath := filepath.Join(tmp, "proxy.json")
	initialInventory := defaultPHPRuntimeInventoryRaw
	initialVhosts := `{
  "vhosts": [
    {
      "name": "app",
      "mode": "php-fpm",
      "hostname": "app.example.com",
      "listen_port": 9081,
      "document_root": "apps/app/public",
      "runtime_id": "php82",
      "generated_target": "app-php",
      "linked_upstream_name": "app"
    }
  ]
}`
	proxyRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "app", URL: "http://127.0.0.1:8080", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "app"},
		},
	}))
	if err := os.WriteFile(inventoryPath, []byte(initialInventory), 0o600); err != nil {
		t.Fatalf("write inventory: %v", err)
	}
	if err := os.WriteFile(vhostPath, []byte(initialVhosts), 0o600); err != nil {
		t.Fatalf("write vhosts: %v", err)
	}
	if err := os.WriteFile(proxyPath, []byte(proxyRaw), 0o600); err != nil {
		t.Fatalf("write proxy: %v", err)
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
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}

	nextRaw := mustJSON(normalizeProxyRulesConfig(ProxyRulesConfig{
		Upstreams: []ProxyUpstream{
			{Name: "primary", URL: "http://127.0.0.1:8081", Weight: 1, Enabled: true},
		},
		DefaultRoute: &ProxyDefaultRoute{
			Action: ProxyRouteAction{Upstream: "primary"},
		},
	}))
	if _, err := ValidateProxyRulesRaw(nextRaw); err != nil {
		t.Fatalf("ValidateProxyRulesRaw: %v", err)
	}
}

func resetPHPProxyFoundationForTest(t *testing.T) func() {
	t.Helper()

	restore := resetPHPFoundationRuntimesForTest(t)

	proxyRuntimeMu.Lock()
	prevProxy := proxyRt
	proxyRt = nil
	proxyRuntimeMu.Unlock()

	siteRuntimeMu.Lock()
	prevSite := siteRt
	siteRt = nil
	siteRuntimeMu.Unlock()

	return func() {
		proxyRuntimeMu.Lock()
		proxyRt = prevProxy
		proxyRuntimeMu.Unlock()

		siteRuntimeMu.Lock()
		siteRt = prevSite
		siteRuntimeMu.Unlock()

		restore()
	}
}

func findProxyUpstreamByName(in []ProxyUpstream, name string) (ProxyUpstream, bool) {
	for _, upstream := range in {
		if upstream.Name == name {
			return upstream, true
		}
	}
	return ProxyUpstream{}, false
}

func findProxyRouteByName(in []ProxyRoute, name string) (ProxyRoute, bool) {
	for _, route := range in {
		if route.Name == name {
			return route, true
		}
	}
	return ProxyRoute{}, false
}
