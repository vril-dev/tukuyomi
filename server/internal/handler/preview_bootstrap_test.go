package handler

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImportPreviewConfigStorageSeedsExplicitPolicyDomains(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)

	if err := ImportPreviewConfigStorage(PreviewBootstrapOptions{}); err != nil {
		t.Fatalf("ImportPreviewConfigStorage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}

	checks := []struct {
		domain    string
		normalize func(string) ([]byte, error)
	}{
		{domain: cacheConfigBlobKey, normalize: normalizeCacheRulesPolicyRaw},
		{domain: bypassConfigBlobKey, normalize: normalizeBypassPolicyRaw},
		{domain: countryBlockConfigBlobKey, normalize: normalizeCountryBlockPolicyRaw},
		{domain: rateLimitConfigBlobKey, normalize: normalizeRateLimitPolicyRaw},
		{domain: botDefenseConfigBlobKey, normalize: normalizeBotDefensePolicyRaw},
		{domain: semanticConfigBlobKey, normalize: normalizeSemanticPolicyRaw},
		{domain: notificationConfigBlobKey, normalize: normalizeNotificationPolicyRaw},
		{domain: ipReputationConfigBlobKey, normalize: normalizeIPReputationPolicyRaw},
	}
	for _, tc := range checks {
		raw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(tc.domain))
		if err != nil {
			t.Fatalf("loadActivePolicyJSONConfig(%s): %v", tc.domain, err)
		}
		if !found {
			t.Fatalf("policy domain %s was not seeded", tc.domain)
		}
		if strings.TrimSpace(string(raw)) == "" {
			t.Fatalf("policy domain %s stored empty raw", tc.domain)
		}
		if _, err := tc.normalize(string(raw)); err != nil {
			t.Fatalf("policy domain %s stored invalid raw: %v\n%s", tc.domain, err, string(raw))
		}
	}
}

func TestImportPreviewConfigStorageSeedsIPReputationFailOpen(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	initSettingsDBStoreForTest(t)

	if err := ImportPreviewConfigStorage(PreviewBootstrapOptions{}); err != nil {
		t.Fatalf("ImportPreviewConfigStorage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	raw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(ipReputationConfigBlobKey))
	if err != nil {
		t.Fatalf("loadActivePolicyJSONConfig(%s): %v", ipReputationConfigBlobKey, err)
	}
	if !found {
		t.Fatalf("policy domain %s was not seeded", ipReputationConfigBlobKey)
	}
	var cfg ipReputationFile
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatalf("json.Unmarshal(ip reputation raw): %v\n%s", err, string(raw))
	}
	if !cfg.Default.FailOpen {
		t.Fatalf("preview ip reputation default fail_open=%v want=true\n%s", cfg.Default.FailOpen, string(raw))
	}
}

func TestImportPreviewConfigStorageCanSeedProxyFromStartupBundle(t *testing.T) {
	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()
	seedDir := t.TempDir()
	seedBundlePath := filepath.Join(seedDir, "config-bundle.json")
	seedBundleRaw := []byte(`{
  "schema_version": 1,
  "source": "preview-protected-test",
  "domains": {
    "proxy": {
      "upstreams": [
        {"enabled": true, "name": "center", "url": "http://center-preview:9090", "weight": 1}
      ],
      "routes": [
        {
          "name": "center-ui",
          "priority": 20,
          "match": {"path": {"type": "prefix", "value": "/center-ui"}},
          "action": {"upstream": "center"}
        }
      ],
      "default_route": null,
      "health_check_path": "/healthz"
    }
  }
}` + "\n")
	if err := os.WriteFile(seedBundlePath, seedBundleRaw, 0o600); err != nil {
		t.Fatalf("write seed bundle: %v", err)
	}
	t.Setenv(startupSeedBundleFileEnv, seedBundlePath)
	t.Setenv(previewProxySeedFromStartupEnv, "1")
	initSettingsDBStoreForTest(t)

	if err := ImportPreviewConfigStorage(PreviewBootstrapOptions{}); err != nil {
		t.Fatalf("ImportPreviewConfigStorage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected db store")
	}
	proxyCfg, _, found, err := store.loadActiveProxyConfig()
	if err != nil {
		t.Fatalf("loadActiveProxyConfig: %v", err)
	}
	if !found {
		t.Fatal("expected proxy config")
	}
	if len(proxyCfg.Upstreams) != 1 || proxyCfg.Upstreams[0].Name != "center" || proxyCfg.Upstreams[0].URL != "http://center-preview:9090" {
		t.Fatalf("unexpected proxy upstreams: %+v", proxyCfg.Upstreams)
	}
	if len(proxyCfg.Routes) != 1 || proxyCfg.Routes[0].Name != "center-ui" || proxyCfg.Routes[0].Action.Upstream != "center" {
		t.Fatalf("unexpected proxy routes: %+v", proxyCfg.Routes)
	}
	if proxyCfg.HealthCheckPath != "/healthz" {
		t.Fatalf("health_check_path=%q want /healthz", proxyCfg.HealthCheckPath)
	}
}
