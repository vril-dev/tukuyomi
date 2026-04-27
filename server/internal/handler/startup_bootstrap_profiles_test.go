package handler

import (
	"path/filepath"
	"strings"
	"testing"

	"tukuyomi/internal/config"
)

func TestStartupProxySeedRaw_UsesImportProfileDefaults(t *testing.T) {
	t.Run("minimal-path-fallback", func(t *testing.T) {
		got := startupProxySeedRaw("conf/proxy.json", nil, false)
		if !strings.Contains(got, `"http://host.docker.internal:18080"`) {
			t.Fatalf("minimal proxy seed missing default upstream: %s", got)
		}
	})

	cases := []struct {
		name    string
		profile string
		want    string
	}{
		{name: "api-gateway", profile: "api-gateway", want: `"http://api:8080"`},
		{name: "nextjs", profile: "nextjs", want: `"http://nextjs:3000"`},
		{name: "wordpress", profile: "wordpress", want: `"http://wordpress:80"`},
		{name: "release-binary", profile: "release-binary", want: `"http://protected-api:8080"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(startupBootstrapProfileEnv, tc.profile)
			got := startupProxySeedRaw("conf/proxy.json", nil, false)
			if !strings.Contains(got, tc.want) {
				t.Fatalf("proxy seed missing %q in %s", tc.want, got)
			}
		})
	}
}

func TestStartupPolicySeedRaw_UsesImportProfileDefaults(t *testing.T) {
	cases := []struct {
		name    string
		profile string
		domain  string
		want    string
	}{
		{name: "api-gateway-bot-defense", profile: "api-gateway", domain: botDefenseConfigBlobKey, want: `"/v1/"`},
		{name: "nextjs-rate-limit", profile: "nextjs", domain: rateLimitConfigBlobKey, want: `"/api/auth"`},
		{name: "wordpress-bypass", profile: "wordpress", domain: bypassConfigBlobKey, want: `"/wp-admin/admin-ajax.php"`},
		{name: "release-binary-notifications-default", profile: "release-binary", domain: notificationConfigBlobKey, want: `"primary-webhook"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(startupBootstrapProfileEnv, tc.profile)
			got, err := startupPolicySeedRaw(tc.domain, nil, false)
			if err != nil {
				t.Fatalf("startupPolicySeedRaw(%s): %v", tc.domain, err)
			}
			if !strings.Contains(got, tc.want) {
				t.Fatalf("policy seed missing %q in %s", tc.want, got)
			}
		})
	}
}

func TestImportPolicyJSONStorage_SeedsProfileDefaultWhenFileMissing(t *testing.T) {
	restore := saveBypassAndCRSConfigForTest()
	defer restore()

	t.Setenv(startupBootstrapProfileEnv, "wordpress")

	tmp := t.TempDir()
	config.BypassFile = filepath.Join(tmp, "conf", "waf-bypass.json")

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := importPolicyJSONStorage(bypassConfigBlobKey, config.BypassFile, normalizeBypassPolicyRaw, "bypass rules seed import"); err != nil {
		t.Fatalf("import bypass storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.loadActivePolicyJSONConfig(mustPolicyJSONSpec(bypassConfigBlobKey))
	if err != nil || !found {
		t.Fatalf("expected bypass normalized rows to be seeded found=%v err=%v", found, err)
	}
	if !strings.Contains(string(gotRaw), "/wp-admin/admin-ajax.php") {
		t.Fatalf("expected wordpress bypass rule in %s", string(gotRaw))
	}
}
