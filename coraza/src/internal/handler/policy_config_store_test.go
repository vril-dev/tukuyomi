package handler

import (
	"database/sql"
	"errors"
	"path/filepath"
	"testing"

	"tukuyomi/internal/bypassconf"
)

func TestNormalizedPolicyConfigStoresTypedRowsAndVersions(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "policy.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})
	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}

	cacheRaw, err := normalizeCacheRulesPolicyRaw(`{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": {"type": "prefix", "value": "/assets/"},
        "methods": ["GET", "HEAD"],
        "ttl": 120,
        "vary": ["Accept-Encoding"]
      }
    ]
  },
  "hosts": {
    "static.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": {"type": "exact", "value": "/private"},
          "ttl": 1
        }
      ]
    }
  }
}`)
	if err != nil {
		t.Fatalf("normalize cache rules: %v", err)
	}
	cacheSpec := mustPolicyJSONSpec(cacheConfigBlobKey)
	rec1, err := store.writePolicyJSONConfigVersion("", cacheSpec, cacheRaw, configVersionSourceImport, "", "test cache import", 0)
	if err != nil {
		t.Fatalf("write cache policy: %v", err)
	}
	loadedCache, loadedRec, found, err := store.loadActivePolicyJSONConfig(cacheSpec)
	if err != nil || !found {
		t.Fatalf("load cache found=%v err=%v", found, err)
	}
	if loadedRec.ETag != rec1.ETag {
		t.Fatalf("cache etag=%q want %q", loadedRec.ETag, rec1.ETag)
	}
	if _, err := normalizeCacheRulesPolicyRaw(string(loadedCache)); err != nil {
		t.Fatalf("loaded cache no longer validates: %v\n%s", err, string(loadedCache))
	}

	cacheRaw2, err := normalizeCacheRulesPolicyRaw(`{"default":{"rules":[]}}`)
	if err != nil {
		t.Fatalf("normalize cache rules 2: %v", err)
	}
	rec2, err := store.writePolicyJSONConfigVersion(rec1.ETag, cacheSpec, cacheRaw2, configVersionSourceApply, "", "test cache apply", 0)
	if err != nil {
		t.Fatalf("write cache policy 2: %v", err)
	}
	if _, err := store.writePolicyJSONConfigVersion(rec1.ETag, cacheSpec, cacheRaw, configVersionSourceApply, "", "stale cache apply", 0); !errors.Is(err, errConfigVersionConflict) {
		t.Fatalf("stale policy write err=%v want conflict", err)
	}
	rec3, err := store.writePolicyJSONConfigVersion(rec2.ETag, cacheSpec, cacheRaw, configVersionSourceRollback, "", "test cache rollback", rec1.VersionID)
	if err != nil {
		t.Fatalf("write cache rollback: %v", err)
	}
	if rec3.Generation != 3 || rec3.RestoredFromVersionID != rec1.VersionID {
		t.Fatalf("rollback rec=%+v want generation=3 restored_from=%d", rec3, rec1.VersionID)
	}

	names := []string{"REQUEST-920-PROTOCOL-ENFORCEMENT.conf", "REQUEST-941-APPLICATION-ATTACK-XSS.conf"}
	if _, err := store.writeCRSDisabledConfigVersion("", names, configVersionSourceImport, "", "test crs import", 0); err != nil {
		t.Fatalf("write crs disabled: %v", err)
	}
	loadedNames, _, found, err := store.loadActiveCRSDisabledConfig()
	if err != nil || !found {
		t.Fatalf("load crs found=%v err=%v", found, err)
	}
	if len(loadedNames) != 2 || loadedNames[0] != names[0] || loadedNames[1] != names[1] {
		t.Fatalf("loaded crs names=%v", loadedNames)
	}

	overrideRec, rules, err := store.writeManagedOverrideRulesVersion("", []managedOverrideRuleVersion{
		{Name: "one.conf", Raw: []byte("SecRule ARGS:test \"@rx one\" \"id:1001,phase:1,pass\"\n")},
		{Name: "two.conf", Raw: []byte("SecRule ARGS:test \"@rx two\" \"id:1002,phase:1,pass\"\n")},
	}, configVersionSourceImport, "", "test override import", 0)
	if err != nil {
		t.Fatalf("write override rules: %v", err)
	}
	loadedRules, loadedOverrideRec, found, err := store.loadActiveManagedOverrideRules()
	if err != nil || !found {
		t.Fatalf("load override found=%v err=%v", found, err)
	}
	if loadedOverrideRec.ETag != overrideRec.ETag || len(loadedRules) != len(rules) {
		t.Fatalf("loaded override rec=%+v rules=%v", loadedOverrideRec, loadedRules)
	}

	db := openPolicySQLiteForTest(t, dbPath)
	defer db.Close()
	for table, wantMin := range map[string]int{
		"cache_rule_scopes":       1,
		"cache_rules":             1,
		"cache_rule_methods":      1,
		"cache_rule_vary_headers": 1,
		"crs_disabled_rules":      2,
		"override_rules":          2,
		"override_rule_versions":  2,
	} {
		if got := countPolicyRowsForTest(t, db, table); got < wantMin {
			t.Fatalf("%s rows=%d want >= %d", table, got, wantMin)
		}
	}
	if got := rec3.Generation; got != 3 {
		t.Fatalf("cache generation=%d want 3", got)
	}
	if got := countPolicyRowsForTest(t, db, "config_rollbacks"); got != 1 {
		t.Fatalf("config_rollbacks rows=%d want 1", got)
	}
	for _, key := range []string{cacheConfigBlobKey, crsDisabledConfigBlobKey, overrideRuleConfigBlobKey("one.conf")} {
		if _, _, found, err := store.GetConfigBlob(key); err != nil || found {
			t.Fatalf("legacy config blob %q found=%v err=%v", key, found, err)
		}
	}
}

func TestPolicyWriteExpectedETagAllowsInitialDBWriteFromFallbackETag(t *testing.T) {
	store := initConfigDBStoreForTest(t)
	spec := mustPolicyJSONSpec(cacheConfigBlobKey)
	raw, err := normalizeCacheRulesPolicyRaw(`{"default":{"rules":[]}}`)
	if err != nil {
		t.Fatalf("normalize cache rules: %v", err)
	}

	fallbackETag := bypassconf.ComputeETag(raw)
	expected := policyWriteExpectedETag(fallbackETag, nil, configVersionRecord{})
	if expected != "" {
		t.Fatalf("initial expected etag=%q want empty", expected)
	}
	rec, err := store.writePolicyJSONConfigVersion(expected, spec, raw, configVersionSourceApply, "", "initial cache rules update", 0)
	if err != nil {
		t.Fatalf("initial policy write should not conflict: %v", err)
	}

	loadedRaw, loadedRec, found, err := store.loadActivePolicyJSONConfig(spec)
	if err != nil || !found {
		t.Fatalf("load active policy found=%v err=%v", found, err)
	}
	if loadedRec.ETag != rec.ETag {
		t.Fatalf("loaded etag=%q want %q", loadedRec.ETag, rec.ETag)
	}
	if translated := policyWriteExpectedETag(fallbackETag, loadedRaw, loadedRec); translated != loadedRec.ETag {
		t.Fatalf("content etag translated to %q want %q", translated, loadedRec.ETag)
	}
}

func openPolicySQLiteForTest(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func countPolicyRowsForTest(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}
