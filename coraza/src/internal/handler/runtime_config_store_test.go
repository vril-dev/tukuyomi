package handler

import (
	"database/sql"
	"path/filepath"
	"testing"

	"tukuyomi/internal/config"
)

func TestNormalizedRuntimeConfigStoresVersionedTypedRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "store.db")
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

	bootstrapCfg, err := config.LoadAppConfigRaw([]byte(`{
  "storage": {
    "db_driver": "sqlite",
    "db_path": "bootstrap-only.db"
  }
}`))
	if err != nil {
		t.Fatalf("load bootstrap app config: %v", err)
	}
	candidateCfg, err := config.LoadAppConfigRaw([]byte(`{
  "server": {
    "listen_addr": ":19090"
  },
  "storage": {
    "db_driver": "mysql",
    "db_path": "must-not-be-authoritative.db",
    "db_dsn": "must-not-be-authoritative"
  },
  "paths": {
    "proxy_config_file": "conf/proxy-from-db.json"
  }
}`))
	if err != nil {
		t.Fatalf("load candidate app config: %v", err)
	}
	appRec, appCfg, err := store.writeAppConfigVersion("", candidateCfg, bootstrapCfg, configVersionSourceImport, "", "test app import", 0)
	if err != nil {
		t.Fatalf("write app config: %v", err)
	}
	loadedApp, loadedAppRec, found, err := store.loadActiveAppConfig(bootstrapCfg)
	if err != nil || !found {
		t.Fatalf("load active app config found=%v err=%v", found, err)
	}
	if loadedAppRec.ETag != appRec.ETag {
		t.Fatalf("app etag=%q want %q", loadedAppRec.ETag, appRec.ETag)
	}
	if loadedApp.Server.ListenAddr != ":19090" || loadedApp.Paths.ProxyConfigFile != "conf/proxy-from-db.json" {
		t.Fatalf("loaded app config mismatch: %+v", loadedApp)
	}
	if loadedApp.Storage.DBDriver != bootstrapCfg.Storage.DBDriver || loadedApp.Storage.DBPath != bootstrapCfg.Storage.DBPath || loadedApp.Storage.DBDSN != bootstrapCfg.Storage.DBDSN {
		t.Fatalf("bootstrap DB connection was not preserved: loaded=%+v bootstrap=%+v candidate=%+v", loadedApp.Storage, bootstrapCfg.Storage, appCfg.Storage)
	}

	siteA := SiteConfigFile{Sites: []SiteConfig{{
		Name:            "disabled-site",
		Enabled:         runtimeConfigBoolPtr(false),
		Hosts:           []string{"app.example.com"},
		DefaultUpstream: "http://127.0.0.1:8080",
		TLS:             SiteTLSConfig{Mode: "legacy"},
	}}}
	siteB := SiteConfigFile{Sites: []SiteConfig{{
		Name:            "disabled-site",
		Enabled:         runtimeConfigBoolPtr(false),
		Hosts:           []string{"app.example.com"},
		DefaultUpstream: "http://127.0.0.1:8081",
		TLS:             SiteTLSConfig{Mode: "legacy"},
	}}}
	rec1, err := store.writeSiteConfigVersion("", siteA, configVersionSourceImport, "", "test import", 0)
	if err != nil {
		t.Fatalf("write site import: %v", err)
	}
	rec2, err := store.writeSiteConfigVersion(rec1.ETag, siteB, configVersionSourceApply, "", "test apply", 0)
	if err != nil {
		t.Fatalf("write site apply: %v", err)
	}
	rec3, err := store.writeSiteConfigVersion(rec2.ETag, siteA, configVersionSourceRollback, "", "test rollback", rec1.VersionID)
	if err != nil {
		t.Fatalf("write site rollback: %v", err)
	}
	if rec1.Generation != 1 || rec2.Generation != 2 || rec3.Generation != 3 {
		t.Fatalf("site generations=%d,%d,%d want 1,2,3", rec1.Generation, rec2.Generation, rec3.Generation)
	}
	if rec3.RestoredFromVersionID != rec1.VersionID {
		t.Fatalf("restored_from=%d want %d", rec3.RestoredFromVersionID, rec1.VersionID)
	}
	loadedSite, loadedSiteRec, found, err := store.loadActiveSiteConfig()
	if err != nil || !found {
		t.Fatalf("load active site found=%v err=%v", found, err)
	}
	if loadedSiteRec.ETag != rec3.ETag || loadedSite.Sites[0].DefaultUpstream != "http://127.0.0.1:8080" {
		t.Fatalf("loaded site rec=%+v cfg=%+v", loadedSiteRec, loadedSite)
	}

	vhostCfg := VhostConfigFile{Vhosts: []VhostConfig{{
		Name:            "static-app",
		Mode:            "static",
		Hostname:        "127.0.0.1",
		ListenPort:      9401,
		DocumentRoot:    "data/vhosts/app/public",
		GeneratedTarget: "static-app",
		TryFiles:        []string{"$uri", "/index.html"},
		RewriteRules:    []VhostRewriteRule{{Pattern: "^/old$", Replacement: "/new", Flag: "last"}},
		AccessRules:     []VhostAccessRule{{PathPattern: "/admin/*", Action: "deny", CIDRs: []string{"127.0.0.1/32"}}},
		PHPValues:       map[string]string{"memory_limit": "128M"},
	}}}
	if _, err := store.writeVhostConfigVersion("", vhostCfg, configVersionSourceImport, "", "test import", 0); err != nil {
		t.Fatalf("write vhost: %v", err)
	}
	loadedVhost, _, found, err := store.loadActiveVhostConfig()
	if err != nil || !found {
		t.Fatalf("load active vhost found=%v err=%v", found, err)
	}
	if got := loadedVhost.Vhosts[0].OverrideFileName; got != "" {
		t.Fatalf("override_file_name persisted=%q want empty", got)
	}
	if got := loadedVhost.Vhosts[0].TryFiles[1]; got != "/index.html" {
		t.Fatalf("try_files[1]=%q", got)
	}

	taskCfg := ScheduledTaskConfigFile{Tasks: []ScheduledTaskRecord{{
		Name:       "cleanup",
		Enabled:    true,
		Schedule:   "*/5 * * * *",
		Command:    "php artisan queue:work",
		Env:        map[string]string{"APP_ENV": "prod"},
		TimeoutSec: 60,
	}}}
	if _, err := store.writeScheduledTaskConfigVersion("", taskCfg, configVersionSourceImport, "", "test import", 0); err != nil {
		t.Fatalf("write scheduled task: %v", err)
	}
	loadedTasks, _, found, err := store.loadActiveScheduledTaskConfig()
	if err != nil || !found {
		t.Fatalf("load active scheduled tasks found=%v err=%v", found, err)
	}
	if got := loadedTasks.Tasks[0].Env["APP_ENV"]; got != "prod" {
		t.Fatalf("scheduled env APP_ENV=%q", got)
	}

	key := proxyBackendLookupKey("primary", "http://127.0.0.1:8080")
	state := upstreamAdminStateDraining
	weight := 7
	runtimeFile := upstreamRuntimeFile{
		Version: upstreamRuntimeVersion,
		Backends: map[string]upstreamRuntimeOverride{
			key: {AdminState: &state, WeightOverride: &weight},
		},
	}
	if _, _, err := store.writeUpstreamRuntimeConfigVersion("", runtimeFile, nil, configVersionSourceImport, "", "test import", 0); err != nil {
		t.Fatalf("write upstream runtime: %v", err)
	}
	loadedRuntime, _, found, err := store.loadActiveUpstreamRuntimeConfig(nil)
	if err != nil || !found {
		t.Fatalf("load active upstream runtime found=%v err=%v", found, err)
	}
	if got := *loadedRuntime.Backends[key].WeightOverride; got != 7 {
		t.Fatalf("weight_override=%d want 7", got)
	}

	db := openSQLiteForRuntimeConfigTest(t, dbPath)
	defer db.Close()
	for table, want := range map[string]int{
		"sites":                      3,
		"site_hosts":                 3,
		"vhosts":                     1,
		"vhost_try_files":            2,
		"scheduled_tasks":            1,
		"scheduled_task_env":         1,
		"upstream_runtime_overrides": 1,
		"config_rollbacks":           1,
	} {
		if got := countRowsForRuntimeConfigTest(t, db, table); got != want {
			t.Fatalf("%s rows=%d want %d", table, got, want)
		}
	}
	if got := countRowsForRuntimeConfigTest(t, db, "app_config_values"); got == 0 {
		t.Fatal("app_config_values should contain typed scalar rows")
	}
	if got := countRowsForRuntimeConfigTest(t, db, "app_config_lists"); got == 0 {
		t.Fatal("app_config_lists should contain typed list rows")
	}
	for _, key := range []string{appConfigBlobKey, siteConfigBlobKey, scheduledTaskConfigBlobKey, upstreamRuntimeConfigBlobKey} {
		if _, _, found, err := store.GetConfigBlob(key); err != nil || found {
			t.Fatalf("legacy config blob %q found=%v err=%v", key, found, err)
		}
	}
}

func runtimeConfigBoolPtr(v bool) *bool {
	return &v
}

func openSQLiteForRuntimeConfigTest(t *testing.T, dbPath string) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	return db
}

func countRowsForRuntimeConfigTest(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	return count
}
