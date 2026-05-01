package handler

import (
	"database/sql"
	"path/filepath"
	"testing"
)

const latestSchemaMigrationVersionForTest = 29

func TestMigrateLogsStatsStoreWithBackendSQLiteCreatesSchemaAndRecordsMigrations(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tukuyomi.db")

	if err := MigrateLogsStatsStoreWithBackend("db", "sqlite", dbPath, ""); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}
	if err := MigrateLogsStatsStoreWithBackend("db", "sqlite", dbPath, ""); err != nil {
		t.Fatalf("migrate sqlite second run: %v", err)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	for _, table := range []string{
		"waf_events",
		"ingest_state",
		"config_blobs",
		"schema_migrations",
		"config_domains",
		"config_versions",
		"config_rollbacks",
		"proxy_settings",
		"proxy_upstreams",
		"proxy_routes",
		"sites",
		"vhosts",
		"scheduled_tasks",
		"upstream_runtime_overrides",
		"php_runtime_inventory",
		"php_runtime_inventory_state",
		"php_runtime_modules",
		"php_runtime_default_disabled_modules",
		"app_config_values",
		"app_config_lists",
		"cache_rule_scopes",
		"cache_rules",
		"cache_rule_methods",
		"cache_rule_vary_headers",
		"bypass_scopes",
		"bypass_entries",
		"country_block_scopes",
		"country_block_countries",
		"rate_limit_scopes",
		"rate_limit_rules",
		"rate_limit_rule_methods",
		"bot_defense_scopes",
		"bot_defense_path_policies",
		"semantic_scopes",
		"notification_settings",
		"notification_sinks",
		"ip_reputation_scopes",
		"response_cache_config",
		"crs_disabled_rules",
		"override_rules",
		"override_rule_versions",
		"waf_rule_assets",
		"waf_rule_asset_contents",
		"scheduled_task_runtime_state",
		"request_country_mmdb_assets",
		"request_country_geoip_configs",
		"request_country_geoip_config_editions",
		"request_country_update_state",
		"admin_users",
		"admin_api_tokens",
		"admin_sessions",
		"admin_auth_audit",
		"center_devices",
		"center_device_enrollments",
		"center_enrollment_tokens",
		"center_device_config_snapshots",
		"center_device_runtime_summaries",
		"center_runtime_artifacts",
		"center_runtime_artifact_files",
		"center_device_runtime_assignments",
		"center_device_runtime_apply_status",
		"center_rule_artifact_bundles",
		"center_rule_artifact_files",
		"edge_device_identities",
	} {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	var version int
	var dirty int
	if err := db.QueryRow(`SELECT version, CASE WHEN dirty THEN 1 ELSE 0 END FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("query migration version: %v", err)
	}
	if version != latestSchemaMigrationVersionForTest || dirty != 0 {
		t.Fatalf("migration version=%d dirty=%d want version=%d dirty=0", version, dirty, latestSchemaMigrationVersionForTest)
	}
	var wafRuleAssetEnabledColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('waf_rule_assets') WHERE name = 'enabled'`).Scan(&wafRuleAssetEnabledColumns); err != nil {
		t.Fatalf("query waf_rule_assets enabled column: %v", err)
	}
	if wafRuleAssetEnabledColumns != 1 {
		t.Fatalf("waf_rule_assets enabled column count=%d want 1", wafRuleAssetEnabledColumns)
	}
	for _, column := range []string{"acme_environment", "acme_email"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('site_tls') WHERE name = ?`, column).Scan(&count); err != nil {
			t.Fatalf("query site_tls column %s: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("site_tls column %s count=%d want 1", column, count)
		}
	}
	for _, column := range []string{"username_normalized", "password_hash", "session_version"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('admin_users') WHERE name = ?`, column).Scan(&count); err != nil {
			t.Fatalf("query admin_users column %s: %v", column, err)
		}
		if count != 1 {
			t.Fatalf("admin_users column %s count=%d want 1", column, count)
		}
	}
	for _, indexName := range []string{"uq_admin_users_username_normalized", "uq_admin_api_tokens_token_hash", "uq_admin_sessions_session_token_hash"} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type = 'index' AND name = ?`, indexName).Scan(&count); err != nil {
			t.Fatalf("query index %s: %v", indexName, err)
		}
		if count != 1 {
			t.Fatalf("index %s count=%d want 1", indexName, count)
		}
	}
	for _, tc := range []struct {
		table  string
		column string
	}{
		{table: "center_devices", column: "product_id"},
		{table: "center_devices", column: "revoked_at_unix"},
		{table: "center_devices", column: "revoked_by"},
		{table: "center_devices", column: "archived_at_unix"},
		{table: "center_devices", column: "archived_by"},
		{table: "center_devices", column: "config_snapshot_revision"},
		{table: "center_devices", column: "config_snapshot_at_unix"},
		{table: "center_devices", column: "config_snapshot_bytes"},
		{table: "center_devices", column: "os"},
		{table: "center_devices", column: "arch"},
		{table: "center_devices", column: "kernel_version"},
		{table: "center_devices", column: "distro_id"},
		{table: "center_devices", column: "distro_id_like"},
		{table: "center_devices", column: "distro_version"},
		{table: "center_devices", column: "runtime_deployment_supported"},
		{table: "center_device_runtime_summaries", column: "runtime_family"},
		{table: "center_device_runtime_summaries", column: "runtime_id"},
		{table: "center_device_runtime_summaries", column: "available"},
		{table: "center_device_runtime_summaries", column: "module_count"},
		{table: "center_device_runtime_summaries", column: "usage_reported"},
		{table: "center_device_runtime_summaries", column: "app_count"},
		{table: "center_device_runtime_summaries", column: "generated_targets_json"},
		{table: "center_device_runtime_summaries", column: "process_running"},
		{table: "center_device_runtime_summaries", column: "artifact_revision"},
		{table: "center_device_runtime_summaries", column: "apply_state"},
		{table: "center_runtime_artifacts", column: "artifact_revision"},
		{table: "center_runtime_artifacts", column: "artifact_hash"},
		{table: "center_runtime_artifacts", column: "runtime_family"},
		{table: "center_runtime_artifacts", column: "runtime_id"},
		{table: "center_runtime_artifacts", column: "target_os"},
		{table: "center_runtime_artifacts", column: "target_arch"},
		{table: "center_runtime_artifacts", column: "target_distro_id"},
		{table: "center_runtime_artifacts", column: "target_distro_version"},
		{table: "center_runtime_artifacts", column: "storage_state"},
		{table: "center_runtime_artifact_files", column: "archive_path"},
		{table: "center_runtime_artifact_files", column: "sha256"},
		{table: "center_device_runtime_assignments", column: "desired_artifact_revision"},
		{table: "center_device_runtime_assignments", column: "desired_state"},
		{table: "center_device_runtime_assignments", column: "dispatched_at_unix"},
		{table: "center_device_runtime_apply_status", column: "local_artifact_revision"},
		{table: "center_device_runtime_apply_status", column: "apply_state"},
		{table: "edge_device_identities", column: "center_product_id"},
		{table: "edge_device_identities", column: "center_status_checked_at_unix"},
		{table: "edge_device_identities", column: "center_status_error"},
		{table: "edge_device_identities", column: "config_snapshot_revision"},
		{table: "edge_device_identities", column: "config_snapshot_pushed_at_unix"},
		{table: "edge_device_identities", column: "config_snapshot_error"},
		{table: "edge_device_identities", column: "rule_artifact_revision"},
		{table: "edge_device_identities", column: "rule_artifact_pushed_at_unix"},
		{table: "edge_device_identities", column: "rule_artifact_error"},
	} {
		var count int
		if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('`+tc.table+`') WHERE name = ?`, tc.column).Scan(&count); err != nil {
			t.Fatalf("query %s.%s column: %v", tc.table, tc.column, err)
		}
		if count != 1 {
			t.Fatalf("%s.%s column count=%d want 1", tc.table, tc.column, count)
		}
	}
}

func TestMigrateLogsStatsStoreWithBackendSQLiteReplacesLegacyMigrationTable(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "tukuyomi.db")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	if _, err := db.Exec(`
		CREATE TABLE schema_migrations (
			migration_name TEXT PRIMARY KEY,
			applied_at_unix INTEGER NOT NULL,
			applied_at TEXT NOT NULL
		);
		INSERT INTO schema_migrations (migration_name, applied_at_unix, applied_at)
		VALUES ('001_init.sql', 1, 'legacy');
	`); err != nil {
		_ = db.Close()
		t.Fatalf("seed legacy schema_migrations: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close sqlite: %v", err)
	}

	if err := MigrateLogsStatsStoreWithBackend("db", "sqlite", dbPath, ""); err != nil {
		t.Fatalf("migrate sqlite: %v", err)
	}

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("reopen sqlite: %v", err)
	}
	defer db.Close()

	var version int
	var dirty int
	if err := db.QueryRow(`SELECT version, CASE WHEN dirty THEN 1 ELSE 0 END FROM schema_migrations`).Scan(&version, &dirty); err != nil {
		t.Fatalf("query migration version: %v", err)
	}
	if version != latestSchemaMigrationVersionForTest || dirty != 0 {
		t.Fatalf("migration version=%d dirty=%d want version=%d dirty=0", version, dirty, latestSchemaMigrationVersionForTest)
	}

	var legacyColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name = 'migration_name'`).Scan(&legacyColumns); err != nil {
		t.Fatalf("query legacy columns: %v", err)
	}
	if legacyColumns != 0 {
		t.Fatalf("legacy migration_name column still exists")
	}
}
