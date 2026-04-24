package handler

import (
	"database/sql"
	"path/filepath"
	"testing"
)

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
	if version != 10 || dirty != 0 {
		t.Fatalf("migration version=%d dirty=%d want version=10 dirty=0", version, dirty)
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
	if version != 10 || dirty != 0 {
		t.Fatalf("migration version=%d dirty=%d want version=10 dirty=0", version, dirty)
	}

	var legacyColumns int
	if err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('schema_migrations') WHERE name = 'migration_name'`).Scan(&legacyColumns); err != nil {
		t.Fatalf("query legacy columns: %v", err)
	}
	if legacyColumns != 0 {
		t.Fatalf("legacy migration_name column still exists")
	}
}
