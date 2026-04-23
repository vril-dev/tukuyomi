package handler

import (
	"database/sql"
	"path/filepath"
	"reflect"
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

	for _, table := range []string{"waf_events", "ingest_state", "config_blobs", "schema_migrations"} {
		var name string
		err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?`, table).Scan(&name)
		if err != nil {
			t.Fatalf("table %s missing: %v", table, err)
		}
	}

	rows, err := db.Query(`SELECT migration_name FROM schema_migrations ORDER BY migration_name`)
	if err != nil {
		t.Fatalf("query migrations: %v", err)
	}
	defer rows.Close()
	var migrations []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatalf("scan migration: %v", err)
		}
		migrations = append(migrations, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("migration rows: %v", err)
	}
	want := []string{"000_schema_migrations.sql", "001_init.sql"}
	if !reflect.DeepEqual(migrations, want) {
		t.Fatalf("migrations=%v want=%v", migrations, want)
	}
}

func TestSplitSQLStatementsHandlesCommentsAndQuotedSemicolons(t *testing.T) {
	statements, err := splitSQLStatements(`
		-- leading comment
		CREATE TABLE example (v TEXT DEFAULT 'a;b');
		/* block ; comment */
		INSERT INTO example (v) VALUES ('c'';d');
	`)
	if err != nil {
		t.Fatalf("split SQL: %v", err)
	}
	want := []string{
		"CREATE TABLE example (v TEXT DEFAULT 'a;b')",
		"INSERT INTO example (v) VALUES ('c'';d')",
	}
	if !reflect.DeepEqual(statements, want) {
		t.Fatalf("statements=%q want=%q", statements, want)
	}
}
