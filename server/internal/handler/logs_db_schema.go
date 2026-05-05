package handler

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"sort"
	"strings"
	"time"

	migrate "github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database"
	migratemysql "github.com/golang-migrate/migrate/v4/database/mysql"
	migratepostgres "github.com/golang-migrate/migrate/v4/database/postgres"
	sourceiofs "github.com/golang-migrate/migrate/v4/source/iofs"
	"tukuyomi/internal/sqlitemigrate"
)

//go:embed dbschema/*/*.up.sql
var embeddedDBSchemaFS embed.FS

const schemaMigrationsTableName = "schema_migrations"

func applyEmbeddedDBMigrations(db *sql.DB, driver string) error {
	if db == nil {
		return errors.New("db is nil")
	}
	driver = strings.ToLower(strings.TrimSpace(driver))
	if err := assertEmbeddedDBMigrationFiles(driver); err != nil {
		return err
	}
	if err := dropLegacyEmbeddedMigrationTable(db, driver); err != nil {
		return err
	}

	sourceDriver, err := sourceiofs.New(embeddedDBSchemaFS, path.Join("dbschema", driver))
	if err != nil {
		return fmt.Errorf("open embedded migrations for driver %s: %w", driver, err)
	}
	databaseDriver, closeDatabaseDriver, err := embeddedMigrationDatabaseDriver(db, driver)
	if err != nil {
		return err
	}
	migrator, err := migrate.NewWithInstance("iofs", sourceDriver, migrationDatabaseName(driver), databaseDriver)
	if err != nil {
		if closeDatabaseDriver {
			_ = databaseDriver.Close()
		}
		return fmt.Errorf("initialize migrator for driver %s: %w", driver, err)
	}

	runErr := migrator.Up()
	if closeDatabaseDriver {
		closeSourceErr, closeDatabaseErr := migrator.Close()
		if closeErr := errors.Join(closeSourceErr, closeDatabaseErr); closeErr != nil && (runErr == nil || errors.Is(runErr, migrate.ErrNoChange)) {
			return fmt.Errorf("close migrator for driver %s: %w", driver, closeErr)
		}
	} else if closeErr := sourceDriver.Close(); closeErr != nil && (runErr == nil || errors.Is(runErr, migrate.ErrNoChange)) {
		return fmt.Errorf("close migration source for driver %s: %w", driver, closeErr)
	}
	if runErr != nil && !errors.Is(runErr, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations for driver %s: %w", driver, runErr)
	}
	if err := repairEmbeddedDBSchemaCompatibility(db, driver); err != nil {
		return err
	}
	return nil
}

func repairEmbeddedDBSchemaCompatibility(db *sql.DB, driver string) error {
	if err := repairRemoteSSHSessionHostPublicKeyColumn(db, driver); err != nil {
		return err
	}
	return nil
}

func repairRemoteSSHSessionHostPublicKeyColumn(db *sql.DB, driver string) error {
	const tableName = "center_remote_ssh_sessions"
	const columnName = "gateway_host_public_key"
	exists, err := dbColumnExists(db, driver, tableName, columnName)
	if err != nil {
		return fmt.Errorf("inspect %s.%s column: %w", tableName, columnName, err)
	}
	if exists {
		return nil
	}
	var statements []string
	switch driver {
	case logStatsDBDriverSQLite:
		statements = []string{
			`ALTER TABLE center_remote_ssh_sessions ADD COLUMN gateway_host_public_key TEXT NOT NULL DEFAULT ''`,
		}
	case logStatsDBDriverMySQL:
		statements = []string{
			`ALTER TABLE center_remote_ssh_sessions ADD COLUMN gateway_host_public_key TEXT NULL AFTER gateway_host_key_fingerprint_sha256`,
			`UPDATE center_remote_ssh_sessions SET gateway_host_public_key = '' WHERE gateway_host_public_key IS NULL`,
			`ALTER TABLE center_remote_ssh_sessions MODIFY COLUMN gateway_host_public_key TEXT NOT NULL`,
		}
	case logStatsDBDriverPostgres:
		statements = []string{
			`ALTER TABLE center_remote_ssh_sessions ADD COLUMN gateway_host_public_key TEXT NOT NULL DEFAULT ''`,
		}
	default:
		return fmt.Errorf("unsupported db driver: %s", driver)
	}
	for _, statement := range statements {
		if _, err := db.Exec(statement); err != nil {
			return fmt.Errorf("repair %s.%s column: %w", tableName, columnName, err)
		}
	}
	return nil
}

func dbColumnExists(db *sql.DB, driver string, tableName string, columnName string) (bool, error) {
	var count int
	switch driver {
	case logStatsDBDriverSQLite:
		rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull int
			var defaultValue any
			var pk int
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
				return false, err
			}
			if strings.EqualFold(name, columnName) {
				return true, nil
			}
		}
		return false, rows.Err()
	case logStatsDBDriverMySQL:
		err := db.QueryRow(`
SELECT COUNT(*)
  FROM information_schema.columns
 WHERE table_schema = DATABASE()
   AND table_name = ?
   AND column_name = ?`, tableName, columnName).Scan(&count)
		return count > 0, err
	case logStatsDBDriverPostgres:
		err := db.QueryRow(`
SELECT COUNT(*)
  FROM information_schema.columns
 WHERE table_schema = current_schema()
   AND table_name = $1
   AND column_name = $2`, tableName, columnName).Scan(&count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported db driver: %s", driver)
	}
}

func migrationDatabaseName(driver string) string {
	return driver
}

func embeddedMigrationDatabaseDriver(db *sql.DB, driver string) (database.Driver, bool, error) {
	switch driver {
	case logStatsDBDriverSQLite:
		migrationDriver, err := sqlitemigrate.NewDriver(db, schemaMigrationsTableName)
		if err != nil {
			return nil, false, fmt.Errorf("initialize sqlite migration driver: %w", err)
		}
		return migrationDriver, false, nil
	case logStatsDBDriverMySQL:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := db.Conn(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("open mysql migration connection: %w", err)
		}
		migrationDriver, err := migratemysql.WithConnection(ctx, conn, &migratemysql.Config{
			MigrationsTable:  schemaMigrationsTableName,
			StatementTimeout: 30 * time.Second,
		})
		if err != nil {
			_ = conn.Close()
			return nil, false, fmt.Errorf("initialize mysql migration driver: %w", err)
		}
		return migrationDriver, true, nil
	case logStatsDBDriverPostgres:
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		conn, err := db.Conn(ctx)
		if err != nil {
			return nil, false, fmt.Errorf("open pgsql migration connection: %w", err)
		}
		migrationDriver, err := migratepostgres.WithConnection(ctx, conn, &migratepostgres.Config{
			MigrationsTable:       schemaMigrationsTableName,
			MultiStatementEnabled: true,
			StatementTimeout:      30 * time.Second,
		})
		if err != nil {
			_ = conn.Close()
			return nil, false, fmt.Errorf("initialize pgsql migration driver: %w", err)
		}
		return migrationDriver, true, nil
	default:
		return nil, false, fmt.Errorf("unsupported db driver: %s", driver)
	}
}

func assertEmbeddedDBMigrationFiles(driver string) error {
	dir := path.Join("dbschema", strings.ToLower(strings.TrimSpace(driver)))
	entries, err := fs.ReadDir(embeddedDBSchemaFS, dir)
	if err != nil {
		return fmt.Errorf("read embedded schema dir %s: %w", dir, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".up.sql") {
			files = append(files, name)
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return fmt.Errorf("no embedded schema migrations for driver %s", driver)
	}
	if files[0] != "000001_init.up.sql" {
		return fmt.Errorf("first embedded schema migration for driver %s must be 000001_init.up.sql", driver)
	}
	return nil
}

func dropLegacyEmbeddedMigrationTable(db *sql.DB, driver string) error {
	legacy, err := hasLegacyEmbeddedMigrationTable(db, driver)
	if err != nil {
		return fmt.Errorf("inspect legacy migration table: %w", err)
	}
	if !legacy {
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := db.ExecContext(ctx, "DROP TABLE "+schemaMigrationsTableName); err != nil {
		return fmt.Errorf("drop legacy migration table: %w", err)
	}
	return nil
}

func hasLegacyEmbeddedMigrationTable(db *sql.DB, driver string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	switch driver {
	case logStatsDBDriverSQLite:
		rows, err := db.QueryContext(ctx, `PRAGMA table_info(schema_migrations)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var (
				cid        int
				name       string
				columnType string
				notNull    int
				defaultVal any
				pk         int
			)
			if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultVal, &pk); err != nil {
				return false, err
			}
			if strings.EqualFold(name, "migration_name") {
				return true, nil
			}
		}
		return false, rows.Err()
	case logStatsDBDriverMySQL:
		var count int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			  FROM information_schema.columns
			 WHERE table_schema = DATABASE()
			   AND table_name = 'schema_migrations'
			   AND column_name = 'migration_name'`).Scan(&count)
		return count > 0, err
	case logStatsDBDriverPostgres:
		var count int
		err := db.QueryRowContext(ctx, `
			SELECT COUNT(*)
			  FROM information_schema.columns
			 WHERE table_schema = current_schema()
			   AND table_name = 'schema_migrations'
			   AND column_name = 'migration_name'`).Scan(&count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported db driver: %s", driver)
	}
}
