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
)

//go:embed dbschema/*/*.sql
var embeddedDBSchemaFS embed.FS

const schemaMigrationBootstrapName = "000_schema_migrations.sql"

func applyEmbeddedDBMigrations(db *sql.DB, driver string) error {
	if db == nil {
		return errors.New("db is nil")
	}
	files, err := embeddedDBMigrationFiles(driver)
	if err != nil {
		return err
	}
	for _, file := range files {
		migrationName := embeddedDBMigrationName(file)
		if migrationName != schemaMigrationBootstrapName {
			applied, err := embeddedDBMigrationApplied(db, driver, migrationName)
			if err != nil {
				return fmt.Errorf("check migration %s: %w", migrationName, err)
			}
			if applied {
				continue
			}
		}
		raw, err := embeddedDBSchemaFS.ReadFile(file)
		if err != nil {
			return fmt.Errorf("read migration %s: %w", migrationName, err)
		}
		statements, err := splitSQLStatements(string(raw))
		if err != nil {
			return fmt.Errorf("parse migration %s: %w", migrationName, err)
		}
		if err := execEmbeddedDBMigration(db, migrationName, statements); err != nil {
			return err
		}
		if err := recordEmbeddedDBMigration(db, driver, migrationName); err != nil {
			return fmt.Errorf("record migration %s: %w", migrationName, err)
		}
	}
	return nil
}

func embeddedDBMigrationFiles(driver string) ([]string, error) {
	dir := path.Join("dbschema", strings.ToLower(strings.TrimSpace(driver)))
	entries, err := fs.ReadDir(embeddedDBSchemaFS, dir)
	if err != nil {
		return nil, fmt.Errorf("read embedded schema dir %s: %w", dir, err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasSuffix(name, ".sql") {
			files = append(files, path.Join(dir, name))
		}
	}
	sort.Strings(files)
	if len(files) == 0 {
		return nil, fmt.Errorf("no embedded schema migrations for driver %s", driver)
	}
	if embeddedDBMigrationName(files[0]) != schemaMigrationBootstrapName {
		return nil, fmt.Errorf("first embedded schema migration for driver %s must be %s", driver, schemaMigrationBootstrapName)
	}
	return files, nil
}

func embeddedDBMigrationName(file string) string {
	return path.Base(file)
}

func embeddedDBMigrationApplied(db *sql.DB, driver, migrationName string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	query := `SELECT 1 FROM schema_migrations WHERE migration_name = ?`
	if driver == logStatsDBDriverPostgres {
		query = `SELECT 1 FROM schema_migrations WHERE migration_name = $1`
	}
	var found int
	err := db.QueryRowContext(ctx, query, migrationName).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return found == 1, nil
}

func execEmbeddedDBMigration(db *sql.DB, migrationName string, statements []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	for _, stmt := range statements {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("apply migration %s: %w", migrationName, err)
		}
	}
	return nil
}

func recordEmbeddedDBMigration(db *sql.DB, driver, migrationName string) error {
	now := time.Now().UTC()
	query := `INSERT OR IGNORE INTO schema_migrations (migration_name, applied_at_unix, applied_at) VALUES (?, ?, ?)`
	switch driver {
	case logStatsDBDriverMySQL:
		query = `INSERT IGNORE INTO schema_migrations (migration_name, applied_at_unix, applied_at) VALUES (?, ?, ?)`
	case logStatsDBDriverPostgres:
		query = `INSERT INTO schema_migrations (migration_name, applied_at_unix, applied_at) VALUES ($1, $2, $3) ON CONFLICT (migration_name) DO NOTHING`
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := db.ExecContext(ctx, query, migrationName, now.Unix(), now.Format(time.RFC3339))
	return err
}

func splitSQLStatements(src string) ([]string, error) {
	var out []string
	var b strings.Builder
	inSingle := false
	inDouble := false
	inBacktick := false
	lineComment := false
	blockComment := false

	flush := func() {
		stmt := strings.TrimSpace(b.String())
		if stmt != "" {
			out = append(out, stmt)
		}
		b.Reset()
	}

	for i := 0; i < len(src); i++ {
		c := src[i]
		var next byte
		if i+1 < len(src) {
			next = src[i+1]
		}

		if lineComment {
			if c == '\n' {
				lineComment = false
				b.WriteByte(c)
			}
			continue
		}
		if blockComment {
			if c == '*' && next == '/' {
				blockComment = false
				i++
			}
			continue
		}

		if !inSingle && !inDouble && !inBacktick {
			switch {
			case c == '-' && next == '-':
				lineComment = true
				i++
				continue
			case c == '#':
				lineComment = true
				continue
			case c == '/' && next == '*':
				blockComment = true
				i++
				continue
			case c == ';':
				flush()
				continue
			}
		}

		b.WriteByte(c)

		switch c {
		case '\'':
			if inDouble || inBacktick {
				continue
			}
			if inSingle && next == '\'' {
				b.WriteByte(next)
				i++
				continue
			}
			inSingle = !inSingle
		case '"':
			if !inSingle && !inBacktick {
				inDouble = !inDouble
			}
		case '`':
			if !inSingle && !inDouble {
				inBacktick = !inBacktick
			}
		}
	}

	if lineComment {
		lineComment = false
	}
	if blockComment {
		return nil, errors.New("unterminated block comment")
	}
	if inSingle || inDouble || inBacktick {
		return nil, errors.New("unterminated quoted SQL literal")
	}
	flush()
	return out, nil
}
