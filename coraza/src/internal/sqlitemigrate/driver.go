package sqlitemigrate

import (
	"database/sql"
	"errors"
	"fmt"
	"io"
	"sync/atomic"

	"github.com/golang-migrate/migrate/v4/database"
)

const DefaultMigrationsTable = "schema_migrations"

type driver struct {
	db              *sql.DB
	migrationsTable string
	locked          atomic.Bool
}

func NewDriver(db *sql.DB, migrationsTable string) (database.Driver, error) {
	if db == nil {
		return nil, errors.New("db is nil")
	}
	if migrationsTable == "" {
		migrationsTable = DefaultMigrationsTable
	}
	d := &driver{
		db:              db,
		migrationsTable: migrationsTable,
	}
	if err := d.ensureVersionTable(); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *driver) Open(_ string) (database.Driver, error) {
	return nil, errors.New("embedded sqlite migration driver requires an existing db instance")
}

func (d *driver) Close() error {
	return nil
}

func (d *driver) Lock() error {
	if !d.locked.CompareAndSwap(false, true) {
		return database.ErrLocked
	}
	return nil
}

func (d *driver) Unlock() error {
	if !d.locked.CompareAndSwap(true, false) {
		return database.ErrNotLocked
	}
	return nil
}

func (d *driver) Run(migration io.Reader) error {
	raw, err := io.ReadAll(migration)
	if err != nil {
		return err
	}
	tx, err := d.db.Begin()
	if err != nil {
		return &database.Error{OrigErr: err, Err: "transaction start failed"}
	}
	if _, err := tx.Exec(string(raw)); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = errors.Join(err, rollbackErr)
		}
		return &database.Error{OrigErr: err, Query: raw}
	}
	if err := tx.Commit(); err != nil {
		return &database.Error{OrigErr: err, Err: "transaction commit failed"}
	}
	return nil
}

func (d *driver) SetVersion(version int, dirty bool) error {
	tx, err := d.db.Begin()
	if err != nil {
		return &database.Error{OrigErr: err, Err: "transaction start failed"}
	}
	deleteQuery := "DELETE FROM " + d.migrationsTable
	if _, err := tx.Exec(deleteQuery); err != nil {
		_ = tx.Rollback()
		return &database.Error{OrigErr: err, Query: []byte(deleteQuery)}
	}
	if version >= 0 || (version == database.NilVersion && dirty) {
		insertQuery := fmt.Sprintf("INSERT INTO %s (version, dirty) VALUES (?, ?)", d.migrationsTable)
		if _, err := tx.Exec(insertQuery, version, dirty); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = errors.Join(err, rollbackErr)
			}
			return &database.Error{OrigErr: err, Query: []byte(insertQuery)}
		}
	}
	if err := tx.Commit(); err != nil {
		return &database.Error{OrigErr: err, Err: "transaction commit failed"}
	}
	return nil
}

func (d *driver) Version() (int, bool, error) {
	query := "SELECT version, dirty FROM " + d.migrationsTable + " LIMIT 1"
	var version int
	var dirty bool
	if err := d.db.QueryRow(query).Scan(&version, &dirty); err != nil {
		return database.NilVersion, false, nil
	}
	return version, dirty, nil
}

func (d *driver) Drop() error {
	return errors.New("drop is not supported by embedded sqlite migration driver")
}

func (d *driver) ensureVersionTable() error {
	if err := d.Lock(); err != nil {
		return err
	}
	defer func() {
		_ = d.Unlock()
	}()
	query := fmt.Sprintf(`
CREATE TABLE IF NOT EXISTS %s (version INTEGER NOT NULL, dirty INTEGER NOT NULL);
CREATE UNIQUE INDEX IF NOT EXISTS version_unique ON %s (version);
`, d.migrationsTable, d.migrationsTable)
	if _, err := d.db.Exec(query); err != nil {
		return &database.Error{OrigErr: err, Query: []byte(query)}
	}
	return nil
}
