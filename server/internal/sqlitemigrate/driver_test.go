package sqlitemigrate

import (
	"database/sql"
	"strings"
	"testing"

	_ "github.com/glebarez/sqlite"
	"github.com/golang-migrate/migrate/v4/database"
)

func TestDriverRunSetVersionAndVersion(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	rawDriver, err := NewDriver(db, "")
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	driver := rawDriver.(database.Driver)

	if err := driver.Run(strings.NewReader("CREATE TABLE example (id INTEGER PRIMARY KEY);")); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if err := driver.SetVersion(12, false); err != nil {
		t.Fatalf("SetVersion: %v", err)
	}
	version, dirty, err := driver.Version()
	if err != nil {
		t.Fatalf("Version: %v", err)
	}
	if version != 12 || dirty {
		t.Fatalf("version=%d dirty=%v", version, dirty)
	}
}

func TestDriverLocking(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open sqlite: %v", err)
	}
	defer db.Close()

	driver, err := NewDriver(db, "")
	if err != nil {
		t.Fatalf("NewDriver: %v", err)
	}
	if err := driver.Lock(); err != nil {
		t.Fatalf("Lock: %v", err)
	}
	if err := driver.Lock(); err != database.ErrLocked {
		t.Fatalf("second Lock=%v want ErrLocked", err)
	}
	if err := driver.Unlock(); err != nil {
		t.Fatalf("Unlock: %v", err)
	}
}
