package handler

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

func TestParseRequestCountryGeoIPConfigAcceptsCountryEdition(t *testing.T) {
	raw := []byte(`
# comment
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-Country GeoLite2-City
`)
	summary, err := parseRequestCountryGeoIPConfig(raw)
	if err != nil {
		t.Fatalf("parseRequestCountryGeoIPConfig() error: %v", err)
	}
	if got, want := summary.SupportedCountryEdition, "GeoLite2-Country"; got != want {
		t.Fatalf("supported edition=%q want=%q", got, want)
	}
	if len(summary.EditionIDs) != 2 {
		t.Fatalf("edition ids=%v want two entries", summary.EditionIDs)
	}
}

func TestParseRequestCountryGeoIPConfigRejectsWithoutSupportedCountryEdition(t *testing.T) {
	raw := []byte(`
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-City
`)
	_, err := parseRequestCountryGeoIPConfig(raw)
	if err == nil {
		t.Fatal("expected error for config without supported country edition")
	}
}

func TestRequestCountryRuntimeMaybeRefreshFromManagedFileSwapsReaderState(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write managed path: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{
			reader:      &maxminddb.Reader{},
			managedPath: path,
			sizeBytes:   99,
			modTime:     time.Unix(20, 0).UTC(),
		}, nil
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   path,
		dbSizeBytes:   1,
		dbModTime:     time.Unix(10, 0).UTC(),
	}
	rt.maybeRefreshFromManagedFile()

	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if got, want := rt.dbSizeBytes, int64(99); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if got := rt.dbModTime; !got.Equal(time.Unix(20, 0).UTC()) {
		t.Fatalf("dbModTime=%s want=%s", got, time.Unix(20, 0).UTC())
	}
	if rt.reader == nil {
		t.Fatal("expected reader to be refreshed")
	}
}

func TestRequestCountryRuntimeMaybeRefreshFromManagedFileKeepsOldStateOnReloadError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "country.mmdb")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatalf("write managed path: %v", err)
	}

	prevLoader := requestCountryMMDBLoader
	requestCountryMMDBLoader = func() (loadedRequestCountryMMDBState, error) {
		return loadedRequestCountryMMDBState{}, os.ErrPermission
	}
	defer func() { requestCountryMMDBLoader = prevLoader }()

	rt := &requestCountryRuntime{
		effectiveMode: "mmdb",
		managedPath:   path,
		dbSizeBytes:   1,
		dbModTime:     time.Unix(10, 0).UTC(),
	}
	rt.maybeRefreshFromManagedFile()

	rt.mu.RLock()
	defer rt.mu.RUnlock()
	if got, want := rt.dbSizeBytes, int64(1); got != want {
		t.Fatalf("dbSizeBytes=%d want=%d", got, want)
	}
	if rt.lastError == "" {
		t.Fatal("expected lastError to be recorded")
	}
}
