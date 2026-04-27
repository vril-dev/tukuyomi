package requestmeta

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestUpdateServiceRunNowRendersCountryOnlyConfigAndPersistsState(t *testing.T) {
	rawConfig := []byte("AccountID 12345\nLicenseKey secret\nEditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country\n")
	summary, err := ParseGeoIPConfig(rawConfig)
	if err != nil {
		t.Fatalf("ParseGeoIPConfig: %v", err)
	}
	var persisted UpdateState
	var replaced []byte
	service := UpdateService{
		ResolveUpdater: func() (string, error) {
			return "/bin/true", nil
		},
		ReadConfig: func() ([]byte, GeoIPConfigSummary, error) {
			return rawConfig, summary, nil
		},
		MakeTempDir: func(pattern string) (string, error) {
			return os.MkdirTemp(t.TempDir(), pattern)
		},
		RunUpdater: func(_ context.Context, _ string, configPath, databaseDir string) error {
			raw, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatalf("temp config path missing: %v", err)
			}
			text := string(raw)
			if !strings.Contains(text, "EditionIDs GeoLite2-Country") {
				t.Fatalf("temp config missing country edition:\n%s", text)
			}
			for _, blocked := range []string{"GeoLite2-ASN", "GeoLite2-City"} {
				if strings.Contains(text, blocked) {
					t.Fatalf("temp config should not request %s:\n%s", blocked, text)
				}
			}
			return os.WriteFile(filepath.Join(databaseDir, "GeoLite2-Country.mmdb"), testCountryMMDBBytes(t), 0o600)
		},
		ReplaceMMDB: func(payload []byte) error {
			replaced = append([]byte(nil), payload...)
			return nil
		},
		PersistState: func(state UpdateState) error {
			persisted = state
			return nil
		},
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
	}

	if err := service.RunNow(context.Background()); err != nil {
		t.Fatalf("RunNow: %v", err)
	}
	if len(replaced) == 0 {
		t.Fatal("expected replacement payload")
	}
	if got, want := persisted.LastResult, "success"; got != want {
		t.Fatalf("LastResult=%q want=%q", got, want)
	}
	if persisted.LastSuccess == "" || persisted.LastError != "" {
		t.Fatalf("unexpected persisted state: %#v", persisted)
	}
}

func TestUpdateServiceRunNowPersistsErrorState(t *testing.T) {
	var persisted UpdateState
	service := UpdateService{
		ResolveUpdater: func() (string, error) {
			return "", os.ErrNotExist
		},
		PersistState: func(state UpdateState) error {
			persisted = state
			return nil
		},
		Now: func() time.Time {
			return time.Unix(1_700_000_000, 0).UTC()
		},
	}

	if err := service.RunNow(context.Background()); err == nil {
		t.Fatal("expected update error")
	}
	if got, want := persisted.LastResult, "error"; got != want {
		t.Fatalf("LastResult=%q want=%q", got, want)
	}
	if persisted.LastError == "" {
		t.Fatalf("expected persisted LastError: %#v", persisted)
	}
}
