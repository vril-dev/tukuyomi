package handler

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"tukuyomi/internal/config"
)

func TestImportResponseCacheConfigStorageSeedsDefaultWithoutFile(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "store.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("InitLogsStatsStoreWithBackend: %v", err)
	}
	defer func() {
		_ = InitLogsStatsStore(false, "", 0)
	}()

	prevCacheStoreFile := config.CacheStoreFile
	missingPath := filepath.Join(tmp, "missing", "cache-store.json")
	config.CacheStoreFile = missingPath
	defer func() {
		config.CacheStoreFile = prevCacheStoreFile
	}()

	if err := importResponseCacheConfigStorage(); err != nil {
		t.Fatalf("importResponseCacheConfigStorage: %v", err)
	}

	store := getLogsStatsStore()
	cfg, _, found, err := store.loadActiveResponseCacheConfig()
	if err != nil {
		t.Fatalf("loadActiveResponseCacheConfig: %v", err)
	}
	if !found {
		t.Fatal("expected response cache config row")
	}
	if got, want := cfg, normalizeResponseCacheConfig(responseCacheConfig{}); !reflect.DeepEqual(got, want) {
		t.Fatalf("response cache config=%+v want=%+v", got, want)
	}
	if _, err := os.Stat(missingPath); !os.IsNotExist(err) {
		t.Fatalf("cache-store seed file should not be created, stat err=%v", err)
	}
}
