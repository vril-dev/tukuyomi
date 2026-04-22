package cacheconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveWatchLoadPath_PrefersLegacyUntilPrimaryExists(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	primary := filepath.Join(dir, "cache-rules.json")
	legacy := filepath.Join(dir, "cache.conf")
	if err := os.WriteFile(legacy, []byte("ALLOW prefix=/legacy/ methods=GET,HEAD ttl=600\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(legacy) error = %v", err)
	}

	if got := resolveWatchLoadPath(primary, legacy); got != legacy {
		t.Fatalf("resolveWatchLoadPath(legacy)=%q want=%q", got, legacy)
	}

	if err := os.WriteFile(primary, []byte("{\n  \"rules\": []\n}\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(primary) error = %v", err)
	}
	if got := resolveWatchLoadPath(primary, legacy); got != primary {
		t.Fatalf("resolveWatchLoadPath(primary)=%q want=%q", got, primary)
	}
}
