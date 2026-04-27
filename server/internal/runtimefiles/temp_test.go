package runtimefiles

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMakeTempDirUsesRuntimeTempRoot(t *testing.T) {
	t.Chdir(t.TempDir())

	path, err := MakeTempDir("country-*")
	if err != nil {
		t.Fatalf("make temp dir: %v", err)
	}
	if !strings.HasPrefix(filepath.ToSlash(path), filepath.ToSlash(filepath.Clean(TempDir))+"/") {
		t.Fatalf("path=%q want under %q", path, TempDir)
	}
}

func TestFileSavedAt(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write file: %v", err)
	}
	if got := FileSavedAt(path); got == "" {
		t.Fatal("saved_at should be populated for an existing file")
	}
	if got := FileSavedAt(filepath.Join(t.TempDir(), "missing.json")); got != "" {
		t.Fatalf("missing saved_at=%q want empty", got)
	}
}
