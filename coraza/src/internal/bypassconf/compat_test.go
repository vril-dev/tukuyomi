package bypassconf

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReloadPrefersLegacyUntilPrimaryExists(t *testing.T) {
	stopWatcher()
	t.Cleanup(stopWatcher)

	dir := t.TempDir()
	primary := filepath.Join(dir, "waf-bypass.json")
	legacy := filepath.Join(dir, "waf.bypass")
	if err := os.WriteFile(legacy, []byte("/legacy/\n"), 0o644); err != nil {
		t.Fatalf("WriteFile(legacy) error = %v", err)
	}

	if err := Init(primary, legacy); err != nil {
		t.Fatalf("Init() error = %v", err)
	}
	if got := GetActivePath(); got != legacy {
		t.Fatalf("activePath=%q want=%q", got, legacy)
	}
	if got := Match("example.com", "/legacy/test", false); got.Action != ACTION_BYPASS {
		t.Fatalf("legacy match action=%v want=%v", got.Action, ACTION_BYPASS)
	}
	if _, err := os.Stat(primary); !os.IsNotExist(err) {
		t.Fatalf("primary file should not be created implicitly, err=%v", err)
	}

	primaryRaw, err := MarshalJSON(File{Default: Scope{Entries: []Entry{{Path: "/primary/"}}}})
	if err != nil {
		t.Fatalf("MarshalJSON(primary) error = %v", err)
	}
	if err := os.WriteFile(primary, primaryRaw, 0o644); err != nil {
		t.Fatalf("WriteFile(primary) error = %v", err)
	}
	if err := Reload(); err != nil {
		t.Fatalf("Reload() error = %v", err)
	}
	if got := GetActivePath(); got != primary {
		t.Fatalf("activePath=%q want=%q", got, primary)
	}
	if got := Match("example.com", "/primary/test", false); got.Action != ACTION_BYPASS {
		t.Fatalf("primary match action=%v want=%v", got.Action, ACTION_BYPASS)
	}
	if got := Match("example.com", "/legacy/test", false); got.Action != ACTION_NONE {
		t.Fatalf("legacy match after primary switch=%v want=%v", got.Action, ACTION_NONE)
	}
}
