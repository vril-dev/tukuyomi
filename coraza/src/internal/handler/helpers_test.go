package handler

import (
	"os"
	"path/filepath"
	"testing"

	"tukuyomi/internal/config"
)

func TestMain(m *testing.M) {
	oldLogFiles := make(map[string]string, len(logFiles))
	for k, v := range logFiles {
		oldLogFiles[k] = v
	}
	oldWAFEventsFile, hadWAFEventsFile := os.LookupEnv("WAF_EVENTS_FILE")
	tmp, err := os.MkdirTemp("", "tukuyomi-handler-tests-*")
	if err == nil {
		logFiles["waf"] = filepath.Join(tmp, "logs", "coraza", "waf-events.ndjson")
		logFiles["accerr"] = filepath.Join(tmp, "logs", "nginx", "access-error.ndjson")
		logFiles["intr"] = filepath.Join(tmp, "logs", "nginx", "interesting.ndjson")
		_ = os.Setenv("WAF_EVENTS_FILE", logFiles["waf"])
	}

	code := m.Run()

	logFiles = oldLogFiles
	if hadWAFEventsFile {
		_ = os.Setenv("WAF_EVENTS_FILE", oldWAFEventsFile)
	} else {
		_ = os.Unsetenv("WAF_EVENTS_FILE")
	}
	if err == nil {
		_ = os.RemoveAll(tmp)
	}
	os.Exit(code)
}

func TestEnsureEditableRulePath(t *testing.T) {
	restore := saveRuleConfig()
	defer restore()

	config.CRSEnable = false
	config.RulesFile = "rules/a.conf, rules/b.conf"

	path, err := ensureEditableRulePath("rules/a.conf")
	if err != nil {
		t.Fatalf("ensureEditableRulePath returned error: %v", err)
	}
	if path != "rules/a.conf" {
		t.Fatalf("path=%q want=%q", path, "rules/a.conf")
	}

	if _, err := ensureEditableRulePath("rules/c.conf"); err == nil {
		t.Fatal("ensureEditableRulePath should reject paths outside configured rules")
	}
}

func TestValidateRaw_StrictOverride(t *testing.T) {
	restore := saveRuleConfig()
	defer restore()

	config.StrictOverride = false
	if _, err := validateRaw("/foo rules/missing.conf\n"); err != nil {
		t.Fatalf("validateRaw should allow missing extra rule when strict=false: %v", err)
	}

	config.StrictOverride = true
	if _, err := validateRaw("/foo rules/missing.conf\n"); err == nil {
		t.Fatal("validateRaw should fail when strict=true and extra rule is missing")
	}
}

func TestReadFileMaybeAndRollback(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "crs-disabled.conf")

	b, had, err := readFileMaybe(path)
	if err != nil {
		t.Fatalf("readFileMaybe missing file error: %v", err)
	}
	if had {
		t.Fatal("readFileMaybe should report hadFile=false for missing file")
	}
	if len(b) != 0 {
		t.Fatalf("readFileMaybe missing file bytes=%d want=0", len(b))
	}

	if err := os.WriteFile(path, []byte("old\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := rollbackCRSDisabledFile(path, true, []byte("prev\n")); err != nil {
		t.Fatalf("rollbackCRSDisabledFile(hadFile=true): %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rolled back file: %v", err)
	}
	if string(after) != "prev\n" {
		t.Fatalf("rollback content=%q want=%q", string(after), "prev\n")
	}

	if err := os.WriteFile(path, []byte("new\n"), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}
	if err := rollbackCRSDisabledFile(path, false, nil); err != nil {
		t.Fatalf("rollbackCRSDisabledFile(hadFile=false): %v", err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("file should be removed on rollback when hadFile=false, err=%v", err)
	}
}

func saveRuleConfig() func() {
	oldRulesFile := config.RulesFile
	oldCRSEnable := config.CRSEnable
	oldCRSSetup := config.CRSSetupFile
	oldCRSRulesDir := config.CRSRulesDir
	oldCRSDisabled := config.CRSDisabledFile
	oldStrict := config.StrictOverride
	return func() {
		config.RulesFile = oldRulesFile
		config.CRSEnable = oldCRSEnable
		config.CRSSetupFile = oldCRSSetup
		config.CRSRulesDir = oldCRSRulesDir
		config.CRSDisabledFile = oldCRSDisabled
		config.StrictOverride = oldStrict
	}
}
