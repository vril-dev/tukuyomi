package waf

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSplitRuleFiles(t *testing.T) {
	in := " rules/a.conf, ,rules/b.conf ,, rules/c.conf "
	got := splitRuleFiles(in)
	want := []string{"rules/a.conf", "rules/b.conf", "rules/c.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitRuleFiles() = %v, want %v", got, want)
	}
}

func TestDiscoverCRSRuleFiles(t *testing.T) {
	dir := t.TempDir()
	setup := filepath.Join(dir, "crs-setup.conf")
	mustWrite(t, setup, "")
	mustWrite(t, filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"), "")
	mustWrite(t, filepath.Join(dir, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"), "")
	mustWrite(t, filepath.Join(dir, "zzz.conf.example"), "")

	got, err := discoverCRSRuleFiles(setup, dir)
	if err != nil {
		t.Fatalf("discoverCRSRuleFiles() error = %v", err)
	}

	want := []string{
		filepath.Join(dir, "REQUEST-901-INITIALIZATION.conf"),
		filepath.Join(dir, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("discoverCRSRuleFiles() = %v, want %v", got, want)
	}
}

func TestComposeInitialRuleFiles_WithCRS(t *testing.T) {
	dir := t.TempDir()
	setup := filepath.Join(dir, "crs-setup.conf")
	rulesDir := filepath.Join(dir, "rules")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	mustWrite(t, setup, "")
	mustWrite(t, filepath.Join(rulesDir, "REQUEST-901-INITIALIZATION.conf"), "")

	got, err := composeInitialRuleFiles("tukuyomi.conf", true, setup, rulesDir, filepath.Join(dir, "crs-disabled.conf"))
	if err != nil {
		t.Fatalf("composeInitialRuleFiles() error = %v", err)
	}

	want := []string{
		setup,
		filepath.Join(rulesDir, "REQUEST-901-INITIALIZATION.conf"),
		"tukuyomi.conf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composeInitialRuleFiles() = %v, want %v", got, want)
	}
}

func TestComposeInitialRuleFiles_WithoutCRS(t *testing.T) {
	got, err := composeInitialRuleFiles("tukuyomi.conf", false, "", "", filepath.Join(t.TempDir(), "crs-disabled.conf"))
	if err != nil {
		t.Fatalf("composeInitialRuleFiles() error = %v", err)
	}
	want := []string{"tukuyomi.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composeInitialRuleFiles() = %v, want %v", got, want)
	}
}

func TestComposeInitialRuleFiles_MissingCRS(t *testing.T) {
	_, err := composeInitialRuleFiles("tukuyomi.conf", true, "missing-setup.conf", "missing-dir", filepath.Join(t.TempDir(), "crs-disabled.conf"))
	if err == nil {
		t.Fatal("expected error when CRS is enabled and files are missing")
	}
}

func TestComposeInitialRuleFiles_WithCRSDisabledFile(t *testing.T) {
	dir := t.TempDir()
	setup := filepath.Join(dir, "crs-setup.conf")
	rulesDir := filepath.Join(dir, "rules")
	disabledFile := filepath.Join(dir, "crs-disabled.conf")
	if err := os.MkdirAll(rulesDir, 0o755); err != nil {
		t.Fatalf("MkdirAll() error = %v", err)
	}
	mustWrite(t, setup, "")
	mustWrite(t, filepath.Join(rulesDir, "REQUEST-901-INITIALIZATION.conf"), "")
	mustWrite(t, filepath.Join(rulesDir, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"), "")
	mustWrite(t, disabledFile, "REQUEST-920-PROTOCOL-ENFORCEMENT.conf\n")

	got, err := composeInitialRuleFiles("tukuyomi.conf", true, setup, rulesDir, disabledFile)
	if err != nil {
		t.Fatalf("composeInitialRuleFiles() error = %v", err)
	}

	want := []string{
		setup,
		filepath.Join(rulesDir, "REQUEST-901-INITIALIZATION.conf"),
		"tukuyomi.conf",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composeInitialRuleFiles() = %v, want %v", got, want)
	}
}

func TestComposeInitialRuleFilesFromAssetsSkipsDisabledBaseRules(t *testing.T) {
	bundle := RuleAssetBundle{Assets: []RuleAsset{
		{Path: "enabled.conf", Kind: ruleAssetKindBase, Raw: []byte("SecRuleEngine On\n")},
		{Path: "disabled.conf", Kind: ruleAssetKindBase, Raw: []byte("SecRequestBodyAccess On\n"), Disabled: true},
	}}

	got, err := composeInitialRuleFilesFromAssets(bundle, "", false, "", "", nil)
	if err != nil {
		t.Fatalf("composeInitialRuleFilesFromAssets() error = %v", err)
	}

	want := []string{"enabled.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("composeInitialRuleFilesFromAssets() = %v, want %v", got, want)
	}
}

func TestBuildWAF_BlocksMaliciousQuery(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.conf")
	mustWrite(t, rulePath, `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@rx (?i)<script>" "id:100001,phase:2,deny,status:403,log,msg:'block-xss'"
`)

	w, err := buildWAF([]string{rulePath})
	if err != nil {
		t.Fatalf("buildWAF() error = %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("/?q=%3Cscript%3Ealert(1)%3C/script%3E", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.local")
	if err := tx.ProcessRequestHeaders(); err != nil {
		t.Fatalf("ProcessRequestHeaders() error = %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("ProcessRequestBody() error = %v", err)
	}

	it := tx.Interruption()
	if it == nil {
		t.Fatal("expected interruption, got nil")
	}
	if it.Status != 403 {
		t.Fatalf("interruption status = %d, want 403", it.Status)
	}
}

func TestBuildWAF_AllowsBenignQuery(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.conf")
	mustWrite(t, rulePath, `
SecRuleEngine On
SecRequestBodyAccess On
SecRule ARGS "@rx (?i)<script>" "id:100001,phase:2,deny,status:403,log,msg:'block-xss'"
`)

	w, err := buildWAF([]string{rulePath})
	if err != nil {
		t.Fatalf("buildWAF() error = %v", err)
	}

	tx := w.NewTransaction()
	defer tx.Close()
	tx.ProcessURI("/?q=hello-world", "GET", "HTTP/1.1")
	tx.AddRequestHeader("Host", "example.local")
	if err := tx.ProcessRequestHeaders(); err != nil {
		t.Fatalf("ProcessRequestHeaders() error = %v", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		t.Fatalf("ProcessRequestBody() error = %v", err)
	}
	if it := tx.Interruption(); it != nil {
		t.Fatalf("unexpected interruption: status=%d rule=%d", it.Status, it.RuleID)
	}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
