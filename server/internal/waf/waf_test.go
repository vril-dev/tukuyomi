package waf

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"tukuyomi/internal/config"
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

func TestCorazaEngineAddsHTTPFramingHeaders(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.conf")
	mustWrite(t, rulePath, `
SecRuleEngine On
SecRule &REQUEST_HEADERS:Content-Length "@eq 0" "id:100002,phase:1,deny,status:403,log,msg:'missing content length'"
`)

	w, err := buildWAF([]string{rulePath})
	if err != nil {
		t.Fatalf("buildWAF() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.local/center-api/devices/test/runtime-builds", strings.NewReader(`{"runtime_family":"php-fpm","runtime_id":"php83"}`))
	req.Host = "example.local"
	decision, err := corazaEngine{w: w}.InspectRequest(req)
	if err != nil {
		t.Fatalf("InspectRequest() error = %v", err)
	}
	if decision.Interruption != nil {
		t.Fatalf("unexpected interruption: status=%d rule=%d", decision.Interruption.Status, decision.Interruption.RuleID)
	}
}

func TestCorazaEngineInspectsRequestURIWithoutSchemeAndHost(t *testing.T) {
	dir := t.TempDir()
	rulePath := filepath.Join(dir, "test.conf")
	mustWrite(t, rulePath, `
SecRuleEngine On
SecRule REQUEST_URI "@beginsWith /admin" "id:100001,phase:1,deny,status:403,log,msg:'admin prefix'"
SecRule REQUEST_URI "@streq /exact/a%2Fb?q=1" "id:100002,phase:1,deny,status:403,log,msg:'exact uri'"
SecRule REQUEST_URI "@streq *" "id:100003,phase:1,deny,status:403,log,msg:'asterisk form'"
SecRule REQUEST_METHOD "@streq CONNECT" "id:100004,phase:1,deny,status:403,log,msg:'connect uri',chain"
SecRule REQUEST_URI "@streq /"
SecRule REQUEST_URI "@beginsWith /api/legacy/" "id:100005,phase:1,pass,nolog,ctl:ruleRemoveById=100006"
SecRule ARGS "@contains attack" "id:100006,phase:2,deny,status:403,log,msg:'attack arg'"
`)

	w, err := buildWAF([]string{rulePath})
	if err != nil {
		t.Fatalf("buildWAF() error = %v", err)
	}

	// quic-go v0.60 and later set the scheme and host on every HTTP/3 request URL.
	http3Request := httptest.NewRequest(http.MethodGet, "/admin/users?a=1", nil)
	http3Request.URL.Scheme = "https"
	http3Request.URL.Host = "example.local"

	tests := []struct {
		name   string
		req    *http.Request
		ruleID int
	}{
		{name: "origin-form", req: httptest.NewRequest(http.MethodGet, "/admin/users?a=1", nil), ruleID: 100001},
		{name: "http absolute-form", req: httptest.NewRequest(http.MethodGet, "http://example.local/admin/users?a=1", nil), ruleID: 100001},
		{name: "https absolute-form", req: httptest.NewRequest(http.MethodGet, "https://example.local/admin/users?a=1", nil), ruleID: 100001},
		{name: "http3 request URL", req: http3Request, ruleID: 100001},
		{name: "encoded slash and query kept", req: httptest.NewRequest(http.MethodGet, "https://example.local/exact/a%2Fb?q=1", nil), ruleID: 100002},
		{name: "asterisk-form", req: httptest.NewRequest(http.MethodOptions, "*", nil), ruleID: 100003},
		{name: "connect authority-form", req: httptest.NewRequest(http.MethodConnect, "example.local:443", nil), ruleID: 100004},
		{name: "prefix exclusion on absolute-form", req: httptest.NewRequest(http.MethodGet, "https://example.local/api/legacy/run?x=attack", nil), ruleID: 0},
		{name: "outside the exclusion", req: httptest.NewRequest(http.MethodGet, "https://example.local/api/other?x=attack", nil), ruleID: 100006},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decision, err := corazaEngine{w: w}.InspectRequest(tt.req)
			if err != nil {
				t.Fatalf("InspectRequest() error = %v", err)
			}
			got := 0
			if decision.Interruption != nil {
				got = decision.Interruption.RuleID
			}
			if got != tt.ruleID {
				t.Fatalf("interruption rule=%d want=%d (url=%q)", got, tt.ruleID, tt.req.URL.String())
			}
		})
	}
}

func TestEngineSelectionRejectsCorazaExtraRulesForNonCorazaMode(t *testing.T) {
	oldMode := config.WAFEngineMode
	config.WAFEngineMode = "mod_security"
	defer func() {
		config.WAFEngineMode = oldMode
	}()

	if got := GetBaseEngine(); got != nil {
		t.Fatalf("GetBaseEngine()=%T, want nil for unavailable non-Coraza mode", got)
	}
	if _, err := GetEngineForExtraRule("custom.conf"); err == nil || !strings.Contains(err.Error(), "mod_security") {
		t.Fatalf("GetEngineForExtraRule() error=%v, want mod_security availability error", err)
	}
}

func mustWrite(t *testing.T, path string, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile(%s) error = %v", path, err)
	}
}
