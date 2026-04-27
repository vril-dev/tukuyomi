package crsselection

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestParseDisabled(t *testing.T) {
	raw := `
# comment
REQUEST-913-SCANNER-DETECTION.conf
REQUEST-920-PROTOCOL-ENFORCEMENT.conf # inline comment
`
	got := ParseDisabled(raw)
	if _, ok := got["REQUEST-913-SCANNER-DETECTION.conf"]; !ok {
		t.Fatal("missing REQUEST-913-SCANNER-DETECTION.conf")
	}
	if _, ok := got["REQUEST-920-PROTOCOL-ENFORCEMENT.conf"]; !ok {
		t.Fatal("missing REQUEST-920-PROTOCOL-ENFORCEMENT.conf")
	}
}

func TestFilterEnabledPaths(t *testing.T) {
	paths := []string{
		"rules/crs/rules/REQUEST-901-INITIALIZATION.conf",
		"rules/crs/rules/REQUEST-920-PROTOCOL-ENFORCEMENT.conf",
	}
	disabled := map[string]struct{}{"REQUEST-920-PROTOCOL-ENFORCEMENT.conf": {}}
	got := FilterEnabledPaths(paths, disabled)
	want := []string{"rules/crs/rules/REQUEST-901-INITIALIZATION.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("FilterEnabledPaths() = %v, want %v", got, want)
	}
}

func TestBuildDisabledFromEnabled(t *testing.T) {
	all := []string{
		filepath.Join("rules", "crs", "rules", "REQUEST-901-INITIALIZATION.conf"),
		filepath.Join("rules", "crs", "rules", "REQUEST-920-PROTOCOL-ENFORCEMENT.conf"),
		filepath.Join("rules", "crs", "rules", "REQUEST-933-APPLICATION-ATTACK-PHP.conf"),
	}
	enabled := []string{"REQUEST-901-INITIALIZATION.conf", "REQUEST-933-APPLICATION-ATTACK-PHP.conf"}
	got, err := BuildDisabledFromEnabled(all, enabled)
	if err != nil {
		t.Fatalf("BuildDisabledFromEnabled() error = %v", err)
	}
	want := []string{"REQUEST-920-PROTOCOL-ENFORCEMENT.conf"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("BuildDisabledFromEnabled() = %v, want %v", got, want)
	}
}

func TestBuildDisabledFromEnabled_Unknown(t *testing.T) {
	all := []string{filepath.Join("rules", "crs", "rules", "REQUEST-901-INITIALIZATION.conf")}
	_, err := BuildDisabledFromEnabled(all, []string{"UNKNOWN.conf"})
	if err == nil || !strings.Contains(err.Error(), "unknown CRS rule") {
		t.Fatalf("unexpected error: %v", err)
	}
}
