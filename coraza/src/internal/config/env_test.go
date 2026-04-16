package config

import (
	"net/netip"
	"testing"
)

func TestIsWeakAPIKey(t *testing.T) {
	cases := []struct {
		key  string
		weak bool
	}{
		{key: "", weak: true},
		{key: "short", weak: true},
		{key: "change-me", weak: true},
		{key: "replace-with-long-random-api-key", weak: true},
		{key: "dev-only-change-this-key-please", weak: false},
		{key: "n2H8x9fQ4mL7pRt2", weak: false},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.key, func(t *testing.T) {
			if got := isWeakAPIKey(tc.key); got != tc.weak {
				t.Fatalf("isWeakAPIKey(%q) = %v, want %v", tc.key, got, tc.weak)
			}
		})
	}
}

func TestTruthyFalsy(t *testing.T) {
	if !isTruthy("1") || !isTruthy("true") || !isTruthy("Yes") || !isTruthy("on") {
		t.Fatal("isTruthy() failed for truthy values")
	}
	if isTruthy("0") || isTruthy("off") || isTruthy("nope") {
		t.Fatal("isTruthy() returned true for falsy values")
	}

	if !isFalsy("0") || !isFalsy("false") || !isFalsy("NO") || !isFalsy("off") {
		t.Fatal("isFalsy() failed for falsy values")
	}
	if isFalsy("1") || isFalsy("on") || isFalsy("yes") {
		t.Fatal("isFalsy() returned true for truthy values")
	}
}

func TestParseCSV(t *testing.T) {
	got := parseCSV(" https://admin.example.com, http://localhost:5173 ,,")
	if len(got) != 2 {
		t.Fatalf("parseCSV() len=%d, want 2", len(got))
	}
	if got[0] != "https://admin.example.com" || got[1] != "http://localhost:5173" {
		t.Fatalf("parseCSV() = %#v", got)
	}
}

func TestParseStorageBackend(t *testing.T) {
	cases := []struct {
		name            string
		in              string
		legacyDBEnabled bool
		want            string
	}{
		{name: "explicit-file", in: "file", legacyDBEnabled: true, want: "file"},
		{name: "explicit-db", in: "db", legacyDBEnabled: false, want: "db"},
		{name: "legacy-fallback-db", in: "", legacyDBEnabled: true, want: "db"},
		{name: "legacy-fallback-file", in: "", legacyDBEnabled: false, want: "file"},
		{name: "invalid-fallback-file", in: "oracle", legacyDBEnabled: true, want: "file"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := parseStorageBackend(tc.in, tc.legacyDBEnabled)
			if got != tc.want {
				t.Fatalf("parseStorageBackend(%q, %v)=%q want=%q", tc.in, tc.legacyDBEnabled, got, tc.want)
			}
		})
	}
}

func TestParseDBDriver(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "sqlite"},
		{in: "sqlite", want: "sqlite"},
		{in: "mysql", want: "mysql"},
		{in: "oracle", want: "sqlite"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in+"->"+tc.want, func(t *testing.T) {
			got := parseDBDriver(tc.in)
			if got != tc.want {
				t.Fatalf("parseDBDriver(%q)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseDBSyncIntervalSec(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 0},
		{in: "-1", want: 0},
		{in: "0", want: 0},
		{in: "10", want: 10},
		{in: "999999", want: 3600},
		{in: "abc", want: 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseDBSyncIntervalSec(tc.in); got != tc.want {
				t.Fatalf("parseDBSyncIntervalSec(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs(t *testing.T) {
	cidrs, prefixes := parseTrustedProxyCIDRs("10.0.0.0/8, 192.0.2.10, invalid")
	if len(cidrs) != 2 {
		t.Fatalf("cidrs len=%d want=2", len(cidrs))
	}
	if cidrs[0] != "10.0.0.0/8" {
		t.Fatalf("cidrs[0]=%q want=%q", cidrs[0], "10.0.0.0/8")
	}
	if cidrs[1] != "192.0.2.10/32" {
		t.Fatalf("cidrs[1]=%q want=%q", cidrs[1], "192.0.2.10/32")
	}
	if len(prefixes) != 2 {
		t.Fatalf("prefixes len=%d want=2", len(prefixes))
	}
	if got := prefixes[1].String(); got != "192.0.2.10/32" {
		t.Fatalf("prefixes[1]=%q want=%q", got, "192.0.2.10/32")
	}
}

func TestParseAdminExternalMode(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "api_only_external"},
		{in: "deny_external", want: "deny_external"},
		{in: "api_only_external", want: "api_only_external"},
		{in: "full_external", want: "full_external"},
		{in: "invalid", want: "api_only_external"},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in+"->"+tc.want, func(t *testing.T) {
			if got := parseAdminExternalMode(tc.in); got != tc.want {
				t.Fatalf("parseAdminExternalMode(%q)=%q want=%q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseAdminTrustedCIDRsDefaults(t *testing.T) {
	cidrs, prefixes := parseAdminTrustedCIDRs("")
	if len(cidrs) != len(defaultAdminTrustedCIDRs) {
		t.Fatalf("len(cidrs)=%d want=%d", len(cidrs), len(defaultAdminTrustedCIDRs))
	}
	for i, want := range defaultAdminTrustedCIDRs {
		if cidrs[i] != want {
			t.Fatalf("cidrs[%d]=%q want=%q", i, cidrs[i], want)
		}
	}
	if len(prefixes) != len(defaultAdminTrustedCIDRs) {
		t.Fatalf("len(prefixes)=%d want=%d", len(prefixes), len(defaultAdminTrustedCIDRs))
	}
}

func TestAdminExposureWarnings(t *testing.T) {
	restoreMode := AdminExternalMode
	restorePrefixes := append([]netip.Prefix(nil), AdminTrustedCIDRPrefixes...)
	defer func() {
		AdminExternalMode = restoreMode
		AdminTrustedCIDRPrefixes = restorePrefixes
	}()

	AdminExternalMode = "api_only_external"
	AdminTrustedCIDRPrefixes = nil
	if got := AdminExposureWarnings(); len(got) != 0 {
		t.Fatalf("unexpected warnings for default posture: %#v", got)
	}

	AdminExternalMode = "full_external"
	AdminTrustedCIDRPrefixes = nil
	if got := AdminExposureWarnings(); len(got) == 0 {
		t.Fatal("expected warning for full_external")
	}

	AdminExternalMode = "api_only_external"
	AdminTrustedCIDRPrefixes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if got := AdminExposureWarnings(); len(got) == 0 {
		t.Fatal("expected warning for catch-all admin trusted cidr")
	}
}

func TestParseCountryHeaderNames(t *testing.T) {
	got := parseCountryHeaderNames("X-Country-Code, CF-IPCountry, x-country-code")
	if len(got) != 2 {
		t.Fatalf("len=%d want=2", len(got))
	}
	if got[0] != "X-Country-Code" {
		t.Fatalf("got[0]=%q want=%q", got[0], "X-Country-Code")
	}
	if got[1] != "CF-IPCountry" {
		t.Fatalf("got[1]=%q want=%q", got[1], "CF-IPCountry")
	}
}

func TestParseWAFDebugHeaderExposure(t *testing.T) {
	cases := []struct {
		name    string
		primary string
		legacy  string
		want    bool
	}{
		{name: "default-off", primary: "", legacy: "", want: false},
		{name: "primary-true", primary: "true", legacy: "", want: true},
		{name: "primary-false-wins", primary: "false", legacy: "true", want: false},
		{name: "legacy-true-fallback", primary: "", legacy: "1", want: true},
		{name: "legacy-false-fallback", primary: "", legacy: "false", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := parseWAFDebugHeaderExposure(tc.primary, tc.legacy); got != tc.want {
				t.Fatalf("parseWAFDebugHeaderExposure(%q, %q)=%v want=%v", tc.primary, tc.legacy, got, tc.want)
			}
		})
	}
}
