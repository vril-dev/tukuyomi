package config

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
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

func TestParseDBDriver(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{in: "", want: "sqlite"},
		{in: "sqlite", want: "sqlite"},
		{in: "mysql", want: "mysql"},
		{in: "pgsql", want: "pgsql"},
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

func TestParseProxyRollbackHistorySize(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 8},
		{in: "-1", want: 1},
		{in: "0", want: 1},
		{in: "1", want: 1},
		{in: "8", want: 8},
		{in: "256", want: 64},
		{in: "abc", want: 8},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseProxyRollbackHistorySize(tc.in); got != tc.want {
				t.Fatalf("parseProxyRollbackHistorySize(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseServerTimeoutSec(t *testing.T) {
	cases := []struct {
		name      string
		in        string
		def       int
		allowZero bool
		want      int
	}{
		{name: "default", in: "", def: 30, allowZero: false, want: 30},
		{name: "negative-fallback", in: "-1", def: 30, allowZero: false, want: 30},
		{name: "zero-disallowed", in: "0", def: 30, allowZero: false, want: 30},
		{name: "zero-allowed", in: "0", def: 30, allowZero: true, want: 0},
		{name: "valid", in: "15", def: 30, allowZero: false, want: 15},
		{name: "cap", in: "999999", def: 30, allowZero: false, want: 3600},
		{name: "invalid-fallback", in: "abc", def: 30, allowZero: false, want: 30},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			if got := parseServerTimeoutSec(tc.in, tc.def, tc.allowZero); got != tc.want {
				t.Fatalf("parseServerTimeoutSec(%q,%d,%v)=%d want=%d", tc.in, tc.def, tc.allowZero, got, tc.want)
			}
		})
	}
}

func TestParseServerMaxHeaderBytes(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 1 << 20},
		{in: "1", want: 1024},
		{in: "1024", want: 1024},
		{in: "2097152", want: 2097152},
		{in: "999999999", want: 16 << 20},
		{in: "abc", want: 1 << 20},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseServerMaxHeaderBytes(tc.in); got != tc.want {
				t.Fatalf("parseServerMaxHeaderBytes(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseServerConcurrency(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 0},
		{in: "-1", want: 0},
		{in: "0", want: 0},
		{in: "100", want: 100},
		{in: "9999999", want: 200000},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseServerConcurrency(tc.in); got != tc.want {
				t.Fatalf("parseServerConcurrency(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseServerQueueSize(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 0},
		{in: "-1", want: 0},
		{in: "0", want: 0},
		{in: "128", want: 128},
		{in: "9999999", want: 200000},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseServerQueueSize(tc.in); got != tc.want {
				t.Fatalf("parseServerQueueSize(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseServerQueueTimeoutMS(t *testing.T) {
	cases := []struct {
		in   string
		want int
	}{
		{in: "", want: 0},
		{in: "-1", want: 0},
		{in: "0", want: 0},
		{in: "100", want: 100},
		{in: "999999", want: 60000},
		{in: "abc", want: 0},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.in, func(t *testing.T) {
			if got := parseServerQueueTimeoutMS(tc.in); got != tc.want {
				t.Fatalf("parseServerQueueTimeoutMS(%q)=%d want=%d", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseRuntimeCaps(t *testing.T) {
	if got := parseRuntimeGOMAXPROCS("-1"); got != 0 {
		t.Fatalf("parseRuntimeGOMAXPROCS(-1)=%d want=0", got)
	}
	if got := parseRuntimeGOMAXPROCS("5000"); got != 4096 {
		t.Fatalf("parseRuntimeGOMAXPROCS(5000)=%d want=4096", got)
	}
	if got := parseRuntimeMemoryLimitMB("-1"); got != 0 {
		t.Fatalf("parseRuntimeMemoryLimitMB(-1)=%d want=0", got)
	}
	if got := parseRuntimeMemoryLimitMB("9999999"); got != 1024*1024 {
		t.Fatalf("parseRuntimeMemoryLimitMB(9999999)=%d want=%d", got, 1024*1024)
	}
}

func TestLoadAppConfigFile(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":18090"},
		"admin": {
			"api_base_path": "/tukuyomi-api",
			"ui_base_path": "/tukuyomi-ui",
			"api_key_primary": "very-strong-random-api-key-12345",
			"session_secret": "very-strong-random-session-secret-12345",
			"session_ttl_sec": 7200
		},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"security_audit": {
			"enabled": true,
			"capture_mode": "enforced_only",
			"hmac_key": "0123456789abcdef0123456789abcdef",
			"hmac_key_id": "sig-test"
		},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("loadAppConfigFile returned error: %v", err)
	}
	if cfg.Server.ListenAddr != ":18090" {
		t.Fatalf("unexpected listen_addr: %s", cfg.Server.ListenAddr)
	}
	if cfg.Paths.ProxyConfigFile != "conf/proxy.json" {
		t.Fatalf("unexpected proxy_config_file: %s", cfg.Paths.ProxyConfigFile)
	}
	if cfg.Paths.PHPRuntimeInventoryFile != "data/php-fpm/inventory.json" {
		t.Fatalf("unexpected php_runtime_inventory_file: %s", cfg.Paths.PHPRuntimeInventoryFile)
	}
	if cfg.Paths.VhostConfigFile != "data/php-fpm/vhosts.json" {
		t.Fatalf("unexpected vhost_config_file: %s", cfg.Paths.VhostConfigFile)
	}
	if cfg.Paths.ScheduledTaskConfigFile != "conf/scheduled-tasks.json" {
		t.Fatalf("unexpected scheduled_task_config_file: %s", cfg.Paths.ScheduledTaskConfigFile)
	}
	if cfg.Paths.CacheRulesFile != "conf/cache-rules.json" {
		t.Fatalf("unexpected cache_rules_file: %s", cfg.Paths.CacheRulesFile)
	}
	if cfg.SecurityAudit.CaptureMode != "enforced_only" {
		t.Fatalf("unexpected security audit capture mode: %s", cfg.SecurityAudit.CaptureMode)
	}
	if cfg.Admin.SessionSecret != "very-strong-random-session-secret-12345" {
		t.Fatalf("unexpected session secret: %q", cfg.Admin.SessionSecret)
	}
	if cfg.Admin.SessionTTLSec != 7200 {
		t.Fatalf("unexpected session ttl: %d", cfg.Admin.SessionTTLSec)
	}
	if cfg.Proxy.Engine.Mode != ProxyEngineModeTukuyomiProxy {
		t.Fatalf("unexpected proxy engine mode: %s", cfg.Proxy.Engine.Mode)
	}
	if err := ReloadFromConfigFile(cfgPath); err != nil {
		t.Fatalf("ReloadFromConfigFile returned error: %v", err)
	}
	if ProxyEngineMode != ProxyEngineModeTukuyomiProxy {
		t.Fatalf("unexpected runtime proxy engine mode: %s", ProxyEngineMode)
	}
}

func TestLoadAppConfigFileRejectsInvalid(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":9090"},
		"admin": {"api_base_path": "/", "ui_base_path": "/tukuyomi-ui"},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := loadAppConfigFile(cfgPath); err == nil {
		t.Fatal("expected validation error, got nil")
	}
}

func TestLoadAppConfigFileRejectsRemovedFileStorageBackend(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":9090"},
		"admin": {"api_base_path": "/tukuyomi-api", "ui_base_path": "/tukuyomi-ui"},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"backend": "file", "db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := loadAppConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "storage.backend=file has been removed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAppConfigFileAcceptsPgSQLStorageDriver(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":9090"},
		"admin": {"api_base_path": "/tukuyomi-api", "ui_base_path": "/tukuyomi-ui"},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "pgsql", "db_dsn": "postgres://user:pass@localhost/tukuyomi?sslmode=disable"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	cfg, err := loadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("loadAppConfigFile returned error: %v", err)
	}
	if cfg.Storage.DBDriver != "pgsql" {
		t.Fatalf("db_driver=%q want pgsql", cfg.Storage.DBDriver)
	}
}

func TestLoadAppConfigFileRejectsRemovedFPTunerMockMode(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":9090"},
		"admin": {"api_base_path": "/tukuyomi-api", "ui_base_path": "/tukuyomi-ui"},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {"rollback_history_size": 8},
		"fp_tuner": {"mode": "mock", "timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := loadAppConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "fp_tuner.mode=mock has been removed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadAppConfigFileRejectsInvalidProxyEngineMode(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "config.json")
	raw := `{
		"server": {"listen_addr": ":9090"},
		"admin": {"api_base_path": "/tukuyomi-api", "ui_base_path": "/tukuyomi-ui"},
		"paths": {
			"proxy_config_file": "conf/proxy.json",
			"security_audit_file": "audit/security-audit.ndjson",
			"security_audit_blob_dir": "audit/security-audit-blobs",
			"rules_file": "tukuyomi.conf"
		},
		"proxy": {
			"rollback_history_size": 8,
			"engine": {"mode": "native"}
		},
		"fp_tuner": {"timeout_sec": 15, "approval_ttl_sec": 600},
		"storage": {"db_driver": "sqlite"}
	}`
	if err := os.WriteFile(cfgPath, []byte(raw), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	_, err := loadAppConfigFile(cfgPath)
	if err == nil {
		t.Fatal("expected validation error, got nil")
	}
	if !strings.Contains(err.Error(), "proxy.engine.mode") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestListenAddrExposesBeyondLoopback(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{addr: ":9090", want: true},
		{addr: "0.0.0.0:9090", want: true},
		{addr: "[::]:9090", want: true},
		{addr: "admin.example.com:9090", want: true},
		{addr: "127.0.0.1:9090", want: false},
		{addr: "[::1]:9090", want: false},
		{addr: "localhost:9090", want: false},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.addr, func(t *testing.T) {
			if got := listenAddrExposesBeyondLoopback(tc.addr); got != tc.want {
				t.Fatalf("listenAddrExposesBeyondLoopback(%q)=%v want=%v", tc.addr, got, tc.want)
			}
		})
	}
}

func TestAdminExposureWarnings(t *testing.T) {
	if got := adminExposureWarnings(":9090", "api_only_external", nil); len(got) != 0 {
		t.Fatalf("unexpected warning for api_only_external: %#v", got)
	}
	if got := adminExposureWarnings("127.0.0.1:9090", "full_external", nil); len(got) != 0 {
		t.Fatalf("unexpected warning for loopback listener: %#v", got)
	}
	got := adminExposureWarnings(":9090", "full_external", nil)
	if len(got) == 0 {
		t.Fatal("expected warning for public full_external listener")
	}
	if !strings.Contains(got[0], "embedded admin UI and admin API") {
		t.Fatalf("unexpected warning text: %#v", got)
	}

	got = adminExposureWarnings(":9090", "api_only_external", []string{"0.0.0.0/0"})
	if len(got) == 0 {
		t.Fatal("expected warning for broad trusted admin cidr")
	}
	if !strings.Contains(strings.Join(got, "\n"), "admin.trusted_cidrs includes 0.0.0.0/0") {
		t.Fatalf("expected trusted_cidrs warning, got: %#v", got)
	}
}

func TestEmitAdminExposureWarnings(t *testing.T) {
	prevListenAddr := ListenAddr
	prevMode := AdminExternalMode
	prevCIDRs := append([]string(nil), AdminTrustedCIDRs...)
	defer func() {
		ListenAddr = prevListenAddr
		AdminExternalMode = prevMode
		AdminTrustedCIDRs = prevCIDRs
	}()

	ListenAddr = ":9090"
	AdminExternalMode = "full_external"
	AdminTrustedCIDRs = nil

	var buf bytes.Buffer
	prevWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevWriter)

	emitAdminExposureWarnings()

	logged := buf.String()
	if !strings.Contains(logged, "[SECURITY][WARN]") || !strings.Contains(logged, "admin.external_mode=full_external") {
		t.Fatalf("warning log missing expected content: %s", logged)
	}
}

func TestEmitAdminExposureWarningsForBroadTrustedCIDR(t *testing.T) {
	prevListenAddr := ListenAddr
	prevMode := AdminExternalMode
	prevCIDRs := append([]string(nil), AdminTrustedCIDRs...)
	defer func() {
		ListenAddr = prevListenAddr
		AdminExternalMode = prevMode
		AdminTrustedCIDRs = prevCIDRs
	}()

	ListenAddr = ":9090"
	AdminExternalMode = "api_only_external"
	AdminTrustedCIDRs = []string{"203.0.113.10/32"}

	var buf bytes.Buffer
	prevWriter := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prevWriter)

	emitAdminExposureWarnings()

	logged := buf.String()
	if !strings.Contains(logged, "[SECURITY][WARN]") || !strings.Contains(logged, "admin.trusted_cidrs includes 203.0.113.10/32") {
		t.Fatalf("trusted cidr warning missing expected content: %s", logged)
	}
}
