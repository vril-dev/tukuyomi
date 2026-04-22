package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

func TestGetSettingsListenerAdmin(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-api/settings/listener-admin", nil)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	GetSettingsListenerAdmin(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	var out struct {
		ETag    string                            `json:"etag"`
		Config  settingsListenerAdminConfig       `json:"config"`
		Secrets settingsListenerAdminSecretStatus `json:"secrets"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if out.ETag == "" {
		t.Fatal("expected etag to be present")
	}
	if out.Config.Server.ListenAddr != ":18090" {
		t.Fatalf("listen_addr=%q want=:18090", out.Config.Server.ListenAddr)
	}
	if out.Config.Admin.APIBasePath != "/tukuyomi-api" {
		t.Fatalf("api_base_path=%q want=/tukuyomi-api", out.Config.Admin.APIBasePath)
	}
	if out.Config.Admin.ListenAddr != ":19090" {
		t.Fatalf("admin.listen_addr=%q want=:19090", out.Config.Admin.ListenAddr)
	}
	if !out.Secrets.AdminSessionSecretConfigured {
		t.Fatal("expected session secret configured metadata")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("very-strong-random-session-secret-12345")) {
		t.Fatal("response must not expose raw session secret")
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("fixture-db-dsn-secret")) {
		t.Fatal("response must not expose raw DB DSN")
	}
}

func TestValidateSettingsListenerAdminRejectsInvalid(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()

	body := settingsListenerAdminPutBody{
		Config: settingsListenerAdminConfig{
			Server: createEmptySettingsTestConfig().Server,
			Admin: settingsListenerAdminAdminConfig{
				APIBasePath:        "/",
				UIBasePath:         "/tukuyomi-ui",
				ExternalMode:       "api_only_external",
				TrustedCIDRs:       []string{"127.0.0.1/32"},
				RateLimit:          settingsListenerAdminRateLimitConfig{StatusCode: 429},
				CORSAllowedOrigins: []string{},
			},
		},
	}
	raw, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/tukuyomi-api/settings/listener-admin/validate", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	ValidateSettingsListenerAdmin(c)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestPutSettingsListenerAdminSavesSubsetAndPreservesSecrets(t *testing.T) {
	gin.SetMode(gin.TestMode)

	cfgPath := writeSettingsConfigFixture(t)
	restore := saveConfigFilePathForTest(t, cfgPath)
	defer restore()

	currentRaw, _, err := readFileMaybe(cfgPath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	etag := bypassconf.ComputeETag(currentRaw)

	next := createEmptySettingsTestConfig()
	next.Server.ListenAddr = ":443"
	next.Server.ReadTimeoutSec = 45
	next.Server.GracefulShutdownTimeoutSec = 60
	next.Server.MaxHeaderBytes = 2097152
	next.Runtime.GOMAXPROCS = 4
	next.Runtime.MemoryLimitMB = 512
	next.RequestMeta.Country.Mode = "mmdb"
	next.Admin.ExternalMode = "deny_external"
	next.Admin.ListenAddr = ":19091"
	next.Admin.TrustedCIDRs = []string{"127.0.0.1/32", "192.168.0.0/16"}
	next.Admin.TrustForwardedFor = true
	next.Storage.Backend = "db"
	next.Storage.DBDriver = "mysql"
	next.Storage.DBPath = "logs/coraza/custom.db"
	next.Storage.DBRetentionDays = 90
	next.Storage.DBSyncIntervalSec = 30
	next.Storage.FileRotateBytes = 1024
	next.Storage.FileMaxBytes = 4096
	next.Storage.FileRetentionDays = 21
	next.Paths.ScheduledTaskConfigFile = "conf/tasks.custom.json"
	next.Proxy.RollbackHistorySize = 12
	next.Proxy.Engine.Mode = config.ProxyEngineModeTukuyomiProxy
	next.CRS.Enable = false
	next.FPTuner.Endpoint = "https://fp.example.test/api"
	next.FPTuner.Model = "gpt-test"
	next.FPTuner.TimeoutSec = 20
	next.FPTuner.RequireApproval = false
	next.FPTuner.ApprovalTTLSec = 1200
	next.FPTuner.AuditFile = "logs/coraza/fp-custom.ndjson"
	next.Observability.Tracing.Enabled = true
	next.Observability.Tracing.ServiceName = "tukuyomi-test"
	next.Observability.Tracing.OTLPEndpoint = "http://otel-collector:4318"
	next.Observability.Tracing.Insecure = true
	next.Observability.Tracing.SampleRatio = 0.5

	body := settingsListenerAdminPutBody{Config: next}
	raw, _ := json.Marshal(body)

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPut, "/tukuyomi-api/settings/listener-admin", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)
	c, _ := gin.CreateTestContext(rec)
	c.Request = req

	PutSettingsListenerAdmin(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}

	saved, err := config.LoadAppConfigFile(cfgPath)
	if err != nil {
		t.Fatalf("reload saved config: %v", err)
	}
	if saved.Server.ListenAddr != ":443" {
		t.Fatalf("saved listen_addr=%q want=:443", saved.Server.ListenAddr)
	}
	if saved.Server.ReadTimeoutSec != 45 {
		t.Fatalf("saved read_timeout_sec=%d want=45", saved.Server.ReadTimeoutSec)
	}
	if saved.Server.GracefulShutdownTimeoutSec != 60 {
		t.Fatalf("saved graceful_shutdown_timeout_sec=%d want=60", saved.Server.GracefulShutdownTimeoutSec)
	}
	if saved.Server.MaxHeaderBytes != 2097152 {
		t.Fatalf("saved max_header_bytes=%d want=2097152", saved.Server.MaxHeaderBytes)
	}
	if saved.Runtime.GOMAXPROCS != 4 {
		t.Fatalf("saved gomaxprocs=%d want=4", saved.Runtime.GOMAXPROCS)
	}
	if saved.Runtime.MemoryLimitMB != 512 {
		t.Fatalf("saved memory_limit_mb=%d want=512", saved.Runtime.MemoryLimitMB)
	}
	if got, want := saved.RequestMeta.Country.Mode, "header"; got != want {
		t.Fatalf("saved request country mode=%q want=%q", got, want)
	}
	if saved.Admin.ExternalMode != "deny_external" {
		t.Fatalf("saved external_mode=%q want=deny_external", saved.Admin.ExternalMode)
	}
	if saved.Admin.ListenAddr != ":19091" {
		t.Fatalf("saved admin.listen_addr=%q want=:19091", saved.Admin.ListenAddr)
	}
	if !saved.Admin.TrustForwardedFor {
		t.Fatal("expected trust_forwarded_for to be saved")
	}
	if saved.Storage.Backend != "db" || saved.Storage.DBDriver != "mysql" {
		t.Fatalf("saved storage backend/driver=%q/%q want=db/mysql", saved.Storage.Backend, saved.Storage.DBDriver)
	}
	if saved.Storage.DBDSN != "fixture-db-dsn-secret" {
		t.Fatalf("db_dsn should be preserved, got %q", saved.Storage.DBDSN)
	}
	if !saved.Observability.Tracing.Enabled {
		t.Fatal("expected tracing enabled after save")
	}
	if saved.Observability.Tracing.SampleRatio != 0.5 {
		t.Fatalf("saved tracing sample_ratio=%v want=0.5", saved.Observability.Tracing.SampleRatio)
	}
	if saved.Paths.ScheduledTaskConfigFile != "conf/tasks.custom.json" {
		t.Fatalf("saved scheduled_task_config_file=%q want custom path", saved.Paths.ScheduledTaskConfigFile)
	}
	if saved.Proxy.RollbackHistorySize != 12 {
		t.Fatalf("saved rollback_history_size=%d want=12", saved.Proxy.RollbackHistorySize)
	}
	if saved.Proxy.Engine.Mode != config.ProxyEngineModeTukuyomiProxy {
		t.Fatalf("saved proxy.engine.mode=%q want=%q", saved.Proxy.Engine.Mode, config.ProxyEngineModeTukuyomiProxy)
	}
	if saved.CRS.Enable {
		t.Fatal("expected crs.enable=false after save")
	}
	if saved.FPTuner.Endpoint != "https://fp.example.test/api" {
		t.Fatalf("saved fp_tuner.endpoint=%q want custom endpoint", saved.FPTuner.Endpoint)
	}
	if saved.FPTuner.Mode != "" {
		t.Fatalf("saved fp_tuner.mode=%q want empty", saved.FPTuner.Mode)
	}
	if saved.FPTuner.MockResponseFile != "" {
		t.Fatalf("saved fp_tuner.mock_response_file=%q want empty", saved.FPTuner.MockResponseFile)
	}
	if saved.FPTuner.APIKey != "fp-secret-token" {
		t.Fatalf("fp_tuner api key should be preserved, got %q", saved.FPTuner.APIKey)
	}
	if saved.Admin.SessionSecret != "very-strong-random-session-secret-12345" {
		t.Fatalf("session secret should be preserved, got %q", saved.Admin.SessionSecret)
	}
}

func writeSettingsConfigFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	raw := `{
  "server": {
    "listen_addr": ":18090",
    "tls": {
      "enabled": false,
      "cert_file": "",
      "key_file": "",
      "min_version": "tls1.2",
      "redirect_http": false,
      "http_redirect_addr": ""
    },
    "http3": {
      "enabled": false,
      "alt_svc_max_age_sec": 86400
    }
  },
  "admin": {
    "api_base_path": "/tukuyomi-api",
    "ui_base_path": "/tukuyomi-ui",
    "listen_addr": ":19090",
    "api_key_primary": "very-strong-random-api-key-12345",
    "session_secret": "very-strong-random-session-secret-12345",
    "session_ttl_sec": 7200,
    "external_mode": "api_only_external",
    "trusted_cidrs": ["127.0.0.1/32"],
    "trust_forwarded_for": false,
    "read_only": false,
    "rate_limit": {
      "enabled": false,
      "rps": 5,
      "burst": 10,
      "status_code": 429,
      "retry_after_seconds": 1
    }
  },
  "paths": {
    "proxy_config_file": "conf/proxy.json",
    "security_audit_file": "logs/coraza/security-audit.ndjson",
    "security_audit_blob_dir": "logs/coraza/security-audit-blobs",
    "rules_file": "rules/tukuyomi.conf"
  },
  "proxy": {
    "rollback_history_size": 8,
    "engine": {"mode": "tukuyomi_proxy"}
  },
  "security_audit": {
    "enabled": true,
    "capture_mode": "enforced_only",
    "hmac_key": "0123456789abcdef0123456789abcdef",
    "hmac_key_id": "sig-test"
  },
  "fp_tuner": {"api_key": "fp-secret-token", "timeout_sec": 15, "approval_ttl_sec": 600},
  "storage": {"backend": "file", "db_driver": "sqlite", "db_dsn": "fixture-db-dsn-secret"}
}`
	if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
		t.Fatalf("write fixture config: %v", err)
	}
	return path
}

func saveConfigFilePathForTest(t *testing.T, path string) func() {
	t.Helper()
	prev := config.ConfigFile
	config.ConfigFile = path
	return func() {
		config.ConfigFile = prev
	}
}

func createEmptySettingsTestConfig() settingsListenerAdminConfig {
	return settingsListenerAdminConfig{
		Server: settingsListenerAdminServerConfig{
			ListenAddr:                  ":18090",
			ReadTimeoutSec:              30,
			ReadHeaderTimeoutSec:        5,
			WriteTimeoutSec:             0,
			IdleTimeoutSec:              120,
			GracefulShutdownTimeoutSec:  30,
			MaxHeaderBytes:              1048576,
			MaxConcurrentRequests:       0,
			MaxQueuedRequests:           0,
			QueuedRequestTimeoutMS:      0,
			MaxConcurrentProxyRequests:  0,
			MaxQueuedProxyRequests:      32,
			QueuedProxyRequestTimeoutMS: 100,
			TLS: settingsListenerAdminServerTLSConfig{
				Enabled:          false,
				CertFile:         "",
				KeyFile:          "",
				MinVersion:       "tls1.2",
				RedirectHTTP:     false,
				HTTPRedirectAddr: "",
			},
			HTTP3: settingsListenerAdminServerHTTP3Config{
				Enabled:         false,
				AltSvcMaxAgeSec: 86400,
			},
		},
		Runtime: settingsListenerAdminRuntimeConfig{
			GOMAXPROCS:    0,
			MemoryLimitMB: 0,
		},
		Admin: settingsListenerAdminAdminConfig{
			APIBasePath:        "/tukuyomi-api",
			UIBasePath:         "/tukuyomi-ui",
			ListenAddr:         "",
			ExternalMode:       "api_only_external",
			TrustedCIDRs:       []string{"127.0.0.1/32"},
			TrustForwardedFor:  false,
			ReadOnly:           false,
			CORSAllowedOrigins: []string{},
			RateLimit: settingsListenerAdminRateLimitConfig{
				Enabled:           false,
				RPS:               5,
				Burst:             10,
				StatusCode:        429,
				RetryAfterSeconds: 1,
			},
		},
		Storage: settingsListenerAdminStorageConfig{
			Backend:           "file",
			DBDriver:          "sqlite",
			DBPath:            "logs/coraza/tukuyomi.db",
			DBRetentionDays:   30,
			DBSyncIntervalSec: 0,
			FileRotateBytes:   8 * 1024 * 1024,
			FileMaxBytes:      256 * 1024 * 1024,
			FileRetentionDays: 7,
		},
		Paths: settingsListenerAdminPathsConfig{
			ProxyConfigFile:         "conf/proxy.json",
			SiteConfigFile:          "conf/sites.json",
			PHPRuntimeInventoryFile: "data/php-fpm/inventory.json",
			VhostConfigFile:         "data/php-fpm/vhosts.json",
			ScheduledTaskConfigFile: "conf/scheduled-tasks.json",
			SecurityAuditFile:       "logs/coraza/security-audit.ndjson",
			SecurityAuditBlobDir:    "logs/coraza/security-audit-blobs",
			CacheStoreFile:          "conf/cache-store.json",
			RulesFile:               "rules/tukuyomi.conf",
			BypassFile:              "conf/waf-bypass.json",
			CountryBlockFile:        "conf/country-block.json",
			RateLimitFile:           "conf/rate-limit.json",
			BotDefenseFile:          "conf/bot-defense.json",
			SemanticFile:            "conf/semantic.json",
			NotificationFile:        "conf/notifications.json",
			IPReputationFile:        "conf/ip-reputation.json",
			LogFile:                 "",
			CRSSetupFile:            "rules/crs/crs-setup.conf",
			CRSRulesDir:             "rules/crs/rules",
			CRSDisabledFile:         "conf/crs-disabled.conf",
		},
		Proxy: settingsListenerAdminProxyConfig{
			RollbackHistorySize: 8,
			Engine: settingsListenerAdminProxyEngineConfig{
				Mode: config.ProxyEngineModeTukuyomiProxy,
			},
		},
		CRS: settingsListenerAdminCRSConfig{
			Enable: true,
		},
		FPTuner: settingsListenerAdminFPTunerConfig{
			Endpoint:        "",
			Model:           "",
			TimeoutSec:      15,
			RequireApproval: true,
			ApprovalTTLSec:  600,
			AuditFile:       "logs/coraza/fp-tuner-audit.ndjson",
		},
		Observability: settingsListenerAdminObservabilityConfig{
			Tracing: settingsListenerAdminTracingConfig{
				Enabled:      false,
				ServiceName:  "tukuyomi",
				OTLPEndpoint: "",
				Insecure:     false,
				SampleRatio:  1,
			},
		},
	}
}
