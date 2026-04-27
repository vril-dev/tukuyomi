package config

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"os"
	"strings"

	"tukuyomi/internal/wafengine"
)

const (
	ProxyEngineModeTukuyomiProxy      = "tukuyomi_proxy"
	DefaultProxyEngineMode            = ProxyEngineModeTukuyomiProxy
	WAFEngineModeCoraza               = wafengine.ModeCoraza
	DefaultWAFEngineMode              = wafengine.DefaultMode
	PersistentStorageBackendLocal     = "local"
	PersistentStorageBackendS3        = "s3"
	PersistentStorageBackendAzureBlob = "azure_blob"
	PersistentStorageBackendGCS       = "gcs"
	DefaultPersistentStorageBackend   = PersistentStorageBackendLocal
	DefaultPersistentStorageLocalDir  = "data/persistent"
)

type appConfigFile struct {
	Server        appServerConfig            `json:"server"`
	Runtime       appRuntimeConfig           `json:"runtime"`
	RequestMeta   appRequestMetaConfig       `json:"request_metadata"`
	Admin         appAdminConfig             `json:"admin"`
	Paths         appPathsConfig             `json:"paths"`
	Proxy         appProxyConfig             `json:"proxy"`
	WAF           appWAFConfig               `json:"waf"`
	SecurityAudit appSecurityAuditConfig     `json:"security_audit"`
	CRS           appCRSConfig               `json:"crs"`
	FPTuner       appFPTunerConfig           `json:"fp_tuner"`
	Storage       appStorageConfig           `json:"storage"`
	Persistent    appPersistentStorageConfig `json:"persistent_storage"`
	Observability appObservabilityConfig     `json:"observability"`
}

type appServerConfig struct {
	ListenAddr                  string                         `json:"listen_addr"`
	ReadTimeoutSec              int                            `json:"read_timeout_sec"`
	ReadHeaderTimeoutSec        int                            `json:"read_header_timeout_sec"`
	WriteTimeoutSec             int                            `json:"write_timeout_sec"`
	IdleTimeoutSec              int                            `json:"idle_timeout_sec"`
	GracefulShutdownTimeoutSec  int                            `json:"graceful_shutdown_timeout_sec"`
	MaxHeaderBytes              int                            `json:"max_header_bytes"`
	MaxConcurrentRequests       int                            `json:"max_concurrent_requests"`
	MaxQueuedRequests           int                            `json:"max_queued_requests"`
	QueuedRequestTimeoutMS      int                            `json:"queued_request_timeout_ms"`
	MaxConcurrentProxyRequests  int                            `json:"max_concurrent_proxy_requests"`
	MaxQueuedProxyRequests      int                            `json:"max_queued_proxy_requests"`
	QueuedProxyRequestTimeoutMS int                            `json:"queued_proxy_request_timeout_ms"`
	ProxyProtocol               appListenerProxyProtocolConfig `json:"proxy_protocol"`
	TLS                         appServerTLSConfig             `json:"tls"`
	HTTP3                       appServerHTTP3Config           `json:"http3"`
}

type appServerTLSConfig struct {
	Enabled          bool                   `json:"enabled"`
	CertFile         string                 `json:"cert_file"`
	KeyFile          string                 `json:"key_file"`
	MinVersion       string                 `json:"min_version"`
	RedirectHTTP     bool                   `json:"redirect_http"`
	HTTPRedirectAddr string                 `json:"http_redirect_addr"`
	ACME             appServerTLSACMEConfig `json:"acme"`
}

type appServerTLSACMEConfig struct {
	Enabled  bool     `json:"enabled"`
	Email    string   `json:"email"`
	Domains  []string `json:"domains"`
	CacheDir string   `json:"cache_dir"`
	Staging  bool     `json:"staging"`
}

type appServerHTTP3Config struct {
	Enabled         bool `json:"enabled"`
	AltSvcMaxAgeSec int  `json:"alt_svc_max_age_sec"`
}

type appRuntimeConfig struct {
	GOMAXPROCS    int `json:"gomaxprocs"`
	MemoryLimitMB int `json:"memory_limit_mb"`
}

type appRequestMetaConfig struct {
	Country appRequestMetaCountryConfig `json:"country"`
}

type appRequestMetaCountryConfig struct {
	Mode string `json:"mode"`
}

type appListenerProxyProtocolConfig struct {
	Enabled      bool     `json:"enabled"`
	TrustedCIDRs []string `json:"trusted_cidrs"`
}

type appAdminConfig struct {
	APIBasePath           string                         `json:"api_base_path"`
	UIBasePath            string                         `json:"ui_base_path"`
	ListenAddr            string                         `json:"listen_addr"`
	SessionSecret         string                         `json:"session_secret"`
	SessionTTLSec         int                            `json:"session_ttl_sec"`
	APIAuthDisable        bool                           `json:"api_auth_disable"`
	ReadOnly              bool                           `json:"read_only"`
	CORSAllowedOrigins    []string                       `json:"cors_allowed_origins"`
	StrictOverride        bool                           `json:"strict_override"`
	AllowInsecureDefaults bool                           `json:"allow_insecure_defaults"`
	ExternalMode          string                         `json:"external_mode"`
	TrustedCIDRs          []string                       `json:"trusted_cidrs"`
	TrustForwardedFor     bool                           `json:"trust_forwarded_for"`
	ProxyProtocol         appListenerProxyProtocolConfig `json:"proxy_protocol"`
	RateLimit             appAdminRateLimitConfig        `json:"rate_limit"`
}

type appAdminRateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	RPS               int  `json:"rps"`
	Burst             int  `json:"burst"`
	StatusCode        int  `json:"status_code"`
	RetryAfterSeconds int  `json:"retry_after_seconds"`
}

type appPathsConfig struct {
	ProxyConfigFile         string `json:"proxy_config_file"`
	SiteConfigFile          string `json:"site_config_file"`
	PHPRuntimeInventoryFile string `json:"php_runtime_inventory_file"`
	VhostConfigFile         string `json:"vhost_config_file"`
	ScheduledTaskConfigFile string `json:"scheduled_task_config_file"`
	SecurityAuditFile       string `json:"security_audit_file"`
	SecurityAuditBlobDir    string `json:"security_audit_blob_dir"`
	CacheRulesFile          string `json:"cache_rules_file"`
	CacheStoreFile          string `json:"cache_store_file"`
	RulesFile               string `json:"rules_file"`
	OverrideRulesDir        string `json:"override_rules_dir"`
	UpstreamRuntimeFile     string `json:"upstream_runtime_file"`
	BypassFile              string `json:"bypass_file"`
	CountryBlockFile        string `json:"country_block_file"`
	RateLimitFile           string `json:"rate_limit_file"`
	BotDefenseFile          string `json:"bot_defense_file"`
	SemanticFile            string `json:"semantic_file"`
	NotificationFile        string `json:"notification_file"`
	IPReputationFile        string `json:"ip_reputation_file"`
	LogFile                 string `json:"log_file"`
	CRSSetupFile            string `json:"crs_setup_file"`
	CRSRulesDir             string `json:"crs_rules_dir"`
	CRSDisabledFile         string `json:"crs_disabled_file"`
}

type appProxyConfig struct {
	RollbackHistorySize int                  `json:"rollback_history_size"`
	AuditFile           string               `json:"audit_file"`
	Engine              appProxyEngineConfig `json:"engine"`
}

type appProxyEngineConfig struct {
	Mode string `json:"mode"`
}

type appWAFConfig struct {
	Engine appWAFEngineConfig `json:"engine"`
}

type appWAFEngineConfig struct {
	Mode string `json:"mode"`
}

type appSecurityAuditConfig struct {
	Enabled                bool     `json:"enabled"`
	CaptureMode            string   `json:"capture_mode"`
	CaptureHeaders         bool     `json:"capture_headers"`
	CaptureBody            bool     `json:"capture_body"`
	MaxBodyBytes           int64    `json:"max_body_bytes"`
	RedactHeaders          []string `json:"redact_headers"`
	RedactBodyContentTypes []string `json:"redact_body_content_types"`
	KeySource              string   `json:"key_source"`
	EncryptionKey          string   `json:"encryption_key"`
	EncryptionKeyID        string   `json:"encryption_key_id"`
	HMACKey                string   `json:"hmac_key"`
	HMACKeyID              string   `json:"hmac_key_id"`
}

type appCRSConfig struct {
	Enable bool `json:"enable"`
}

type appFPTunerConfig struct {
	Mode             string `json:"mode,omitempty"`
	Endpoint         string `json:"endpoint"`
	APIKey           string `json:"api_key"`
	Model            string `json:"model"`
	TimeoutSec       int    `json:"timeout_sec"`
	MockResponseFile string `json:"mock_response_file,omitempty"`
	RequireApproval  bool   `json:"require_approval"`
	ApprovalTTLSec   int    `json:"approval_ttl_sec"`
	AuditFile        string `json:"audit_file"`
}

type appStorageConfig struct {
	// Deprecated: runtime storage is DB-only. Empty or "db" is accepted;
	// "file" is rejected during validation.
	Backend           string `json:"backend,omitempty"`
	DBDriver          string `json:"db_driver"`
	DBDSN             string `json:"db_dsn"`
	DBPath            string `json:"db_path"`
	DBRetentionDays   int    `json:"db_retention_days"`
	DBSyncIntervalSec int    `json:"db_sync_interval_sec"`
	FileRotateBytes   int64  `json:"file_rotate_bytes"`
	FileMaxBytes      int64  `json:"file_max_bytes"`
	FileRetentionDays int    `json:"file_retention_days"`
}

type appPersistentStorageConfig struct {
	Backend   string                              `json:"backend"`
	Local     appPersistentStorageLocalConfig     `json:"local"`
	S3        appPersistentStorageS3Config        `json:"s3"`
	AzureBlob appPersistentStorageAzureBlobConfig `json:"azure_blob"`
	GCS       appPersistentStorageGCSConfig       `json:"gcs"`
}

type appPersistentStorageLocalConfig struct {
	BaseDir string `json:"base_dir"`
}

type appPersistentStorageS3Config struct {
	Bucket         string `json:"bucket"`
	Region         string `json:"region"`
	Endpoint       string `json:"endpoint"`
	Prefix         string `json:"prefix"`
	ForcePathStyle bool   `json:"force_path_style"`
}

type appPersistentStorageAzureBlobConfig struct {
	AccountName string `json:"account_name"`
	Container   string `json:"container"`
	Endpoint    string `json:"endpoint"`
	Prefix      string `json:"prefix"`
}

type appPersistentStorageGCSConfig struct {
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix"`
}

type appObservabilityConfig struct {
	RequestLog appRequestLogConfig `json:"request_log"`
	Tracing    appTracingConfig    `json:"tracing"`
}

type appRequestLogConfig struct {
	Enabled bool `json:"enabled"`
}

type appTracingConfig struct {
	Enabled      bool    `json:"enabled"`
	ServiceName  string  `json:"service_name"`
	OTLPEndpoint string  `json:"otlp_endpoint"`
	Insecure     bool    `json:"insecure"`
	SampleRatio  float64 `json:"sample_ratio"`
}

func defaultAppConfigFile() appConfigFile {
	return appConfigFile{
		Server: appServerConfig{
			ListenAddr:                  ":9090",
			ReadTimeoutSec:              30,
			ReadHeaderTimeoutSec:        5,
			WriteTimeoutSec:             0,
			IdleTimeoutSec:              120,
			GracefulShutdownTimeoutSec:  30,
			MaxHeaderBytes:              1 << 20,
			MaxConcurrentRequests:       0,
			MaxQueuedRequests:           0,
			QueuedRequestTimeoutMS:      0,
			MaxConcurrentProxyRequests:  0,
			MaxQueuedProxyRequests:      32,
			QueuedProxyRequestTimeoutMS: 100,
			ProxyProtocol: appListenerProxyProtocolConfig{
				Enabled:      false,
				TrustedCIDRs: nil,
			},
			TLS: appServerTLSConfig{
				Enabled:          false,
				CertFile:         "",
				KeyFile:          "",
				MinVersion:       defaultServerTLSMinVersion,
				RedirectHTTP:     false,
				HTTPRedirectAddr: "",
				ACME: appServerTLSACMEConfig{
					Enabled:  false,
					Email:    "",
					Domains:  nil,
					CacheDir: "",
					Staging:  false,
				},
			},
			HTTP3: appServerHTTP3Config{
				Enabled:         false,
				AltSvcMaxAgeSec: 86400,
			},
		},
		Runtime: appRuntimeConfig{
			GOMAXPROCS:    0,
			MemoryLimitMB: 0,
		},
		RequestMeta: appRequestMetaConfig{
			Country: appRequestMetaCountryConfig{
				Mode: "header",
			},
		},
		Admin: appAdminConfig{
			APIBasePath:           "/tukuyomi-api",
			UIBasePath:            "/tukuyomi-ui",
			ListenAddr:            "",
			SessionSecret:         "",
			SessionTTLSec:         28800,
			APIAuthDisable:        false,
			ReadOnly:              false,
			CORSAllowedOrigins:    nil,
			StrictOverride:        false,
			AllowInsecureDefaults: false,
			ExternalMode:          "api_only_external",
			TrustedCIDRs:          []string{"127.0.0.1/32", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			TrustForwardedFor:     false,
			ProxyProtocol: appListenerProxyProtocolConfig{
				Enabled:      false,
				TrustedCIDRs: nil,
			},
			RateLimit: appAdminRateLimitConfig{
				Enabled:           false,
				RPS:               0,
				Burst:             0,
				StatusCode:        429,
				RetryAfterSeconds: 1,
			},
		},
		Paths: appPathsConfig{
			ProxyConfigFile:         "conf/proxy.json",
			SiteConfigFile:          "conf/sites.json",
			PHPRuntimeInventoryFile: "data/php-fpm/inventory.json",
			VhostConfigFile:         "data/php-fpm/vhosts.json",
			ScheduledTaskConfigFile: "conf/scheduled-tasks.json",
			SecurityAuditFile:       "audit/security-audit.ndjson",
			SecurityAuditBlobDir:    "audit/security-audit-blobs",
			CacheRulesFile:          DefaultCacheRulesFilePath,
			CacheStoreFile:          "conf/cache-store.json",
			RulesFile:               DefaultBaseRuleAssetPath,
			OverrideRulesDir:        "conf/rules",
			UpstreamRuntimeFile:     DefaultUpstreamRuntimeFilePath,
			BypassFile:              DefaultBypassFilePath,
			CountryBlockFile:        DefaultCountryBlockFilePath,
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
		Proxy: appProxyConfig{
			RollbackHistorySize: 8,
			AuditFile:           "audit/proxy-rules-audit.ndjson",
			Engine: appProxyEngineConfig{
				Mode: DefaultProxyEngineMode,
			},
		},
		WAF: appWAFConfig{
			Engine: appWAFEngineConfig{
				Mode: DefaultWAFEngineMode,
			},
		},
		SecurityAudit: appSecurityAuditConfig{
			Enabled:                false,
			CaptureMode:            "off",
			CaptureHeaders:         true,
			CaptureBody:            false,
			MaxBodyBytes:           32 * 1024,
			RedactHeaders:          []string{"Authorization", "Proxy-Authorization", "Cookie", "Set-Cookie", "X-API-Key"},
			RedactBodyContentTypes: []string{"multipart/form-data"},
			KeySource:              "config",
			EncryptionKey:          "",
			EncryptionKeyID:        "local-dev-aes-gcm",
			HMACKey:                "",
			HMACKeyID:              "local-dev-hmac",
		},
		CRS: appCRSConfig{
			Enable: true,
		},
		FPTuner: appFPTunerConfig{
			Endpoint:        "",
			APIKey:          "",
			Model:           "",
			TimeoutSec:      15,
			RequireApproval: true,
			ApprovalTTLSec:  600,
			AuditFile:       "audit/fp-tuner-audit.ndjson",
		},
		Storage: appStorageConfig{
			Backend:           "",
			DBDriver:          "sqlite",
			DBDSN:             "",
			DBPath:            "db/tukuyomi.db",
			DBRetentionDays:   30,
			DBSyncIntervalSec: 0,
			FileRotateBytes:   8 * 1024 * 1024,
			FileMaxBytes:      256 * 1024 * 1024,
			FileRetentionDays: 7,
		},
		Persistent: appPersistentStorageConfig{
			Backend: DefaultPersistentStorageBackend,
			Local: appPersistentStorageLocalConfig{
				BaseDir: DefaultPersistentStorageLocalDir,
			},
			S3: appPersistentStorageS3Config{
				Bucket:         "",
				Region:         "",
				Endpoint:       "",
				Prefix:         "",
				ForcePathStyle: false,
			},
			AzureBlob: appPersistentStorageAzureBlobConfig{
				AccountName: "",
				Container:   "",
				Endpoint:    "",
				Prefix:      "",
			},
			GCS: appPersistentStorageGCSConfig{
				Bucket: "",
				Prefix: "",
			},
		},
		Observability: appObservabilityConfig{
			RequestLog: appRequestLogConfig{
				Enabled: false,
			},
			Tracing: appTracingConfig{
				Enabled:      false,
				ServiceName:  "tukuyomi",
				OTLPEndpoint: "",
				Insecure:     false,
				SampleRatio:  1.0,
			},
		},
	}
}

func loadAppConfigFile(path string) (appConfigFile, error) {
	cfg := defaultAppConfigFile()
	f, err := os.Open(path)
	if err != nil {
		return appConfigFile{}, fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return appConfigFile{}, fmt.Errorf("decode json: %w", err)
	}
	normalizeAppConfigFile(&cfg)
	if err := validateAppConfigFile(cfg); err != nil {
		return appConfigFile{}, err
	}
	return cfg, nil
}

func normalizeAppConfigFile(cfg *appConfigFile) {
	cfg.Server.ListenAddr = strings.TrimSpace(cfg.Server.ListenAddr)
	normalizeAppServerTLSConfig(&cfg.Server.TLS)
	cfg.RequestMeta.Country.Mode = strings.ToLower(strings.TrimSpace(cfg.RequestMeta.Country.Mode))
	cfg.Admin.APIBasePath = strings.TrimSpace(cfg.Admin.APIBasePath)
	cfg.Admin.UIBasePath = strings.TrimSpace(cfg.Admin.UIBasePath)
	cfg.Admin.ListenAddr = strings.TrimSpace(cfg.Admin.ListenAddr)
	cfg.Admin.SessionSecret = strings.TrimSpace(cfg.Admin.SessionSecret)
	cfg.Admin.ExternalMode = strings.ToLower(strings.TrimSpace(cfg.Admin.ExternalMode))
	for i := range cfg.Server.ProxyProtocol.TrustedCIDRs {
		cfg.Server.ProxyProtocol.TrustedCIDRs[i] = strings.TrimSpace(cfg.Server.ProxyProtocol.TrustedCIDRs[i])
	}
	for i := range cfg.Admin.ProxyProtocol.TrustedCIDRs {
		cfg.Admin.ProxyProtocol.TrustedCIDRs[i] = strings.TrimSpace(cfg.Admin.ProxyProtocol.TrustedCIDRs[i])
	}
	cfg.FPTuner.Mode = strings.ToLower(strings.TrimSpace(cfg.FPTuner.Mode))
	cfg.FPTuner.Endpoint = strings.TrimSpace(cfg.FPTuner.Endpoint)
	cfg.FPTuner.APIKey = strings.TrimSpace(cfg.FPTuner.APIKey)
	cfg.FPTuner.Model = strings.TrimSpace(cfg.FPTuner.Model)
	cfg.Proxy.Engine.Mode = normalizeAppProxyEngineMode(cfg.Proxy.Engine.Mode)
	cfg.WAF.Engine.Mode = normalizeAppWAFEngineMode(cfg.WAF.Engine.Mode)
	cfg.SecurityAudit.CaptureMode = strings.ToLower(strings.TrimSpace(cfg.SecurityAudit.CaptureMode))
	cfg.SecurityAudit.KeySource = strings.ToLower(strings.TrimSpace(cfg.SecurityAudit.KeySource))
	cfg.SecurityAudit.EncryptionKey = strings.TrimSpace(cfg.SecurityAudit.EncryptionKey)
	cfg.SecurityAudit.EncryptionKeyID = strings.TrimSpace(cfg.SecurityAudit.EncryptionKeyID)
	cfg.SecurityAudit.HMACKey = strings.TrimSpace(cfg.SecurityAudit.HMACKey)
	cfg.SecurityAudit.HMACKeyID = strings.TrimSpace(cfg.SecurityAudit.HMACKeyID)
	for i := range cfg.SecurityAudit.RedactHeaders {
		cfg.SecurityAudit.RedactHeaders[i] = strings.TrimSpace(cfg.SecurityAudit.RedactHeaders[i])
	}
	for i := range cfg.SecurityAudit.RedactBodyContentTypes {
		cfg.SecurityAudit.RedactBodyContentTypes[i] = strings.TrimSpace(cfg.SecurityAudit.RedactBodyContentTypes[i])
	}
	cfg.Paths.ProxyConfigFile = strings.TrimSpace(cfg.Paths.ProxyConfigFile)
	cfg.Paths.SiteConfigFile = strings.TrimSpace(cfg.Paths.SiteConfigFile)
	cfg.Paths.PHPRuntimeInventoryFile = strings.TrimSpace(cfg.Paths.PHPRuntimeInventoryFile)
	cfg.Paths.VhostConfigFile = strings.TrimSpace(cfg.Paths.VhostConfigFile)
	cfg.Paths.ScheduledTaskConfigFile = strings.TrimSpace(cfg.Paths.ScheduledTaskConfigFile)
	cfg.Paths.SecurityAuditFile = strings.TrimSpace(cfg.Paths.SecurityAuditFile)
	cfg.Paths.SecurityAuditBlobDir = strings.TrimSpace(cfg.Paths.SecurityAuditBlobDir)
	cfg.Paths.CacheStoreFile = strings.TrimSpace(cfg.Paths.CacheStoreFile)
	cfg.Paths.RulesFile = NormalizeBaseRuleAssetSpec(cfg.Paths.RulesFile)
	cfg.Paths.OverrideRulesDir = strings.TrimSpace(cfg.Paths.OverrideRulesDir)
	if cfg.Paths.OverrideRulesDir == "" {
		cfg.Paths.OverrideRulesDir = "conf/rules"
	}
	cfg.Paths.UpstreamRuntimeFile = strings.TrimSpace(cfg.Paths.UpstreamRuntimeFile)
	if cfg.Paths.UpstreamRuntimeFile == "" {
		cfg.Paths.UpstreamRuntimeFile = DefaultUpstreamRuntimeFilePath
	}
	cfg.Paths.BypassFile = strings.TrimSpace(cfg.Paths.BypassFile)
	cfg.Paths.CountryBlockFile = strings.TrimSpace(cfg.Paths.CountryBlockFile)
	cfg.Paths.RateLimitFile = strings.TrimSpace(cfg.Paths.RateLimitFile)
	cfg.Paths.BotDefenseFile = strings.TrimSpace(cfg.Paths.BotDefenseFile)
	cfg.Paths.SemanticFile = strings.TrimSpace(cfg.Paths.SemanticFile)
	cfg.Paths.NotificationFile = strings.TrimSpace(cfg.Paths.NotificationFile)
	cfg.Paths.IPReputationFile = strings.TrimSpace(cfg.Paths.IPReputationFile)
	cfg.Paths.LogFile = strings.TrimSpace(cfg.Paths.LogFile)
	cfg.Paths.CRSSetupFile = strings.TrimSpace(cfg.Paths.CRSSetupFile)
	cfg.Paths.CRSRulesDir = strings.TrimSpace(cfg.Paths.CRSRulesDir)
	cfg.Paths.CRSDisabledFile = strings.TrimSpace(cfg.Paths.CRSDisabledFile)
	cfg.Storage.Backend = strings.ToLower(strings.TrimSpace(cfg.Storage.Backend))
	cfg.Storage.DBDriver = strings.ToLower(strings.TrimSpace(cfg.Storage.DBDriver))
	cfg.Storage.DBDSN = strings.TrimSpace(cfg.Storage.DBDSN)
	cfg.Storage.DBPath = strings.TrimSpace(cfg.Storage.DBPath)
	normalizePersistentStorageConfig(&cfg.Persistent)
	cfg.Observability.Tracing.ServiceName = strings.TrimSpace(cfg.Observability.Tracing.ServiceName)
	cfg.Observability.Tracing.OTLPEndpoint = strings.TrimSpace(cfg.Observability.Tracing.OTLPEndpoint)
}

func normalizePersistentStorageConfig(cfg *appPersistentStorageConfig) {
	cfg.Backend = strings.ToLower(strings.TrimSpace(cfg.Backend))
	if cfg.Backend == "" {
		cfg.Backend = DefaultPersistentStorageBackend
	}
	cfg.Local.BaseDir = strings.TrimSpace(cfg.Local.BaseDir)
	if cfg.Local.BaseDir == "" {
		cfg.Local.BaseDir = DefaultPersistentStorageLocalDir
	}
	cfg.S3.Bucket = strings.TrimSpace(cfg.S3.Bucket)
	cfg.S3.Region = strings.TrimSpace(cfg.S3.Region)
	cfg.S3.Endpoint = strings.TrimSpace(cfg.S3.Endpoint)
	cfg.S3.Prefix = normalizePersistentStoragePrefix(cfg.S3.Prefix)
	cfg.AzureBlob.AccountName = strings.TrimSpace(cfg.AzureBlob.AccountName)
	cfg.AzureBlob.Container = strings.TrimSpace(cfg.AzureBlob.Container)
	cfg.AzureBlob.Endpoint = strings.TrimSpace(cfg.AzureBlob.Endpoint)
	cfg.AzureBlob.Prefix = normalizePersistentStoragePrefix(cfg.AzureBlob.Prefix)
	cfg.GCS.Bucket = strings.TrimSpace(cfg.GCS.Bucket)
	cfg.GCS.Prefix = normalizePersistentStoragePrefix(cfg.GCS.Prefix)
}

func normalizePersistentStoragePrefix(prefix string) string {
	return strings.Trim(strings.TrimSpace(prefix), "/")
}

func validateAppConfigFile(cfg appConfigFile) error {
	if cfg.Server.ListenAddr == "" {
		return fmt.Errorf("server.listen_addr is required")
	}
	switch cfg.RequestMeta.Country.Mode {
	case "", "header", "mmdb":
	default:
		return fmt.Errorf("request_metadata.country.mode must be one of: header, mmdb")
	}
	if cfg.Admin.APIBasePath == "" {
		return fmt.Errorf("admin.api_base_path is required")
	}
	if !strings.HasPrefix(cfg.Admin.APIBasePath, "/") {
		return fmt.Errorf("admin.api_base_path must start with '/'")
	}
	if cfg.Admin.APIBasePath == "/" {
		return fmt.Errorf("admin.api_base_path cannot be '/'")
	}
	if cfg.Admin.UIBasePath == "" {
		return fmt.Errorf("admin.ui_base_path is required")
	}
	if !strings.HasPrefix(cfg.Admin.UIBasePath, "/") {
		return fmt.Errorf("admin.ui_base_path must start with '/'")
	}
	if cfg.Admin.UIBasePath == "/" {
		return fmt.Errorf("admin.ui_base_path cannot be '/'")
	}
	if cfg.Admin.APIBasePath == cfg.Admin.UIBasePath {
		return fmt.Errorf("admin.api_base_path and admin.ui_base_path must be different")
	}
	if cfg.Admin.SessionTTLSec < 0 {
		return fmt.Errorf("admin.session_ttl_sec must be >= 0")
	}
	switch cfg.Admin.ExternalMode {
	case "", "deny_external", "api_only_external", "full_external":
	default:
		return fmt.Errorf("admin.external_mode must be one of: deny_external, api_only_external, full_external")
	}
	for i, raw := range cfg.Admin.TrustedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("admin.trusted_cidrs[%d] invalid CIDR: %w", i, err)
		}
	}
	if err := validateAppListenerProxyProtocolConfig("server.proxy_protocol", cfg.Server.ProxyProtocol); err != nil {
		return err
	}
	if err := validateAppAdminListenerConfig(cfg); err != nil {
		return err
	}
	if err := validateAppAdminProxyProtocolConfig(cfg); err != nil {
		return err
	}
	if cfg.Admin.RateLimit.RPS < 0 || cfg.Admin.RateLimit.Burst < 0 || cfg.Admin.RateLimit.RetryAfterSeconds < 0 {
		return fmt.Errorf("admin.rate_limit values must be >= 0")
	}
	if cfg.Admin.RateLimit.Enabled {
		if cfg.Admin.RateLimit.RPS <= 0 {
			return fmt.Errorf("admin.rate_limit.rps must be > 0 when enabled=true")
		}
		if cfg.Admin.RateLimit.Burst <= 0 {
			return fmt.Errorf("admin.rate_limit.burst must be > 0 when enabled=true")
		}
		if cfg.Admin.RateLimit.StatusCode < 400 || cfg.Admin.RateLimit.StatusCode > 599 {
			return fmt.Errorf("admin.rate_limit.status_code must be between 400 and 599")
		}
	}
	if cfg.Paths.ProxyConfigFile == "" {
		return fmt.Errorf("paths.proxy_config_file is required")
	}
	if cfg.Paths.SiteConfigFile == "" {
		return fmt.Errorf("paths.site_config_file is required")
	}
	if cfg.Paths.PHPRuntimeInventoryFile == "" {
		return fmt.Errorf("paths.php_runtime_inventory_file is required")
	}
	if cfg.Paths.VhostConfigFile == "" {
		return fmt.Errorf("paths.vhost_config_file is required")
	}
	if cfg.Paths.ScheduledTaskConfigFile == "" {
		return fmt.Errorf("paths.scheduled_task_config_file is required")
	}
	if cfg.Paths.SecurityAuditFile == "" {
		return fmt.Errorf("paths.security_audit_file is required")
	}
	if cfg.Paths.SecurityAuditBlobDir == "" {
		return fmt.Errorf("paths.security_audit_blob_dir is required")
	}
	if cfg.Paths.CacheRulesFile == "" {
		return fmt.Errorf("paths.cache_rules_file is required")
	}
	if cfg.Paths.CacheStoreFile == "" {
		return fmt.Errorf("paths.cache_store_file is required")
	}
	if cfg.Paths.RulesFile == "" {
		return fmt.Errorf("paths.rules_file is required")
	}
	if cfg.Paths.UpstreamRuntimeFile == "" {
		return fmt.Errorf("paths.upstream_runtime_file is required")
	}
	if cfg.Paths.IPReputationFile == "" {
		return fmt.Errorf("paths.ip_reputation_file is required")
	}
	if cfg.Proxy.RollbackHistorySize < 1 || cfg.Proxy.RollbackHistorySize > 64 {
		return fmt.Errorf("proxy.rollback_history_size must be between 1 and 64")
	}
	switch cfg.Proxy.Engine.Mode {
	case ProxyEngineModeTukuyomiProxy:
	default:
		return fmt.Errorf("proxy.engine.mode must be %s", ProxyEngineModeTukuyomiProxy)
	}
	if err := wafengine.ValidateConfiguredMode(cfg.WAF.Engine.Mode); err != nil {
		return fmt.Errorf("waf.engine.mode: %w", err)
	}
	switch cfg.SecurityAudit.CaptureMode {
	case "", "off", "enforced_only", "security_events", "all_security_findings":
	default:
		return fmt.Errorf("security_audit.capture_mode must be one of: off, enforced_only, security_events, all_security_findings")
	}
	switch cfg.SecurityAudit.KeySource {
	case "", "config", "env":
	default:
		return fmt.Errorf("security_audit.key_source must be one of: config, env")
	}
	if cfg.SecurityAudit.MaxBodyBytes < 0 || cfg.SecurityAudit.MaxBodyBytes > 16*1024*1024 {
		return fmt.Errorf("security_audit.max_body_bytes must be between 0 and 16777216")
	}
	if cfg.Server.ReadTimeoutSec < 0 ||
		cfg.Server.ReadHeaderTimeoutSec < 0 ||
		cfg.Server.WriteTimeoutSec < 0 ||
		cfg.Server.IdleTimeoutSec < 0 ||
		cfg.Server.GracefulShutdownTimeoutSec < 0 {
		return fmt.Errorf("server timeout values must be >= 0")
	}
	if cfg.Server.MaxHeaderBytes < 0 ||
		cfg.Server.MaxConcurrentRequests < 0 ||
		cfg.Server.MaxQueuedRequests < 0 ||
		cfg.Server.QueuedRequestTimeoutMS < 0 ||
		cfg.Server.MaxConcurrentProxyRequests < 0 ||
		cfg.Server.MaxQueuedProxyRequests < 0 ||
		cfg.Server.QueuedProxyRequestTimeoutMS < 0 {
		return fmt.Errorf("server resource limits must be >= 0")
	}
	if cfg.Server.QueuedRequestTimeoutMS > 60000 || cfg.Server.QueuedProxyRequestTimeoutMS > 60000 {
		return fmt.Errorf("server queued request timeout values must be <= 60000")
	}
	if err := validateAppServerTLSConfig(cfg.Server); err != nil {
		return err
	}
	if err := validateAppServerHTTP3Config(cfg.Server); err != nil {
		return err
	}
	if cfg.Runtime.GOMAXPROCS < 0 || cfg.Runtime.MemoryLimitMB < 0 {
		return fmt.Errorf("runtime resource limits must be >= 0")
	}
	switch cfg.Storage.Backend {
	case "", "db":
	case "file":
		return fmt.Errorf("storage.backend=file has been removed; use storage.db_driver=sqlite, mysql, or pgsql")
	default:
		return fmt.Errorf("storage.backend must be empty or db")
	}
	if cfg.Storage.DBDriver != "sqlite" && cfg.Storage.DBDriver != "mysql" && cfg.Storage.DBDriver != "pgsql" {
		return fmt.Errorf("storage.db_driver must be one of: sqlite, mysql, pgsql")
	}
	if cfg.Storage.DBRetentionDays < 0 {
		return fmt.Errorf("storage.db_retention_days must be >= 0")
	}
	if cfg.Storage.DBSyncIntervalSec < 0 {
		return fmt.Errorf("storage.db_sync_interval_sec must be >= 0")
	}
	if cfg.Storage.FileRotateBytes < 0 || cfg.Storage.FileMaxBytes < 0 || cfg.Storage.FileRetentionDays < 0 {
		return fmt.Errorf("storage.file_* values must be >= 0")
	}
	if err := validatePersistentStorageConfig(cfg.Persistent); err != nil {
		return err
	}
	fpMode := strings.ToLower(strings.TrimSpace(cfg.FPTuner.Mode))
	if fpMode == "mock" {
		return fmt.Errorf("fp_tuner.mode=mock has been removed; configure fp_tuner.endpoint for the HTTP provider")
	}
	if fpMode != "" && fpMode != "http" {
		return fmt.Errorf("fp_tuner.mode must be empty or http")
	}
	if cfg.FPTuner.TimeoutSec < 1 || cfg.FPTuner.TimeoutSec > 300 {
		return fmt.Errorf("fp_tuner.timeout_sec must be between 1 and 300")
	}
	if cfg.FPTuner.ApprovalTTLSec < 10 || cfg.FPTuner.ApprovalTTLSec > 86400 {
		return fmt.Errorf("fp_tuner.approval_ttl_sec must be between 10 and 86400")
	}
	if cfg.Observability.Tracing.SampleRatio < 0 || cfg.Observability.Tracing.SampleRatio > 1 {
		return fmt.Errorf("observability.tracing.sample_ratio must be between 0 and 1")
	}
	if cfg.Observability.Tracing.Enabled {
		if cfg.Observability.Tracing.OTLPEndpoint == "" {
			return fmt.Errorf("observability.tracing.otlp_endpoint is required when enabled=true")
		}
		if cfg.Observability.Tracing.ServiceName == "" {
			return fmt.Errorf("observability.tracing.service_name is required when enabled=true")
		}
	}
	return nil
}

func validatePersistentStorageConfig(cfg appPersistentStorageConfig) error {
	switch cfg.Backend {
	case PersistentStorageBackendLocal:
		if strings.TrimSpace(cfg.Local.BaseDir) == "" {
			return fmt.Errorf("persistent_storage.local.base_dir is required when persistent_storage.backend=local")
		}
	case PersistentStorageBackendS3:
		if strings.TrimSpace(cfg.S3.Bucket) == "" {
			return fmt.Errorf("persistent_storage.s3.bucket is required when persistent_storage.backend=s3")
		}
		if strings.ContainsAny(cfg.S3.Bucket, "/\x00") {
			return fmt.Errorf("persistent_storage.s3.bucket contains invalid characters")
		}
		if err := validatePersistentStorageEndpoint("persistent_storage.s3.endpoint", cfg.S3.Endpoint); err != nil {
			return err
		}
	case PersistentStorageBackendAzureBlob:
		if strings.TrimSpace(cfg.AzureBlob.AccountName) == "" {
			return fmt.Errorf("persistent_storage.azure_blob.account_name is required when persistent_storage.backend=azure_blob")
		}
		if strings.TrimSpace(cfg.AzureBlob.Container) == "" {
			return fmt.Errorf("persistent_storage.azure_blob.container is required when persistent_storage.backend=azure_blob")
		}
		return fmt.Errorf("persistent_storage.backend=azure_blob is not available in this build; use local until the Azure Blob adapter and ACME issuance coordinator are implemented")
	case PersistentStorageBackendGCS:
		if strings.TrimSpace(cfg.GCS.Bucket) == "" {
			return fmt.Errorf("persistent_storage.gcs.bucket is required when persistent_storage.backend=gcs")
		}
		return fmt.Errorf("persistent_storage.backend=gcs is not available in this build; use local until the GCS adapter and ACME issuance coordinator are implemented")
	default:
		return fmt.Errorf("persistent_storage.backend must be one of: local, s3, azure_blob, gcs")
	}
	if err := validatePersistentStoragePrefix("persistent_storage.s3.prefix", cfg.S3.Prefix); err != nil {
		return err
	}
	if err := validatePersistentStoragePrefix("persistent_storage.azure_blob.prefix", cfg.AzureBlob.Prefix); err != nil {
		return err
	}
	if err := validatePersistentStoragePrefix("persistent_storage.gcs.prefix", cfg.GCS.Prefix); err != nil {
		return err
	}
	return nil
}

func validatePersistentStoragePrefix(field string, prefix string) error {
	if strings.Contains(prefix, "\x00") {
		return fmt.Errorf("%s contains invalid NUL byte", field)
	}
	for _, part := range strings.Split(prefix, "/") {
		if part == "." || part == ".." {
			return fmt.Errorf("%s must not contain relative path segments", field)
		}
	}
	return nil
}

func validatePersistentStorageEndpoint(field string, endpoint string) error {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return nil
	}
	parsed, err := url.Parse(endpoint)
	if err != nil {
		return fmt.Errorf("%s invalid: %w", field, err)
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return fmt.Errorf("%s must start with http:// or https://", field)
	}
	if parsed.Host == "" {
		return fmt.Errorf("%s host is required", field)
	}
	return nil
}

func normalizeAppProxyEngineMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return DefaultProxyEngineMode
	}
	return mode
}

func normalizeAppWAFEngineMode(mode string) string {
	return wafengine.Normalize(mode)
}

func validateAppAdminListenerConfig(cfg appConfigFile) error {
	adminAddr := strings.TrimSpace(cfg.Admin.ListenAddr)
	if adminAddr == "" {
		return nil
	}
	normalizedAdminAddr, err := normalizeValidatedListenAddr(adminAddr)
	if err != nil {
		return fmt.Errorf("admin.listen_addr invalid: %w", err)
	}
	publicAddr, err := normalizeValidatedListenAddr(cfg.Server.ListenAddr)
	if err != nil {
		return fmt.Errorf("server.listen_addr invalid: %w", err)
	}
	if listenAddrsCollide(normalizedAdminAddr, publicAddr) {
		return fmt.Errorf("admin.listen_addr must be different from server.listen_addr")
	}
	if redirectAddr := strings.TrimSpace(cfg.Server.TLS.HTTPRedirectAddr); redirectAddr != "" {
		normalizedRedirectAddr, err := normalizeValidatedListenAddr(redirectAddr)
		if err != nil {
			return fmt.Errorf("server.tls.http_redirect_addr invalid: %w", err)
		}
		if listenAddrsCollide(normalizedAdminAddr, normalizedRedirectAddr) {
			return fmt.Errorf("admin.listen_addr must be different from server.tls.http_redirect_addr")
		}
	}
	return nil
}

func validateAppListenerProxyProtocolConfig(field string, cfg appListenerProxyProtocolConfig) error {
	if cfg.Enabled && len(cfg.TrustedCIDRs) == 0 {
		return fmt.Errorf("%s.trusted_cidrs is required when enabled=true", field)
	}
	for i, raw := range cfg.TrustedCIDRs {
		if _, err := netip.ParsePrefix(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("%s.trusted_cidrs[%d] invalid CIDR: %w", field, i, err)
		}
	}
	return nil
}

func validateAppAdminProxyProtocolConfig(cfg appConfigFile) error {
	if strings.TrimSpace(cfg.Admin.ListenAddr) == "" {
		if cfg.Admin.ProxyProtocol.Enabled {
			return fmt.Errorf("admin.proxy_protocol requires admin.listen_addr")
		}
		if len(cfg.Admin.ProxyProtocol.TrustedCIDRs) > 0 {
			return fmt.Errorf("admin.proxy_protocol.trusted_cidrs requires admin.listen_addr")
		}
		return nil
	}
	return validateAppListenerProxyProtocolConfig("admin.proxy_protocol", cfg.Admin.ProxyProtocol)
}

func normalizeValidatedListenAddr(raw string) (string, error) {
	addr := parseListenAddr(raw)
	if _, err := net.ResolveTCPAddr("tcp", addr); err != nil {
		return "", err
	}
	return addr, nil
}

func listenAddrsCollide(a string, b string) bool {
	if strings.TrimSpace(a) == "" || strings.TrimSpace(b) == "" {
		return false
	}
	left, err := net.ResolveTCPAddr("tcp", a)
	if err != nil {
		return parseListenAddr(a) == parseListenAddr(b)
	}
	right, err := net.ResolveTCPAddr("tcp", b)
	if err != nil {
		return parseListenAddr(a) == parseListenAddr(b)
	}
	if left.Port != right.Port {
		return false
	}
	if listenHostWildcard(left.IP) || listenHostWildcard(right.IP) {
		return true
	}
	return left.IP.Equal(right.IP)
}

func listenHostWildcard(ip net.IP) bool {
	return ip == nil || ip.IsUnspecified()
}
