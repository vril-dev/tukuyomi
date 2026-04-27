package handler

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
	"tukuyomi/internal/serverruntime"
	"tukuyomi/internal/wafengine"
)

type settingsListenerAdminServerTLSConfig struct {
	Enabled          bool                                     `json:"enabled"`
	CertFile         string                                   `json:"cert_file"`
	KeyFile          string                                   `json:"key_file"`
	MinVersion       string                                   `json:"min_version"`
	RedirectHTTP     bool                                     `json:"redirect_http"`
	HTTPRedirectAddr string                                   `json:"http_redirect_addr"`
	ACME             settingsListenerAdminServerTLSACMEConfig `json:"acme"`
}

type settingsListenerAdminServerTLSACMEConfig struct {
	CacheDir string `json:"cache_dir"`
}

type settingsListenerAdminServerHTTP3Config struct {
	Enabled         bool `json:"enabled"`
	AltSvcMaxAgeSec int  `json:"alt_svc_max_age_sec"`
}

type settingsListenerAdminProxyProtocolConfig struct {
	Enabled      bool     `json:"enabled"`
	TrustedCIDRs []string `json:"trusted_cidrs"`
}

type settingsListenerAdminServerConfig struct {
	ListenAddr                  string                                   `json:"listen_addr"`
	ReadTimeoutSec              int                                      `json:"read_timeout_sec"`
	ReadHeaderTimeoutSec        int                                      `json:"read_header_timeout_sec"`
	WriteTimeoutSec             int                                      `json:"write_timeout_sec"`
	IdleTimeoutSec              int                                      `json:"idle_timeout_sec"`
	GracefulShutdownTimeoutSec  int                                      `json:"graceful_shutdown_timeout_sec"`
	MaxHeaderBytes              int                                      `json:"max_header_bytes"`
	MaxConcurrentRequests       int                                      `json:"max_concurrent_requests"`
	MaxQueuedRequests           int                                      `json:"max_queued_requests"`
	QueuedRequestTimeoutMS      int                                      `json:"queued_request_timeout_ms"`
	MaxConcurrentProxyRequests  int                                      `json:"max_concurrent_proxy_requests"`
	MaxQueuedProxyRequests      int                                      `json:"max_queued_proxy_requests"`
	QueuedProxyRequestTimeoutMS int                                      `json:"queued_proxy_request_timeout_ms"`
	ProxyProtocol               settingsListenerAdminProxyProtocolConfig `json:"proxy_protocol"`
	TLS                         settingsListenerAdminServerTLSConfig     `json:"tls"`
	HTTP3                       settingsListenerAdminServerHTTP3Config   `json:"http3"`
}

type settingsListenerAdminRuntimeConfig struct {
	GOMAXPROCS    int `json:"gomaxprocs"`
	MemoryLimitMB int `json:"memory_limit_mb"`
}

type settingsListenerAdminRequestMetadataCountryConfig struct {
	Mode string `json:"mode"`
}

type settingsListenerAdminRequestMetadataConfig struct {
	Country settingsListenerAdminRequestMetadataCountryConfig `json:"country"`
}

type settingsListenerAdminStorageConfig struct {
	Backend           string `json:"backend,omitempty"`
	DBDriver          string `json:"db_driver"`
	DBPath            string `json:"db_path"`
	DBRetentionDays   int    `json:"db_retention_days"`
	DBSyncIntervalSec int    `json:"db_sync_interval_sec"`
	FileRotateBytes   int64  `json:"file_rotate_bytes"`
	FileMaxBytes      int64  `json:"file_max_bytes"`
	FileRetentionDays int    `json:"file_retention_days"`
}

type settingsListenerAdminPersistentStorageConfig struct {
	Backend   string                                            `json:"backend"`
	Local     settingsListenerAdminPersistentStorageLocalConfig `json:"local"`
	S3        settingsListenerAdminPersistentStorageS3Config    `json:"s3"`
	AzureBlob settingsListenerAdminPersistentStorageAzureConfig `json:"azure_blob"`
	GCS       settingsListenerAdminPersistentStorageGCSConfig   `json:"gcs"`
}

type settingsListenerAdminPersistentStorageLocalConfig struct {
	BaseDir string `json:"base_dir"`
}

type settingsListenerAdminPersistentStorageS3Config struct {
	Bucket         string `json:"bucket"`
	Region         string `json:"region"`
	Endpoint       string `json:"endpoint"`
	Prefix         string `json:"prefix"`
	ForcePathStyle bool   `json:"force_path_style"`
}

type settingsListenerAdminPersistentStorageAzureConfig struct {
	AccountName string `json:"account_name"`
	Container   string `json:"container"`
	Endpoint    string `json:"endpoint"`
	Prefix      string `json:"prefix"`
}

type settingsListenerAdminPersistentStorageGCSConfig struct {
	Bucket string `json:"bucket"`
	Prefix string `json:"prefix"`
}

type settingsListenerAdminPathsConfig struct {
	ProxyConfigFile          string `json:"proxy_config_file"`
	SiteConfigFile           string `json:"site_config_file"`
	PHPRuntimeInventoryFile  string `json:"php_runtime_inventory_file"`
	PSGIRuntimeInventoryFile string `json:"psgi_runtime_inventory_file"`
	VhostConfigFile          string `json:"vhost_config_file"`
	ScheduledTaskConfigFile  string `json:"scheduled_task_config_file"`
	SecurityAuditFile        string `json:"security_audit_file"`
	SecurityAuditBlobDir     string `json:"security_audit_blob_dir"`
	CacheRulesFile           string `json:"cache_rules_file"`
	CacheStoreFile           string `json:"cache_store_file"`
	RulesFile                string `json:"rules_file"`
	OverrideRulesDir         string `json:"override_rules_dir"`
	UpstreamRuntimeFile      string `json:"upstream_runtime_file"`
	BypassFile               string `json:"bypass_file"`
	CountryBlockFile         string `json:"country_block_file"`
	RateLimitFile            string `json:"rate_limit_file"`
	BotDefenseFile           string `json:"bot_defense_file"`
	SemanticFile             string `json:"semantic_file"`
	NotificationFile         string `json:"notification_file"`
	IPReputationFile         string `json:"ip_reputation_file"`
	LogFile                  string `json:"log_file"`
	CRSSetupFile             string `json:"crs_setup_file"`
	CRSRulesDir              string `json:"crs_rules_dir"`
	CRSDisabledFile          string `json:"crs_disabled_file"`
}

type settingsListenerAdminProxyEngineConfig struct {
	Mode string `json:"mode"`
}

type settingsListenerAdminProxyConfig struct {
	RollbackHistorySize int                                    `json:"rollback_history_size"`
	Engine              settingsListenerAdminProxyEngineConfig `json:"engine"`
}

type settingsListenerAdminWAFEngineConfig struct {
	Mode string `json:"mode"`
}

type settingsListenerAdminWAFConfig struct {
	Engine settingsListenerAdminWAFEngineConfig `json:"engine"`
}

type settingsListenerAdminCRSConfig struct {
	Enable bool `json:"enable"`
}

type settingsListenerAdminFPTunerConfig struct {
	Endpoint        string `json:"endpoint"`
	Model           string `json:"model"`
	TimeoutSec      int    `json:"timeout_sec"`
	RequireApproval bool   `json:"require_approval"`
	ApprovalTTLSec  int    `json:"approval_ttl_sec"`
	AuditFile       string `json:"audit_file"`
}

type settingsListenerAdminTracingConfig struct {
	Enabled      bool    `json:"enabled"`
	ServiceName  string  `json:"service_name"`
	OTLPEndpoint string  `json:"otlp_endpoint"`
	Insecure     bool    `json:"insecure"`
	SampleRatio  float64 `json:"sample_ratio"`
}

type settingsListenerAdminObservabilityConfig struct {
	Tracing settingsListenerAdminTracingConfig `json:"tracing"`
}

type settingsListenerAdminRateLimitConfig struct {
	Enabled           bool `json:"enabled"`
	RPS               int  `json:"rps"`
	Burst             int  `json:"burst"`
	StatusCode        int  `json:"status_code"`
	RetryAfterSeconds int  `json:"retry_after_seconds"`
}

type settingsListenerAdminAdminConfig struct {
	APIBasePath        string                                   `json:"api_base_path"`
	UIBasePath         string                                   `json:"ui_base_path"`
	ListenAddr         string                                   `json:"listen_addr"`
	ExternalMode       string                                   `json:"external_mode"`
	TrustedCIDRs       []string                                 `json:"trusted_cidrs"`
	TrustForwardedFor  bool                                     `json:"trust_forwarded_for"`
	ProxyProtocol      settingsListenerAdminProxyProtocolConfig `json:"proxy_protocol"`
	ReadOnly           bool                                     `json:"read_only"`
	CORSAllowedOrigins []string                                 `json:"cors_allowed_origins"`
	RateLimit          settingsListenerAdminRateLimitConfig     `json:"rate_limit"`
}

type settingsListenerAdminConfig struct {
	Server        settingsListenerAdminServerConfig            `json:"server"`
	Runtime       settingsListenerAdminRuntimeConfig           `json:"runtime"`
	RequestMeta   settingsListenerAdminRequestMetadataConfig   `json:"request_metadata"`
	Admin         settingsListenerAdminAdminConfig             `json:"admin"`
	Storage       settingsListenerAdminStorageConfig           `json:"storage"`
	Persistent    settingsListenerAdminPersistentStorageConfig `json:"persistent_storage"`
	Paths         settingsListenerAdminPathsConfig             `json:"paths"`
	Proxy         settingsListenerAdminProxyConfig             `json:"proxy"`
	WAF           settingsListenerAdminWAFConfig               `json:"waf"`
	CRS           settingsListenerAdminCRSConfig               `json:"crs"`
	FPTuner       settingsListenerAdminFPTunerConfig           `json:"fp_tuner"`
	Observability settingsListenerAdminObservabilityConfig     `json:"observability"`
}

type settingsListenerAdminSecretStatus struct {
	AdminSessionSecretConfigured  bool   `json:"admin_session_secret_configured"`
	StorageDBDSNConfigured        bool   `json:"storage_db_dsn_configured"`
	SecurityAuditKeySource        string `json:"security_audit_key_source"`
	SecurityAuditEncryptionKeyID  string `json:"security_audit_encryption_key_id"`
	SecurityAuditEncryptionKeySet bool   `json:"security_audit_encryption_key_configured"`
	SecurityAuditHMACKeyID        string `json:"security_audit_hmac_key_id"`
	SecurityAuditHMACKeySet       bool   `json:"security_audit_hmac_key_configured"`
	FPTunerAPIKeyConfigured       bool   `json:"fp_tuner_api_key_configured"`
}

type settingsListenerAdminRuntimeStatus struct {
	RequestCountryConfiguredMode      string                 `json:"request_country_configured_mode"`
	RequestCountryEffectiveMode       string                 `json:"request_country_effective_mode"`
	RequestCountryManagedPath         string                 `json:"request_country_managed_path"`
	RequestCountryLoaded              bool                   `json:"request_country_loaded"`
	RequestCountryDBSizeBytes         int64                  `json:"request_country_db_size_bytes"`
	RequestCountryDBModTime           string                 `json:"request_country_db_mod_time"`
	RequestCountryLastError           string                 `json:"request_country_last_error"`
	ListenAddr                        string                 `json:"listen_addr"`
	APIBasePath                       string                 `json:"api_base_path"`
	UIBasePath                        string                 `json:"ui_base_path"`
	AdminListenAddr                   string                 `json:"admin_listen_addr"`
	ServerTLSEnabled                  bool                   `json:"server_tls_enabled"`
	ServerTLSSource                   string                 `json:"server_tls_source"`
	ServerTLSMinVersion               string                 `json:"server_tls_min_version"`
	ServerTLSRedirectHTTP             bool                   `json:"server_tls_redirect_http"`
	ServerTLSHTTPRedirectAddr         string                 `json:"server_tls_http_redirect_addr"`
	ServerHTTP3Enabled                bool                   `json:"server_http3_enabled"`
	ServerHTTP3Advertised             bool                   `json:"server_http3_advertised"`
	ServerHTTP3AltSvc                 string                 `json:"server_http3_alt_svc"`
	ServerProxyProtocolEnabled        bool                   `json:"server_proxy_protocol_enabled"`
	ServerProxyProtocolTrustedCIDRs   []string               `json:"server_proxy_protocol_trusted_cidrs"`
	AdminExternalMode                 string                 `json:"admin_external_mode"`
	AdminTrustedCIDRs                 []string               `json:"admin_trusted_cidrs"`
	AdminTrustForwardedFor            bool                   `json:"admin_trust_forwarded_for"`
	AdminProxyProtocolEnabled         bool                   `json:"admin_proxy_protocol_enabled"`
	AdminProxyProtocolTrustedCIDRs    []string               `json:"admin_proxy_protocol_trusted_cidrs"`
	AdminReadOnly                     bool                   `json:"admin_read_only"`
	AdminRateLimitEnabled             bool                   `json:"admin_rate_limit_enabled"`
	AdminRateLimitRPS                 int                    `json:"admin_rate_limit_rps"`
	AdminRateLimitBurst               int                    `json:"admin_rate_limit_burst"`
	AdminRateLimitStatusCode          int                    `json:"admin_rate_limit_status_code"`
	AdminRateLimitRetryAfterSec       int                    `json:"admin_rate_limit_retry_after_seconds"`
	RuntimeGOMAXPROCS                 int                    `json:"runtime_gomaxprocs"`
	RuntimeMemoryLimitMB              int                    `json:"runtime_memory_limit_mb"`
	ServerGracefulShutdownTimeoutSec  int                    `json:"server_graceful_shutdown_timeout_sec"`
	ServerMaxConcurrentReqs           int                    `json:"server_max_concurrent_requests"`
	ServerMaxQueuedReqs               int                    `json:"server_max_queued_requests"`
	ServerQueuedTimeoutMS             int                    `json:"server_queued_request_timeout_ms"`
	ServerMaxConcurrentProxy          int                    `json:"server_max_concurrent_proxy_requests"`
	ServerMaxQueuedProxy              int                    `json:"server_max_queued_proxy_requests"`
	ServerQueuedProxyTimeoutMS        int                    `json:"server_queued_proxy_request_timeout_ms"`
	ProxyEngineMode                   string                 `json:"proxy_engine_mode"`
	WAFEngineMode                     string                 `json:"waf_engine_mode"`
	WAFEngineModes                    []wafengine.Capability `json:"waf_engine_modes"`
	StorageDBDriver                   string                 `json:"storage_db_driver"`
	StorageDBPath                     string                 `json:"storage_db_path"`
	StorageDBRetentionDays            int                    `json:"storage_db_retention_days"`
	StorageDBSyncIntervalSec          int                    `json:"storage_db_sync_interval_sec"`
	StorageFileRotateBytes            int64                  `json:"storage_file_rotate_bytes"`
	StorageFileMaxBytes               int64                  `json:"storage_file_max_bytes"`
	StorageFileRetentionDays          int                    `json:"storage_file_retention_days"`
	PersistentStorageBackend          string                 `json:"persistent_storage_backend"`
	PersistentStorageLocalBaseDir     string                 `json:"persistent_storage_local_base_dir"`
	PersistentStorageS3Bucket         string                 `json:"persistent_storage_s3_bucket"`
	PersistentStorageS3Region         string                 `json:"persistent_storage_s3_region"`
	PersistentStorageS3Endpoint       string                 `json:"persistent_storage_s3_endpoint"`
	PersistentStorageS3Prefix         string                 `json:"persistent_storage_s3_prefix"`
	PersistentStorageS3ForcePathStyle bool                   `json:"persistent_storage_s3_force_path_style"`
	TracingEnabled                    bool                   `json:"tracing_enabled"`
	TracingServiceName                string                 `json:"tracing_service_name"`
	TracingOTLPEndpoint               string                 `json:"tracing_otlp_endpoint"`
	TracingInsecure                   bool                   `json:"tracing_insecure"`
	TracingSampleRatio                float64                `json:"tracing_sample_ratio"`
}

type settingsListenerAdminPutBody struct {
	Config settingsListenerAdminConfig `json:"config"`
}

func GetSettingsListenerAdmin(c *gin.Context) {
	_, etag, cfg, err := loadSettingsAppConfig()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"etag":             etag,
		"config_file":      currentSettingsConfigPath(),
		"restart_required": true,
		"config":           buildSettingsListenerAdminConfig(cfg),
		"secrets":          buildSettingsListenerAdminSecretStatus(cfg),
		"runtime":          buildSettingsListenerAdminRuntimeStatus(),
	})
}

func ValidateSettingsListenerAdmin(c *gin.Context) {
	var in settingsListenerAdminPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	current, err := loadSettingsAppConfigOnly()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	applySettingsListenerAdminConfig(&current, in.Config)
	if _, bootstrap, err := loadBootstrapAppConfig(); err == nil {
		preserveBootstrapDBConnection(&current, bootstrap)
	}
	normalized, err := config.NormalizeAndValidateAppConfigFile(current)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if err := ValidateRequestCountryRuntimeConfig(normalized); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"messages":         []string{},
		"restart_required": true,
		"config":           buildSettingsListenerAdminConfig(normalized),
		"secrets":          buildSettingsListenerAdminSecretStatus(normalized),
	})
}

func PutSettingsListenerAdmin(c *gin.Context) {
	var in settingsListenerAdminPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}

	raw, etag, current, err := loadSettingsAppConfig()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if ifMatch != etag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": etag})
		return
	}

	applySettingsListenerAdminConfig(&current, in.Config)
	if _, bootstrap, err := loadBootstrapAppConfig(); err == nil {
		preserveBootstrapDBConnection(&current, bootstrap)
	}
	normalized, err := config.NormalizeAndValidateAppConfigFile(current)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if err := ValidateRequestCountryRuntimeConfig(normalized); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	nextRaw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if nextRaw == raw {
		c.JSON(http.StatusOK, gin.H{
			"ok":               true,
			"etag":             etag,
			"restart_required": true,
			"config":           buildSettingsListenerAdminConfig(normalized),
			"secrets":          buildSettingsListenerAdminSecretStatus(normalized),
			"runtime":          buildSettingsListenerAdminRuntimeStatus(),
		})
		return
	}
	nextETag, err := persistSettingsAppConfig(normalized, etag)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": etag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"etag":             nextETag,
		"restart_required": true,
		"config":           buildSettingsListenerAdminConfig(normalized),
		"secrets":          buildSettingsListenerAdminSecretStatus(normalized),
		"runtime":          buildSettingsListenerAdminRuntimeStatus(),
	})
}

func currentSettingsConfigPath() string {
	path := strings.TrimSpace(config.ConfigFile)
	if path == "" {
		return "conf/config.json"
	}
	return path
}

func loadSettingsAppConfig() (string, string, config.AppConfigFile, error) {
	return loadAppConfigStorage(true)
}

func loadSettingsAppConfigOnly() (config.AppConfigFile, error) {
	_, _, cfg, err := loadAppConfigStorage(true)
	return cfg, err
}

func persistSettingsAppConfig(next config.AppConfigFile, expectedETag string) (string, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return "", err
	}
	_, bootstrap, err := loadBootstrapAppConfig()
	if err != nil {
		return "", err
	}
	rec, _, err := store.writeAppConfigVersion(expectedETag, next, bootstrap, configVersionSourceApply, "", "settings app config update", 0)
	if err != nil {
		return "", err
	}
	return rec.ETag, nil
}

func buildSettingsListenerAdminConfig(cfg config.AppConfigFile) settingsListenerAdminConfig {
	return settingsListenerAdminConfig{
		Server: settingsListenerAdminServerConfig{
			ListenAddr:                  cfg.Server.ListenAddr,
			ReadTimeoutSec:              cfg.Server.ReadTimeoutSec,
			ReadHeaderTimeoutSec:        cfg.Server.ReadHeaderTimeoutSec,
			WriteTimeoutSec:             cfg.Server.WriteTimeoutSec,
			IdleTimeoutSec:              cfg.Server.IdleTimeoutSec,
			GracefulShutdownTimeoutSec:  cfg.Server.GracefulShutdownTimeoutSec,
			MaxHeaderBytes:              cfg.Server.MaxHeaderBytes,
			MaxConcurrentRequests:       cfg.Server.MaxConcurrentRequests,
			MaxQueuedRequests:           cfg.Server.MaxQueuedRequests,
			QueuedRequestTimeoutMS:      cfg.Server.QueuedRequestTimeoutMS,
			MaxConcurrentProxyRequests:  cfg.Server.MaxConcurrentProxyRequests,
			MaxQueuedProxyRequests:      cfg.Server.MaxQueuedProxyRequests,
			QueuedProxyRequestTimeoutMS: cfg.Server.QueuedProxyRequestTimeoutMS,
			ProxyProtocol: settingsListenerAdminProxyProtocolConfig{
				Enabled:      cfg.Server.ProxyProtocol.Enabled,
				TrustedCIDRs: append([]string(nil), cfg.Server.ProxyProtocol.TrustedCIDRs...),
			},
			TLS: settingsListenerAdminServerTLSConfig{
				Enabled:          cfg.Server.TLS.Enabled,
				CertFile:         cfg.Server.TLS.CertFile,
				KeyFile:          cfg.Server.TLS.KeyFile,
				MinVersion:       cfg.Server.TLS.MinVersion,
				RedirectHTTP:     cfg.Server.TLS.RedirectHTTP,
				HTTPRedirectAddr: cfg.Server.TLS.HTTPRedirectAddr,
				ACME: settingsListenerAdminServerTLSACMEConfig{
					CacheDir: cfg.Server.TLS.ACME.CacheDir,
				},
			},
			HTTP3: settingsListenerAdminServerHTTP3Config{
				Enabled:         cfg.Server.HTTP3.Enabled,
				AltSvcMaxAgeSec: cfg.Server.HTTP3.AltSvcMaxAgeSec,
			},
		},
		Runtime: settingsListenerAdminRuntimeConfig{
			GOMAXPROCS:    cfg.Runtime.GOMAXPROCS,
			MemoryLimitMB: cfg.Runtime.MemoryLimitMB,
		},
		RequestMeta: settingsListenerAdminRequestMetadataConfig{
			Country: settingsListenerAdminRequestMetadataCountryConfig{
				Mode: cfg.RequestMeta.Country.Mode,
			},
		},
		Admin: settingsListenerAdminAdminConfig{
			APIBasePath:       cfg.Admin.APIBasePath,
			UIBasePath:        cfg.Admin.UIBasePath,
			ListenAddr:        cfg.Admin.ListenAddr,
			ExternalMode:      cfg.Admin.ExternalMode,
			TrustedCIDRs:      append([]string(nil), cfg.Admin.TrustedCIDRs...),
			TrustForwardedFor: cfg.Admin.TrustForwardedFor,
			ProxyProtocol: settingsListenerAdminProxyProtocolConfig{
				Enabled:      cfg.Admin.ProxyProtocol.Enabled,
				TrustedCIDRs: append([]string(nil), cfg.Admin.ProxyProtocol.TrustedCIDRs...),
			},
			ReadOnly:           cfg.Admin.ReadOnly,
			CORSAllowedOrigins: append([]string(nil), cfg.Admin.CORSAllowedOrigins...),
			RateLimit: settingsListenerAdminRateLimitConfig{
				Enabled:           cfg.Admin.RateLimit.Enabled,
				RPS:               cfg.Admin.RateLimit.RPS,
				Burst:             cfg.Admin.RateLimit.Burst,
				StatusCode:        cfg.Admin.RateLimit.StatusCode,
				RetryAfterSeconds: cfg.Admin.RateLimit.RetryAfterSeconds,
			},
		},
		Storage: settingsListenerAdminStorageConfig{
			Backend:           "",
			DBDriver:          cfg.Storage.DBDriver,
			DBPath:            cfg.Storage.DBPath,
			DBRetentionDays:   cfg.Storage.DBRetentionDays,
			DBSyncIntervalSec: cfg.Storage.DBSyncIntervalSec,
			FileRotateBytes:   cfg.Storage.FileRotateBytes,
			FileMaxBytes:      cfg.Storage.FileMaxBytes,
			FileRetentionDays: cfg.Storage.FileRetentionDays,
		},
		Persistent: settingsListenerAdminPersistentStorageConfig{
			Backend: cfg.Persistent.Backend,
			Local: settingsListenerAdminPersistentStorageLocalConfig{
				BaseDir: cfg.Persistent.Local.BaseDir,
			},
			S3: settingsListenerAdminPersistentStorageS3Config{
				Bucket:         cfg.Persistent.S3.Bucket,
				Region:         cfg.Persistent.S3.Region,
				Endpoint:       cfg.Persistent.S3.Endpoint,
				Prefix:         cfg.Persistent.S3.Prefix,
				ForcePathStyle: cfg.Persistent.S3.ForcePathStyle,
			},
			AzureBlob: settingsListenerAdminPersistentStorageAzureConfig{
				AccountName: cfg.Persistent.AzureBlob.AccountName,
				Container:   cfg.Persistent.AzureBlob.Container,
				Endpoint:    cfg.Persistent.AzureBlob.Endpoint,
				Prefix:      cfg.Persistent.AzureBlob.Prefix,
			},
			GCS: settingsListenerAdminPersistentStorageGCSConfig{
				Bucket: cfg.Persistent.GCS.Bucket,
				Prefix: cfg.Persistent.GCS.Prefix,
			},
		},
		Paths: settingsListenerAdminPathsConfig{
			ProxyConfigFile:          cfg.Paths.ProxyConfigFile,
			SiteConfigFile:           cfg.Paths.SiteConfigFile,
			PHPRuntimeInventoryFile:  cfg.Paths.PHPRuntimeInventoryFile,
			PSGIRuntimeInventoryFile: cfg.Paths.PSGIRuntimeInventoryFile,
			VhostConfigFile:          cfg.Paths.VhostConfigFile,
			ScheduledTaskConfigFile:  cfg.Paths.ScheduledTaskConfigFile,
			SecurityAuditFile:        cfg.Paths.SecurityAuditFile,
			SecurityAuditBlobDir:     cfg.Paths.SecurityAuditBlobDir,
			CacheRulesFile:           cfg.Paths.CacheRulesFile,
			CacheStoreFile:           cfg.Paths.CacheStoreFile,
			RulesFile:                cfg.Paths.RulesFile,
			OverrideRulesDir:         cfg.Paths.OverrideRulesDir,
			UpstreamRuntimeFile:      cfg.Paths.UpstreamRuntimeFile,
			BypassFile:               cfg.Paths.BypassFile,
			CountryBlockFile:         cfg.Paths.CountryBlockFile,
			RateLimitFile:            cfg.Paths.RateLimitFile,
			BotDefenseFile:           cfg.Paths.BotDefenseFile,
			SemanticFile:             cfg.Paths.SemanticFile,
			NotificationFile:         cfg.Paths.NotificationFile,
			IPReputationFile:         cfg.Paths.IPReputationFile,
			LogFile:                  cfg.Paths.LogFile,
			CRSSetupFile:             cfg.Paths.CRSSetupFile,
			CRSRulesDir:              cfg.Paths.CRSRulesDir,
			CRSDisabledFile:          cfg.Paths.CRSDisabledFile,
		},
		Proxy: settingsListenerAdminProxyConfig{
			RollbackHistorySize: cfg.Proxy.RollbackHistorySize,
			Engine: settingsListenerAdminProxyEngineConfig{
				Mode: cfg.Proxy.Engine.Mode,
			},
		},
		WAF: settingsListenerAdminWAFConfig{
			Engine: settingsListenerAdminWAFEngineConfig{
				Mode: cfg.WAF.Engine.Mode,
			},
		},
		CRS: settingsListenerAdminCRSConfig{
			Enable: cfg.CRS.Enable,
		},
		FPTuner: settingsListenerAdminFPTunerConfig{
			Endpoint:        cfg.FPTuner.Endpoint,
			Model:           cfg.FPTuner.Model,
			TimeoutSec:      cfg.FPTuner.TimeoutSec,
			RequireApproval: cfg.FPTuner.RequireApproval,
			ApprovalTTLSec:  cfg.FPTuner.ApprovalTTLSec,
			AuditFile:       cfg.FPTuner.AuditFile,
		},
		Observability: settingsListenerAdminObservabilityConfig{
			Tracing: settingsListenerAdminTracingConfig{
				Enabled:      cfg.Observability.Tracing.Enabled,
				ServiceName:  cfg.Observability.Tracing.ServiceName,
				OTLPEndpoint: cfg.Observability.Tracing.OTLPEndpoint,
				Insecure:     cfg.Observability.Tracing.Insecure,
				SampleRatio:  cfg.Observability.Tracing.SampleRatio,
			},
		},
	}
}

func applySettingsListenerAdminConfig(cfg *config.AppConfigFile, next settingsListenerAdminConfig) {
	cfg.Server.ListenAddr = next.Server.ListenAddr
	cfg.Server.ReadTimeoutSec = next.Server.ReadTimeoutSec
	cfg.Server.ReadHeaderTimeoutSec = next.Server.ReadHeaderTimeoutSec
	cfg.Server.WriteTimeoutSec = next.Server.WriteTimeoutSec
	cfg.Server.IdleTimeoutSec = next.Server.IdleTimeoutSec
	cfg.Server.GracefulShutdownTimeoutSec = next.Server.GracefulShutdownTimeoutSec
	cfg.Server.MaxHeaderBytes = next.Server.MaxHeaderBytes
	cfg.Server.MaxConcurrentRequests = next.Server.MaxConcurrentRequests
	cfg.Server.MaxQueuedRequests = next.Server.MaxQueuedRequests
	cfg.Server.QueuedRequestTimeoutMS = next.Server.QueuedRequestTimeoutMS
	cfg.Server.MaxConcurrentProxyRequests = next.Server.MaxConcurrentProxyRequests
	cfg.Server.MaxQueuedProxyRequests = next.Server.MaxQueuedProxyRequests
	cfg.Server.QueuedProxyRequestTimeoutMS = next.Server.QueuedProxyRequestTimeoutMS
	cfg.Server.ProxyProtocol.Enabled = next.Server.ProxyProtocol.Enabled
	cfg.Server.ProxyProtocol.TrustedCIDRs = append([]string(nil), next.Server.ProxyProtocol.TrustedCIDRs...)
	cfg.Server.TLS.Enabled = next.Server.TLS.Enabled
	cfg.Server.TLS.CertFile = next.Server.TLS.CertFile
	cfg.Server.TLS.KeyFile = next.Server.TLS.KeyFile
	cfg.Server.TLS.MinVersion = next.Server.TLS.MinVersion
	cfg.Server.TLS.RedirectHTTP = next.Server.TLS.RedirectHTTP
	cfg.Server.TLS.HTTPRedirectAddr = next.Server.TLS.HTTPRedirectAddr
	cfg.Server.TLS.ACME.CacheDir = next.Server.TLS.ACME.CacheDir
	cfg.Server.HTTP3.Enabled = next.Server.HTTP3.Enabled
	cfg.Server.HTTP3.AltSvcMaxAgeSec = next.Server.HTTP3.AltSvcMaxAgeSec
	cfg.Runtime.GOMAXPROCS = next.Runtime.GOMAXPROCS
	cfg.Runtime.MemoryLimitMB = next.Runtime.MemoryLimitMB

	cfg.Admin.APIBasePath = next.Admin.APIBasePath
	cfg.Admin.UIBasePath = next.Admin.UIBasePath
	cfg.Admin.ListenAddr = next.Admin.ListenAddr
	cfg.Admin.ExternalMode = next.Admin.ExternalMode
	cfg.Admin.TrustedCIDRs = append([]string(nil), next.Admin.TrustedCIDRs...)
	cfg.Admin.TrustForwardedFor = next.Admin.TrustForwardedFor
	cfg.Admin.ProxyProtocol.Enabled = next.Admin.ProxyProtocol.Enabled
	cfg.Admin.ProxyProtocol.TrustedCIDRs = append([]string(nil), next.Admin.ProxyProtocol.TrustedCIDRs...)
	cfg.Admin.ReadOnly = next.Admin.ReadOnly
	cfg.Admin.CORSAllowedOrigins = append([]string(nil), next.Admin.CORSAllowedOrigins...)
	cfg.Admin.RateLimit.Enabled = next.Admin.RateLimit.Enabled
	cfg.Admin.RateLimit.RPS = next.Admin.RateLimit.RPS
	cfg.Admin.RateLimit.Burst = next.Admin.RateLimit.Burst
	cfg.Admin.RateLimit.StatusCode = next.Admin.RateLimit.StatusCode
	cfg.Admin.RateLimit.RetryAfterSeconds = next.Admin.RateLimit.RetryAfterSeconds

	cfg.Storage.Backend = ""
	cfg.Storage.DBDriver = next.Storage.DBDriver
	cfg.Storage.DBPath = next.Storage.DBPath
	cfg.Storage.DBRetentionDays = next.Storage.DBRetentionDays
	cfg.Storage.DBSyncIntervalSec = next.Storage.DBSyncIntervalSec
	cfg.Storage.FileRotateBytes = next.Storage.FileRotateBytes
	cfg.Storage.FileMaxBytes = next.Storage.FileMaxBytes
	cfg.Storage.FileRetentionDays = next.Storage.FileRetentionDays

	cfg.Persistent.Backend = next.Persistent.Backend
	cfg.Persistent.Local.BaseDir = next.Persistent.Local.BaseDir
	cfg.Persistent.S3.Bucket = next.Persistent.S3.Bucket
	cfg.Persistent.S3.Region = next.Persistent.S3.Region
	cfg.Persistent.S3.Endpoint = next.Persistent.S3.Endpoint
	cfg.Persistent.S3.Prefix = next.Persistent.S3.Prefix
	cfg.Persistent.S3.ForcePathStyle = next.Persistent.S3.ForcePathStyle
	cfg.Persistent.AzureBlob.AccountName = next.Persistent.AzureBlob.AccountName
	cfg.Persistent.AzureBlob.Container = next.Persistent.AzureBlob.Container
	cfg.Persistent.AzureBlob.Endpoint = next.Persistent.AzureBlob.Endpoint
	cfg.Persistent.AzureBlob.Prefix = next.Persistent.AzureBlob.Prefix
	cfg.Persistent.GCS.Bucket = next.Persistent.GCS.Bucket
	cfg.Persistent.GCS.Prefix = next.Persistent.GCS.Prefix

	cfg.Paths.ProxyConfigFile = next.Paths.ProxyConfigFile
	cfg.Paths.SiteConfigFile = next.Paths.SiteConfigFile
	cfg.Paths.PHPRuntimeInventoryFile = next.Paths.PHPRuntimeInventoryFile
	if strings.TrimSpace(next.Paths.PSGIRuntimeInventoryFile) != "" {
		cfg.Paths.PSGIRuntimeInventoryFile = next.Paths.PSGIRuntimeInventoryFile
	} else if strings.TrimSpace(cfg.Paths.PSGIRuntimeInventoryFile) == "" {
		cfg.Paths.PSGIRuntimeInventoryFile = "data/psgi/inventory.json"
	}
	cfg.Paths.VhostConfigFile = next.Paths.VhostConfigFile
	cfg.Paths.ScheduledTaskConfigFile = next.Paths.ScheduledTaskConfigFile
	cfg.Paths.SecurityAuditFile = next.Paths.SecurityAuditFile
	cfg.Paths.SecurityAuditBlobDir = next.Paths.SecurityAuditBlobDir
	cfg.Paths.CacheRulesFile = next.Paths.CacheRulesFile
	cfg.Paths.CacheStoreFile = next.Paths.CacheStoreFile
	cfg.Paths.RulesFile = next.Paths.RulesFile
	cfg.Paths.OverrideRulesDir = next.Paths.OverrideRulesDir
	cfg.Paths.UpstreamRuntimeFile = next.Paths.UpstreamRuntimeFile
	cfg.Paths.BypassFile = next.Paths.BypassFile
	cfg.Paths.CountryBlockFile = next.Paths.CountryBlockFile
	cfg.Paths.RateLimitFile = next.Paths.RateLimitFile
	cfg.Paths.BotDefenseFile = next.Paths.BotDefenseFile
	cfg.Paths.SemanticFile = next.Paths.SemanticFile
	cfg.Paths.NotificationFile = next.Paths.NotificationFile
	cfg.Paths.IPReputationFile = next.Paths.IPReputationFile
	cfg.Paths.LogFile = next.Paths.LogFile
	cfg.Paths.CRSSetupFile = next.Paths.CRSSetupFile
	cfg.Paths.CRSRulesDir = next.Paths.CRSRulesDir
	cfg.Paths.CRSDisabledFile = next.Paths.CRSDisabledFile

	cfg.Proxy.RollbackHistorySize = next.Proxy.RollbackHistorySize
	cfg.Proxy.Engine.Mode = next.Proxy.Engine.Mode
	cfg.WAF.Engine.Mode = next.WAF.Engine.Mode
	cfg.CRS.Enable = next.CRS.Enable

	cfg.FPTuner.Mode = ""
	cfg.FPTuner.Endpoint = next.FPTuner.Endpoint
	cfg.FPTuner.Model = next.FPTuner.Model
	cfg.FPTuner.TimeoutSec = next.FPTuner.TimeoutSec
	cfg.FPTuner.MockResponseFile = ""
	cfg.FPTuner.RequireApproval = next.FPTuner.RequireApproval
	cfg.FPTuner.ApprovalTTLSec = next.FPTuner.ApprovalTTLSec
	cfg.FPTuner.AuditFile = next.FPTuner.AuditFile

	cfg.Observability.Tracing.Enabled = next.Observability.Tracing.Enabled
	cfg.Observability.Tracing.ServiceName = next.Observability.Tracing.ServiceName
	cfg.Observability.Tracing.OTLPEndpoint = next.Observability.Tracing.OTLPEndpoint
	cfg.Observability.Tracing.Insecure = next.Observability.Tracing.Insecure
	cfg.Observability.Tracing.SampleRatio = next.Observability.Tracing.SampleRatio
}

func buildSettingsListenerAdminRuntimeStatus() settingsListenerAdminRuntimeStatus {
	serverHTTP3Status := serverruntime.HTTP3StatusSnapshot()
	serverTLSStatus := ServerTLSRuntimeStatusSnapshot()
	requestCountryStatus := RequestCountryRuntimeStatusSnapshot()
	return settingsListenerAdminRuntimeStatus{
		RequestCountryConfiguredMode:      requestCountryStatus.ConfiguredMode,
		RequestCountryEffectiveMode:       requestCountryStatus.EffectiveMode,
		RequestCountryManagedPath:         requestCountryStatus.ManagedPath,
		RequestCountryLoaded:              requestCountryStatus.Loaded,
		RequestCountryDBSizeBytes:         requestCountryStatus.DBSizeBytes,
		RequestCountryDBModTime:           requestCountryStatus.DBModTime,
		RequestCountryLastError:           requestCountryStatus.LastError,
		ListenAddr:                        config.ListenAddr,
		APIBasePath:                       config.APIBasePath,
		UIBasePath:                        config.UIBasePath,
		AdminListenAddr:                   config.AdminListenAddr,
		ServerTLSEnabled:                  config.ServerTLSEnabled,
		ServerTLSSource:                   serverTLSStatus.Source,
		ServerTLSMinVersion:               config.ServerTLSMinVersion,
		ServerTLSRedirectHTTP:             config.ServerTLSRedirectHTTP,
		ServerTLSHTTPRedirectAddr:         config.ServerTLSHTTPRedirectAddr,
		ServerHTTP3Enabled:                config.ServerHTTP3Enabled,
		ServerHTTP3Advertised:             serverHTTP3Status.Advertised,
		ServerHTTP3AltSvc:                 serverHTTP3Status.AltSvc,
		ServerProxyProtocolEnabled:        config.ServerProxyProtocolEnabled,
		ServerProxyProtocolTrustedCIDRs:   append([]string(nil), config.ServerProxyProtocolTrustedCIDRs...),
		AdminExternalMode:                 config.AdminExternalMode,
		AdminTrustedCIDRs:                 append([]string(nil), config.AdminTrustedCIDRs...),
		AdminTrustForwardedFor:            config.AdminTrustForwardedFor,
		AdminProxyProtocolEnabled:         config.AdminProxyProtocolEnabled,
		AdminProxyProtocolTrustedCIDRs:    append([]string(nil), config.AdminProxyProtocolTrustedCIDRs...),
		AdminReadOnly:                     config.AdminReadOnly,
		AdminRateLimitEnabled:             config.AdminRateLimitEnabled,
		AdminRateLimitRPS:                 config.AdminRateLimitRPS,
		AdminRateLimitBurst:               config.AdminRateLimitBurst,
		AdminRateLimitStatusCode:          config.AdminRateLimitStatusCode,
		AdminRateLimitRetryAfterSec:       config.AdminRateLimitRetryAfter,
		RuntimeGOMAXPROCS:                 config.RuntimeGOMAXPROCS,
		RuntimeMemoryLimitMB:              config.RuntimeMemoryLimitMB,
		ServerGracefulShutdownTimeoutSec:  int(config.ServerGracefulShutdownTimeout / time.Second),
		ServerMaxConcurrentReqs:           config.ServerMaxConcurrentReqs,
		ServerMaxQueuedReqs:               config.ServerMaxQueuedReqs,
		ServerQueuedTimeoutMS:             int(config.ServerQueuedRequestTimeout / time.Millisecond),
		ServerMaxConcurrentProxy:          config.ServerMaxConcurrentProxy,
		ServerMaxQueuedProxy:              config.ServerMaxQueuedProxy,
		ServerQueuedProxyTimeoutMS:        int(config.ServerQueuedProxyRequestTimeout / time.Millisecond),
		ProxyEngineMode:                   normalizeProxyEngineMode(config.ProxyEngineMode),
		WAFEngineMode:                     normalizeSettingsWAFEngineMode(config.WAFEngineMode),
		WAFEngineModes:                    wafengine.Capabilities(),
		StorageDBDriver:                   config.DBDriver,
		StorageDBPath:                     config.DBPath,
		StorageDBRetentionDays:            config.DBRetentionDays,
		StorageDBSyncIntervalSec:          int(config.DBSyncInterval / time.Second),
		StorageFileRotateBytes:            config.FileRotateBytes,
		StorageFileMaxBytes:               config.FileMaxBytes,
		StorageFileRetentionDays:          int(config.FileRetention / (24 * time.Hour)),
		PersistentStorageBackend:          config.PersistentStorageBackend,
		PersistentStorageLocalBaseDir:     config.PersistentStorageLocalBaseDir,
		PersistentStorageS3Bucket:         config.PersistentStorageS3Bucket,
		PersistentStorageS3Region:         config.PersistentStorageS3Region,
		PersistentStorageS3Endpoint:       config.PersistentStorageS3Endpoint,
		PersistentStorageS3Prefix:         config.PersistentStorageS3Prefix,
		PersistentStorageS3ForcePathStyle: config.PersistentStorageS3ForcePathStyle,
		TracingEnabled:                    config.TracingEnabled,
		TracingServiceName:                config.TracingServiceName,
		TracingOTLPEndpoint:               config.TracingOTLPEndpoint,
		TracingInsecure:                   config.TracingInsecure,
		TracingSampleRatio:                config.TracingSampleRatio,
	}
}

func normalizeSettingsWAFEngineMode(mode string) string {
	return wafengine.Normalize(mode)
}

func buildSettingsListenerAdminSecretStatus(cfg config.AppConfigFile) settingsListenerAdminSecretStatus {
	return settingsListenerAdminSecretStatus{
		AdminSessionSecretConfigured:  strings.TrimSpace(cfg.Admin.SessionSecret) != "",
		StorageDBDSNConfigured:        strings.TrimSpace(cfg.Storage.DBDSN) != "",
		SecurityAuditKeySource:        cfg.SecurityAudit.KeySource,
		SecurityAuditEncryptionKeyID:  cfg.SecurityAudit.EncryptionKeyID,
		SecurityAuditEncryptionKeySet: strings.TrimSpace(cfg.SecurityAudit.EncryptionKey) != "",
		SecurityAuditHMACKeyID:        cfg.SecurityAudit.HMACKeyID,
		SecurityAuditHMACKeySet:       strings.TrimSpace(cfg.SecurityAudit.HMACKey) != "",
		FPTunerAPIKeyConfigured:       strings.TrimSpace(cfg.FPTuner.APIKey) != "",
	}
}
