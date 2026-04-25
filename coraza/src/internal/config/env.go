package config

import (
	"log"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

var (
	ConfigFile                          string
	ProxyConfigFile                     string
	SiteConfigFile                      string
	PHPRuntimeInventoryFile             string
	VhostConfigFile                     string
	ScheduledTaskConfigFile             string
	SecurityAuditFile                   string
	SecurityAuditBlobDir                string
	CacheStoreFile                      string
	CacheRulesFile                      string
	UIBasePath                          string
	UpstreamRuntimeFile                 string
	ProxyRollbackMax                    int
	ProxyAuditFile                      string
	ProxyEngineMode                     string
	WAFEngineMode                       string
	SecurityAuditEnabled                bool
	SecurityAuditCaptureMode            string
	SecurityAuditCaptureHeaders         bool
	SecurityAuditCaptureBody            bool
	SecurityAuditMaxBodyBytes           int64
	SecurityAuditRedactHeaders          []string
	SecurityAuditRedactBodyContentTypes []string
	SecurityAuditKeySource              string
	SecurityAuditEncryptionKey          string
	SecurityAuditEncryptionKeyID        string
	SecurityAuditHMACKey                string
	SecurityAuditHMACKeyID              string
	ListenAddr                          string
	ServerReadTimeout                   time.Duration
	ServerReadHeaderTimeout             time.Duration
	ServerWriteTimeout                  time.Duration
	ServerIdleTimeout                   time.Duration
	ServerGracefulShutdownTimeout       time.Duration
	ServerMaxHeaderBytes                int
	ServerMaxConcurrentReqs             int
	ServerMaxQueuedReqs                 int
	ServerQueuedRequestTimeout          time.Duration
	ServerMaxConcurrentProxy            int
	ServerMaxQueuedProxy                int
	ServerQueuedProxyRequestTimeout     time.Duration
	ServerProxyProtocolEnabled          bool
	ServerProxyProtocolTrustedCIDRs     []string
	ServerTLSEnabled                    bool
	ServerTLSCertFile                   string
	ServerTLSKeyFile                    string
	ServerTLSMinVersion                 string
	ServerTLSRedirectHTTP               bool
	ServerTLSHTTPRedirectAddr           string
	ServerHTTP3Enabled                  bool
	ServerHTTP3AltSvcMaxAgeSec          int
	ServerTLSACMEEnabled                bool
	ServerTLSACMEEmail                  string
	ServerTLSACMEDomains                []string
	ServerTLSACMECacheDir               string
	ServerTLSACMEStaging                bool
	RuntimeGOMAXPROCS                   int
	RuntimeMemoryLimitMB                int
	RequestCountryMode                  string
	RulesFile                           string
	OverrideRulesDir                    string
	BypassFile                          string
	CountryBlockFile                    string
	RateLimitFile                       string
	BotDefenseFile                      string
	SemanticFile                        string
	NotificationFile                    string
	IPReputationFile                    string
	LogFile                             string
	StrictOverride                      bool
	APIBasePath                         string
	AdminListenAddr                     string
	AdminReadOnly                       bool
	AdminExternalMode                   string
	AdminTrustedCIDRs                   []string
	AdminTrustForwardedFor              bool
	AdminProxyProtocolEnabled           bool
	AdminProxyProtocolTrustedCIDRs      []string
	AdminSessionSecret                  string
	AdminSessionTTL                     time.Duration
	APIAuthDisable                      bool
	APICORSOrigins                      []string
	AdminRateLimitEnabled               bool
	AdminRateLimitRPS                   int
	AdminRateLimitBurst                 int
	AdminRateLimitStatusCode            int
	AdminRateLimitRetryAfter            int
	CRSEnable                           bool
	CRSSetupFile                        string
	CRSRulesDir                         string
	CRSDisabledFile                     string

	AllowInsecureDefaults bool

	FPTunerEndpoint        string
	FPTunerAPIKey          string
	FPTunerModel           string
	FPTunerTimeout         time.Duration
	FPTunerRequireApproval bool
	FPTunerApprovalTTL     time.Duration
	FPTunerAuditFile       string

	DBDriver        string
	DBDSN           string
	DBPath          string
	DBRetentionDays int
	DBSyncInterval  time.Duration
	FileRotateBytes int64
	FileMaxBytes    int64
	FileRetention   time.Duration

	PersistentStorageBackend          string
	PersistentStorageLocalBaseDir     string
	PersistentStorageS3Bucket         string
	PersistentStorageS3Region         string
	PersistentStorageS3Endpoint       string
	PersistentStorageS3Prefix         string
	PersistentStorageS3ForcePathStyle bool
	PersistentStorageAzureAccountName string
	PersistentStorageAzureContainer   string
	PersistentStorageAzureEndpoint    string
	PersistentStorageAzurePrefix      string
	PersistentStorageGCSBucket        string
	PersistentStorageGCSPrefix        string

	TracingEnabled      bool
	TracingServiceName  string
	TracingOTLPEndpoint string
	TracingInsecure     bool
	TracingSampleRatio  float64
	RequestLogEnabled   bool
)

func LoadEnv() {
	_ = godotenv.Load()
	path := strings.TrimSpace(os.Getenv("WAF_CONFIG_FILE"))
	if err := ReloadFromConfigFile(path); err != nil {
		log.Fatalf("[CONFIG][FATAL] load %s: %v", ConfigFile, err)
	}
}

func ReloadFromConfigFile(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		path = "conf/config.json"
	}
	cfg, err := loadAppConfigFile(path)
	if err != nil {
		ConfigFile = path
		return err
	}
	ConfigFile = path
	applyAppConfig(cfg)
	enforceSecureDefaults()
	emitAdminExposureWarnings()
	return nil
}

func applyAppConfig(cfg appConfigFile) {
	ProxyConfigFile = strings.TrimSpace(cfg.Paths.ProxyConfigFile)
	if ProxyConfigFile == "" {
		ProxyConfigFile = "conf/proxy.json"
	}
	SiteConfigFile = strings.TrimSpace(cfg.Paths.SiteConfigFile)
	if SiteConfigFile == "" {
		SiteConfigFile = "conf/sites.json"
	}
	PHPRuntimeInventoryFile = strings.TrimSpace(cfg.Paths.PHPRuntimeInventoryFile)
	if PHPRuntimeInventoryFile == "" {
		PHPRuntimeInventoryFile = "data/php-fpm/inventory.json"
	}
	VhostConfigFile = strings.TrimSpace(cfg.Paths.VhostConfigFile)
	if VhostConfigFile == "" {
		VhostConfigFile = "data/php-fpm/vhosts.json"
	}
	ScheduledTaskConfigFile = strings.TrimSpace(cfg.Paths.ScheduledTaskConfigFile)
	if ScheduledTaskConfigFile == "" {
		ScheduledTaskConfigFile = "conf/scheduled-tasks.json"
	}
	SecurityAuditFile = strings.TrimSpace(cfg.Paths.SecurityAuditFile)
	if SecurityAuditFile == "" {
		SecurityAuditFile = "audit/security-audit.ndjson"
	}
	SecurityAuditBlobDir = strings.TrimSpace(cfg.Paths.SecurityAuditBlobDir)
	if SecurityAuditBlobDir == "" {
		SecurityAuditBlobDir = "audit/security-audit-blobs"
	}
	CacheRulesFile = strings.TrimSpace(cfg.Paths.CacheRulesFile)
	if CacheRulesFile == "" {
		CacheRulesFile = DefaultCacheRulesFilePath
	}
	CacheStoreFile = strings.TrimSpace(cfg.Paths.CacheStoreFile)
	if CacheStoreFile == "" {
		CacheStoreFile = "conf/cache-store.json"
	}
	UIBasePath = strings.TrimSpace(cfg.Admin.UIBasePath)
	if UIBasePath == "" {
		UIBasePath = "/tukuyomi-ui"
	}

	ProxyRollbackMax = parseProxyRollbackHistorySize(strconv.Itoa(cfg.Proxy.RollbackHistorySize))
	ProxyAuditFile = strings.TrimSpace(cfg.Proxy.AuditFile)
	ProxyEngineMode = normalizeAppProxyEngineMode(cfg.Proxy.Engine.Mode)
	WAFEngineMode = normalizeAppWAFEngineMode(cfg.WAF.Engine.Mode)
	if override := strings.TrimSpace(os.Getenv("WAF_PROXY_AUDIT_FILE")); override != "" {
		ProxyAuditFile = override
	}
	if ProxyAuditFile == "" {
		ProxyAuditFile = "audit/proxy-rules-audit.ndjson"
	}
	SecurityAuditEnabled = cfg.SecurityAudit.Enabled
	SecurityAuditCaptureMode = strings.ToLower(strings.TrimSpace(cfg.SecurityAudit.CaptureMode))
	if SecurityAuditCaptureMode == "" {
		SecurityAuditCaptureMode = "off"
	}
	SecurityAuditCaptureHeaders = cfg.SecurityAudit.CaptureHeaders
	SecurityAuditCaptureBody = cfg.SecurityAudit.CaptureBody
	SecurityAuditMaxBodyBytes = cfg.SecurityAudit.MaxBodyBytes
	if SecurityAuditMaxBodyBytes <= 0 {
		SecurityAuditMaxBodyBytes = 32 * 1024
	}
	SecurityAuditRedactHeaders = append([]string(nil), cfg.SecurityAudit.RedactHeaders...)
	SecurityAuditRedactBodyContentTypes = append([]string(nil), cfg.SecurityAudit.RedactBodyContentTypes...)
	SecurityAuditKeySource = strings.ToLower(strings.TrimSpace(cfg.SecurityAudit.KeySource))
	if SecurityAuditKeySource == "" {
		SecurityAuditKeySource = "config"
	}
	SecurityAuditEncryptionKey = strings.TrimSpace(cfg.SecurityAudit.EncryptionKey)
	SecurityAuditEncryptionKeyID = strings.TrimSpace(cfg.SecurityAudit.EncryptionKeyID)
	if SecurityAuditEncryptionKeyID == "" {
		SecurityAuditEncryptionKeyID = "local-dev-aes-gcm"
	}
	SecurityAuditHMACKey = strings.TrimSpace(cfg.SecurityAudit.HMACKey)
	SecurityAuditHMACKeyID = strings.TrimSpace(cfg.SecurityAudit.HMACKeyID)
	if SecurityAuditHMACKeyID == "" {
		SecurityAuditHMACKeyID = "local-dev-hmac"
	}
	if SecurityAuditKeySource == "env" || strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_ENCRYPTION_KEY")) != "" {
		SecurityAuditEncryptionKey = strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_ENCRYPTION_KEY"))
	}
	if SecurityAuditKeySource == "env" || strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID")) != "" {
		if override := strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID")); override != "" {
			SecurityAuditEncryptionKeyID = override
		}
	}
	if SecurityAuditKeySource == "env" || strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_HMAC_KEY")) != "" {
		SecurityAuditHMACKey = strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_HMAC_KEY"))
	}
	if SecurityAuditKeySource == "env" || strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_HMAC_KEY_ID")) != "" {
		if override := strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_HMAC_KEY_ID")); override != "" {
			SecurityAuditHMACKeyID = override
		}
	}
	if override := strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_FILE")); override != "" {
		SecurityAuditFile = override
	}
	if override := strings.TrimSpace(os.Getenv("WAF_SECURITY_AUDIT_BLOB_DIR")); override != "" {
		SecurityAuditBlobDir = override
	}
	ListenAddr = parseListenAddr(cfg.Server.ListenAddr)
	ServerReadTimeout = time.Duration(parseServerTimeoutSec(strconv.Itoa(cfg.Server.ReadTimeoutSec), 30, false)) * time.Second
	ServerReadHeaderTimeout = time.Duration(parseServerTimeoutSec(strconv.Itoa(cfg.Server.ReadHeaderTimeoutSec), 5, false)) * time.Second
	ServerWriteTimeout = time.Duration(parseServerTimeoutSec(strconv.Itoa(cfg.Server.WriteTimeoutSec), 0, true)) * time.Second
	ServerIdleTimeout = time.Duration(parseServerTimeoutSec(strconv.Itoa(cfg.Server.IdleTimeoutSec), 120, false)) * time.Second
	ServerGracefulShutdownTimeout = time.Duration(parseServerTimeoutSec(strconv.Itoa(cfg.Server.GracefulShutdownTimeoutSec), 30, false)) * time.Second
	ServerMaxHeaderBytes = parseServerMaxHeaderBytes(strconv.Itoa(cfg.Server.MaxHeaderBytes))
	ServerMaxConcurrentReqs = parseServerConcurrency(strconv.Itoa(cfg.Server.MaxConcurrentRequests))
	ServerMaxQueuedReqs = parseServerQueueSize(strconv.Itoa(cfg.Server.MaxQueuedRequests))
	ServerQueuedRequestTimeout = time.Duration(parseServerQueueTimeoutMS(strconv.Itoa(cfg.Server.QueuedRequestTimeoutMS))) * time.Millisecond
	ServerMaxConcurrentProxy = parseServerConcurrency(strconv.Itoa(cfg.Server.MaxConcurrentProxyRequests))
	ServerMaxQueuedProxy = parseServerQueueSize(strconv.Itoa(cfg.Server.MaxQueuedProxyRequests))
	ServerQueuedProxyRequestTimeout = time.Duration(parseServerQueueTimeoutMS(strconv.Itoa(cfg.Server.QueuedProxyRequestTimeoutMS))) * time.Millisecond
	ServerProxyProtocolEnabled = cfg.Server.ProxyProtocol.Enabled
	ServerProxyProtocolTrustedCIDRs = append([]string(nil), cfg.Server.ProxyProtocol.TrustedCIDRs...)
	ServerTLSEnabled = cfg.Server.TLS.Enabled
	ServerTLSCertFile = strings.TrimSpace(cfg.Server.TLS.CertFile)
	ServerTLSKeyFile = strings.TrimSpace(cfg.Server.TLS.KeyFile)
	ServerTLSMinVersion = normalizeServerTLSMinVersion(cfg.Server.TLS.MinVersion)
	ServerTLSRedirectHTTP = cfg.Server.TLS.RedirectHTTP
	ServerTLSHTTPRedirectAddr = strings.TrimSpace(cfg.Server.TLS.HTTPRedirectAddr)
	if ServerTLSHTTPRedirectAddr != "" {
		ServerTLSHTTPRedirectAddr = parseListenAddr(ServerTLSHTTPRedirectAddr)
	}
	ServerHTTP3Enabled = cfg.Server.HTTP3.Enabled
	ServerHTTP3AltSvcMaxAgeSec = cfg.Server.HTTP3.AltSvcMaxAgeSec
	if ServerHTTP3AltSvcMaxAgeSec < 0 {
		ServerHTTP3AltSvcMaxAgeSec = 86400
	}
	ServerTLSACMEEnabled = cfg.Server.TLS.ACME.Enabled
	ServerTLSACMEEmail = strings.TrimSpace(cfg.Server.TLS.ACME.Email)
	ServerTLSACMEDomains = append([]string(nil), cfg.Server.TLS.ACME.Domains...)
	ServerTLSACMECacheDir = strings.TrimSpace(cfg.Server.TLS.ACME.CacheDir)
	ServerTLSACMEStaging = cfg.Server.TLS.ACME.Staging
	RuntimeGOMAXPROCS = parseRuntimeGOMAXPROCS(strconv.Itoa(cfg.Runtime.GOMAXPROCS))
	RuntimeMemoryLimitMB = parseRuntimeMemoryLimitMB(strconv.Itoa(cfg.Runtime.MemoryLimitMB))
	RequestCountryMode = strings.ToLower(strings.TrimSpace(cfg.RequestMeta.Country.Mode))
	if RequestCountryMode == "" {
		RequestCountryMode = "header"
	}

	RulesFile = strings.TrimSpace(cfg.Paths.RulesFile)
	if RulesFile == "" {
		RulesFile = DefaultBaseRuleAssetPath
	}
	OverrideRulesDir = strings.TrimSpace(cfg.Paths.OverrideRulesDir)
	if OverrideRulesDir == "" {
		OverrideRulesDir = "conf/rules"
	}
	UpstreamRuntimeFile = strings.TrimSpace(cfg.Paths.UpstreamRuntimeFile)
	if UpstreamRuntimeFile == "" {
		UpstreamRuntimeFile = DefaultUpstreamRuntimeFilePath
	}
	BypassFile = strings.TrimSpace(cfg.Paths.BypassFile)
	if BypassFile == "" {
		BypassFile = DefaultBypassFilePath
	}
	CountryBlockFile = strings.TrimSpace(cfg.Paths.CountryBlockFile)
	if CountryBlockFile == "" {
		CountryBlockFile = DefaultCountryBlockFilePath
	}
	RateLimitFile = strings.TrimSpace(cfg.Paths.RateLimitFile)
	if RateLimitFile == "" {
		RateLimitFile = "conf/rate-limit.json"
	}
	BotDefenseFile = strings.TrimSpace(cfg.Paths.BotDefenseFile)
	if BotDefenseFile == "" {
		BotDefenseFile = "conf/bot-defense.json"
	}
	SemanticFile = strings.TrimSpace(cfg.Paths.SemanticFile)
	if SemanticFile == "" {
		SemanticFile = "conf/semantic.json"
	}
	NotificationFile = strings.TrimSpace(cfg.Paths.NotificationFile)
	if NotificationFile == "" {
		NotificationFile = "conf/notifications.json"
	}
	IPReputationFile = strings.TrimSpace(cfg.Paths.IPReputationFile)
	if IPReputationFile == "" {
		IPReputationFile = "conf/ip-reputation.json"
	}
	LogFile = strings.TrimSpace(cfg.Paths.LogFile)

	StrictOverride = cfg.Admin.StrictOverride
	APIBasePath = strings.TrimSpace(cfg.Admin.APIBasePath)
	if APIBasePath == "" {
		APIBasePath = "/tukuyomi-api"
	}
	if !strings.HasPrefix(APIBasePath, "/") {
		APIBasePath = "/" + APIBasePath
	}
	if APIBasePath == "/" {
		log.Fatal("api_base_path cannot be root path '/'")
	}
	AdminListenAddr = strings.TrimSpace(cfg.Admin.ListenAddr)
	if AdminListenAddr != "" {
		AdminListenAddr = parseListenAddr(AdminListenAddr)
	}
	AdminExternalMode = strings.ToLower(strings.TrimSpace(cfg.Admin.ExternalMode))
	if AdminExternalMode == "" {
		AdminExternalMode = "api_only_external"
	}
	AdminTrustedCIDRs = append([]string(nil), cfg.Admin.TrustedCIDRs...)
	AdminTrustForwardedFor = cfg.Admin.TrustForwardedFor
	AdminProxyProtocolEnabled = cfg.Admin.ProxyProtocol.Enabled
	AdminProxyProtocolTrustedCIDRs = append([]string(nil), cfg.Admin.ProxyProtocol.TrustedCIDRs...)
	AdminSessionSecret = strings.TrimSpace(cfg.Admin.SessionSecret)
	adminSessionTTLSec := cfg.Admin.SessionTTLSec
	if adminSessionTTLSec < 300 || adminSessionTTLSec > 604800 {
		adminSessionTTLSec = 28800
	}
	AdminSessionTTL = time.Duration(adminSessionTTLSec) * time.Second
	APIAuthDisable = cfg.Admin.APIAuthDisable
	AdminReadOnly = cfg.Admin.ReadOnly
	AdminRateLimitEnabled = cfg.Admin.RateLimit.Enabled
	AdminRateLimitRPS = cfg.Admin.RateLimit.RPS
	AdminRateLimitBurst = cfg.Admin.RateLimit.Burst
	AdminRateLimitStatusCode = cfg.Admin.RateLimit.StatusCode
	AdminRateLimitRetryAfter = cfg.Admin.RateLimit.RetryAfterSeconds
	APICORSOrigins = make([]string, 0, len(cfg.Admin.CORSAllowedOrigins))
	for _, origin := range cfg.Admin.CORSAllowedOrigins {
		origin = strings.TrimSpace(origin)
		if origin != "" {
			APICORSOrigins = append(APICORSOrigins, origin)
		}
	}

	CRSEnable = cfg.CRS.Enable
	CRSSetupFile = strings.TrimSpace(cfg.Paths.CRSSetupFile)
	if CRSSetupFile == "" {
		CRSSetupFile = "rules/crs/crs-setup.conf"
	}
	CRSRulesDir = strings.TrimSpace(cfg.Paths.CRSRulesDir)
	if CRSRulesDir == "" {
		CRSRulesDir = "rules/crs/rules"
	}
	CRSDisabledFile = strings.TrimSpace(cfg.Paths.CRSDisabledFile)
	if CRSDisabledFile == "" {
		CRSDisabledFile = "conf/crs-disabled.conf"
	}

	FPTunerEndpoint = strings.TrimSpace(cfg.FPTuner.Endpoint)
	FPTunerAPIKey = strings.TrimSpace(cfg.FPTuner.APIKey)
	FPTunerModel = strings.TrimSpace(cfg.FPTuner.Model)
	timeoutSec := cfg.FPTuner.TimeoutSec
	if timeoutSec < 1 || timeoutSec > 300 {
		timeoutSec = 15
	}
	FPTunerTimeout = time.Duration(timeoutSec) * time.Second
	FPTunerRequireApproval = cfg.FPTuner.RequireApproval
	approvalTTLSec := cfg.FPTuner.ApprovalTTLSec
	if approvalTTLSec < 10 || approvalTTLSec > 86400 {
		approvalTTLSec = 600
	}
	FPTunerApprovalTTL = time.Duration(approvalTTLSec) * time.Second
	FPTunerAuditFile = strings.TrimSpace(cfg.FPTuner.AuditFile)
	if FPTunerAuditFile == "" {
		FPTunerAuditFile = "audit/fp-tuner-audit.ndjson"
	}

	DBDriver = parseDBDriver(cfg.Storage.DBDriver)
	if override := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_DRIVER")); override != "" {
		DBDriver = parseDBDriver(override)
	}
	DBDSN = strings.TrimSpace(cfg.Storage.DBDSN)
	if override := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_DSN")); override != "" {
		DBDSN = override
	}
	DBPath = strings.TrimSpace(cfg.Storage.DBPath)
	if override := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_PATH")); override != "" {
		DBPath = override
	}
	if DBPath == "" {
		DBPath = "db/tukuyomi.db"
	}
	DBRetentionDays = cfg.Storage.DBRetentionDays
	if override := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_RETENTION_DAYS")); override != "" {
		DBRetentionDays = parseIntDefault(override, DBRetentionDays)
	}
	if DBRetentionDays < 0 {
		DBRetentionDays = 0
	}
	if DBRetentionDays > 3650 {
		DBRetentionDays = 3650
	}
	dbSyncSec := parseDBSyncIntervalSec(strconv.Itoa(cfg.Storage.DBSyncIntervalSec))
	if override := strings.TrimSpace(os.Getenv("WAF_STORAGE_DB_SYNC_INTERVAL_SEC")); override != "" {
		dbSyncSec = parseDBSyncIntervalSec(override)
	}
	DBSyncInterval = time.Duration(dbSyncSec) * time.Second
	FileRotateBytes = cfg.Storage.FileRotateBytes
	FileMaxBytes = cfg.Storage.FileMaxBytes
	FileRetention = time.Duration(cfg.Storage.FileRetentionDays) * 24 * time.Hour

	PersistentStorageBackend = strings.ToLower(strings.TrimSpace(cfg.Persistent.Backend))
	if PersistentStorageBackend == "" {
		PersistentStorageBackend = DefaultPersistentStorageBackend
	}
	PersistentStorageLocalBaseDir = strings.TrimSpace(cfg.Persistent.Local.BaseDir)
	if PersistentStorageLocalBaseDir == "" {
		PersistentStorageLocalBaseDir = DefaultPersistentStorageLocalDir
	}
	PersistentStorageS3Bucket = strings.TrimSpace(cfg.Persistent.S3.Bucket)
	PersistentStorageS3Region = strings.TrimSpace(cfg.Persistent.S3.Region)
	PersistentStorageS3Endpoint = strings.TrimSpace(cfg.Persistent.S3.Endpoint)
	PersistentStorageS3Prefix = strings.Trim(strings.TrimSpace(cfg.Persistent.S3.Prefix), "/")
	PersistentStorageS3ForcePathStyle = cfg.Persistent.S3.ForcePathStyle
	PersistentStorageAzureAccountName = strings.TrimSpace(cfg.Persistent.AzureBlob.AccountName)
	PersistentStorageAzureContainer = strings.TrimSpace(cfg.Persistent.AzureBlob.Container)
	PersistentStorageAzureEndpoint = strings.TrimSpace(cfg.Persistent.AzureBlob.Endpoint)
	PersistentStorageAzurePrefix = strings.Trim(strings.TrimSpace(cfg.Persistent.AzureBlob.Prefix), "/")
	PersistentStorageGCSBucket = strings.TrimSpace(cfg.Persistent.GCS.Bucket)
	PersistentStorageGCSPrefix = strings.Trim(strings.TrimSpace(cfg.Persistent.GCS.Prefix), "/")

	AllowInsecureDefaults = cfg.Admin.AllowInsecureDefaults

	RequestLogEnabled = cfg.Observability.RequestLog.Enabled
	TracingEnabled = cfg.Observability.Tracing.Enabled
	TracingServiceName = strings.TrimSpace(cfg.Observability.Tracing.ServiceName)
	TracingOTLPEndpoint = strings.TrimSpace(cfg.Observability.Tracing.OTLPEndpoint)
	TracingInsecure = cfg.Observability.Tracing.Insecure
	TracingSampleRatio = cfg.Observability.Tracing.SampleRatio
}

func enforceSecureDefaults() {
	if AllowInsecureDefaults {
		log.Println("[SECURITY][WARN] admin.allow_insecure_defaults enabled; weak bootstrap settings are allowed")
		return
	}

	if APIAuthDisable {
		log.Fatal("[SECURITY] admin.api_auth_disable is enabled; set admin.allow_insecure_defaults=true only for local testing")
	}
	if isWeakAPIKey(AdminSessionSecret) {
		log.Fatal("[SECURITY] admin.session_secret is weak; set a random secret with 16+ chars")
	}
}

func emitAdminExposureWarnings() {
	for _, warning := range adminExposureWarnings(ListenAddr, AdminExternalMode, AdminTrustedCIDRs) {
		log.Printf("[SECURITY][WARN] %s", warning)
	}
}

func adminExposureWarnings(listenAddr string, externalMode string, trustedCIDRs []string) []string {
	mode := strings.ToLower(strings.TrimSpace(externalMode))
	if mode == "" {
		mode = "api_only_external"
	}
	if !listenAddrExposesBeyondLoopback(listenAddr) {
		return nil
	}

	warnings := make([]string, 0, 3)
	if mode == "full_external" {
		warnings = append(warnings,
			"admin.external_mode=full_external with a non-loopback server.listen_addr exposes the embedded admin UI and admin API to any network path that can reach this listener",
			"prefer admin.external_mode=api_only_external (default) or deny_external, and add front-side allowlists/auth if you intentionally expose admin paths",
		)
	}

	for _, raw := range trustedCIDRs {
		if riskyPrefix, ok := trustedCIDRExposesBeyondPrivate(raw); ok {
			warnings = append(warnings,
				"admin.trusted_cidrs includes "+riskyPrefix+", so the embedded admin UI and admin API remain reachable from that network even when admin.external_mode is not full_external",
			)
			break
		}
	}
	return warnings
}

func listenAddrExposesBeyondLoopback(addr string) bool {
	s := parseListenAddr(addr)
	if strings.HasPrefix(s, ":") {
		return true
	}
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return true
	}
	host = strings.Trim(host, "[]")
	if host == "" || host == "*" {
		return true
	}
	if strings.EqualFold(host, "localhost") {
		return false
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return true
	}
	return !ip.IsLoopback()
}

func trustedCIDRExposesBeyondPrivate(raw string) (string, bool) {
	prefix, err := netip.ParsePrefix(strings.TrimSpace(raw))
	if err != nil {
		return "", false
	}
	if prefix.Bits() == 0 {
		return prefix.String(), true
	}
	addr := prefix.Addr()
	if addr.IsLoopback() || addr.IsPrivate() || addr.IsLinkLocalUnicast() {
		return "", false
	}
	return prefix.String(), true
}

func isWeakAPIKey(v string) bool {
	trimmed := strings.TrimSpace(v)
	s := strings.ToLower(trimmed)
	if s == "" || len(trimmed) < 16 {
		return true
	}

	weak := map[string]struct{}{
		"change-me":                        {},
		"changeme":                         {},
		"replace-with-long-random-api-key": {},
		"replace-me":                       {},
		"example":                          {},
		"test":                             {},
	}
	_, ok := weak[s]
	return ok
}

func isTruthy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func isFalsy(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "0", "false", "no", "off":
		return true
	default:
		return false
	}
}

func parseCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		s := strings.TrimSpace(p)
		if s == "" {
			continue
		}
		out = append(out, s)
	}

	return out
}

func parseIntDefault(v string, d int) int {
	s := strings.TrimSpace(v)
	if s == "" {
		return d
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return d
	}
	return n
}

func parseDBDriver(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "":
		return "sqlite"
	case "sqlite", "mysql", "pgsql":
		return s
	default:
		log.Printf("[CONFIG][WARN] unsupported storage.db_driver=%q, fallback=sqlite", s)
		return "sqlite"
	}
}

func parseDBSyncIntervalSec(v string) int {
	n := parseIntDefault(v, 0)
	if n < 0 {
		return 0
	}
	if n > 3600 {
		return 3600
	}
	return n
}

func parseListenAddr(v string) string {
	s := strings.TrimSpace(v)
	if s == "" {
		return ":9090"
	}
	if strings.HasPrefix(s, ":") {
		return s
	}
	if _, err := strconv.Atoi(s); err == nil {
		return ":" + s
	}
	return s
}

func parseProxyRollbackHistorySize(v string) int {
	n := parseIntDefault(v, 8)
	if n < 1 {
		return 1
	}
	if n > 64 {
		return 64
	}
	return n
}

func parseServerTimeoutSec(v string, def int, allowZero bool) int {
	n := parseIntDefault(v, def)
	if n < 0 {
		return def
	}
	if n == 0 && !allowZero {
		return def
	}
	if n > 3600 {
		return 3600
	}
	return n
}

func parseServerMaxHeaderBytes(v string) int {
	n := parseIntDefault(v, 1<<20)
	if n < 1024 {
		return 1024
	}
	if n > 16<<20 {
		return 16 << 20
	}
	return n
}

func parseServerConcurrency(v string) int {
	n := parseIntDefault(v, 0)
	if n < 0 {
		return 0
	}
	if n > 200000 {
		return 200000
	}
	return n
}

func parseServerQueueSize(v string) int {
	return parseServerConcurrency(v)
}

func parseServerQueueTimeoutMS(v string) int {
	n := parseIntDefault(v, 0)
	if n < 0 {
		return 0
	}
	if n > 60000 {
		return 60000
	}
	return n
}

func parseRuntimeGOMAXPROCS(v string) int {
	n := parseIntDefault(v, 0)
	if n < 0 {
		return 0
	}
	if n > 4096 {
		return 4096
	}
	return n
}

func parseRuntimeMemoryLimitMB(v string) int {
	n := parseIntDefault(v, 0)
	if n < 0 {
		return 0
	}
	if n > 1024*1024 {
		return 1024 * 1024
	}
	return n
}
