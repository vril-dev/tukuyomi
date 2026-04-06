package config

import (
	"log"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

var (
	AppURL                         string
	RulesFile                      string
	BypassFile                     string
	CountryBlockFile               string
	CountryHeaderNames             []string
	RateLimitFile                  string
	IPReputationFile               string
	BotDefenseFile                 string
	SemanticFile                   string
	NotificationFile               string
	LogFile                        string
	LogOutputFile                  string
	ProxyErrorHTMLFile             string
	ProxyErrorRedirectURL          string
	StrictOverride                 bool
	APIBasePath                    string
	UIBasePath                     string
	TrustedProxyCIDRs              []string
	TrustedProxyPrefixes           []netip.Prefix
	ForwardInternalResponseHeaders bool
	ResponseCacheMode              string
	ResponseCacheMaxEntries        int
	ResponseCacheMaxBodyBytes      int64
	ResponseCacheStaleSeconds      int
	ResponseCacheRefreshTimeout    time.Duration
	ResponseCacheRefreshBackoff    time.Duration
	APIKeyPrimary                  string
	APIKeySecondary                string
	APIAuthDisable                 bool
	APICORSOrigins                 []string
	CRSEnable                      bool
	CRSSetupFile                   string
	CRSRulesDir                    string
	CRSDisabledFile                string

	AllowInsecureDefaults bool

	FPTunerMode             string
	FPTunerEndpoint         string
	FPTunerAPIKey           string
	FPTunerModel            string
	FPTunerTimeout          time.Duration
	FPTunerMockResponseFile string
	FPTunerRequireApproval  bool
	FPTunerApprovalTTL      time.Duration
	FPTunerAuditFile        string

	StorageBackend  string
	DBEnabled       bool
	DBDriver        string
	DBDSN           string
	DBPath          string
	DBRetentionDays int
	DBSyncInterval  time.Duration
)

func LoadEnv() {
	_ = godotenv.Load()

	AppURL = os.Getenv("WAF_APP_URL")
	RulesFile = os.Getenv("WAF_RULES_FILE")
	BypassFile = os.Getenv("WAF_BYPASS_FILE")
	CountryBlockFile = strings.TrimSpace(os.Getenv("WAF_COUNTRY_BLOCK_FILE"))
	if CountryBlockFile == "" {
		CountryBlockFile = "conf/country-block.conf"
	}
	CountryHeaderNames = parseCountryHeaderNames(os.Getenv("WAF_COUNTRY_HEADER_NAMES"))
	RateLimitFile = strings.TrimSpace(os.Getenv("WAF_RATE_LIMIT_FILE"))
	if RateLimitFile == "" {
		RateLimitFile = "conf/rate-limit.conf"
	}
	IPReputationFile = strings.TrimSpace(os.Getenv("WAF_IP_REPUTATION_FILE"))
	if IPReputationFile == "" {
		IPReputationFile = "conf/ip-reputation.conf"
	}
	BotDefenseFile = strings.TrimSpace(os.Getenv("WAF_BOT_DEFENSE_FILE"))
	if BotDefenseFile == "" {
		BotDefenseFile = "conf/bot-defense.conf"
	}
	SemanticFile = strings.TrimSpace(os.Getenv("WAF_SEMANTIC_FILE"))
	if SemanticFile == "" {
		SemanticFile = "conf/semantic.conf"
	}
	NotificationFile = strings.TrimSpace(os.Getenv("WAF_NOTIFICATION_FILE"))
	if NotificationFile == "" {
		NotificationFile = "conf/notifications.conf"
	}
	LogFile = os.Getenv("WAF_LOG_FILE")
	LogOutputFile = strings.TrimSpace(os.Getenv("WAF_LOG_OUTPUT_FILE"))
	if LogOutputFile == "" {
		LogOutputFile = "conf/log-output.json"
	}
	ProxyErrorHTMLFile = strings.TrimSpace(os.Getenv("WAF_PROXY_ERROR_HTML_FILE"))
	ProxyErrorRedirectURL = strings.TrimSpace(os.Getenv("WAF_PROXY_ERROR_REDIRECT_URL"))
	StrictOverride = os.Getenv("WAF_STRICT_OVERRIDE") == "true"

	APIBasePath = os.Getenv("WAF_API_BASEPATH")
	if APIBasePath == "" {
		APIBasePath = "/tukuyomi-api"
	}
	if !strings.HasPrefix(APIBasePath, "/") {
		APIBasePath = "/" + APIBasePath
	}
	if APIBasePath == "/" {
		log.Fatal("WAF_API_BASEPATH cannot be root path '/'")
	}
	UIBasePath = os.Getenv("WAF_UI_BASEPATH")
	if UIBasePath == "" {
		UIBasePath = "/tukuyomi-admin"
	}
	if !strings.HasPrefix(UIBasePath, "/") {
		UIBasePath = "/" + UIBasePath
	}
	if UIBasePath != "/" {
		UIBasePath = strings.TrimRight(UIBasePath, "/")
	}
	if UIBasePath == "/" {
		log.Fatal("WAF_UI_BASEPATH cannot be root path '/'")
	}
	if UIBasePath == APIBasePath {
		log.Fatal("WAF_UI_BASEPATH must differ from WAF_API_BASEPATH")
	}
	TrustedProxyCIDRs, TrustedProxyPrefixes = parseTrustedProxyCIDRs(os.Getenv("WAF_TRUSTED_PROXY_CIDRS"))
	ForwardInternalResponseHeaders = isTruthy(os.Getenv("WAF_FORWARD_INTERNAL_RESPONSE_HEADERS"))
	ResponseCacheMode = parseResponseCacheMode(os.Getenv("WAF_RESPONSE_CACHE_MODE"))
	ResponseCacheMaxEntries = parseResponseCacheMaxEntries(os.Getenv("WAF_RESPONSE_CACHE_MAX_ENTRIES"))
	ResponseCacheMaxBodyBytes = parseResponseCacheMaxBodyBytes(os.Getenv("WAF_RESPONSE_CACHE_MAX_BODY_BYTES"))
	ResponseCacheStaleSeconds = parseResponseCacheStaleSeconds(os.Getenv("WAF_RESPONSE_CACHE_STALE_SECONDS"))
	ResponseCacheRefreshTimeout = time.Duration(parseResponseCacheRefreshTimeoutSeconds(os.Getenv("WAF_RESPONSE_CACHE_REFRESH_TIMEOUT_SECONDS"))) * time.Second
	ResponseCacheRefreshBackoff = time.Duration(parseResponseCacheRefreshBackoffSeconds(os.Getenv("WAF_RESPONSE_CACHE_REFRESH_BACKOFF_SECONDS"))) * time.Second

	APIKeyPrimary = strings.TrimSpace(os.Getenv("WAF_API_KEY_PRIMARY"))
	APIKeySecondary = strings.TrimSpace(os.Getenv("WAF_API_KEY_SECONDARY"))
	APIAuthDisable = isTruthy(os.Getenv("WAF_API_AUTH_DISABLE"))
	APICORSOrigins = parseCSV(os.Getenv("WAF_API_CORS_ALLOWED_ORIGINS"))

	CRSEnable = !isFalsy(os.Getenv("WAF_CRS_ENABLE"))
	CRSSetupFile = strings.TrimSpace(os.Getenv("WAF_CRS_SETUP_FILE"))
	if CRSSetupFile == "" {
		CRSSetupFile = "rules/crs/crs-setup.conf"
	}
	CRSRulesDir = strings.TrimSpace(os.Getenv("WAF_CRS_RULES_DIR"))
	if CRSRulesDir == "" {
		CRSRulesDir = "rules/crs/rules"
	}
	CRSDisabledFile = strings.TrimSpace(os.Getenv("WAF_CRS_DISABLED_FILE"))
	if CRSDisabledFile == "" {
		CRSDisabledFile = "conf/crs-disabled.conf"
	}

	FPTunerMode = strings.ToLower(strings.TrimSpace(os.Getenv("WAF_FP_TUNER_MODE")))
	if FPTunerMode == "" {
		FPTunerMode = "mock"
	}
	FPTunerEndpoint = strings.TrimSpace(os.Getenv("WAF_FP_TUNER_ENDPOINT"))
	FPTunerAPIKey = strings.TrimSpace(os.Getenv("WAF_FP_TUNER_API_KEY"))
	FPTunerModel = strings.TrimSpace(os.Getenv("WAF_FP_TUNER_MODEL"))
	FPTunerMockResponseFile = strings.TrimSpace(os.Getenv("WAF_FP_TUNER_MOCK_RESPONSE_FILE"))
	if FPTunerMockResponseFile == "" {
		FPTunerMockResponseFile = "conf/fp-tuner-mock-response.json"
	}
	timeoutSec := parseIntDefault(os.Getenv("WAF_FP_TUNER_TIMEOUT_SEC"), 15)
	if timeoutSec < 1 || timeoutSec > 300 {
		timeoutSec = 15
	}
	FPTunerTimeout = time.Duration(timeoutSec) * time.Second
	FPTunerRequireApproval = !isFalsy(os.Getenv("WAF_FP_TUNER_REQUIRE_APPROVAL"))
	approvalTTLSec := parseIntDefault(os.Getenv("WAF_FP_TUNER_APPROVAL_TTL_SEC"), 600)
	if approvalTTLSec < 10 || approvalTTLSec > 86400 {
		approvalTTLSec = 600
	}
	FPTunerApprovalTTL = time.Duration(approvalTTLSec) * time.Second
	FPTunerAuditFile = strings.TrimSpace(os.Getenv("WAF_FP_TUNER_AUDIT_FILE"))
	if FPTunerAuditFile == "" {
		FPTunerAuditFile = "logs/coraza/fp-tuner-audit.ndjson"
	}
	legacyDBEnabled := isTruthy(os.Getenv("WAF_DB_ENABLED"))
	StorageBackend = parseStorageBackend(os.Getenv("WAF_STORAGE_BACKEND"), legacyDBEnabled)
	DBEnabled = StorageBackend == "db"
	DBDriver = parseDBDriver(os.Getenv("WAF_DB_DRIVER"))
	DBDSN = strings.TrimSpace(os.Getenv("WAF_DB_DSN"))
	DBPath = strings.TrimSpace(os.Getenv("WAF_DB_PATH"))
	if DBPath == "" {
		DBPath = "logs/coraza/tukuyomi.db"
	}
	DBRetentionDays = parseIntDefault(os.Getenv("WAF_DB_RETENTION_DAYS"), 30)
	if DBRetentionDays < 0 {
		DBRetentionDays = 0
	}
	if DBRetentionDays > 3650 {
		DBRetentionDays = 3650
	}
	dbSyncSec := parseDBSyncIntervalSec(os.Getenv("WAF_DB_SYNC_INTERVAL_SEC"))
	DBSyncInterval = time.Duration(dbSyncSec) * time.Second

	AllowInsecureDefaults = isTruthy(os.Getenv("WAF_ALLOW_INSECURE_DEFAULTS"))
	enforceSecureDefaults()
}

func enforceSecureDefaults() {
	if AllowInsecureDefaults {
		log.Println("[SECURITY][WARN] WAF_ALLOW_INSECURE_DEFAULTS enabled; weak bootstrap settings are allowed")
		return
	}

	if APIAuthDisable {
		log.Fatal("[SECURITY] WAF_API_AUTH_DISABLE is enabled; set WAF_ALLOW_INSECURE_DEFAULTS=1 only for local testing")
	}
	if isWeakAPIKey(APIKeyPrimary) {
		log.Fatal("[SECURITY] WAF_API_KEY_PRIMARY is weak; set a random key with 16+ chars")
	}
	if APIKeySecondary != "" && isWeakAPIKey(APIKeySecondary) {
		log.Fatal("[SECURITY] WAF_API_KEY_SECONDARY is weak; set a random key with 16+ chars or leave it empty")
	}
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

func parseStorageBackend(v string, legacyDBEnabled bool) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "file", "db":
		return s
	case "":
		if legacyDBEnabled {
			return "db"
		}
		return "file"
	default:
		log.Printf("[CONFIG][WARN] unsupported WAF_STORAGE_BACKEND=%q, fallback=file", s)
		return "file"
	}
}

func parseDBDriver(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "":
		return "sqlite"
	case "sqlite", "mysql":
		return s
	default:
		log.Printf("[CONFIG][WARN] unsupported WAF_DB_DRIVER=%q, fallback=sqlite", s)
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

func parseTrustedProxyCIDRs(v string) ([]string, []netip.Prefix) {
	parts := parseCSV(v)
	if len(parts) == 0 {
		return nil, nil
	}

	cidrs := make([]string, 0, len(parts))
	prefixes := make([]netip.Prefix, 0, len(parts))
	for _, part := range parts {
		if prefix, err := netip.ParsePrefix(part); err == nil {
			prefix = prefix.Masked()
			cidrs = append(cidrs, prefix.String())
			prefixes = append(prefixes, prefix)
			continue
		}
		if addr, err := netip.ParseAddr(part); err == nil {
			addr = addr.Unmap()
			prefix := netip.PrefixFrom(addr, addr.BitLen())
			cidrs = append(cidrs, prefix.String())
			prefixes = append(prefixes, prefix)
			continue
		}
		log.Printf("[CONFIG][WARN] invalid WAF_TRUSTED_PROXY_CIDRS entry ignored: %q", part)
	}

	if len(cidrs) == 0 {
		return nil, nil
	}

	return cidrs, prefixes
}

func parseResponseCacheMode(v string) string {
	s := strings.ToLower(strings.TrimSpace(v))
	switch s {
	case "", "off":
		return "off"
	case "memory":
		return "memory"
	default:
		log.Printf("[CONFIG][WARN] unsupported WAF_RESPONSE_CACHE_MODE=%q, fallback=off", s)
		return "off"
	}
}

func parseResponseCacheMaxEntries(v string) int {
	n := parseIntDefault(v, 512)
	if n < 0 {
		return 0
	}
	if n > 10000 {
		return 10000
	}
	return n
}

func parseResponseCacheMaxBodyBytes(v string) int64 {
	n := parseIntDefault(v, 1<<20)
	if n < 0 {
		return 0
	}
	if n > 64<<20 {
		return 64 << 20
	}
	return int64(n)
}

func parseResponseCacheStaleSeconds(v string) int {
	n := parseIntDefault(v, 30)
	if n < 0 {
		return 0
	}
	if n > 86400 {
		return 86400
	}
	return n
}

func parseResponseCacheRefreshTimeoutSeconds(v string) int {
	n := parseIntDefault(v, 5)
	if n < 1 {
		return 1
	}
	if n > 300 {
		return 300
	}
	return n
}

func parseResponseCacheRefreshBackoffSeconds(v string) int {
	n := parseIntDefault(v, 5)
	if n < 0 {
		return 0
	}
	if n > 300 {
		return 300
	}
	return n
}

func parseCountryHeaderNames(v string) []string {
	parts := parseCSV(v)
	if len(parts) == 0 {
		parts = []string{"X-Country-Code", "CF-IPCountry"}
	}

	out := make([]string, 0, len(parts))
	seen := map[string]struct{}{}
	for _, part := range parts {
		name := strings.TrimSpace(part)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}

	if len(out) == 0 {
		return []string{"X-Country-Code", "CF-IPCountry"}
	}

	return out
}
