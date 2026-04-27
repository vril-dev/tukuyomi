package botdefensesignals

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

type BrowserConfig struct {
	Enabled            bool
	CookieName         string
	ScoreThreshold     int
	RiskScorePerSignal int
}

type DeviceConfig struct {
	Enabled                    bool
	CookieName                 string
	RequireTimeZone            bool
	RequirePlatform            bool
	RequireHardwareConcurrency bool
	CheckMobileTouch           bool
	ScoreThreshold             int
	RiskScorePerSignal         int
}

type HeaderConfig struct {
	Enabled                bool
	RequireAcceptLanguage  bool
	RequireFetchMetadata   bool
	RequireClientHints     bool
	RequireUpgradeInsecure bool
	ScoreThreshold         int
	RiskScorePerSignal     int
}

type TLSConfig struct {
	Enabled            bool
	RequireSNI         bool
	RequireALPN        bool
	RequireModernTLS   bool
	ScoreThreshold     int
	RiskScorePerSignal int
}

type InjectionConfig struct {
	RuntimeEnabled         bool
	DeviceSignalsEnabled   bool
	InvisibleHTMLInjection bool
	CookieName             string
}

type Telemetry struct {
	WebDriver           bool   `json:"wd"`
	LanguageCount       int    `json:"lc"`
	ScreenWidth         int    `json:"sw"`
	ScreenHeight        int    `json:"sh"`
	TimeZone            string `json:"tz"`
	Platform            string `json:"pf"`
	HardwareConcurrency int    `json:"hc"`
	MaxTouchPoints      int    `json:"mt"`
}

func EvaluateBrowser(cfg BrowserConfig, r *http.Request, hasValidChallengeCookie bool) (int, []string) {
	if !cfg.Enabled || r == nil {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	cookie, err := r.Cookie(strings.TrimSpace(cfg.CookieName))
	if err != nil {
		if hasValidChallengeCookie {
			signals = append(signals, "js_cookie_missing_after_challenge")
		}
		return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
	}

	telemetry, ok := ParseTelemetryCookie(cookie.Value)
	if !ok {
		signals = append(signals, "js_cookie_invalid")
		return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
	}
	if telemetry.WebDriver {
		signals = append(signals, "webdriver")
	}
	if telemetry.LanguageCount <= 0 {
		signals = append(signals, "languages_missing")
	}
	if telemetry.ScreenWidth <= 0 || telemetry.ScreenHeight <= 0 {
		signals = append(signals, "screen_invalid")
	}
	return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
}

func EvaluateDevice(cfg DeviceConfig, r *http.Request) (int, []string) {
	if !cfg.Enabled || r == nil || !LooksLikeBrowserRequest(r) {
		return 0, nil
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		return 0, nil
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return 0, nil
	}
	telemetry, ok := ParseTelemetryCookie(cookie.Value)
	if !ok {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if cfg.RequireTimeZone && strings.TrimSpace(telemetry.TimeZone) == "" {
		signals = append(signals, "timezone_missing")
	}
	if cfg.RequirePlatform && strings.TrimSpace(telemetry.Platform) == "" {
		signals = append(signals, "platform_missing")
	}
	if cfg.RequireHardwareConcurrency && telemetry.HardwareConcurrency <= 0 {
		signals = append(signals, "hardware_concurrency_invalid")
	}
	if cfg.CheckMobileTouch && isLikelyMobileUserAgent(r.UserAgent()) && telemetry.MaxTouchPoints <= 0 {
		signals = append(signals, "mobile_touch_mismatch")
	}
	return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
}

func EvaluateHeaders(cfg HeaderConfig, r *http.Request) (int, []string) {
	if !cfg.Enabled || r == nil || !LooksLikeBrowserRequest(r) {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if cfg.RequireAcceptLanguage && strings.TrimSpace(r.Header.Get("Accept-Language")) == "" {
		signals = append(signals, "accept_language_missing")
	}
	if cfg.RequireFetchMetadata && !hasAnyHeaderValue(r.Header, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest") {
		signals = append(signals, "fetch_metadata_missing")
	}
	if cfg.RequireClientHints && isLikelyChromiumUserAgent(r.UserAgent()) && strings.TrimSpace(r.Header.Get("Sec-CH-UA")) == "" {
		signals = append(signals, "client_hints_missing")
	}
	if cfg.RequireUpgradeInsecure && isLikelyHTMLNavigation(r) && strings.TrimSpace(r.Header.Get("Upgrade-Insecure-Requests")) == "" {
		signals = append(signals, "upgrade_insecure_requests_missing")
	}
	return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
}

func EvaluateTLS(cfg TLSConfig, r *http.Request) (int, []string) {
	if !cfg.Enabled || r == nil || r.TLS == nil || !LooksLikeBrowserRequest(r) {
		return 0, nil
	}
	signals := make([]string, 0, 3)
	if cfg.RequireSNI && strings.TrimSpace(r.TLS.ServerName) == "" {
		signals = append(signals, "tls_sni_missing")
	}
	if cfg.RequireALPN && strings.TrimSpace(r.TLS.NegotiatedProtocol) == "" {
		signals = append(signals, "tls_alpn_missing")
	}
	if cfg.RequireModernTLS && r.TLS.Version > 0 && r.TLS.Version < tls.VersionTLS12 {
		signals = append(signals, "tls_legacy_version")
	}
	return scoreSignals(signals, cfg.ScoreThreshold, cfg.RiskScorePerSignal)
}

func ParseTelemetryCookie(raw string) (Telemetry, bool) {
	decoded, err := url.QueryUnescape(strings.TrimSpace(raw))
	if err != nil {
		return Telemetry{}, false
	}
	var telemetry Telemetry
	if err := json.Unmarshal([]byte(decoded), &telemetry); err != nil {
		return Telemetry{}, false
	}
	return telemetry, true
}

func LooksLikeBrowserRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	ua := strings.ToLower(strings.TrimSpace(r.UserAgent()))
	if ua == "" {
		return false
	}
	if strings.Contains(ua, "mozilla/") || strings.Contains(ua, "applewebkit/") || strings.Contains(ua, "chrome/") || strings.Contains(ua, "safari/") || strings.Contains(ua, "firefox/") || strings.Contains(ua, "edg/") {
		return true
	}
	return hasAnyHeaderValue(r.Header, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest", "Sec-CH-UA")
}

func CanInjectTelemetry(cfg InjectionConfig, req *http.Request, res *http.Response) bool {
	if !cfg.RuntimeEnabled || !cfg.DeviceSignalsEnabled || !cfg.InvisibleHTMLInjection {
		return false
	}
	if req == nil || res == nil || res.Body == nil {
		return false
	}
	if req.Method != http.MethodGet || !LooksLikeBrowserRequest(req) || !isLikelyHTMLNavigation(req) {
		return false
	}
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return false
	}
	if !strings.Contains(strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Type"))), "text/html") {
		return false
	}
	encoding := strings.ToLower(strings.TrimSpace(res.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" {
		return false
	}
	if !allowsInlineScript(strings.TrimSpace(res.Header.Get("Content-Security-Policy"))) {
		return false
	}
	cookieName := strings.TrimSpace(cfg.CookieName)
	if cookieName == "" {
		return false
	}
	if cookie, err := req.Cookie(cookieName); err == nil {
		if telemetry, ok := ParseTelemetryCookie(cookie.Value); ok && telemetryComplete(telemetry) {
			return false
		}
	}
	return true
}

func AcceptsHTML(rawAccept string) bool {
	v := strings.ToLower(strings.TrimSpace(rawAccept))
	if v == "" {
		return false
	}
	return strings.Contains(v, "text/html") || strings.Contains(v, "*/*")
}

func scoreSignals(signals []string, threshold int, riskScorePerSignal int) (int, []string) {
	if len(signals) < threshold {
		return 0, nil
	}
	return len(signals) * riskScorePerSignal, signals
}

func isLikelyChromiumUserAgent(ua string) bool {
	v := strings.ToLower(strings.TrimSpace(ua))
	return strings.Contains(v, "chrome/") || strings.Contains(v, "chromium/") || strings.Contains(v, "edg/")
}

func isLikelyMobileUserAgent(ua string) bool {
	v := strings.ToLower(strings.TrimSpace(ua))
	return strings.Contains(v, " mobile ") ||
		strings.Contains(v, "iphone") ||
		strings.Contains(v, "ipad") ||
		strings.Contains(v, "android") ||
		strings.Contains(v, "mobile safari")
}

func isLikelyHTMLNavigation(r *http.Request) bool {
	if r == nil || r.Method != http.MethodGet {
		return false
	}
	accept := strings.ToLower(strings.TrimSpace(r.Header.Get("Accept")))
	return strings.Contains(accept, "text/html")
}

func allowsInlineScript(csp string) bool {
	if strings.TrimSpace(csp) == "" {
		return true
	}
	lower := strings.ToLower(csp)
	if !strings.Contains(lower, "script-src") {
		return true
	}
	return strings.Contains(lower, "'unsafe-inline'")
}

func hasAnyHeaderValue(h http.Header, keys ...string) bool {
	for _, key := range keys {
		if strings.TrimSpace(h.Get(key)) != "" {
			return true
		}
	}
	return false
}

func telemetryComplete(telemetry Telemetry) bool {
	return telemetry.LanguageCount > 0 &&
		telemetry.ScreenWidth > 0 &&
		telemetry.ScreenHeight > 0 &&
		strings.TrimSpace(telemetry.TimeZone) != "" &&
		strings.TrimSpace(telemetry.Platform) != "" &&
		telemetry.HardwareConcurrency > 0
}
