package handler

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

func evaluateBotDefenseBrowserSignals(rt *runtimeBotDefenseConfig, r *http.Request, hasValidChallengeCookie bool) (int, []string) {
	if rt == nil || !rt.BrowserSignals.Enabled || r == nil {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	cookie, err := r.Cookie(rt.BrowserSignals.JSCookieName)
	if err != nil {
		if hasValidChallengeCookie {
			signals = append(signals, "js_cookie_missing_after_challenge")
		}
		if len(signals) < rt.BrowserSignals.ScoreThreshold {
			return 0, nil
		}
		return len(signals) * rt.BrowserSignals.RiskScorePerSignal, signals
	}

	telemetry, ok := parseBotDefenseBrowserSignalCookie(cookie.Value)
	if !ok {
		signals = append(signals, "js_cookie_invalid")
		if len(signals) < rt.BrowserSignals.ScoreThreshold {
			return 0, nil
		}
		return len(signals) * rt.BrowserSignals.RiskScorePerSignal, signals
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
	if len(signals) < rt.BrowserSignals.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * rt.BrowserSignals.RiskScorePerSignal, signals
}

func evaluateBotDefenseDeviceSignals(rt *runtimeBotDefenseConfig, r *http.Request) (int, []string) {
	if rt == nil || !rt.DeviceSignals.Enabled || r == nil {
		return 0, nil
	}
	if !looksLikeBrowserRequest(r) {
		return 0, nil
	}
	cookieName := botDefenseTelemetryCookieName(rt)
	if cookieName == "" {
		return 0, nil
	}
	cookie, err := r.Cookie(cookieName)
	if err != nil {
		return 0, nil
	}
	telemetry, ok := parseBotDefenseBrowserSignalCookie(cookie.Value)
	if !ok {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if rt.DeviceSignals.RequireTimeZone && strings.TrimSpace(telemetry.TimeZone) == "" {
		signals = append(signals, "timezone_missing")
	}
	if rt.DeviceSignals.RequirePlatform && strings.TrimSpace(telemetry.Platform) == "" {
		signals = append(signals, "platform_missing")
	}
	if rt.DeviceSignals.RequireHardwareConcurrency && telemetry.HardwareConcurrency <= 0 {
		signals = append(signals, "hardware_concurrency_invalid")
	}
	if rt.DeviceSignals.CheckMobileTouch && isLikelyMobileUserAgent(r.UserAgent()) && telemetry.MaxTouchPoints <= 0 {
		signals = append(signals, "mobile_touch_mismatch")
	}
	if len(signals) < rt.DeviceSignals.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * rt.DeviceSignals.RiskScorePerSignal, signals
}

func evaluateBotDefenseHeaderSignals(rt *runtimeBotDefenseConfig, r *http.Request) (int, []string) {
	if rt == nil || !rt.HeaderSignals.Enabled || r == nil {
		return 0, nil
	}
	if !looksLikeBrowserRequest(r) {
		return 0, nil
	}
	signals := make([]string, 0, 4)
	if rt.HeaderSignals.RequireAcceptLanguage && strings.TrimSpace(r.Header.Get("Accept-Language")) == "" {
		signals = append(signals, "accept_language_missing")
	}
	if rt.HeaderSignals.RequireFetchMetadata && !hasAnyHeaderValue(r.Header, "Sec-Fetch-Site", "Sec-Fetch-Mode", "Sec-Fetch-Dest") {
		signals = append(signals, "fetch_metadata_missing")
	}
	if rt.HeaderSignals.RequireClientHints && isLikelyChromiumUserAgent(r.UserAgent()) && strings.TrimSpace(r.Header.Get("Sec-CH-UA")) == "" {
		signals = append(signals, "client_hints_missing")
	}
	if rt.HeaderSignals.RequireUpgradeInsecure && isLikelyHTMLNavigation(r) && strings.TrimSpace(r.Header.Get("Upgrade-Insecure-Requests")) == "" {
		signals = append(signals, "upgrade_insecure_requests_missing")
	}
	if len(signals) < rt.HeaderSignals.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * rt.HeaderSignals.RiskScorePerSignal, signals
}

func evaluateBotDefenseTLSSignals(rt *runtimeBotDefenseConfig, r *http.Request) (int, []string) {
	if rt == nil || !rt.TLSSignals.Enabled || r == nil || r.TLS == nil {
		return 0, nil
	}
	if !looksLikeBrowserRequest(r) {
		return 0, nil
	}
	signals := make([]string, 0, 3)
	if rt.TLSSignals.RequireSNI && strings.TrimSpace(r.TLS.ServerName) == "" {
		signals = append(signals, "tls_sni_missing")
	}
	if rt.TLSSignals.RequireALPN && strings.TrimSpace(r.TLS.NegotiatedProtocol) == "" {
		signals = append(signals, "tls_alpn_missing")
	}
	if rt.TLSSignals.RequireModernTLS && r.TLS.Version > 0 && r.TLS.Version < tls.VersionTLS12 {
		signals = append(signals, "tls_legacy_version")
	}
	if len(signals) < rt.TLSSignals.ScoreThreshold {
		return 0, nil
	}
	return len(signals) * rt.TLSSignals.RiskScorePerSignal, signals
}

func parseBotDefenseBrowserSignalCookie(raw string) (botDefenseBrowserSignalCookie, bool) {
	decoded, err := url.QueryUnescape(strings.TrimSpace(raw))
	if err != nil {
		return botDefenseBrowserSignalCookie{}, false
	}
	var telemetry botDefenseBrowserSignalCookie
	if err := json.Unmarshal([]byte(decoded), &telemetry); err != nil {
		return botDefenseBrowserSignalCookie{}, false
	}
	return telemetry, true
}

func botDefenseTelemetryCookieName(rt *runtimeBotDefenseConfig) string {
	if rt == nil {
		return ""
	}
	return strings.TrimSpace(rt.BrowserSignals.JSCookieName)
}

func looksLikeBrowserRequest(r *http.Request) bool {
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

func canInjectBotDefenseTelemetry(rt *runtimeBotDefenseConfig, req *http.Request, res *http.Response) bool {
	if rt == nil || !rt.Raw.Enabled || !rt.DeviceSignals.Enabled || !rt.DeviceSignals.InvisibleHTMLInjection {
		return false
	}
	if req == nil || res == nil || res.Body == nil {
		return false
	}
	if req.Method != http.MethodGet || !looksLikeBrowserRequest(req) || !isLikelyHTMLNavigation(req) {
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
	cookieName := botDefenseTelemetryCookieName(rt)
	if cookieName == "" {
		return false
	}
	if cookie, err := req.Cookie(cookieName); err == nil {
		if telemetry, ok := parseBotDefenseBrowserSignalCookie(cookie.Value); ok {
			if telemetry.LanguageCount > 0 &&
				telemetry.ScreenWidth > 0 &&
				telemetry.ScreenHeight > 0 &&
				strings.TrimSpace(telemetry.TimeZone) != "" &&
				strings.TrimSpace(telemetry.Platform) != "" &&
				telemetry.HardwareConcurrency > 0 {
				return false
			}
		}
	}
	return true
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

func acceptsHTML(rawAccept string) bool {
	v := strings.ToLower(strings.TrimSpace(rawAccept))
	if v == "" {
		return false
	}
	return strings.Contains(v, "text/html") || strings.Contains(v, "*/*")
}
