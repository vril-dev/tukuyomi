package handler

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"tukuyomi/internal/observability"
)

const (
	proxyResponseHeaderSanitizeModeAuto   = "auto"
	proxyResponseHeaderSanitizeModeManual = "manual"
	proxyResponseHeaderSanitizeModeOff    = "off"

	proxyResponseHeaderSanitizeSourceURL = "https://owasp.org/www-project-secure-headers/ci/headers_remove.json"
)

// Embedded from the OWASP Secure Headers Project removal catalog.
// Refresh by replacing this vendored file from proxyResponseHeaderSanitizeSourceURL
// and rerunning the handler test suite before commit.
//
//go:embed proxy_response_header_sanitize_owasp_headers_remove.json
var proxyResponseHeaderSanitizeCatalogRaw []byte

type ProxyResponseHeaderSanitizeConfig struct {
	Mode         string   `json:"mode,omitempty"`
	CustomRemove []string `json:"custom_remove,omitempty"`
	CustomKeep   []string `json:"custom_keep,omitempty"`
	DebugLog     bool     `json:"debug_log,omitempty"`
}

type proxyResponseHeaderSanitizeCatalog struct {
	LastUpdateUTC string   `json:"last_update_utc"`
	Headers       []string `json:"headers"`
}

type proxyResponseHeaderSanitizeCatalogData struct {
	LastUpdateUTC string
	Headers       []string
	HeaderSet     map[string]struct{}
}

type proxyResponseHeaderSanitizePolicy struct {
	Mode      string
	DebugLog  bool
	RemoveSet map[string]struct{}
}

type proxyResponseHeaderPolicySurface string

const (
	proxyResponseHeaderPolicySurfaceLive        proxyResponseHeaderPolicySurface = "live_proxy_response"
	proxyResponseHeaderPolicySurfaceCacheStore  proxyResponseHeaderPolicySurface = "cache_store"
	proxyResponseHeaderPolicySurfaceCacheReplay proxyResponseHeaderPolicySurface = "cache_replay"
)

type proxyResponseHeaderProcessingPlan struct {
	FeatureSanitize bool
	HardSafety      bool
}

type proxyResponseHeaderFilterOptions struct {
	ExtraRemove map[string]struct{}
	Request     *http.Request
	Surface     string
}

type proxyResponseHeaderFilterResult struct {
	Header        http.Header
	PolicyRemoved []string
	Changed       bool
}

var (
	proxyResponseHeaderSanitizeCatalogDataValue = mustLoadProxyResponseHeaderSanitizeCatalog()
	proxyResponseCacheRestrictedResponseHeaders = proxyResponseHeaderNameSet(
		"Connection",
		"Proxy-Connection",
		"Keep-Alive",
		"TE",
		"Trailer",
		"Transfer-Encoding",
		"Upgrade",
		"Date",
		"Age",
		"Set-Cookie",
		proxyResponseCacheHeader,
		proxyResponseCacheRequestID,
		"X-WAF-Hit",
		"X-WAF-RuleIDs",
	)
)

func mustLoadProxyResponseHeaderSanitizeCatalog() proxyResponseHeaderSanitizeCatalogData {
	var payload proxyResponseHeaderSanitizeCatalog
	if err := json.Unmarshal(proxyResponseHeaderSanitizeCatalogRaw, &payload); err != nil {
		panic(fmt.Sprintf("decode embedded response header sanitize catalog: %v", err))
	}
	payload.Headers = normalizeProxyResponseHeaderSanitizeNameList(payload.Headers)
	if err := validateProxyResponseHeaderSanitizeNames(payload.Headers, "embedded response header sanitize catalog"); err != nil {
		panic(err.Error())
	}
	return proxyResponseHeaderSanitizeCatalogData{
		LastUpdateUTC: strings.TrimSpace(payload.LastUpdateUTC),
		Headers:       payload.Headers,
		HeaderSet:     proxyResponseHeaderNameSet(payload.Headers...),
	}
}

func normalizeProxyResponseHeaderSanitizeConfig(in ProxyResponseHeaderSanitizeConfig) ProxyResponseHeaderSanitizeConfig {
	out := in
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	if out.Mode == "" {
		out.Mode = proxyResponseHeaderSanitizeModeAuto
	}
	out.CustomRemove = normalizeProxyResponseHeaderSanitizeNameList(out.CustomRemove)
	out.CustomKeep = normalizeProxyResponseHeaderSanitizeNameList(out.CustomKeep)
	return out
}

func normalizeProxyResponseHeaderSanitizeNameList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		next := canonicalProxyResponseHeaderSanitizeName(raw)
		if strings.TrimSpace(raw) == "" {
			next = ""
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func canonicalProxyResponseHeaderSanitizeName(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	return http.CanonicalHeaderKey(value)
}

func validateProxyResponseHeaderSanitizeConfig(cfg ProxyResponseHeaderSanitizeConfig) error {
	switch cfg.Mode {
	case proxyResponseHeaderSanitizeModeAuto, proxyResponseHeaderSanitizeModeManual, proxyResponseHeaderSanitizeModeOff:
	default:
		return fmt.Errorf("response_header_sanitize.mode must be one of auto|manual|off")
	}
	if err := validateProxyResponseHeaderSanitizeNames(cfg.CustomRemove, "response_header_sanitize.custom_remove"); err != nil {
		return err
	}
	if err := validateProxyResponseHeaderSanitizeNames(cfg.CustomKeep, "response_header_sanitize.custom_keep"); err != nil {
		return err
	}
	return nil
}

func validateProxyResponseHeaderSanitizeNames(in []string, field string) error {
	for _, name := range in {
		if name == "" {
			return fmt.Errorf("%s must not contain blank header names", field)
		}
		if !proxyRouteHeaderNamePattern.MatchString(name) {
			return fmt.Errorf("%s contains invalid header name %q", field, name)
		}
	}
	return nil
}

func buildProxyResponseHeaderSanitizePolicy(cfg ProxyResponseHeaderSanitizeConfig) proxyResponseHeaderSanitizePolicy {
	policy := proxyResponseHeaderSanitizePolicy{
		Mode:     cfg.Mode,
		DebugLog: cfg.DebugLog,
	}
	switch cfg.Mode {
	case proxyResponseHeaderSanitizeModeAuto:
		policy.RemoveSet = cloneProxyResponseHeaderNameSet(proxyResponseHeaderSanitizeCatalogDataValue.HeaderSet)
		for _, name := range cfg.CustomKeep {
			delete(policy.RemoveSet, name)
		}
	case proxyResponseHeaderSanitizeModeManual:
		policy.RemoveSet = map[string]struct{}{}
	case proxyResponseHeaderSanitizeModeOff:
		policy.RemoveSet = map[string]struct{}{}
	default:
		return policy
	}
	for _, name := range cfg.CustomRemove {
		policy.RemoveSet[name] = struct{}{}
	}
	if len(policy.RemoveSet) == 0 {
		policy.RemoveSet = nil
	}
	return policy
}

func cloneProxyResponseHeaderNameSet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for name := range in {
		out[name] = struct{}{}
	}
	return out
}

func proxyResponseHeaderNameSet(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name := canonicalProxyResponseHeaderSanitizeName(raw)
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func sanitizeProxyLiveResponseHeaders(res *http.Response) {
	if res == nil {
		return
	}
	cfg := currentProxyConfig()
	plan := planProxyResponseHeaderProcessing(proxyResponseHeaderPolicySurfaceLive, cfg.responseHeaderSanitizePolicy)
	if !plan.NeedsHeaderIteration() {
		return
	}
	filtered := filterProxyResponseHeaders(res.Header, cfg.responseHeaderSanitizePolicy, proxyResponseHeaderFilterOptions{
		Request: res.Request,
		Surface: string(proxyResponseHeaderPolicySurfaceLive),
	})
	res.Header = filtered.Header
}

func sanitizeProxyResponseHeaderMapInPlace(header http.Header, req *http.Request, surface proxyResponseHeaderPolicySurface) {
	if header == nil {
		return
	}
	cfg := currentProxyConfig()
	plan := planProxyResponseHeaderProcessing(surface, cfg.responseHeaderSanitizePolicy)
	if !plan.NeedsHeaderIteration() {
		return
	}
	var extraRemove map[string]struct{}
	if plan.HardSafety {
		extraRemove = proxyResponseCacheRestrictedResponseHeaders
	}
	filtered := filterProxyResponseHeaders(header, cfg.responseHeaderSanitizePolicy, proxyResponseHeaderFilterOptions{
		ExtraRemove: extraRemove,
		Request:     req,
		Surface:     string(surface),
	})
	if !filtered.Changed {
		return
	}
	for key := range header {
		delete(header, key)
	}
	for key, vals := range filtered.Header {
		header[key] = vals
	}
}

func sanitizeProxyCachedResponseHeader(in http.Header, req *http.Request, surface proxyResponseHeaderPolicySurface) http.Header {
	cfg := currentProxyConfig()
	plan := planProxyResponseHeaderProcessing(surface, cfg.responseHeaderSanitizePolicy)
	if !plan.NeedsHeaderIteration() {
		return in
	}
	var extraRemove map[string]struct{}
	if plan.HardSafety {
		extraRemove = proxyResponseCacheRestrictedResponseHeaders
	}
	filtered := filterProxyResponseHeaders(in, cfg.responseHeaderSanitizePolicy, proxyResponseHeaderFilterOptions{
		ExtraRemove: extraRemove,
		Request:     req,
		Surface:     string(surface),
	})
	return filtered.Header
}

func planProxyResponseHeaderProcessing(surface proxyResponseHeaderPolicySurface, policy proxyResponseHeaderSanitizePolicy) proxyResponseHeaderProcessingPlan {
	plan := proxyResponseHeaderProcessingPlan{
		FeatureSanitize: len(policy.RemoveSet) > 0,
	}
	switch surface {
	case proxyResponseHeaderPolicySurfaceCacheStore, proxyResponseHeaderPolicySurfaceCacheReplay:
		plan.HardSafety = true
	}
	return plan
}

func (p proxyResponseHeaderProcessingPlan) NeedsHeaderIteration() bool {
	return p.FeatureSanitize || p.HardSafety
}

func filterProxyResponseHeaders(in http.Header, policy proxyResponseHeaderSanitizePolicy, opts proxyResponseHeaderFilterOptions) proxyResponseHeaderFilterResult {
	if in == nil {
		return proxyResponseHeaderFilterResult{Header: make(http.Header), Changed: true}
	}

	changed := false
	var policyRemoved map[string]struct{}
	for key := range in {
		name := http.CanonicalHeaderKey(key)
		if name != key {
			changed = true
		}
		if _, ok := opts.ExtraRemove[name]; ok {
			changed = true
			continue
		}
		if _, ok := policy.RemoveSet[name]; ok {
			changed = true
			if policyRemoved == nil {
				policyRemoved = make(map[string]struct{}, 1)
			}
			policyRemoved[name] = struct{}{}
			continue
		}
	}

	removed := proxyResponseHeaderSetNames(policyRemoved)
	emitProxyResponseHeaderSanitizeLog(policy, removed, opts.Request, opts.Surface)
	if !changed {
		return proxyResponseHeaderFilterResult{
			Header:        in,
			PolicyRemoved: removed,
		}
	}

	out := make(http.Header, len(in))
	for key, vals := range in {
		name := http.CanonicalHeaderKey(key)
		if _, ok := opts.ExtraRemove[name]; ok {
			continue
		}
		if _, ok := policy.RemoveSet[name]; ok {
			continue
		}
		out[name] = append(out[name], vals...)
	}
	return proxyResponseHeaderFilterResult{
		Header:        out,
		PolicyRemoved: removed,
		Changed:       true,
	}
}

func proxyResponseHeaderSetNames(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for name := range in {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func emitProxyResponseHeaderSanitizeLog(policy proxyResponseHeaderSanitizePolicy, removed []string, req *http.Request, surface string) {
	if !policy.DebugLog || len(removed) == 0 {
		return
	}
	evt := map[string]any{
		"ts":              time.Now().UTC().Format(time.RFC3339Nano),
		"service":         "coraza",
		"level":           "INFO",
		"event":           "proxy_response_header_sanitize",
		"path":            requestPath(req),
		"trace_id":        observability.TraceIDFromContext(requestContext(req)),
		"ip":              requestRemoteIP(req),
		"mode":            policy.Mode,
		"surface":         strings.TrimSpace(surface),
		"removed_headers": removed,
	}
	appendProxyRouteLogFields(evt, req)
	emitJSONLog(evt)
}
