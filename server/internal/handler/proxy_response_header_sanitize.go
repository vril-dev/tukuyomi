package handler

import (
	"net/http"
	"strings"
	"time"

	"tukuyomi/internal/observability"
	"tukuyomi/internal/proxyheaders"
)

const (
	proxyResponseHeaderSanitizeModeAuto   = proxyheaders.ModeAuto
	proxyResponseHeaderSanitizeModeManual = proxyheaders.ModeManual
	proxyResponseHeaderSanitizeModeOff    = proxyheaders.ModeOff

	proxyResponseHeaderSanitizeSourceURL = proxyheaders.SourceURL
)

type ProxyResponseHeaderSanitizeConfig = proxyheaders.Config

type proxyResponseHeaderSanitizePolicy = proxyheaders.Policy

type proxyResponseHeaderPolicySurface = proxyheaders.Surface

const (
	proxyResponseHeaderPolicySurfaceLive        proxyResponseHeaderPolicySurface = proxyheaders.SurfaceLive
	proxyResponseHeaderPolicySurfaceCacheStore  proxyResponseHeaderPolicySurface = proxyheaders.SurfaceCacheStore
	proxyResponseHeaderPolicySurfaceCacheReplay proxyResponseHeaderPolicySurface = proxyheaders.SurfaceCacheReplay
)

type proxyResponseHeaderProcessingPlan = proxyheaders.ProcessingPlan

type proxyResponseHeaderFilterOptions = proxyheaders.FilterOptions

type proxyResponseHeaderFilterResult = proxyheaders.FilterResult

var (
	proxyResponseCacheRestrictedResponseHeaders = proxyheaders.NameSet(
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

func normalizeProxyResponseHeaderSanitizeConfig(in ProxyResponseHeaderSanitizeConfig) ProxyResponseHeaderSanitizeConfig {
	return proxyheaders.NormalizeConfig(in)
}

func normalizeProxyResponseHeaderSanitizeNameList(in []string) []string {
	return proxyheaders.NormalizeNameList(in)
}

func canonicalProxyResponseHeaderSanitizeName(raw string) string {
	return proxyheaders.CanonicalName(raw)
}

func validateProxyResponseHeaderSanitizeConfig(cfg ProxyResponseHeaderSanitizeConfig) error {
	return proxyheaders.ValidateConfig(cfg)
}

func validateProxyResponseHeaderSanitizeNames(in []string, field string) error {
	return proxyheaders.ValidateNames(in, field)
}

func buildProxyResponseHeaderSanitizePolicy(cfg ProxyResponseHeaderSanitizeConfig) proxyResponseHeaderSanitizePolicy {
	return proxyheaders.BuildPolicy(cfg)
}

func cloneProxyResponseHeaderNameSet(in map[string]struct{}) map[string]struct{} {
	return proxyheaders.CloneNameSet(in)
}

func proxyResponseHeaderNameSet(names ...string) map[string]struct{} {
	return proxyheaders.NameSet(names...)
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
	return proxyheaders.Plan(surface, policy)
}

func filterProxyResponseHeaders(in http.Header, policy proxyResponseHeaderSanitizePolicy, opts proxyResponseHeaderFilterOptions) proxyResponseHeaderFilterResult {
	if opts.Log == nil {
		opts.Log = func(evt proxyheaders.FilterLog) {
			emitProxyResponseHeaderSanitizeLog(evt.Policy, evt.Removed, evt.Request, evt.Surface)
		}
	}
	return proxyheaders.FilterHeaders(in, policy, opts)
}

func proxyResponseHeaderSetNames(in map[string]struct{}) []string {
	return proxyheaders.SetNames(in)
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
