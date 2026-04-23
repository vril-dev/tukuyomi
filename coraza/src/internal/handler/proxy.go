package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/observability"
	"tukuyomi/internal/waf"
)

type ctxKey string

const (
	ctxKeyReqID            ctxKey = "req_id"
	ctxKeyWafHit           ctxKey = "waf_hit"
	ctxKeyWafRule          ctxKey = "waf_rules"
	ctxKeyIP               ctxKey = "client_ip"
	ctxKeyCountry          ctxKey = "country"
	ctxKeyCountrySource    ctxKey = "country_source"
	ctxKeyRouteClass       ctxKey = "route_classification"
	ctxKeyRouteSelection   ctxKey = "route_transport_selection"
	ctxKeySelectedUpstream ctxKey = "selected_upstream"
	ctxKeyRequestBodyCount ctxKey = "request_body_count"
	ctxKeyProxyState       ctxKey = "proxy_state"
)

type proxyRequestContextState struct {
	RequestID              string
	ClientIP               string
	Country                string
	CountrySource          string
	WAFHit                 bool
	WAFRuleIDs             string
	BodyCounter            *proxyRequestBodyCounter
	RouteClassification    proxyRouteClassification
	HasRouteClassification bool
	RouteSelection         proxyRouteTransportSelection
	HasRouteSelection      bool
	SelectedUpstream       string
}

type proxyRequestBodyCounter struct {
	rc    io.ReadCloser
	bytes int64
}

func (c *proxyRequestBodyCounter) Read(p []byte) (int, error) {
	if c == nil || c.rc == nil {
		return 0, io.EOF
	}
	n, err := c.rc.Read(p)
	c.bytes += int64(n)
	return n, err
}

func (c *proxyRequestBodyCounter) Close() error {
	if c == nil || c.rc == nil {
		return nil
	}
	return c.rc.Close()
}

func attachProxyRequestBodyCounter(req *http.Request) *http.Request {
	if req == nil {
		return nil
	}
	counter := &proxyRequestBodyCounter{}
	if req.Body != nil {
		counter.rc = req.Body
		req.Body = counter
	}
	req, state := ensureProxyRequestContextState(req)
	state.BodyCounter = counter
	return req
}

func proxyRequestBodyBytes(req *http.Request) int64 {
	if req == nil {
		return 0
	}
	if state, ok := proxyRequestContextStateFromContext(req.Context()); ok && state.BodyCounter != nil {
		return state.BodyCounter.bytes
	}
	counter, _ := req.Context().Value(ctxKeyRequestBodyCount).(*proxyRequestBodyCounter)
	if counter == nil {
		return 0
	}
	return counter.bytes
}

func ensureProxyRequestContextState(req *http.Request) (*http.Request, *proxyRequestContextState) {
	if req == nil {
		return nil, nil
	}
	if state, ok := proxyRequestContextStateFromContext(req.Context()); ok {
		return req, state
	}
	state := &proxyRequestContextState{}
	return req.WithContext(context.WithValue(req.Context(), ctxKeyProxyState, state)), state
}

func withNewProxyRequestContextState(ctx context.Context) (context.Context, *proxyRequestContextState) {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		return ctx, state
	}
	state := &proxyRequestContextState{}
	return context.WithValue(ctx, ctxKeyProxyState, state), state
}

func proxyRequestContextStateFromContext(ctx context.Context) (*proxyRequestContextState, bool) {
	if ctx == nil {
		return nil, false
	}
	state, ok := ctx.Value(ctxKeyProxyState).(*proxyRequestContextState)
	return state, ok && state != nil
}

func proxyContextRequestID(ctx context.Context) string {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		if state.RequestID != "" {
			return state.RequestID
		}
	}
	value, _ := ctx.Value(ctxKeyReqID).(string)
	return value
}

func proxyContextClientIP(ctx context.Context) string {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		if state.ClientIP != "" {
			return state.ClientIP
		}
	}
	value, _ := ctx.Value(ctxKeyIP).(string)
	return value
}

func proxyContextCountry(ctx context.Context) string {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		if state.Country != "" {
			return state.Country
		}
	}
	value, _ := ctx.Value(ctxKeyCountry).(string)
	return value
}

func proxyContextCountrySource(ctx context.Context) string {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		if state.CountrySource != "" {
			return state.CountrySource
		}
	}
	value, _ := ctx.Value(ctxKeyCountrySource).(string)
	return value
}

func proxyContextWAFDebug(ctx context.Context) (bool, string) {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		return state.WAFHit, state.WAFRuleIDs
	}
	wafHit, _ := ctx.Value(ctxKeyWafHit).(bool)
	ruleIDs, _ := ctx.Value(ctxKeyWafRule).(string)
	return wafHit, ruleIDs
}

func withProxySelectedUpstream(ctx context.Context, upstream string) context.Context {
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		state.SelectedUpstream = upstream
		return ctx
	}
	return context.WithValue(ctx, ctxKeySelectedUpstream, upstream)
}

func proxyResponseBytes(w http.ResponseWriter) int64 {
	if w == nil {
		return 0
	}
	if sizeWriter, ok := w.(interface{ Size() int }); ok {
		if size := sizeWriter.Size(); size > 0 {
			return int64(size)
		}
	}
	return 0
}

func proxyResponseStatus(w http.ResponseWriter, fallback int) int {
	if w == nil {
		return fallback
	}
	if statusWriter, ok := w.(interface{ Status() int }); ok {
		if status := statusWriter.Status(); status > 0 {
			return status
		}
	}
	return fallback
}

func appendProxyTransferLogFields(evt map[string]any, req *http.Request, w http.ResponseWriter) {
	if evt == nil {
		return
	}
	evt["request_body_bytes"] = proxyRequestBodyBytes(req)
	evt["response_body_bytes"] = proxyResponseBytes(w)
}

func appendProxyRequestContextLogFields(evt map[string]any, req *http.Request) {
	if evt == nil || req == nil {
		return
	}
	ctx := req.Context()
	if state, ok := proxyRequestContextStateFromContext(ctx); ok {
		if state.RequestID != "" {
			evt["req_id"] = state.RequestID
		}
		if state.Country != "" {
			evt["country"] = state.Country
		}
		if state.CountrySource != "" {
			evt["country_source"] = state.CountrySource
		}
		return
	}
	if reqID := proxyContextRequestID(ctx); reqID != "" {
		evt["req_id"] = reqID
	}
	if country := proxyContextCountry(ctx); country != "" {
		evt["country"] = country
	}
	if countrySource := proxyContextCountrySource(ctx); countrySource != "" {
		evt["country_source"] = countrySource
	}
}

func emitProxyAccessLog(req *http.Request, w http.ResponseWriter, reqID, clientIP, country string) {
	if req == nil || w == nil {
		return
	}
	mode := currentProxyAccessLogMode()
	if mode == proxyAccessLogModeOff {
		return
	}
	evt := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"service":  "coraza",
		"level":    "INFO",
		"event":    "proxy_access",
		"req_id":   reqID,
		"trace_id": observability.TraceIDFromContext(req.Context()),
		"ip":       clientIP,
		"country":  country,
		"path":     req.URL.Path,
		"status":   proxyResponseStatus(w, http.StatusOK),
	}
	if mode == proxyAccessLogModeMinimal {
		emitProxyAccessLogEvent(evt)
		return
	}
	appendProxyRouteLogFields(evt, req)
	appendProxyRequestContextLogFields(evt, req)
	appendProxyTransferLogFields(evt, req, w)
	emitProxyAccessLogEvent(evt)
}

func onProxyResponse(res *http.Response) error {
	if err := maybeBufferProxyResponseBody(res); err != nil {
		return err
	}
	if err := maybeInjectBotDefenseTelemetry(res); err != nil {
		return err
	}
	annotateWAFHit(res)
	applyCacheHeaders(res)
	applyRouteResponseHeaders(res)
	applyProxyStickySessionCookie(res)
	if err := maybeCompressProxyResponse(res); err != nil {
		return err
	}
	sanitizeProxyLiveResponseHeaders(res)
	return nil
}

func applyRouteResponseHeaders(res *http.Response) {
	if res == nil || res.Request == nil {
		return
	}
	classification, ok := proxyRouteClassificationFromContext(res.Request.Context())
	if !ok {
		return
	}
	applyProxyRouteHeaders(res.Header, classification.ResponseHeaderOps)
}

func annotateWAFHit(res *http.Response) {
	if res == nil || res.Request == nil {
		return
	}

	ctx := res.Request.Context()
	wafHit, rid := proxyContextWAFDebug(ctx)
	if !wafHit {
		return
	}
	if cfg := currentProxyConfig(); cfg.ExposeWAFDebugHeaders && res.Header != nil {
		res.Header.Set("X-WAF-Hit", "1")
		if rid != "" {
			res.Header.Set("X-WAF-RuleIDs", rid)
		}
	}

	reqID := proxyContextRequestID(ctx)
	ip := proxyContextClientIP(ctx)
	country := proxyContextCountry(ctx)
	path := res.Request.URL.Path
	status := res.StatusCode
	evt := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"service":  "coraza",
		"level":    "INFO",
		"event":    "waf_hit_allow",
		"req_id":   reqID,
		"trace_id": observability.TraceIDFromContext(ctx),
		"ip":       ip,
		"country":  country,
		"path":     path,
		"rules":    rid,
		"status":   status,
	}
	appendProxyRouteLogFields(evt, res.Request)
	emitJSONLog(evt)
}

func applyCacheHeaders(res *http.Response) {
	rs := cacheconf.Get()
	if rs == nil || res == nil || res.Request == nil {
		return
	}

	method := res.Request.Method
	if method != http.MethodGet && method != http.MethodHead {
		return
	}

	path := res.Request.URL.Path
	if rule, allow := rs.Match(res.Request.Host, res.Request.TLS != nil, method, path); allow {
		ttl := rule.TTL
		if ttl <= 0 {
			ttl = 600
		}

		h := res.Header
		h.Set("X-Tukuyomi-Cacheable", "1")
		h.Set("X-Accel-Expires", strconv.Itoa(ttl))
		if vary := proxyEffectiveResponseCacheVary(rule.Vary); len(vary) > 0 {
			h.Set("Vary", strings.Join(vary, ", "))
		}
	}
}

func ensureProxyRequestID(c *proxyServeContext) string {
	if c == nil || c.Request == nil {
		return ""
	}
	reqID := c.Request.Header.Get("X-Request-ID")
	if reqID == "" {
		reqID = genReqID()
		c.Request.Header.Set("X-Request-ID", reqID)
	}
	if c.Writer != nil {
		c.Writer.Header().Set("X-Request-ID", reqID)
	}

	return reqID
}

func selectWAFEngine(reqHost, reqPath string, tls bool) coraza.WAF {
	wafEngine := waf.GetBaseWAF()
	switch mr := bypassconf.Match(reqHost, reqPath, tls); mr.Action {
	case bypassconf.ACTION_BYPASS:
		return nil
	case bypassconf.ACTION_RULE:
		log.Printf("[BYPASS][RULE] host=%s path=%s extra=%s", reqHost, reqPath, mr.ExtraRule)
		ruleWAF, err := waf.GetWAFForExtraRule(mr.ExtraRule)
		if err != nil {
			log.Printf("[BYPASS][RULE][WARN] %v (fallback=default-rules)", err)
			return wafEngine
		}

		return ruleWAF
	default:
		return wafEngine
	}
}

func setWAFContext(c *proxyServeContext, reqID, clientIP, country, countrySource string, wafHit bool, ruleIDs string) {
	if c == nil || c.Request == nil {
		return
	}
	req, state := ensureProxyRequestContextState(c.Request)
	state.RequestID = reqID
	state.ClientIP = clientIP
	state.Country = country
	state.CountrySource = countrySource
	state.WAFHit = wafHit
	state.WAFRuleIDs = ruleIDs
	c.Request = req
}

func attachProxyRouteTransportSelection(c *proxyServeContext, classification proxyRouteClassification, reqID, clientIP, country string) bool {
	if c == nil || c.Request == nil {
		return false
	}
	selection, err := resolveProxyRouteTransportSelection(c.Request, classification, proxyRuntimeHealth())
	if err == nil {
		ctx := withProxyRouteTransportSelection(c.Request.Context(), selection)
		if ctx != c.Request.Context() {
			c.Request = c.Request.WithContext(ctx)
		}
		return true
	}
	currentProxyErrorResponse().Write(c.Writer, c.Request)
	evt := map[string]any{
		"ts":       time.Now().UTC().Format(time.RFC3339Nano),
		"service":  "coraza",
		"level":    "ERROR",
		"event":    "proxy_target_selection_error",
		"req_id":   reqID,
		"trace_id": observability.TraceIDFromContext(c.Request.Context()),
		"ip":       clientIP,
		"country":  country,
		"path":     c.Request.URL.Path,
		"status":   proxyResponseStatus(c.Writer, http.StatusBadGateway),
		"error":    err.Error(),
	}
	appendProxyRouteLogFields(evt, c.Request)
	appendProxyTransferLogFields(evt, c.Request, c.Writer)
	emitJSONLogAndAppendEvent(evt)
	c.Abort()
	return false
}

func ProxyHandler(c *gin.Context) {
	pc := newProxyServeContextFromGin(c)
	serveProxyRequest(pc)
	pc.syncGinContext()
}

func ServeProxyHTTP(w http.ResponseWriter, r *http.Request) {
	serveProxyRequest(newProxyServeContext(w, r))
}

func serveProxyRequest(c *proxyServeContext) {
	if c == nil || c.Writer == nil || c.Request == nil {
		return
	}
	reqID := ensureProxyRequestID(c)
	clientIP := requestClientIPHTTP(c.Request)
	requestMetadataCtx := newRequestMetadataResolverContext(clientIP)
	if err := runRequestMetadataResolvers(c.Request, newRequestMetadataResolvers(), requestMetadataCtx); err != nil {
		c.JSON(http.StatusInternalServerError, map[string]any{"error": err.Error()})
		return
	}
	country := requestMetadataCtx.Country
	countrySource := requestMetadataCtx.CountrySource
	c.Request = attachProxyRequestBodyCounter(c.Request)
	setWAFContext(c, reqID, clientIP, country, countrySource, false, "")
	proxyCfg := currentProxyConfig()
	routeClassification, err := resolveProxyRouteClassificationWithHealth(c.Request, proxyCfg, proxyRuntimeHealth())
	if err != nil {
		currentProxyErrorResponse().Write(c.Writer, c.Request)
		evt := map[string]any{
			"ts":       time.Now().UTC().Format(time.RFC3339Nano),
			"service":  "coraza",
			"level":    "ERROR",
			"event":    "proxy_route_error",
			"req_id":   reqID,
			"trace_id": observability.TraceIDFromContext(c.Request.Context()),
			"ip":       clientIP,
			"country":  country,
			"path":     c.Request.URL.Path,
			"status":   proxyResponseStatus(c.Writer, http.StatusBadGateway),
			"error":    err.Error(),
		}
		appendProxyRouteLogFields(evt, c.Request)
		appendProxyTransferLogFields(evt, c.Request, c.Writer)
		emitJSONLogAndAppendEvent(evt)
		c.Abort()
		return
	}
	if ctx := withProxyRouteClassification(c.Request.Context(), routeClassification); ctx != c.Request.Context() {
		c.Request = c.Request.WithContext(ctx)
	}
	auditTrail := newSecurityAuditTrail(c.Request, reqID, clientIP, country)
	if auditTrail != nil {
		auditTrail.CountrySource = countrySource
	}
	if auditTrail != nil {
		defer auditTrail.FinalizeHTTP(c.Writer)
	}
	proxyServed := false
	defer func() {
		if proxyServed {
			emitProxyAccessLog(c.Request, c.Writer, reqID, clientIP, country)
		}
	}()
	if routeClassification.LogSelection {
		evt := map[string]any{
			"ts":             time.Now().UTC().Format(time.RFC3339Nano),
			"service":        "coraza",
			"level":          "INFO",
			"event":          "proxy_route",
			"req_id":         reqID,
			"trace_id":       observability.TraceIDFromContext(c.Request.Context()),
			"ip":             clientIP,
			"country":        country,
			"country_source": countrySource,
			"path":           c.Request.URL.Path,
		}
		appendProxyRouteLogFields(evt, c.Request)
		emitJSONLogAndAppendEvent(evt)
	}

	if IsCountryBlocked(c.Request.Host, c.Request.TLS != nil, country) {
		if auditTrail != nil {
			auditTrail.recordCountryBlock(http.StatusForbidden, country)
			auditTrail.setTerminal("country_block", "country_block", "blocked", http.StatusForbidden)
		}
		evt := map[string]any{
			"ts":             time.Now().UTC().Format(time.RFC3339Nano),
			"service":        "coraza",
			"level":          "WARN",
			"event":          "country_block",
			"req_id":         reqID,
			"trace_id":       observability.TraceIDFromContext(c.Request.Context()),
			"ip":             clientIP,
			"country":        country,
			"country_source": countrySource,
			"path":           c.Request.URL.Path,
			"status":         http.StatusForbidden,
		}
		appendProxyRouteLogFields(evt, c.Request)
		emitJSONLogAndAppendEvent(evt)
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	requestSecurityCtx := newRequestSecurityPluginContext(reqID, clientIP, country, time.Now().UTC())
	requestSecurityCtx.CountrySource = countrySource
	requestSecurityCtx.RequestHost = c.Request.Host
	requestSecurityCtx.RequestTLS = c.Request.TLS != nil
	requestSecurityCtx.AuditTrail = auditTrail
	requestSecurityPlugins := newRequestSecurityPlugins()
	if !runRequestSecurityPlugins(c, requestSecurityPluginPhasePreWAF, requestSecurityPlugins, requestSecurityCtx) {
		return
	}
	semanticEval := requestSecurityCtx.Semantic
	requestRiskScore := requestSecurityRiskScore(requestSecurityCtx)

	rateDecision := EvaluateRateLimit(c.Request, clientIP, country, requestRiskScore, time.Now().UTC())
	if !rateDecision.Allowed {
		securityEvt := requestSecurityCtx.newSecurityEvent(c.Request, "rate_limit", "rate_limit", requestSecurityEventTypeRateLimited, requestSecurityEventActionBlock)
		securityEvt.Enforced = true
		securityEvt.Status = rateDecision.Status
		securityEvt.RiskScore = rateDecision.RiskScore
		securityEvt.Attributes = map[string]any{
			"policy_id":      rateDecision.PolicyID,
			"host_scope":     rateDecision.HostScope,
			"limit":          rateDecision.Limit,
			"base_limit":     rateDecision.BaseLimit,
			"window_sec":     rateDecision.WindowSeconds,
			"retry_after":    rateDecision.RetryAfterSeconds,
			"rl_key_hash":    rateDecision.Key,
			"key_by":         rateDecision.KeyBy,
			"adaptive":       rateDecision.Adaptive,
			"semantic_score": semanticEval.Score,
			"bot_risk_score": requestSecurityCtx.BotSuspicionScore,
		}
		if len(requestSecurityCtx.BotSuspicionSignals) > 0 {
			securityEvt.Attributes["bot_signals"] = append([]string(nil), requestSecurityCtx.BotSuspicionSignals...)
		}
		requestSecurityCtx.publishSecurityEvent(securityEvt)

		effectiveRateDecision := rateDecision
		responseStatus := rateDecision.Status
		promotedToQuarantine := requestSecurityCtx.RateLimitFeedback.Promoted && !requestSecurityCtx.RateLimitFeedback.DryRun
		if promotedToQuarantine {
			if botRT := currentBotDefenseRuntime(); botRT != nil && botRT.Quarantine.StatusCode > 0 {
				responseStatus = botRT.Quarantine.StatusCode
				effectiveRateDecision.Status = responseStatus
			}
		}
		if auditTrail != nil {
			auditTrail.recordRateLimit(effectiveRateDecision, semanticEval.Score, requestSecurityCtx.BotSuspicionScore, requestSecurityCtx.RateLimitFeedback)
			if promotedToQuarantine {
				auditTrail.setTerminal("rate_limit_feedback", requestSecurityEventTypeRateLimitPromotion, "quarantine", responseStatus)
			} else {
				auditTrail.setTerminal("rate_limit", "rate_limited", "rate_limited", responseStatus)
			}
		}
		evt := map[string]any{
			"ts":             time.Now().UTC().Format(time.RFC3339Nano),
			"service":        "coraza",
			"level":          "WARN",
			"event":          "rate_limited",
			"req_id":         reqID,
			"trace_id":       observability.TraceIDFromContext(c.Request.Context()),
			"ip":             clientIP,
			"country":        country,
			"country_source": countrySource,
			"path":           c.Request.URL.Path,
			"status":         responseStatus,
			"policy_id":      rateDecision.PolicyID,
			"host_scope":     rateDecision.HostScope,
			"limit":          rateDecision.Limit,
			"base_limit":     rateDecision.BaseLimit,
			"window_sec":     rateDecision.WindowSeconds,
			"rl_key_hash":    rateDecision.Key,
			"key_by":         rateDecision.KeyBy,
			"adaptive":       rateDecision.Adaptive,
			"risk_score":     rateDecision.RiskScore,
			"semantic_score": semanticEval.Score,
			"bot_risk_score": requestSecurityCtx.BotSuspicionScore,
		}
		if len(requestSecurityCtx.BotSuspicionSignals) > 0 {
			evt["bot_signals"] = strings.Join(requestSecurityCtx.BotSuspicionSignals, ",")
		}
		if requestSecurityCtx.RateLimitFeedback.Promoted {
			evt["quarantine_promoted"] = true
			evt["quarantine_promotion_dry_run"] = requestSecurityCtx.RateLimitFeedback.DryRun
			evt["quarantine_promotion_strikes"] = requestSecurityCtx.RateLimitFeedback.Strikes
		}
		appendProxyRouteLogFields(evt, c.Request)
		emitJSONLogAndAppendEvent(evt)
		if !promotedToQuarantine {
			c.Header("Retry-After", strconv.Itoa(rateDecision.RetryAfterSeconds))
		}
		c.AbortWithStatus(responseStatus)
		return
	}

	reqPath := c.Request.URL.Path
	wafEngine := selectWAFEngine(c.Request.Host, reqPath, c.Request.TLS != nil)
	if wafEngine == nil {
		if err := maybeBufferProxyRequestBody(c.Request); err != nil {
			c.JSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		if !attachProxyRouteTransportSelection(c, routeClassification, reqID, clientIP, country) {
			return
		}
		proxyServed = true
		ServeProxyWithCacheHTTP(c.Writer, c.Request)
		return
	}

	tx := wafEngine.NewTransaction()
	defer func() {
		tx.ProcessLogging()
		tx.Close()
	}()

	tx.ProcessURI(c.Request.URL.String(), c.Request.Method, c.Request.Proto)
	tx.AddRequestHeader("Host", c.Request.Host)
	if err := tx.ProcessRequestHeaders(); err != nil {
		log.Println("Header error:", err)
	}
	if _, err := tx.ProcessRequestBody(); err != nil {
		log.Println("Body error:", err)
	}

	wafHit := false
	ruleIDs := make([]string, 0, 4)
	for _, matched := range tx.MatchedRules() {
		wafHit = true
		if matched.Rule() != nil {
			ruleIDs = append(ruleIDs, strconv.Itoa(matched.Rule().ID()))
		}
	}

	setWAFContext(c, reqID, clientIP, country, countrySource, wafHit, strings.Join(unique(ruleIDs), ","))

	if it := tx.Interruption(); it != nil {
		primaryMatch, havePrimaryMatch := selectPrimaryWAFMatch(tx.MatchedRules(), it.RuleID)
		securityEvt := requestSecurityCtx.newSecurityEvent(c.Request, "waf", "waf", requestSecurityEventTypeWAFBlock, requestSecurityEventActionBlock)
		securityEvt.Phase = "waf"
		securityEvt.Enforced = true
		securityEvt.Status = it.Status
		securityEvt.Attributes = map[string]any{
			"rule_id":          it.RuleID,
			"matched_rule_ids": unique(ruleIDs),
		}
		if havePrimaryMatch {
			if primaryMatch.Variable != "" {
				securityEvt.Attributes["matched_variable"] = primaryMatch.Variable
			}
			if primaryMatch.Value != "" {
				securityEvt.Attributes["matched_value"] = primaryMatch.Value
			}
		}
		requestSecurityCtx.publishSecurityEvent(securityEvt)
		if auditTrail != nil {
			wafNodeIDs := auditTrail.recordWAFMatches(tx.MatchedRules())
			auditTrail.recordWAFBlock(it.RuleID, it.Status, wafNodeIDs)
			auditTrail.setTerminal("waf", "waf_block", "blocked", it.Status)
		}
		evt := map[string]any{
			"ts":             time.Now().UTC().Format(time.RFC3339Nano),
			"service":        "coraza",
			"level":          "WARN",
			"event":          "waf_block",
			"req_id":         reqID,
			"trace_id":       observability.TraceIDFromContext(c.Request.Context()),
			"ip":             clientIP,
			"country":        country,
			"country_source": countrySource,
			"path":           c.Request.URL.Path,
			"rule_id":        it.RuleID,
			"status":         it.Status,
		}
		if havePrimaryMatch {
			if primaryMatch.Variable != "" {
				evt["matched_variable"] = primaryMatch.Variable
			}
			if primaryMatch.Value != "" {
				evt["matched_value"] = primaryMatch.Value
			}
		}
		appendProxyRouteLogFields(evt, c.Request)
		emitJSONLogAndAppendEvent(evt)
		c.AbortWithStatus(it.Status)
		return
	}

	if err := maybeBufferProxyRequestBody(c.Request); err != nil {
		c.JSON(http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if !attachProxyRouteTransportSelection(c, routeClassification, reqID, clientIP, country) {
		return
	}
	proxyServed = true
	ServeProxyWithCacheHTTP(c.Writer, c.Request)
}

func genReqID() string {
	return fmt.Sprintf("%x", time.Now().UnixNano())
}

func unique(in []string) []string {
	m := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if _, ok := m[s]; !ok && s != "" {
			m[s] = struct{}{}
			out = append(out, s)
		}
	}

	return out
}

func emitJSONLog(obj map[string]any) {
	_, _ = encodeAndEmitJSONLog(obj)
}

func emitJSONLogAndAppendEvent(obj map[string]any) {
	raw, err := encodeAndEmitJSONLog(obj)
	if err != nil {
		return
	}
	_ = appendEncodedEventToFile(raw)
}

func encodeAndEmitJSONLog(obj map[string]any) ([]byte, error) {
	raw, err := json.Marshal(obj)
	if err == nil {
		log.Println(string(raw))
	}
	ObserveNotificationLogEvent(obj)
	return raw, err
}

func proxyRuntimeHealth() *upstreamHealthMonitor {
	rt := proxyRuntimeInstance()
	if rt == nil {
		return nil
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.health
}

func releaseProxyRouteSelection(selection proxyRouteTransportSelection) {
	if selection.HealthKey == "" {
		return
	}
	if health := proxyRuntimeHealth(); health != nil {
		health.ReleaseTarget(selection.HealthKey)
	}
}

func appendEncodedEventToFile(raw []byte) error {
	path := strings.TrimSpace(config.LogFile)
	if path == "" {
		path = "logs/waf/waf-events.ndjson"
	}
	return appendEncodedWAFEvent(raw, path)
}

func appendEncodedEventsToFile(raws [][]byte) error {
	path := strings.TrimSpace(config.LogFile)
	if path == "" {
		path = "logs/waf/waf-events.ndjson"
	}
	return appendEncodedWAFEvents(raws, path)
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func requestRemoteIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	host := strings.TrimSpace(r.RemoteAddr)
	if host == "" {
		return ""
	}
	if idx := strings.LastIndex(host, ":"); idx > 0 {
		return host[:idx]
	}
	return host
}
