package handler

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/corazawaf/coraza/v3"
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

type ctxKey string

const (
	ctxKeyReqID   ctxKey = "req_id"
	ctxKeyWafHit  ctxKey = "waf_hit"
	ctxKeyWafRule ctxKey = "waf_rules"
	ctxKeyIP      ctxKey = "client_ip"
	ctxKeyCountry ctxKey = "country"
)

var proxy *httputil.ReverseProxy
var proxyInitOnce sync.Once

type proxyStatusRecorder struct {
	gin.ResponseWriter
	proxyErr string
}

func (w *proxyStatusRecorder) markProxyError(err error) {
	if err == nil {
		return
	}
	w.proxyErr = strings.TrimSpace(err.Error())
}

func ensureProxy() {
	proxyInitOnce.Do(func() {
		u, err := url.Parse(config.AppURL)
		if err != nil {
			log.Fatalf("Invalid WAF_APP_URL: %v", err)
		}
		errorResp, err := newProxyErrorResponse(config.ProxyErrorHTMLFile, config.ProxyErrorRedirectURL)
		if err != nil {
			log.Fatalf("Invalid upstream proxy error response config: %v", err)
		}
		proxy = httputil.NewSingleHostReverseProxy(u)
		proxy.ModifyResponse = onProxyResponse
		proxy.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			if rec, ok := w.(*proxyStatusRecorder); ok {
				rec.markProxyError(err)
			}
			emitJSONLog(map[string]any{
				"ts":      time.Now().UTC().Format(time.RFC3339Nano),
				"service": "coraza",
				"level":   "ERROR",
				"event":   "proxy_error",
				"path":    requestPath(r),
				"ip":      requestRemoteIP(r),
				"status":  http.StatusBadGateway,
				"error":   err.Error(),
			})
			errorResp.Write(w, r)
		}
	})
}

func onProxyResponse(res *http.Response) error {
	sanitizeInternalResponseHeaders(res)
	annotateWAFHit(res)
	applyCacheHeaders(res)
	applyResponseCache(res)

	return nil
}

func sanitizeInternalResponseHeaders(res *http.Response) {
	if res == nil || res.Header == nil {
		return
	}

	res.Header.Del("X-WAF-Hit")
	res.Header.Del("X-WAF-RuleIDs")
}

func annotateWAFHit(res *http.Response) {
	if res == nil || res.Request == nil {
		return
	}

	ctx := res.Request.Context()
	if hit, _ := ctx.Value(ctxKeyWafHit).(bool); !hit {
		return
	}
	ruleIDs, _ := ctx.Value(ctxKeyWafRule).(string)
	addCurrentWAFHitHeaders(res.Header, res.Request, true, ruleIDs)
	emitWAFHitAllowEvent(res.Request, res.StatusCode)
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
	if rule, allow := rs.Match(method, path); allow {
		ttl := rule.TTL
		if ttl <= 0 {
			ttl = 600
		}

		h := res.Header
		h.Set("X-Tukuyomi-Cacheable", "1")
		h.Set("X-Accel-Expires", strconv.Itoa(ttl))
		if len(rule.Vary) > 0 {
			h.Set("Vary", strings.Join(rule.Vary, ", "))
		}
	}
}

func ensureRequestID(c *gin.Context) string {
	reqID := trustedRequestID(c)
	if reqID == "" {
		reqID = genReqID()
	}
	c.Request.Header.Set("X-Request-ID", reqID)
	c.Writer.Header().Set("X-Request-ID", reqID)

	return reqID
}

func selectWAFEngine(reqPath string) coraza.WAF {
	wafEngine := waf.GetBaseWAF()
	switch mr := bypassconf.Match(reqPath); mr.Action {
	case bypassconf.ACTION_BYPASS:
		return nil
	case bypassconf.ACTION_RULE:
		log.Printf("[BYPASS][RULE] %s extra=%s", reqPath, mr.ExtraRule)
		ruleWAF, err := waf.GetWAFForExtraRule(mr.ExtraRule)
		if err != nil {
			if config.StrictOverride {
				log.Fatalf("[BYPASS][RULE][STRICT] %v", err)
			}
			log.Printf("[BYPASS][RULE][WARN] %v (fallback=default-rules)", err)
			return wafEngine
		}

		return ruleWAF
	default:
		return wafEngine
	}
}

func setWAFContext(c *gin.Context, reqID, clientIP, country string, wafHit bool, ruleIDs string) {
	ctx := context.WithValue(c.Request.Context(), ctxKeyReqID, reqID)
	ctx = context.WithValue(ctx, ctxKeyIP, clientIP)
	ctx = context.WithValue(ctx, ctxKeyCountry, country)
	ctx = context.WithValue(ctx, ctxKeyWafHit, wafHit)
	ctx = context.WithValue(ctx, ctxKeyWafRule, ruleIDs)
	c.Request = c.Request.WithContext(ctx)
}

func ProxyHandler(c *gin.Context) {
	ensureProxy()
	startedAt := time.Now().UTC()

	reqID := ensureRequestID(c)
	clientIP := requestClientIP(c)
	country := requestCountryCode(c)

	if IsCountryBlocked(country) {
		evt := map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "country_block",
			"req_id":  reqID,
			"ip":      clientIP,
			"country": country,
			"path":    c.Request.URL.Path,
			"status":  http.StatusForbidden,
		}
		emitJSONLog(evt)
		_ = appendEventToFile(evt)
		emitOperationalAccessLogs(operationalLogEntry{
			Timestamp:      time.Now().UTC(),
			RequestID:      reqID,
			IP:             clientIP,
			Country:        country,
			Method:         c.Request.Method,
			Path:           requestPath(c.Request),
			Query:          c.Request.URL.RawQuery,
			UserAgent:      c.Request.UserAgent(),
			Status:         http.StatusForbidden,
			UpstreamStatus: strconv.Itoa(http.StatusForbidden),
			Duration:       time.Since(startedAt),
			Event:          "country_block",
		})
		c.AbortWithStatus(http.StatusForbidden)
		return
	}

	requestSecurityCtx := newRequestSecurityPluginContext(reqID, clientIP, country, time.Now().UTC())
	requestSecurityPlugins := newRequestSecurityPlugins()
	if !runRequestSecurityPlugins(c, requestSecurityPluginPhasePreWAF, requestSecurityPlugins, requestSecurityCtx) {
		return
	}
	semanticEval := requestSecurityCtx.Semantic

	rateDecision := EvaluateRateLimit(c.Request, clientIP, country, semanticEval.Score, time.Now().UTC())
	if !rateDecision.Allowed {
		evt := map[string]any{
			"ts":          time.Now().UTC().Format(time.RFC3339Nano),
			"service":     "coraza",
			"level":       "WARN",
			"event":       "rate_limited",
			"req_id":      reqID,
			"ip":          clientIP,
			"country":     country,
			"path":        c.Request.URL.Path,
			"status":      rateDecision.Status,
			"policy_id":   rateDecision.PolicyID,
			"limit":       rateDecision.Limit,
			"base_limit":  rateDecision.BaseLimit,
			"window_sec":  rateDecision.WindowSeconds,
			"rl_key_hash": rateDecision.Key,
			"key_by":      rateDecision.KeyBy,
			"adaptive":    rateDecision.Adaptive,
			"risk_score":  rateDecision.RiskScore,
		}
		emitJSONLog(evt)
		_ = appendEventToFile(evt)
		c.Header("Retry-After", strconv.Itoa(rateDecision.RetryAfterSeconds))
		emitOperationalAccessLogs(operationalLogEntry{
			Timestamp:      time.Now().UTC(),
			RequestID:      reqID,
			IP:             clientIP,
			Country:        country,
			Method:         c.Request.Method,
			Path:           requestPath(c.Request),
			Query:          c.Request.URL.RawQuery,
			UserAgent:      c.Request.UserAgent(),
			Status:         rateDecision.Status,
			UpstreamStatus: strconv.Itoa(rateDecision.Status),
			Duration:       time.Since(startedAt),
			Event:          "rate_limited",
		})
		c.AbortWithStatus(rateDecision.Status)
		return
	}

	reqPath := c.Request.URL.Path
	wafEngine := selectWAFEngine(reqPath)
	if wafEngine == nil {
		log.Printf("[BYPASS][HIT] %s -> skip WAF", reqPath)
		setWAFContext(c, reqID, clientIP, country, false, "")
		cachePlan := buildResponseCachePlan(c.Request)
		if tryServeCachedResponse(c, cachePlan, reqID, clientIP, country, false, "", startedAt) {
			return
		}
		setResponseCacheContext(c, cachePlan)
		rec := &proxyStatusRecorder{ResponseWriter: c.Writer}
		c.Writer = rec
		proxy.ServeHTTP(rec, c.Request)
		emitOperationalAccessLogs(operationalLogEntry{
			Timestamp:      time.Now().UTC(),
			RequestID:      reqID,
			IP:             clientIP,
			Country:        country,
			Method:         c.Request.Method,
			Path:           requestPath(c.Request),
			Query:          c.Request.URL.RawQuery,
			UserAgent:      c.Request.UserAgent(),
			Status:         recorderStatus(rec),
			UpstreamStatus: recorderUpstreamStatus(rec),
			Duration:       time.Since(startedAt),
			Event:          recorderEvent(rec, false),
			Error:          rec.proxyErr,
		})
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
		// Rule().ID() on v3; fallback to mr.RuleID if your type differs
		if matched.Rule() != nil {
			ruleIDs = append(ruleIDs, strconv.Itoa(matched.Rule().ID()))
		}
	}

	setWAFContext(c, reqID, clientIP, country, wafHit, strings.Join(unique(ruleIDs), ","))

	if it := tx.Interruption(); it != nil {
		evt := map[string]any{
			"ts":      time.Now().UTC().Format(time.RFC3339Nano),
			"service": "coraza",
			"level":   "WARN",
			"event":   "waf_block",
			"req_id":  reqID, "ip": clientIP, "country": country, "path": c.Request.URL.Path,
			"rule_id": it.RuleID, "status": it.Status,
		}
		emitJSONLog(evt)
		_ = appendEventToFile(evt)
		emitOperationalAccessLogs(operationalLogEntry{
			Timestamp:      time.Now().UTC(),
			RequestID:      reqID,
			IP:             clientIP,
			Country:        country,
			Method:         c.Request.Method,
			Path:           requestPath(c.Request),
			Query:          c.Request.URL.RawQuery,
			UserAgent:      c.Request.UserAgent(),
			Status:         it.Status,
			UpstreamStatus: strconv.Itoa(it.Status),
			Duration:       time.Since(startedAt),
			WAFHit:         wafHit,
			WAFRules:       strings.Join(unique(ruleIDs), ","),
			Event:          "waf_block",
		})
		c.AbortWithStatus(it.Status)
		return
	}

	cachePlan := buildResponseCachePlan(c.Request)
	if tryServeCachedResponse(c, cachePlan, reqID, clientIP, country, wafHit, strings.Join(unique(ruleIDs), ","), startedAt) {
		return
	}
	setResponseCacheContext(c, cachePlan)

	rec := &proxyStatusRecorder{ResponseWriter: c.Writer}
	c.Writer = rec
	proxy.ServeHTTP(rec, c.Request)
	emitOperationalAccessLogs(operationalLogEntry{
		Timestamp:      time.Now().UTC(),
		RequestID:      reqID,
		IP:             clientIP,
		Country:        country,
		Method:         c.Request.Method,
		Path:           requestPath(c.Request),
		Query:          c.Request.URL.RawQuery,
		UserAgent:      c.Request.UserAgent(),
		Status:         recorderStatus(rec),
		UpstreamStatus: recorderUpstreamStatus(rec),
		Duration:       time.Since(startedAt),
		WAFHit:         wafHit,
		WAFRules:       strings.Join(unique(ruleIDs), ","),
		Event:          recorderEvent(rec, wafHit),
		Error:          rec.proxyErr,
	})
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

func recorderStatus(rec *proxyStatusRecorder) int {
	if rec == nil {
		return http.StatusOK
	}
	if status := rec.Status(); status > 0 {
		return status
	}
	return http.StatusOK
}

func recorderUpstreamStatus(rec *proxyStatusRecorder) string {
	if rec == nil || strings.TrimSpace(rec.proxyErr) != "" {
		return ""
	}
	return strconv.Itoa(recorderStatus(rec))
}

func recorderEvent(rec *proxyStatusRecorder, wafHit bool) string {
	if rec != nil && strings.TrimSpace(rec.proxyErr) != "" {
		return "proxy_error"
	}
	if wafHit {
		return "waf_hit_allow"
	}
	return "response"
}

func addCurrentWAFHitHeaders(h http.Header, req *http.Request, wafHit bool, ruleIDs string) {
	if !wafHit || h == nil || req == nil || !config.ForwardInternalResponseHeaders {
		return
	}

	h.Set("X-WAF-Hit", "1")
	if ruleIDs != "" {
		h.Set("X-WAF-RuleIDs", ruleIDs)
	}
}

func emitWAFHitAllowEvent(req *http.Request, status int) {
	if req == nil {
		return
	}

	ctx := req.Context()
	reqID, _ := ctx.Value(ctxKeyReqID).(string)
	ip, _ := ctx.Value(ctxKeyIP).(string)
	country, _ := ctx.Value(ctxKeyCountry).(string)
	ruleIDs, _ := ctx.Value(ctxKeyWafRule).(string)
	emitJSONLog(map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"service": "coraza",
		"level":   "INFO",
		"event":   "waf_hit_allow",
		"req_id":  reqID,
		"ip":      ip,
		"country": country,
		"path":    req.URL.Path,
		"rules":   ruleIDs,
		"status":  status,
	})
}
