package handler

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
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
	if res.Header != nil {
		if config.ForwardInternalResponseHeaders {
			res.Header.Set("X-WAF-Hit", "1")
			if ruleIDs != "" {
				res.Header.Set("X-WAF-RuleIDs", ruleIDs)
			}
		}
	}

	reqID, _ := ctx.Value(ctxKeyReqID).(string)
	ip, _ := ctx.Value(ctxKeyIP).(string)
	country, _ := ctx.Value(ctxKeyCountry).(string)
	path := res.Request.URL.Path
	status := res.StatusCode
	emitJSONLog(map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"service": "coraza",
		"level":   "INFO",
		"event":   "waf_hit_allow",
		"req_id":  reqID,
		"ip":      ip,
		"country": country,
		"path":    path,
		"rules":   ruleIDs,
		"status":  status,
	})
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
		c.AbortWithStatus(rateDecision.Status)
		return
	}

	reqPath := c.Request.URL.Path
	wafEngine := selectWAFEngine(reqPath)
	if wafEngine == nil {
		log.Printf("[BYPASS][HIT] %s -> skip WAF", reqPath)
		proxy.ServeHTTP(c.Writer, c.Request)
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
		c.AbortWithStatus(it.Status)
		return
	}

	proxy.ServeHTTP(c.Writer, c.Request)
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
	if b, err := json.Marshal(obj); err == nil {
		log.Println(string(b))
	}
	ObserveNotificationLogEvent(obj)
}

func appendEventToFile(obj map[string]any) error {
	path := os.Getenv("WAF_EVENTS_FILE")
	if path == "" {
		path = "/app/logs/coraza/waf-events.ndjson"
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))

	return err
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
