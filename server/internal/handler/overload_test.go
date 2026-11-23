package handler

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/config"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/overloadstate"
)

func TestStatusHandlerIncludesOverloadState(t *testing.T) {
	restore := saveOverloadConfig()
	defer restore()
	defer overloadstate.SetProvider(nil)

	config.ServerMaxConcurrentReqs = 32
	config.ServerMaxQueuedReqs = 0
	config.ServerQueuedRequestTimeout = 0
	config.ServerMaxConcurrentProxy = 24
	config.ServerMaxQueuedProxy = 32
	config.ServerQueuedProxyRequestTimeout = 100 * time.Millisecond

	overloadstate.SetProvider(func() map[string]middleware.ConcurrencyGuardSnapshot {
		return map[string]middleware.ConcurrencyGuardSnapshot{
			"global": {
				Name:                   "global",
				Enabled:                true,
				Limit:                  32,
				QueueEnabled:           false,
				QueueCapacity:          0,
				QueueTimeoutMS:         0,
				AdmittedImmediateTotal: 40,
			},
			"proxy": {
				Name:                      "proxy",
				Enabled:                   true,
				Limit:                     24,
				InFlight:                  24,
				QueueEnabled:              true,
				QueueCapacity:             32,
				QueueCurrent:              3,
				QueuePeak:                 5,
				QueueTimeoutMS:            100,
				AdmittedImmediateTotal:    100,
				AdmittedQueuedTotal:       12,
				QueueEnteredTotal:         12,
				RejectedQueueFullTotal:    2,
				RejectedQueueTimeoutTotal: 1,
				QueueWaitTotalMS:          480,
				LastQueueWaitMS:           40,
			},
		}
	})

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	StatusHandler(ctx)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusOK)
	}

	var body map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("json.Unmarshal: %v", err)
	}

	if got := int(body["server_max_queued_proxy_requests"].(float64)); got != 32 {
		t.Fatalf("server_max_queued_proxy_requests=%d want=32", got)
	}
	if got := body["app_version"]; got != "" {
		t.Fatalf("app_version=%#v want empty", got)
	}
	if got := body["runtime_process_model"]; got != config.RuntimeProcessModel {
		t.Fatalf("runtime_process_model=%#v want %q", got, config.RuntimeProcessModel)
	}
	if got := int(body["server_queued_proxy_request_timeout_ms"].(float64)); got != 100 {
		t.Fatalf("server_queued_proxy_request_timeout_ms=%d want=100", got)
	}
	global, ok := body["server_overload_global"].(map[string]any)
	if !ok {
		t.Fatalf("server_overload_global=%#v", body["server_overload_global"])
	}
	if got := global["queue_enabled"].(bool); got {
		t.Fatalf("global queue_enabled=%v want=false", got)
	}
	proxy, ok := body["server_overload_proxy"].(map[string]any)
	if !ok {
		t.Fatalf("server_overload_proxy=%#v", body["server_overload_proxy"])
	}
	if got := int(proxy["queue_current"].(float64)); got != 3 {
		t.Fatalf("proxy queue_current=%d want=3", got)
	}
	if got := int(proxy["rejected_queue_full_total"].(float64)); got != 2 {
		t.Fatalf("proxy rejected_queue_full_total=%d want=2", got)
	}
	capabilities, ok := body["waf_engine_modes"].([]any)
	if !ok || len(capabilities) != 2 {
		t.Fatalf("waf_engine_modes=%#v", body["waf_engine_modes"])
	}
	coraza, ok := capabilities[0].(map[string]any)
	if !ok || coraza["mode"] != config.WAFEngineModeCoraza || coraza["available"] != true {
		t.Fatalf("unexpected coraza capability: %#v", capabilities[0])
	}
	modSecurity, ok := capabilities[1].(map[string]any)
	if !ok || modSecurity["mode"] != "mod_security" || modSecurity["available"] != false {
		t.Fatalf("unexpected mod_security capability: %#v", capabilities[1])
	}
}

func TestMetricsHandlerIncludesOverloadMetrics(t *testing.T) {
	defer overloadstate.SetProvider(nil)

	overloadstate.SetProvider(func() map[string]middleware.ConcurrencyGuardSnapshot {
		return map[string]middleware.ConcurrencyGuardSnapshot{
			"global": {
				Name:                   "global",
				Enabled:                true,
				Limit:                  32,
				InFlight:               4,
				AdmittedImmediateTotal: 44,
			},
			"proxy": {
				Name:                      "proxy",
				Enabled:                   true,
				Limit:                     24,
				InFlight:                  24,
				QueueEnabled:              true,
				QueueCapacity:             32,
				QueueCurrent:              2,
				QueuePeak:                 5,
				QueueTimeoutMS:            100,
				AdmittedImmediateTotal:    100,
				AdmittedQueuedTotal:       11,
				QueueEnteredTotal:         13,
				RejectedQueueFullTotal:    2,
				RejectedQueueTimeoutTotal: 3,
				QueueWaitTotalMS:          512,
				QueueWaitMaxMS:            96,
				LastQueueWaitMS:           41,
			},
		}
	})

	rec := httptest.NewRecorder()
	ctx, _ := gin.CreateTestContext(rec)
	MetricsHandler(ctx)

	body := rec.Body.String()
	for _, needle := range []string{
		`tukuyomi_overload_queue_current{scope="proxy"} 2`,
		`tukuyomi_overload_admitted_total{mode="queued",scope="proxy"} 11`,
		`tukuyomi_overload_rejected_total{reason="queue_timeout",scope="proxy"} 3`,
		`tukuyomi_overload_queue_wait_total_ms{scope="proxy"} 512`,
		`tukuyomi_overload_guard_enabled{scope="global"} 1`,
	} {
		if !strings.Contains(body, needle) {
			t.Fatalf("missing metrics line %q in body:\n%s", needle, body)
		}
	}
}

func saveOverloadConfig() func() {
	oldServerMaxConcurrentReqs := config.ServerMaxConcurrentReqs
	oldServerMaxQueuedReqs := config.ServerMaxQueuedReqs
	oldServerQueuedRequestTimeout := config.ServerQueuedRequestTimeout
	oldServerMaxConcurrentProxy := config.ServerMaxConcurrentProxy
	oldServerMaxQueuedProxy := config.ServerMaxQueuedProxy
	oldServerQueuedProxyRequestTimeout := config.ServerQueuedProxyRequestTimeout

	return func() {
		config.ServerMaxConcurrentReqs = oldServerMaxConcurrentReqs
		config.ServerMaxQueuedReqs = oldServerMaxQueuedReqs
		config.ServerQueuedRequestTimeout = oldServerQueuedRequestTimeout
		config.ServerMaxConcurrentProxy = oldServerMaxConcurrentProxy
		config.ServerMaxQueuedProxy = oldServerMaxQueuedProxy
		config.ServerQueuedProxyRequestTimeout = oldServerQueuedProxyRequestTimeout
	}
}

func TestRejectExcessRequestHeadersCountsValuesAndWarnsOncePerMinute(t *testing.T) {
	lastRequestHeaderLimitWarning.Store(0)
	before := requestHeaderLimitRejectedTotal.Load()

	var logs bytes.Buffer
	prevOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOutput)

	newRequest := func(values int) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		for i := 0; i < values; i++ {
			req.Header.Add("X-Repeat", "secret-value")
		}
		return req
	}

	rec := httptest.NewRecorder()
	if RejectExcessRequestHeaders(rec, newRequest(3), RequestHeaderLimits{MaxCount: 3}) {
		t.Fatalf("rejected a request at the limit: status=%d", rec.Code)
	}
	if rec.Code != http.StatusOK || rec.Body.Len() != 0 {
		t.Fatalf("wrote a response for an allowed request: status=%d body=%q", rec.Code, rec.Body.String())
	}
	if RejectExcessRequestHeaders(httptest.NewRecorder(), newRequest(config.DefaultServerMaxHeaderCount), RequestHeaderLimits{}) {
		t.Fatal("limit 0 must mean the default: rejected a request at the default limit")
	}
	if !RejectExcessRequestHeaders(httptest.NewRecorder(), newRequest(config.DefaultServerMaxHeaderCount+1), RequestHeaderLimits{}) {
		t.Fatal("limit 0 must mean the default: allowed a request over the default limit")
	}
	before = requestHeaderLimitRejectedTotal.Load()
	lastRequestHeaderLimitWarning.Store(0)
	logs.Reset()

	// Distinct names and a mix of repeated and distinct names are counted
	// together, value by value.
	distinct := httptest.NewRequest(http.MethodGet, "/", nil)
	mixed := httptest.NewRequest(http.MethodGet, "/", nil)
	for i := 0; i < 4; i++ {
		distinct.Header.Add("X-Field-"+strconv.Itoa(i), "v")
	}
	mixed.Header.Add("X-A", "1")
	mixed.Header.Add("X-A", "2")
	mixed.Header.Add("X-B", "1")
	mixed.Header.Add("X-C", "1")
	for name, req := range map[string]*http.Request{"distinct": distinct, "mixed": mixed} {
		rec := httptest.NewRecorder()
		if !RejectExcessRequestHeaders(rec, req, RequestHeaderLimits{MaxCount: 3}) || rec.Code != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("%s names: allowed 4 header values with limit 3 (status=%d)", name, rec.Code)
		}
	}
	before = requestHeaderLimitRejectedTotal.Load()
	lastRequestHeaderLimitWarning.Store(0)
	logs.Reset()

	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		if !RejectExcessRequestHeaders(rec, newRequest(4), RequestHeaderLimits{MaxCount: 3}) {
			t.Fatal("allowed a request over the limit with one repeated header name")
		}
		if rec.Code != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("status=%d want=%d", rec.Code, http.StatusRequestHeaderFieldsTooLarge)
		}
		var body map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || body["error"] != "request header fields too large" {
			t.Fatalf("body=%q err=%v", rec.Body.String(), err)
		}
	}
	if got := requestHeaderLimitRejectedTotal.Load() - before; got != 3 {
		t.Fatalf("rejected counter grew by %d want 3", got)
	}
	if got := strings.Count(logs.String(), "[PROXY][HEADER_LIMIT][WARN]"); got != 1 {
		t.Fatalf("warnings=%d want 1 logs=%s", got, logs.String())
	}
	if !strings.Contains(logs.String(), "203.0.113.9") || strings.Contains(logs.String(), "secret-value") || strings.Contains(logs.String(), "X-Repeat") {
		t.Fatalf("warning must name the peer and no header names or values: %s", logs.String())
	}
}

func TestRejectExcessRequestHeadersLimitsCookieBytesAndPairs(t *testing.T) {
	lastRequestCookieLimitWarning.Store(0)
	headerBefore := requestHeaderLimitRejectedTotal.Load()
	cookieBefore := requestCookieLimitRejectedTotal.Load()

	var logs bytes.Buffer
	prevOutput := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prevOutput)

	limits := RequestHeaderLimits{MaxCount: 100, MaxCookieBytes: 32, MaxCookiePairs: 3}
	withCookies := func(values ...string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "203.0.113.9:4000"
		for _, value := range values {
			req.Header.Add("Cookie", value)
		}
		return req
	}
	allowed := map[string]*http.Request{
		"bytes at the limit":        withCookies(strings.Repeat("a", 30) + "=1"),
		"pairs at the limit":        withCookies("a=1; b=2; c=3"),
		"empty fragments not pairs": withCookies("a=1;; ; b=2;c=3;"),
		"lines summed at the limit": withCookies("a=1; b=2", "c=3"),
		"no cookie":                 withCookies(),
		"bare names count as pairs": withCookies("a; b; c"),
		"ascii space fragments":     withCookies("a=1; \t ; ;b=2; c=3"),
	}
	for name, req := range allowed {
		rec := httptest.NewRecorder()
		if RejectExcessRequestHeaders(rec, req, limits) {
			t.Fatalf("%s: rejected (status=%d)", name, rec.Code)
		}
	}
	rejected := map[string]*http.Request{
		"bytes over the limit":        withCookies(strings.Repeat("a", 31) + "=1"),
		"pairs over the limit":        withCookies("a=1; b=2; c=3; d=4"),
		"bare names over the limit":   withCookies("a;b;c;d"),
		"lines summed over the pairs": withCookies("a=1; b=2", "c=3", "d=4"),
		"lines summed over the bytes": withCookies(strings.Repeat("a", 20), strings.Repeat("b", 13)),
		// The WAF trims only ASCII control characters and spaces, so these
		// fragments are cookies it inspects and must be counted.
		"no-break space fragments":    withCookies(strings.Repeat("\u00a0;", 4)),
		"ideographic space fragments": withCookies(strings.Repeat("\u3000;", 4)),
		"next-line fragments":         withCookies(strings.Repeat("\u0085;", 4)),
	}
	for name, req := range rejected {
		rec := httptest.NewRecorder()
		if !RejectExcessRequestHeaders(rec, req, limits) || rec.Code != http.StatusRequestHeaderFieldsTooLarge {
			t.Fatalf("%s: allowed (status=%d)", name, rec.Code)
		}
	}
	if got := requestCookieLimitRejectedTotal.Load() - cookieBefore; got != uint64(len(rejected)) {
		t.Fatalf("cookie counter grew by %d want %d", got, len(rejected))
	}
	if got := requestHeaderLimitRejectedTotal.Load() - headerBefore; got != 0 {
		t.Fatalf("header field counter grew by %d for cookie rejections", got)
	}
	if got := strings.Count(logs.String(), "[PROXY][COOKIE_LIMIT][WARN]"); got != 1 {
		t.Fatalf("cookie warnings=%d want 1 logs=%s", got, logs.String())
	}
	if strings.Contains(logs.String(), "aaaa") || strings.Contains(logs.String(), "d=4") {
		t.Fatalf("warning logged cookie data: %s", logs.String())
	}

	// The warning names the setting that was exceeded.
	for _, tc := range []struct {
		req  *http.Request
		want string
	}{
		{req: withCookies(strings.Repeat("a", 40)), want: "server.max_cookie_bytes=32"},
		{req: withCookies("a;b;c;d"), want: "server.max_cookie_pairs=3"},
	} {
		lastRequestCookieLimitWarning.Store(0)
		logs.Reset()
		RejectExcessRequestHeaders(httptest.NewRecorder(), tc.req, limits)
		if !strings.Contains(logs.String(), tc.want) {
			t.Fatalf("warning=%q want it to name %s", logs.String(), tc.want)
		}
	}

	// Zero limits mean the defaults.
	if RejectExcessRequestHeaders(httptest.NewRecorder(), withCookies(strings.Repeat("a", config.DefaultServerMaxCookieBytes-2)+"=1"), RequestHeaderLimits{}) {
		t.Fatal("zero limits: rejected cookie bytes at the default limit")
	}
	if !RejectExcessRequestHeaders(httptest.NewRecorder(), withCookies(strings.Repeat("a", config.DefaultServerMaxCookieBytes-1)+"=1"), RequestHeaderLimits{}) {
		t.Fatal("zero limits: allowed cookie bytes over the default limit")
	}
	pairs := make([]string, 0, config.DefaultServerMaxCookiePairs+1)
	for i := 0; i < config.DefaultServerMaxCookiePairs; i++ {
		pairs = append(pairs, "a")
	}
	if RejectExcessRequestHeaders(httptest.NewRecorder(), withCookies(strings.Join(pairs, ";")), RequestHeaderLimits{}) {
		t.Fatal("zero limits: rejected cookie pairs at the default limit")
	}
	pairs = append(pairs, "a")
	if !RejectExcessRequestHeaders(httptest.NewRecorder(), withCookies(strings.Join(pairs, ";")), RequestHeaderLimits{}) {
		t.Fatal("zero limits: allowed cookie pairs over the default limit")
	}
}
