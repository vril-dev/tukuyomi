package handler

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

type testRequestSecurityPlugin struct {
	name    string
	phase   requestSecurityPluginPhase
	enabled bool
	handle  func(*proxyServeContext, *requestSecurityPluginContext) bool
}

func (p testRequestSecurityPlugin) Name() string {
	return p.name
}

func (p testRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
	return p.phase
}

func (p testRequestSecurityPlugin) Enabled() bool {
	return p.enabled
}

func (p testRequestSecurityPlugin) Handle(c *proxyServeContext, ctx *requestSecurityPluginContext) bool {
	if p.handle == nil {
		return true
	}
	return p.handle(c, ctx)
}

func TestNewRequestSecurityPluginsBuiltins(t *testing.T) {
	plugins := newRequestSecurityPlugins()
	if len(plugins) != 3 {
		t.Fatalf("plugin count=%d want=3", len(plugins))
	}
	got := []string{
		plugins[0].Name(),
		plugins[1].Name(),
		plugins[2].Name(),
	}
	want := []string{"ip_reputation", "bot_defense", "semantic"}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("plugin[%d]=%q want=%q", i, got[i], want[i])
		}
		if plugins[i].Phase() != requestSecurityPluginPhasePreWAF {
			t.Fatalf("plugin[%d] phase=%q want=%q", i, plugins[i].Phase(), requestSecurityPluginPhasePreWAF)
		}
	}
}

func TestRunRequestSecurityPluginsStopsOnHandledResponse(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	var order []string
	plugins := []requestSecurityPlugin{
		testRequestSecurityPlugin{
			name:    "first",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "first")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "second",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "second")
				return false
			},
		},
		testRequestSecurityPlugin{
			name:    "third",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "third")
				return true
			},
		},
	}

	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.1", "JP", time.Unix(1, 0))
	if ok := runRequestSecurityPlugins(newProxyServeContextFromGin(c), requestSecurityPluginPhasePreWAF, plugins, ctx); ok {
		t.Fatal("expected plugin chain to stop")
	}
	if len(order) != 2 || order[0] != "first" || order[1] != "second" {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestRunRequestSecurityPluginsSkipsDisabledAndWrongPhase(t *testing.T) {
	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "/demo", nil)

	var order []string
	plugins := []requestSecurityPlugin{
		testRequestSecurityPlugin{
			name:    "disabled",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: false,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "disabled")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "wrong-phase",
			phase:   requestSecurityPluginPhasePostWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "wrong-phase")
				return true
			},
		},
		testRequestSecurityPlugin{
			name:    "active",
			phase:   requestSecurityPluginPhasePreWAF,
			enabled: true,
			handle: func(_ *proxyServeContext, _ *requestSecurityPluginContext) bool {
				order = append(order, "active")
				return true
			},
		},
	}

	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.1", "JP", time.Unix(1, 0))
	if ok := runRequestSecurityPlugins(newProxyServeContextFromGin(c), requestSecurityPluginPhasePreWAF, plugins, ctx); !ok {
		t.Fatal("expected plugin chain to continue")
	}
	if len(order) != 1 || order[0] != "active" {
		t.Fatalf("unexpected order: %#v", order)
	}
}

func TestRequestSecurityRiskScoreAddsSemanticAndBotSignals(t *testing.T) {
	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.1", "JP", time.Unix(1, 0))
	ctx.Semantic.Score = 6
	ctx.BotSuspicionScore = 4

	if got := requestSecurityRiskScore(ctx); got != 10 {
		t.Fatalf("requestSecurityRiskScore()=%d want=10", got)
	}
}

func TestBotDefenseRequestSecurityPlugin_DryRunDoesNotAbort(t *testing.T) {
	raw := `{
  "enabled": true,
  "dry_run": true,
  "mode": "suspicious",
  "path_prefixes": ["/"],
  "header_signals": {
    "enabled": true,
    "require_accept_language": true,
    "require_fetch_metadata": true,
    "require_client_hints": true,
    "require_upgrade_insecure_requests": true,
    "score_threshold": 2,
    "risk_score_per_signal": 2
  }
}`
	rt, err := ValidateBotDefenseRaw(raw)
	if err != nil {
		t.Fatalf("ValidateBotDefenseRaw() unexpected error: %v", err)
	}

	restore := saveBotDefenseStateForTest()
	defer restore()
	resetBotDefenseDecisionHistory()
	t.Cleanup(resetBotDefenseDecisionHistory)
	botDefenseMu.Lock()
	botDefenseRuntime = rt
	botDefenseMu.Unlock()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	c.Request.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/123.0.0.0 Safari/537.36")
	c.Request.Header.Set("Accept", "text/html,application/xhtml+xml")

	ctx := newRequestSecurityPluginContext("req-1", "10.0.0.30", "JP", time.Unix(1700004300, 0))
	p := newBotDefenseRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); !ok {
		t.Fatal("dry-run plugin should allow request to continue")
	}
	if got := rec.Header().Get("X-Tukuyomi-Bot-Dry-Run"); got != botDefenseActionChallenge {
		t.Fatalf("X-Tukuyomi-Bot-Dry-Run=%q want=%q", got, botDefenseActionChallenge)
	}
	items := recentBotDefenseDecisions(1)
	if len(items) != 1 || !items[0].DryRun {
		t.Fatalf("recent bot decisions=%#v want dry-run record", items)
	}
}

func TestSemanticRequestSecurityPlugin_ChallengeLogsEnforcingStatus(t *testing.T) {
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	logPath, restoreLogFile := setRequestSecurityLogFileForTest(t)
	defer restoreLogFile()

	raw := `{
  "enabled": true,
  "mode": "challenge",
  "exempt_path_prefixes": [],
  "log_threshold": 1,
  "challenge_threshold": 2,
  "block_threshold": 10,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+1", nil)
	c.Request.Header.Set("User-Agent", "curl/8.0")
	c.Request.Header.Set("Referer", "https://console.example.test/login")
	c.Request.AddCookie(&http.Cookie{Name: "session", Value: "session-abc-123"})
	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice@example.com"}`))
	c.Request.Header.Set("Authorization", "Bearer header."+tokenPayload+".sig")

	ctx := newRequestSecurityPluginContext("req-sem-challenge", "10.0.0.1", "JP", time.Unix(1700000000, 0))
	p := newSemanticRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); ok {
		t.Fatal("semantic challenge should stop the request")
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusTooManyRequests)
	}

	event := readLastRequestSecurityLogEvent(t, logPath)
	if got := anyToString(event["event"]); got != "semantic_anomaly" {
		t.Fatalf("event=%q want=semantic_anomaly", got)
	}
	if got := intValue(event["status"]); got != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", got, http.StatusTooManyRequests)
	}
	if got := anyToString(event["actor_key"]); got == "" {
		t.Fatalf("actor_key should be present: %#v", event)
	}
	if got := anyToString(event["path_class"]); got != "/" {
		t.Fatalf("path_class=%q want=/", got)
	}
	if got := anyToString(event["surface_class"]); got != "query+headers" {
		t.Fatalf("surface_class=%q want=query+headers", got)
	}
	context, ok := event["semantic_context"].(map[string]any)
	if !ok {
		t.Fatalf("semantic_context missing or invalid: %#v", event["semantic_context"])
	}
	if got := anyToString(context["subject_source"]); got != "bearer_jwt_sub" {
		t.Fatalf("subject_source=%q want=bearer_jwt_sub", got)
	}
	if got := anyToString(context["session_source"]); got != "cookie:session" {
		t.Fatalf("session_source=%q want=cookie:session", got)
	}
	fingerprints, ok := event["semantic_fingerprints"].(map[string]any)
	if !ok {
		t.Fatalf("semantic_fingerprints missing or invalid: %#v", event["semantic_fingerprints"])
	}
	if got := anyToString(fingerprints["query_hash"]); got == "" {
		t.Fatalf("query_hash should be present: %#v", fingerprints)
	}
	if got := anyToString(fingerprints["header_hash"]); got == "" {
		t.Fatalf("header_hash should be present: %#v", fingerprints)
	}
	buckets, ok := event["semantic_feature_buckets"].([]any)
	if !ok || len(buckets) == 0 {
		t.Fatalf("semantic_feature_buckets missing or invalid: %#v", event["semantic_feature_buckets"])
	}
}

func TestSemanticRequestSecurityPlugin_BlockLogsEnforcingStatus(t *testing.T) {
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	logPath, restoreLogFile := setRequestSecurityLogFileForTest(t)
	defer restoreLogFile()

	raw := `{
  "enabled": true,
  "mode": "block",
  "exempt_path_prefixes": [],
  "log_threshold": 1,
  "challenge_threshold": 2,
  "block_threshold": 3,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+password+from+users", nil)
	c.Request.Header.Set("User-Agent", "Mozilla/5.0")

	ctx := newRequestSecurityPluginContext("req-sem-block", "10.0.0.2", "JP", time.Unix(1700000001, 0))
	p := newSemanticRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); ok {
		t.Fatal("semantic block should stop the request")
	}
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusForbidden)
	}

	event := readLastRequestSecurityLogEvent(t, logPath)
	if got := anyToString(event["event"]); got != "semantic_anomaly" {
		t.Fatalf("event=%q want=semantic_anomaly", got)
	}
	if got := intValue(event["status"]); got != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", got, http.StatusForbidden)
	}
}

func TestSemanticRequestSecurityPlugin_LogOnlyOmitsStatus(t *testing.T) {
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	logPath, restoreLogFile := setRequestSecurityLogFileForTest(t)
	defer restoreLogFile()

	raw := `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": [],
  "log_threshold": 1,
  "challenge_threshold": 3,
  "block_threshold": 6,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+1", nil)
	c.Request.Header.Set("User-Agent", "curl/8.0")

	ctx := newRequestSecurityPluginContext("req-sem-log", "10.0.0.3", "JP", time.Unix(1700000002, 0))
	p := newSemanticRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); !ok {
		t.Fatal("semantic log_only should allow request to continue")
	}

	event := readLastRequestSecurityLogEvent(t, logPath)
	if got := anyToString(event["event"]); got != "semantic_anomaly" {
		t.Fatalf("event=%q want=semantic_anomaly", got)
	}
	if _, ok := event["status"]; ok {
		t.Fatalf("status should be omitted for log_only event: %#v", event)
	}
}

func TestSemanticRequestSecurityPlugin_LogsProviderContributionSeparately(t *testing.T) {
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	logPath, restoreLogFile := setRequestSecurityLogFileForTest(t)
	defer restoreLogFile()

	raw := `{
  "enabled": true,
  "mode": "challenge",
  "provider": {
    "enabled": true,
    "name": "builtin_attack_family",
    "timeout_ms": 25
  },
  "exempt_path_prefixes": [],
  "log_threshold": 5,
  "challenge_threshold": 5,
  "block_threshold": 9,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/login?q=union+select+1", nil)
	c.Request.Header.Set("User-Agent", "curl/8.0")

	ctx := newRequestSecurityPluginContext("req-sem-provider", "10.0.0.6", "JP", time.Unix(1700000003, 0))
	p := newSemanticRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); ok {
		t.Fatal("semantic provider-backed challenge should stop the request")
	}

	event := readLastRequestSecurityLogEvent(t, logPath)
	if got := intValue(event["provider_score"]); got <= 0 {
		t.Fatalf("provider_score=%d want>0", got)
	}
	if got := anyToString(event["provider_name"]); got != semanticProviderNameBuiltinAttackFamily {
		t.Fatalf("provider_name=%q want=%q", got, semanticProviderNameBuiltinAttackFamily)
	}
	if got := anyToString(event["provider_attack_family"]); got != "sql_injection" {
		t.Fatalf("provider_attack_family=%q want=sql_injection", got)
	}
	if got := anyToString(event["provider_confidence"]); got == "" {
		t.Fatalf("provider_confidence should be present: %#v", event)
	}
	reasons, ok := event["provider_reason_list"].([]any)
	if !ok || len(reasons) == 0 {
		t.Fatalf("provider_reason_list missing or invalid: %#v", event["provider_reason_list"])
	}
	foundFamilyReason := false
	for _, reason := range reasons {
		if anyToString(reason) == "provider:attack_family:sql_injection" {
			foundFamilyReason = true
			break
		}
	}
	if !foundFamilyReason {
		t.Fatalf("provider_reason_list=%#v want provider:attack_family:sql_injection", reasons)
	}
	breakdown, ok := event["provider_score_breakdown"].([]any)
	if !ok || len(breakdown) == 0 {
		t.Fatalf("provider_score_breakdown missing or invalid: %#v", event["provider_score_breakdown"])
	}
}

func TestSemanticRequestSecurityPlugin_LogsStatefulContributionSeparately(t *testing.T) {
	restoreSemantic := saveSemanticStateForTest()
	defer restoreSemantic()
	logPath, restoreLogFile := setRequestSecurityLogFileForTest(t)
	defer restoreLogFile()

	raw := `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": [],
  "log_threshold": 2,
  "challenge_threshold": 6,
  "block_threshold": 9,
  "max_inspect_body": 16384,
  "temporal_window_seconds": 30,
  "temporal_max_entries_per_ip": 32,
  "temporal_burst_threshold": 100,
  "temporal_burst_score": 2,
  "temporal_path_fanout_threshold": 100,
  "temporal_path_fanout_score": 2,
  "temporal_ua_churn_threshold": 100,
  "temporal_ua_churn_score": 1
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	now := time.Unix(1700000400, 0)
	for i := range 2 {
		req := httptest.NewRequest(http.MethodGet, "http://example.test/search?q=union+select+password+from+users", nil)
		req.Header.Set("User-Agent", "curl/8.0")
		req.AddCookie(&http.Cookie{Name: "session", Value: "stateful-session"})
		_ = EvaluateSemanticWithRequestID(req, "10.0.0.5", "req-stateful-pre", now.Add(time.Duration(i)*time.Second))
	}

	gin.SetMode(gin.TestMode)
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	c.Request = httptest.NewRequest(http.MethodGet, "http://example.test/admin/settings", nil)
	c.Request.Header.Set("User-Agent", "curl/8.0")
	c.Request.AddCookie(&http.Cookie{Name: "session", Value: "stateful-session"})

	ctx := newRequestSecurityPluginContext("req-sem-stateful", "10.0.0.5", "JP", now.Add(3*time.Second))
	p := newSemanticRequestSecurityPlugin()
	if ok := p.Handle(newProxyServeContextFromGin(c), ctx); !ok {
		t.Fatal("stateful log_only should allow request to continue")
	}

	event := readLastRequestSecurityLogEvent(t, logPath)
	if got := anyToString(event["event"]); got != "semantic_anomaly" {
		t.Fatalf("event=%q want=semantic_anomaly", got)
	}
	if got := intValue(event["base_score"]); got != 0 {
		t.Fatalf("base_score=%d want=0", got)
	}
	if got := intValue(event["stateful_score"]); got < statefulAdminAfterSuspiciousScore {
		t.Fatalf("stateful_score=%d want>=%d", got, statefulAdminAfterSuspiciousScore)
	}
	reasons, ok := event["stateful_reason_list"].([]any)
	if !ok || len(reasons) == 0 {
		t.Fatalf("stateful_reason_list missing or invalid: %#v", event["stateful_reason_list"])
	}
	if got := anyToString(event["target_class"]); got != "admin_management" {
		t.Fatalf("target_class=%q want=admin_management", got)
	}
	history, ok := event["semantic_stateful_history"].(map[string]any)
	if !ok {
		t.Fatalf("semantic_stateful_history missing or invalid: %#v", event["semantic_stateful_history"])
	}
	if got := intValue(history["prior_suspicious_requests"]); got != 2 {
		t.Fatalf("prior_suspicious_requests=%d want=2", got)
	}
}

func setRequestSecurityLogFileForTest(t *testing.T) (string, func()) {
	t.Helper()

	oldLogFile := config.LogFile
	logPath := filepath.Join(t.TempDir(), "waf-events.ndjson")
	config.LogFile = logPath

	return logPath, func() {
		config.LogFile = oldLogFile
	}
}

func readLastRequestSecurityLogEvent(t *testing.T, path string) map[string]any {
	t.Helper()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	lines := bytesSplitKeep(raw, '\n')
	if len(lines) == 0 {
		t.Fatal("expected at least one log line")
	}

	var event map[string]any
	last := trimLastNewline(lines[len(lines)-1])
	if err := json.Unmarshal(last, &event); err != nil {
		t.Fatalf("decode log event: %v", err)
	}
	return event
}
