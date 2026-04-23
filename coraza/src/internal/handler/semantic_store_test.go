package handler

import (
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestValidateSemanticRaw(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "challenge",
  "provider": {
    "enabled": true,
    "name": "builtin_attack_family",
    "timeout_ms": 25
  },
  "exempt_path_prefixes": ["/healthz"],
  "log_threshold": 2,
  "challenge_threshold": 4,
  "block_threshold": 8,
  "max_inspect_body": 8192
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}
	if rt == nil || !rt.Raw.Enabled {
		t.Fatalf("runtime config should be enabled: %#v", rt)
	}
	if rt.Raw.Mode != "challenge" {
		t.Fatalf("mode=%q want=challenge", rt.Raw.Mode)
	}
	if !rt.Raw.Provider.Enabled || rt.Raw.Provider.Name != semanticProviderNameBuiltinAttackFamily {
		t.Fatalf("provider=%#v want enabled builtin", rt.Raw.Provider)
	}
}

func TestValidateSemanticRaw_RejectsUnknownProvider(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "log_only",
  "provider": {
    "enabled": true,
    "name": "unknown",
    "timeout_ms": 25
  },
  "exempt_path_prefixes": [],
  "log_threshold": 2,
  "challenge_threshold": 4,
  "block_threshold": 8,
  "max_inspect_body": 8192
}`
	if _, err := ValidateSemanticRaw(raw); err == nil {
		t.Fatal("expected provider validation error")
	}
}

func TestEvaluateSemantic_BlockAction(t *testing.T) {
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
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+password+from+users", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	eval := EvaluateSemantic(req)
	if eval.Action != semanticActionBlock {
		t.Fatalf("expected block action, got=%+v", eval)
	}
	if eval.Score < 3 {
		t.Fatalf("expected score >= 3, got=%d", eval.Score)
	}
}

func TestEvaluateSemantic_ChallengeCookiePass(t *testing.T) {
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
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	now := time.Unix(1_700_000_000, 0).UTC()
	req1 := httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+1", nil)
	req1.Header.Set("User-Agent", "curl/8.0")
	eval := EvaluateSemantic(req1)
	if eval.Action != semanticActionChallenge {
		t.Fatalf("expected challenge action, got=%+v", eval)
	}
	if HasValidSemanticChallengeCookie(req1, "10.0.0.1", now) {
		t.Fatal("request without cookie should not pass challenge")
	}

	token := issueSemanticChallengeToken(rt.Default, "10.0.0.1", "curl/8.0", now)
	req2 := httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+1", nil)
	req2.Header.Set("User-Agent", "curl/8.0")
	req2.AddCookie(&http.Cookie{Name: rt.Default.challengeCookieName, Value: token})
	if !HasValidSemanticChallengeCookie(req2, "10.0.0.1", now.Add(1*time.Second)) {
		t.Fatal("request with valid cookie should pass challenge")
	}
}

func TestEvaluateSemantic_TemporalPathFanoutBlock(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "block",
  "exempt_path_prefixes": [],
  "log_threshold": 2,
  "challenge_threshold": 2,
  "block_threshold": 2,
  "max_inspect_body": 16384,
  "temporal_window_seconds": 30,
  "temporal_max_entries_per_ip": 32,
  "temporal_burst_threshold": 100,
  "temporal_burst_score": 2,
  "temporal_path_fanout_threshold": 3,
  "temporal_path_fanout_score": 2,
  "temporal_ua_churn_threshold": 100,
  "temporal_ua_churn_score": 1
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	base := time.Unix(1_700_000_000, 0).UTC()
	for _, path := range []string{"/a", "/b"} {
		req := httptest.NewRequest(http.MethodGet, "http://example.test"+path, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0")
		eval := EvaluateSemanticWithContext(req, "10.0.0.1", base)
		if eval.Action != semanticActionNone {
			t.Fatalf("expected no action before threshold, got=%+v", eval)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/c", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	eval := EvaluateSemanticWithContext(req, "10.0.0.1", base.Add(2*time.Second))
	if eval.Action != semanticActionBlock {
		t.Fatalf("expected block action from temporal fanout, got=%+v", eval)
	}
	if !strings.Contains(strings.Join(eval.Reasons, ","), "temporal:ip_path_fanout") {
		t.Fatalf("expected temporal fanout reason, got=%v", eval.Reasons)
	}
}

func TestEvaluateSemanticWithRequestID_UsesHostScopePrecedence(t *testing.T) {
	raw := `{
  "default": {
    "enabled": true,
    "mode": "log_only",
    "exempt_path_prefixes": [],
    "log_threshold": 1,
    "challenge_threshold": 8,
    "block_threshold": 12,
    "max_inspect_body": 16384
  },
  "hosts": {
    "admin.example.com": {
      "mode": "challenge",
      "challenge_threshold": 2,
      "block_threshold": 10
    },
    "admin.example.com:8443": {
      "mode": "block",
      "challenge_threshold": 2,
      "block_threshold": 3
    }
  }
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	restore := saveSemanticStateForTest()
	defer restore()
	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	now := time.Now().UTC()

	reqPort := httptest.NewRequest(http.MethodGet, "https://admin.example.com:8443/?q=union+select+1", nil)
	reqPort.Header.Set("User-Agent", "curl/8.0")
	portEval := EvaluateSemanticWithRequestID(reqPort, "203.0.113.10", "req-sem-port", now)
	if portEval.HostScope != "admin.example.com:8443" || portEval.Action != semanticActionBlock {
		t.Fatalf("port scope mismatch: scope=%q action=%q", portEval.HostScope, portEval.Action)
	}

	reqHost := httptest.NewRequest(http.MethodGet, "https://admin.example.com/?q=union+select+1", nil)
	reqHost.Header.Set("User-Agent", "curl/8.0")
	hostEval := EvaluateSemanticWithRequestID(reqHost, "203.0.113.10", "req-sem-host", now)
	if hostEval.HostScope != "admin.example.com" || hostEval.Action != semanticActionChallenge {
		t.Fatalf("host scope mismatch: scope=%q action=%q", hostEval.HostScope, hostEval.Action)
	}

	reqDefault := httptest.NewRequest(http.MethodGet, "https://www.example.com/?q=union+select+1", nil)
	reqDefault.Header.Set("User-Agent", "curl/8.0")
	defaultEval := EvaluateSemanticWithRequestID(reqDefault, "203.0.113.10", "req-sem-default", now)
	if defaultEval.HostScope != semanticDefaultScope || defaultEval.Action != semanticActionLogOnly {
		t.Fatalf("default scope mismatch: scope=%q action=%q", defaultEval.HostScope, defaultEval.Action)
	}
}

func TestEvaluateSemanticWithContext_IsolatesTemporalRiskByHostScope(t *testing.T) {
	raw := `{
  "default": {
    "enabled": false
  },
  "hosts": {
    "one.example.com": {
      "enabled": true,
      "mode": "block",
      "exempt_path_prefixes": [],
      "log_threshold": 2,
      "challenge_threshold": 2,
      "block_threshold": 2,
      "max_inspect_body": 16384,
      "temporal_window_seconds": 30,
      "temporal_max_entries_per_ip": 32,
      "temporal_burst_threshold": 100,
      "temporal_burst_score": 2,
      "temporal_path_fanout_threshold": 2,
      "temporal_path_fanout_score": 2,
      "temporal_ua_churn_threshold": 100,
      "temporal_ua_churn_score": 1
    },
    "two.example.com": {
      "enabled": true,
      "mode": "block",
      "exempt_path_prefixes": [],
      "log_threshold": 2,
      "challenge_threshold": 2,
      "block_threshold": 2,
      "max_inspect_body": 16384,
      "temporal_window_seconds": 30,
      "temporal_max_entries_per_ip": 32,
      "temporal_burst_threshold": 100,
      "temporal_burst_score": 2,
      "temporal_path_fanout_threshold": 2,
      "temporal_path_fanout_score": 2,
      "temporal_ua_churn_threshold": 100,
      "temporal_ua_churn_score": 1
    }
  }
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	restore := saveSemanticStateForTest()
	defer restore()
	semanticMu.Lock()
	semanticRuntime = rt
	semanticMu.Unlock()

	base := time.Unix(1_700_020_000, 0).UTC()
	clientIP := "203.0.113.20"

	reqOneA := httptest.NewRequest(http.MethodGet, "http://one.example.com/a", nil)
	reqOneA.Header.Set("User-Agent", "Mozilla/5.0")
	first := EvaluateSemanticWithContext(reqOneA, clientIP, base)
	if first.Action != semanticActionNone {
		t.Fatalf("first request should not trigger yet, got=%+v", first)
	}

	reqOneB := httptest.NewRequest(http.MethodGet, "http://one.example.com/b", nil)
	reqOneB.Header.Set("User-Agent", "Mozilla/5.0")
	second := EvaluateSemanticWithContext(reqOneB, clientIP, base.Add(time.Second))
	if second.HostScope != "one.example.com" || second.Action != semanticActionBlock {
		t.Fatalf("host one should block after path fanout: scope=%q action=%q", second.HostScope, second.Action)
	}
	if !slices.Contains(second.Reasons, "temporal:ip_path_fanout") {
		t.Fatalf("expected temporal fanout reason, got=%v", second.Reasons)
	}

	reqTwo := httptest.NewRequest(http.MethodGet, "http://two.example.com/c", nil)
	reqTwo.Header.Set("User-Agent", "Mozilla/5.0")
	otherHost := EvaluateSemanticWithContext(reqTwo, clientIP, base.Add(2*time.Second))
	if otherHost.HostScope != "two.example.com" || otherHost.Action != semanticActionNone {
		t.Fatalf("host two should keep isolated state: scope=%q action=%q", otherHost.HostScope, otherHost.Action)
	}
}

func TestEvaluateSemanticWithRequestID_BuildsTelemetry(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": [],
  "log_threshold": 1,
  "challenge_threshold": 3,
  "block_threshold": 10,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	tokenPayload := base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"alice@example.com"}`))
	req := httptest.NewRequest(
		http.MethodPost,
		"http://example.test/api/v1/users/12345/profile?debug=%3Cscript%3Ealert(1)%3C%2Fscript%3E&utm_source=ads",
		strings.NewReader(`{"note":"UNION SELECT password FROM users","userId":12345}`),
	)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "curl/8.0")
	req.Header.Set("Referer", "https://console.example.test/login")
	req.Header.Set("Authorization", "Bearer header."+tokenPayload+".sig")
	req.AddCookie(&http.Cookie{Name: "session", Value: "session-abc-123"})

	eval := EvaluateSemanticWithRequestID(req, "203.0.113.10", "req-sem-telemetry", time.Unix(1_700_000_100, 0).UTC())
	if eval.Action != semanticActionLogOnly {
		t.Fatalf("expected log_only action, got=%+v", eval)
	}
	if eval.Telemetry == nil {
		t.Fatal("expected semantic telemetry to be populated")
	}
	if eval.Telemetry.Context.RequestKey != "req-sem-telemetry" {
		t.Fatalf("request_key=%q want=req-sem-telemetry", eval.Telemetry.Context.RequestKey)
	}
	if eval.Telemetry.Context.ActorBasis != "subject" {
		t.Fatalf("actor_basis=%q want=subject", eval.Telemetry.Context.ActorBasis)
	}
	if eval.Telemetry.Context.ActorKey == "" || eval.Telemetry.Context.ClientKey == "" {
		t.Fatalf("expected actor/client keys, got=%+v", eval.Telemetry.Context)
	}
	if eval.Telemetry.Context.SubjectSource != "bearer_jwt_sub" {
		t.Fatalf("subject_source=%q want=bearer_jwt_sub", eval.Telemetry.Context.SubjectSource)
	}
	if eval.Telemetry.Context.SessionSource != "cookie:session" {
		t.Fatalf("session_source=%q want=cookie:session", eval.Telemetry.Context.SessionSource)
	}
	if eval.Telemetry.Context.PathClass != "/api/v1/users/{num}/profile" {
		t.Fatalf("path_class=%q want=/api/v1/users/{num}/profile", eval.Telemetry.Context.PathClass)
	}
	if eval.Telemetry.Context.TargetClass != "account_security" {
		t.Fatalf("target_class=%q want=account_security", eval.Telemetry.Context.TargetClass)
	}
	if eval.Telemetry.Context.SurfaceClass != "query+json_body+headers" {
		t.Fatalf("surface_class=%q want=query+json_body+headers", eval.Telemetry.Context.SurfaceClass)
	}
	if eval.Telemetry.Fingerprints.QueryHash == "" ||
		eval.Telemetry.Fingerprints.JSONHash == "" ||
		eval.Telemetry.Fingerprints.HeaderHash == "" ||
		eval.Telemetry.Fingerprints.CombinedHash == "" {
		t.Fatalf("expected query/json/header/combined fingerprints, got=%+v", eval.Telemetry.Fingerprints)
	}
	if !slices.Contains(eval.Telemetry.FeatureBuckets, "actor:subject") {
		t.Fatalf("feature buckets=%v want actor:subject", eval.Telemetry.FeatureBuckets)
	}
	if !slices.Contains(eval.Telemetry.FeatureBuckets, "surface:json_body") {
		t.Fatalf("feature buckets=%v want surface:json_body", eval.Telemetry.FeatureBuckets)
	}
	if !slices.Contains(eval.Telemetry.FeatureBuckets, "target:account_security") {
		t.Fatalf("feature buckets=%v want target:account_security", eval.Telemetry.FeatureBuckets)
	}
}

func TestEvaluateSemanticWithRequestID_StatefulSensitivePathAfterSuspiciousHistory(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "log_only",
  "exempt_path_prefixes": [],
  "log_threshold": 2,
  "challenge_threshold": 5,
  "block_threshold": 8,
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
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	now := time.Unix(1_700_000_300, 0).UTC()
	for i := range 2 {
		req := httptest.NewRequest(
			http.MethodGet,
			"http://example.test/search?q=union+select+password+from+users",
			nil,
		)
		req.Header.Set("User-Agent", "curl/8.0")
		req.AddCookie(&http.Cookie{Name: "session", Value: "stateful-session"})
		eval := EvaluateSemanticWithRequestID(req, "203.0.113.10", "req-pre-"+strconv.Itoa(i), now.Add(time.Duration(i)*time.Second))
		if eval.BaseScore <= 0 {
			t.Fatalf("precondition request should have base score > 0, got=%+v", eval)
		}
	}

	adminReq := httptest.NewRequest(http.MethodGet, "http://example.test/admin/settings", nil)
	adminReq.Header.Set("User-Agent", "curl/8.0")
	adminReq.AddCookie(&http.Cookie{Name: "session", Value: "stateful-session"})
	eval := EvaluateSemanticWithRequestID(adminReq, "203.0.113.10", "req-admin", now.Add(3*time.Second))
	if eval.BaseScore != 0 {
		t.Fatalf("base_score=%d want=0", eval.BaseScore)
	}
	if eval.StatefulScore < statefulAdminAfterSuspiciousScore {
		t.Fatalf("stateful_score=%d want>=%d", eval.StatefulScore, statefulAdminAfterSuspiciousScore)
	}
	if eval.Action != semanticActionLogOnly {
		t.Fatalf("expected log_only from stateful score, got=%+v", eval)
	}
	if !slices.Contains(eval.StatefulReasons, "stateful:admin_after_suspicious_activity") {
		t.Fatalf("stateful reasons=%v want admin_after_suspicious_activity", eval.StatefulReasons)
	}
	if eval.StatefulSnapshot == nil {
		t.Fatal("expected stateful snapshot")
	}
	if eval.StatefulSnapshot.PriorSuspiciousRequests != 2 {
		t.Fatalf("prior_suspicious_requests=%d want=2", eval.StatefulSnapshot.PriorSuspiciousRequests)
	}
	if eval.Telemetry == nil || eval.Telemetry.Context.TargetClass != "admin_management" {
		t.Fatalf("target_class=%q want=admin_management", eval.Telemetry.Context.TargetClass)
	}
}

func TestEvaluateSemanticWithRequestID_LocalProviderSupplementsScore(t *testing.T) {
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
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/login?q=union+select+1", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	eval := EvaluateSemanticWithRequestID(req, "203.0.113.30", "req-provider", time.Unix(1_700_000_500, 0).UTC())
	if eval.BaseScore != 4 {
		t.Fatalf("base_score=%d want=4", eval.BaseScore)
	}
	if eval.ProviderScore <= 0 {
		t.Fatalf("provider_score=%d want>0", eval.ProviderScore)
	}
	if eval.Action != semanticActionChallenge {
		t.Fatalf("action=%q want=challenge", eval.Action)
	}
	if eval.ProviderResult == nil {
		t.Fatal("expected provider result")
	}
	if eval.ProviderResult.Name != semanticProviderNameBuiltinAttackFamily {
		t.Fatalf("provider name=%q want=%q", eval.ProviderResult.Name, semanticProviderNameBuiltinAttackFamily)
	}
	if eval.ProviderResult.AttackFamily != "sql_injection" {
		t.Fatalf("attack_family=%q want=sql_injection", eval.ProviderResult.AttackFamily)
	}
	if eval.ProviderResult.Confidence == "" {
		t.Fatalf("confidence should be present: %#v", eval.ProviderResult)
	}
	if !slices.Contains(eval.ProviderReasons, "provider:attack_family:sql_injection") {
		t.Fatalf("provider reasons=%v want provider:attack_family:sql_injection", eval.ProviderReasons)
	}
}

func TestEvaluateSemanticWithRequestID_DisabledProviderPreservesBaseline(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "log_only",
  "provider": {
    "enabled": false,
    "name": "builtin_attack_family",
    "timeout_ms": 25
  },
  "exempt_path_prefixes": [],
  "log_threshold": 1,
  "challenge_threshold": 5,
  "block_threshold": 9,
  "max_inspect_body": 16384
}`
	rt, err := ValidateSemanticRaw(raw)
	if err != nil {
		t.Fatalf("ValidateSemanticRaw() unexpected error: %v", err)
	}

	semanticMu.Lock()
	prev := semanticRuntime
	semanticRuntime = rt
	semanticMu.Unlock()
	defer func() {
		semanticMu.Lock()
		semanticRuntime = prev
		semanticMu.Unlock()
	}()

	req := httptest.NewRequest(http.MethodGet, "http://example.test/login?q=union+select+1", nil)
	req.Header.Set("User-Agent", "curl/8.0")
	eval := EvaluateSemanticWithRequestID(req, "203.0.113.31", "req-provider-off", time.Unix(1_700_000_510, 0).UTC())
	if eval.ProviderScore != 0 || eval.ProviderResult != nil {
		t.Fatalf("provider should be disabled: %+v", eval)
	}
	if eval.Score != eval.BaseScore+eval.StatefulScore {
		t.Fatalf("score=%d want=%d", eval.Score, eval.BaseScore+eval.StatefulScore)
	}
}

func TestSyncSemanticStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveSemanticStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "semantic.json")
	raw := `{
  "enabled": true,
  "mode": "challenge",
  "exempt_path_prefixes": ["/healthz"],
  "log_threshold": 2,
  "challenge_threshold": 4,
  "block_threshold": 8,
  "max_inspect_body": 8192
}`
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write semantic file: %v", err)
	}
	if err := InitSemantic(path); err != nil {
		t.Fatalf("init semantic: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := SyncSemanticStorage(); err != nil {
		t.Fatalf("sync semantic storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(semanticConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected semantic config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(raw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), raw)
	}
}

func TestSyncSemanticStorage_RestoresFileAndRuntimeFromDB(t *testing.T) {
	restore := saveSemanticStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "semantic.json")
	fileRaw := `{
  "enabled": false,
  "mode": "off",
  "exempt_path_prefixes": [],
  "log_threshold": 4,
  "challenge_threshold": 7,
  "block_threshold": 9,
  "max_inspect_body": 16384
}`
	if err := os.WriteFile(path, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write semantic file: %v", err)
	}
	if err := InitSemantic(path); err != nil {
		t.Fatalf("init semantic: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	dbRaw := `{
  "enabled": true,
  "mode": "block",
  "exempt_path_prefixes": ["/healthz"],
  "log_threshold": 1,
  "challenge_threshold": 2,
  "block_threshold": 3,
  "max_inspect_body": 8192
}`
	if err := store.UpsertConfigBlob(semanticConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncSemanticStorage(); err != nil {
		t.Fatalf("sync semantic storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read semantic file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}

	cfg := GetSemanticConfig()
	if !cfg.Enabled || cfg.Mode != "block" || cfg.BlockThreshold != 3 {
		t.Fatalf("runtime config mismatch: enabled=%v mode=%q block_threshold=%d", cfg.Enabled, cfg.Mode, cfg.BlockThreshold)
	}
}

func saveSemanticStateForTest() func() {
	semanticMu.RLock()
	oldPath := semanticPath
	oldRuntime := semanticRuntime
	semanticMu.RUnlock()

	return func() {
		semanticMu.Lock()
		semanticPath = oldPath
		semanticRuntime = oldRuntime
		semanticMu.Unlock()
	}
}
