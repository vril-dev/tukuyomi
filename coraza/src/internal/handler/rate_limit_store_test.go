package handler

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateRateLimitRaw(t *testing.T) {
	raw := `{
  "enabled": true,
  "allowlist_ips": ["127.0.0.1/32"],
  "allowlist_countries": ["JP"],
  "feedback": {
    "enabled": true,
    "strikes_required": 2,
    "strike_window_seconds": 120,
    "adaptive_only": true
  },
  "default_policy": {
    "enabled": true,
    "limit": 100,
    "window_seconds": 60,
    "burst": 10,
    "key_by": "ip",
    "action": {"status": 429, "retry_after_seconds": 60}
  },
  "rules": [
    {
      "name": "login",
      "match_type": "prefix",
      "match_value": "/login",
      "methods": ["POST"],
      "policy": {
        "enabled": true,
        "limit": 5,
        "window_seconds": 60,
        "burst": 0,
        "key_by": "ip_country",
        "action": {"status": 429, "retry_after_seconds": 60}
      }
    }
  ]
}`

	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}
	if rt == nil || !rt.Raw.Default.Enabled {
		t.Fatalf("runtime config should be enabled: %#v", rt)
	}
	if got := len(rt.Default.Rules); got != 1 {
		t.Fatalf("len(rt.Rules)=%d want=1", got)
	}
	if !rt.Raw.Default.Feedback.Enabled || !rt.Default.Feedback.AdaptiveOnly || rt.Default.Feedback.StrikeWindow != 120*time.Second {
		t.Fatalf("feedback was not normalized: %#v %#v", rt.Raw.Default.Feedback, rt.Default.Feedback)
	}
}

func TestEvaluateRateLimit_BlocksAfterLimit(t *testing.T) {
	raw := `{
  "enabled": true,
  "allowlist_ips": [],
  "allowlist_countries": [],
  "default_policy": {
    "enabled": true,
    "limit": 2,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {"status": 429, "retry_after_seconds": 30}
  },
  "rules": []
}`
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}

	rateLimitMu.Lock()
	prevRuntime := rateLimitRuntime
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	defer func() {
		rateLimitMu.Lock()
		rateLimitRuntime = prevRuntime
		rateLimitMu.Unlock()
	}()

	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	now := time.Unix(1_700_000_000, 0).UTC()
	r1 := httptest.NewRequest("GET", "/items", nil)
	r2 := httptest.NewRequest("GET", "/items", nil)
	r3 := httptest.NewRequest("GET", "/items", nil)
	d1 := EvaluateRateLimit(r1, "10.0.0.1", "JP", 0, now)
	d2 := EvaluateRateLimit(r2, "10.0.0.1", "JP", 0, now.Add(1*time.Second))
	d3 := EvaluateRateLimit(r3, "10.0.0.1", "JP", 0, now.Add(2*time.Second))

	if !d1.Allowed || !d2.Allowed {
		t.Fatalf("first two requests should be allowed: d1=%+v d2=%+v", d1, d2)
	}
	if d3.Allowed {
		t.Fatalf("third request should be blocked: d3=%+v", d3)
	}
	if d3.Status != 429 {
		t.Fatalf("blocked status=%d want=429", d3.Status)
	}
}

func TestEvaluateRateLimit_UsesSessionAndAdaptiveScore(t *testing.T) {
	raw := `{
  "enabled": true,
  "session_cookie_names": ["session_id"],
  "adaptive_enabled": true,
  "adaptive_score_threshold": 6,
  "adaptive_limit_factor_percent": 50,
  "adaptive_burst_factor_percent": 0,
  "default_policy": {
    "enabled": true,
    "limit": 4,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "session",
    "action": {"status": 429, "retry_after_seconds": 30}
  },
  "rules": []
}`
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}

	restore := saveRateLimitStateForTest()
	defer restore()
	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	now := time.Unix(1_700_100_000, 0).UTC()
	req1 := httptest.NewRequest("GET", "/items", nil)
	req1.AddCookie(mustCookie("session_id", "abc"))
	req2 := httptest.NewRequest("GET", "/items", nil)
	req2.AddCookie(mustCookie("session_id", "abc"))
	req3 := httptest.NewRequest("GET", "/items", nil)
	req3.AddCookie(mustCookie("session_id", "abc"))

	d1 := EvaluateRateLimit(req1, "10.0.0.1", "JP", 6, now)
	d2 := EvaluateRateLimit(req2, "10.0.0.2", "JP", 6, now.Add(time.Second))
	d3 := EvaluateRateLimit(req3, "10.0.0.3", "JP", 6, now.Add(2*time.Second))

	if !d1.Allowed || !d2.Allowed {
		t.Fatalf("first two adaptive session requests should be allowed: d1=%+v d2=%+v", d1, d2)
	}
	if d3.Allowed {
		t.Fatalf("third adaptive session request should be blocked: d3=%+v", d3)
	}
	if !d3.Adaptive {
		t.Fatalf("expected adaptive decision: %+v", d3)
	}
	if d3.BaseLimit != 4 || d3.Limit != 2 {
		t.Fatalf("unexpected adaptive limits: %+v", d3)
	}
}

func TestEvaluateRateLimit_UsesJWTSubjectKey(t *testing.T) {
	raw := `{
  "enabled": true,
  "jwt_header_names": ["Authorization"],
  "default_policy": {
    "enabled": true,
    "limit": 1,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "jwt_sub",
    "action": {"status": 429, "retry_after_seconds": 30}
  },
  "rules": []
}`
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}

	restore := saveRateLimitStateForTest()
	defer restore()
	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	now := time.Unix(1_700_200_000, 0).UTC()
	req1 := httptest.NewRequest("GET", "/items", nil)
	req1.Header.Set("Authorization", "Bearer header.eyJzdWIiOiJ1c2VyLTEifQ.sig")
	req2 := httptest.NewRequest("GET", "/items", nil)
	req2.Header.Set("Authorization", "Bearer header.eyJzdWIiOiJ1c2VyLTEifQ.sig")

	d1 := EvaluateRateLimit(req1, "10.0.0.1", "JP", 0, now)
	d2 := EvaluateRateLimit(req2, "10.0.0.2", "JP", 0, now.Add(time.Second))

	if !d1.Allowed {
		t.Fatalf("first jwt subject request should be allowed: %+v", d1)
	}
	if d2.Allowed {
		t.Fatalf("second jwt subject request should be blocked across IPs: %+v", d2)
	}
	if d2.KeyBy != rateLimitKeyByJWTSub {
		t.Fatalf("unexpected key_by: %+v", d2)
	}
}

func TestEvaluateRateLimit_HostScopePrecedence(t *testing.T) {
	raw := `{
  "default": {
    "enabled": true,
    "default_policy": {
      "enabled": true,
      "limit": 1,
      "window_seconds": 60,
      "burst": 0,
      "key_by": "ip",
      "action": {"status": 429, "retry_after_seconds": 30}
    },
    "rules": []
  },
  "hosts": {
    "example.com": {
      "default_policy": {
        "enabled": true,
        "limit": 2,
        "window_seconds": 60,
        "burst": 0,
        "key_by": "ip",
        "action": {"status": 429, "retry_after_seconds": 30}
      }
    },
    "example.com:8080": {
      "default_policy": {
        "enabled": true,
        "limit": 3,
        "window_seconds": 60,
        "burst": 0,
        "key_by": "ip",
        "action": {"status": 429, "retry_after_seconds": 30}
      }
    }
  }
}`
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}

	restore := saveRateLimitStateForTest()
	defer restore()
	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	now := time.Unix(1_700_300_000, 0).UTC()
	req8080a := httptest.NewRequest("GET", "http://example.com:8080/items", nil)
	req8080b := httptest.NewRequest("GET", "http://example.com:8080/items", nil)
	req8080c := httptest.NewRequest("GET", "http://example.com:8080/items", nil)
	req8080d := httptest.NewRequest("GET", "http://example.com:8080/items", nil)
	d8080a := EvaluateRateLimit(req8080a, "10.0.0.30", "JP", 0, now)
	d8080b := EvaluateRateLimit(req8080b, "10.0.0.30", "JP", 0, now.Add(time.Second))
	d8080c := EvaluateRateLimit(req8080c, "10.0.0.30", "JP", 0, now.Add(2*time.Second))
	d8080d := EvaluateRateLimit(req8080d, "10.0.0.30", "JP", 0, now.Add(3*time.Second))
	if !d8080a.Allowed || !d8080b.Allowed || !d8080c.Allowed {
		t.Fatalf("first three :8080 requests should be allowed: %+v %+v %+v", d8080a, d8080b, d8080c)
	}
	if d8080d.Allowed {
		t.Fatalf("fourth :8080 request should be blocked: %+v", d8080d)
	}
	if d8080d.HostScope != "example.com:8080" {
		t.Fatalf("host scope=%q want example.com:8080", d8080d.HostScope)
	}

	reqHostA := httptest.NewRequest("GET", "http://example.com/items", nil)
	reqHostB := httptest.NewRequest("GET", "http://example.com/items", nil)
	reqHostC := httptest.NewRequest("GET", "http://example.com/items", nil)
	dHostA := EvaluateRateLimit(reqHostA, "10.0.0.31", "JP", 0, now)
	dHostB := EvaluateRateLimit(reqHostB, "10.0.0.31", "JP", 0, now.Add(time.Second))
	dHostC := EvaluateRateLimit(reqHostC, "10.0.0.31", "JP", 0, now.Add(2*time.Second))
	if !dHostA.Allowed || !dHostB.Allowed {
		t.Fatalf("first two host-only requests should be allowed: %+v %+v", dHostA, dHostB)
	}
	if dHostC.Allowed {
		t.Fatalf("third host-only request should be blocked: %+v", dHostC)
	}
	if dHostC.HostScope != "example.com" {
		t.Fatalf("host scope=%q want example.com", dHostC.HostScope)
	}

	reqDefaultA := httptest.NewRequest("GET", "http://www.example.com/items", nil)
	reqDefaultB := httptest.NewRequest("GET", "http://www.example.com/items", nil)
	dDefaultA := EvaluateRateLimit(reqDefaultA, "10.0.0.32", "JP", 0, now)
	dDefaultB := EvaluateRateLimit(reqDefaultB, "10.0.0.32", "JP", 0, now.Add(time.Second))
	if !dDefaultA.Allowed {
		t.Fatalf("first default request should be allowed: %+v", dDefaultA)
	}
	if dDefaultB.Allowed {
		t.Fatalf("second default request should be blocked: %+v", dDefaultB)
	}
	if dDefaultB.HostScope != rateLimitDefaultScope {
		t.Fatalf("host scope=%q want default", dDefaultB.HostScope)
	}
}

func TestEvaluateRateLimit_IsolatesCountersAcrossHostScopes(t *testing.T) {
	raw := `{
  "default": {
    "enabled": true,
    "default_policy": {
      "enabled": true,
      "limit": 1,
      "window_seconds": 60,
      "burst": 0,
      "key_by": "ip",
      "action": {"status": 429, "retry_after_seconds": 30}
    },
    "rules": []
  },
  "hosts": {
    "one.example.com": {},
    "two.example.com": {}
  }
}`
	rt, err := ValidateRateLimitRaw(raw)
	if err != nil {
		t.Fatalf("ValidateRateLimitRaw() unexpected error: %v", err)
	}

	restore := saveRateLimitStateForTest()
	defer restore()
	rateLimitMu.Lock()
	rateLimitRuntime = rt
	rateLimitMu.Unlock()
	rateCounterMu.Lock()
	rateCounters = map[string]rateCounter{}
	rateCounterSweep = 0
	rateCounterMu.Unlock()

	now := time.Unix(1_700_301_000, 0).UTC()
	reqOneA := httptest.NewRequest("GET", "http://one.example.com/items", nil)
	reqTwoA := httptest.NewRequest("GET", "http://two.example.com/items", nil)
	reqOneB := httptest.NewRequest("GET", "http://one.example.com/items", nil)
	dOneA := EvaluateRateLimit(reqOneA, "10.0.0.40", "JP", 0, now)
	dTwoA := EvaluateRateLimit(reqTwoA, "10.0.0.40", "JP", 0, now.Add(time.Second))
	dOneB := EvaluateRateLimit(reqOneB, "10.0.0.40", "JP", 0, now.Add(2*time.Second))
	if !dOneA.Allowed || !dTwoA.Allowed {
		t.Fatalf("first request per host scope should be allowed: %+v %+v", dOneA, dTwoA)
	}
	if dOneB.Allowed {
		t.Fatalf("second request on the first host scope should be blocked: %+v", dOneB)
	}
	if dOneB.HostScope != "one.example.com" {
		t.Fatalf("host scope=%q want one.example.com", dOneB.HostScope)
	}
}

func TestSyncRateLimitStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveRateLimitStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "rate-limit.json")
	raw := rateLimitRawForTest(77)
	if err := os.WriteFile(path, []byte(raw), 0o644); err != nil {
		t.Fatalf("write rate-limit file: %v", err)
	}
	if err := InitRateLimit(path); err != nil {
		t.Fatalf("init rate-limit: %v", err)
	}

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	if err := SyncRateLimitStorage(); err != nil {
		t.Fatalf("sync rate-limit storage: %v", err)
	}

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	gotRaw, _, found, err := store.GetConfigBlob(rateLimitConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected rate-limit config blob to be seeded")
	}
	if strings.TrimSpace(string(gotRaw)) != strings.TrimSpace(raw) {
		t.Fatalf("seeded blob mismatch:\n got=%s\nwant=%s", string(gotRaw), raw)
	}
}

func TestSyncRateLimitStorage_RestoresFileAndRuntimeFromDB(t *testing.T) {
	restore := saveRateLimitStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "rate-limit.json")
	fileRaw := rateLimitRawForTest(120)
	if err := os.WriteFile(path, []byte(fileRaw), 0o644); err != nil {
		t.Fatalf("write rate-limit file: %v", err)
	}
	if err := InitRateLimit(path); err != nil {
		t.Fatalf("init rate-limit: %v", err)
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
	dbRaw := rateLimitRawForTest(9)
	if err := store.UpsertConfigBlob(rateLimitConfigBlobKey, []byte(dbRaw), "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	if err := SyncRateLimitStorage(); err != nil {
		t.Fatalf("sync rate-limit storage: %v", err)
	}

	gotFileRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read rate-limit file: %v", err)
	}
	if strings.TrimSpace(string(gotFileRaw)) != strings.TrimSpace(dbRaw) {
		t.Fatalf("file should be restored from db blob:\n got=%s\nwant=%s", string(gotFileRaw), dbRaw)
	}

	cfg := GetRateLimitConfig()
	if cfg.Default.DefaultPolicy.Limit != 9 {
		t.Fatalf("runtime default_policy.limit=%d want=9", cfg.Default.DefaultPolicy.Limit)
	}
}

func saveRateLimitStateForTest() func() {
	rateLimitMu.RLock()
	oldPath := rateLimitPath
	oldRuntime := rateLimitRuntime
	rateLimitMu.RUnlock()

	rateCounterMu.Lock()
	oldCounters := make(map[string]rateCounter, len(rateCounters))
	for k, v := range rateCounters {
		oldCounters[k] = v
	}
	oldSweep := rateCounterSweep
	rateCounterMu.Unlock()
	rateLimitFeedbackStateMu.Lock()
	oldFeedbackState := make(map[string]rateLimitFeedbackState, len(rateLimitFeedbackStateByKey))
	for k, v := range rateLimitFeedbackStateByKey {
		oldFeedbackState[k] = v
	}
	oldFeedbackSweep := rateLimitFeedbackStateSweep
	rateLimitFeedbackStateMu.Unlock()
	oldRequests := rateLimitRequestsTotal.Load()
	oldAllowed := rateLimitAllowedTotal.Load()
	oldBlocked := rateLimitBlockedTotal.Load()
	oldAdaptive := rateLimitAdaptiveTotal.Load()

	return func() {
		rateLimitMu.Lock()
		rateLimitPath = oldPath
		rateLimitRuntime = oldRuntime
		rateLimitMu.Unlock()

		rateCounterMu.Lock()
		rateCounters = oldCounters
		rateCounterSweep = oldSweep
		rateCounterMu.Unlock()
		rateLimitFeedbackStateMu.Lock()
		rateLimitFeedbackStateByKey = oldFeedbackState
		rateLimitFeedbackStateSweep = oldFeedbackSweep
		rateLimitFeedbackStateMu.Unlock()
		rateLimitRequestsTotal.Store(oldRequests)
		rateLimitAllowedTotal.Store(oldAllowed)
		rateLimitBlockedTotal.Store(oldBlocked)
		rateLimitAdaptiveTotal.Store(oldAdaptive)
	}
}

func rateLimitRawForTest(limit int) string {
	return fmt.Sprintf(`{
  "enabled": true,
  "allowlist_ips": [],
  "allowlist_countries": [],
  "default_policy": {
    "enabled": true,
    "limit": %d,
    "window_seconds": 60,
    "burst": 0,
    "key_by": "ip",
    "action": {"status": 429, "retry_after_seconds": 60}
  },
  "rules": []
}`, limit)
}

func mustCookie(name, value string) *http.Cookie {
	return &http.Cookie{Name: name, Value: value}
}
