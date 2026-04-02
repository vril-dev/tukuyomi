package handler

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestValidateSemanticRaw(t *testing.T) {
	raw := `{
  "enabled": true,
  "mode": "challenge",
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

	token := issueSemanticChallengeToken(rt, "10.0.0.1", "curl/8.0", now)
	req2 := httptest.NewRequest(http.MethodGet, "http://example.test/?q=union+select+1", nil)
	req2.Header.Set("User-Agent", "curl/8.0")
	req2.AddCookie(&http.Cookie{Name: rt.challengeCookieName, Value: token})
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

func TestSyncSemanticStorage_SeedsDBFromFileWhenMissingBlob(t *testing.T) {
	restore := saveSemanticStateForTest()
	defer restore()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "semantic.conf")
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
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
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
	path := filepath.Join(tmp, "semantic.conf")
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
		_ = InitLogsStatsStoreWithBackend("file", "", "", "", 0)
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
