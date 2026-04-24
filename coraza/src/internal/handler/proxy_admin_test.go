package handler

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

func TestRollbackPreviewProxyRulesHandler(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, initial)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, etag, _, _, _ := ProxyRulesSnapshot()

	next := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true }
  ]
}`
	if _, _, err := ApplyProxyRulesRaw(etag, next); err != nil {
		t.Fatalf("ApplyProxyRulesRaw: %v", err)
	}
	initialPrepared, err := prepareProxyRulesRaw(initial)
	if err != nil {
		t.Fatalf("prepareProxyRulesRaw(initial): %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/proxy-rules/rollback-preview", nil)
	c.Request = req

	RollbackPreviewProxyRulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var body struct {
		OK   bool   `json:"ok"`
		Raw  string `json:"raw"`
		ETag string `json:"etag"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal response: %v", err)
	}
	if !body.OK {
		t.Fatalf("response = %#v", body)
	}
	if body.Raw != initialPrepared.raw {
		t.Fatalf("preview raw mismatch: %q", body.Raw)
	}
	if body.ETag != etag {
		t.Fatalf("preview etag=%q want=%q", body.ETag, etag)
	}
}

func TestPutProxyRulesAppendsAuditEntry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	auditPath := filepath.Join(tmp, "proxy-audit.ndjson")
	restore := setProxyAuditFileForTest(t, auditPath)
	defer restore()

	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, initial)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, etag, _, _, _ := ProxyRulesSnapshot()

	next := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true }
  ]
}`
	body, _ := json.Marshal(map[string]any{"raw": next})
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPut, "/proxy-rules", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("If-Match", etag)
	req.Header.Set("X-Tukuyomi-Actor", "alice@example.com")
	req.Header.Set("X-Real-IP", "203.0.113.10")
	c.Request = req

	PutProxyRules(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries, err := readProxyRulesAudit(20)
	if err != nil {
		t.Fatalf("readProxyRulesAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d want=1", len(entries))
	}
	entry := entries[0]
	if entry.Event != "proxy_rules_apply" {
		t.Fatalf("event=%q", entry.Event)
	}
	if entry.Actor != "alice@example.com" {
		t.Fatalf("actor=%q", entry.Actor)
	}
	if entry.IP != "203.0.113.10" {
		t.Fatalf("ip=%q", entry.IP)
	}
	if entry.PrevETag != etag {
		t.Fatalf("prev_etag=%q want=%q", entry.PrevETag, etag)
	}
	if entry.NextETag == "" || entry.NextETag == etag {
		t.Fatalf("next_etag=%q", entry.NextETag)
	}
	if entry.BeforeRaw == entry.AfterRaw {
		t.Fatalf("before/after raw should differ")
	}
	if entry.RestoredFrom != nil {
		t.Fatalf("restored_from should be nil: %#v", entry.RestoredFrom)
	}
}

func TestRollbackProxyRulesAppendsAuditEntry(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	auditPath := filepath.Join(tmp, "proxy-audit.ndjson")
	restore := setProxyAuditFileForTest(t, auditPath)
	defer restore()

	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, initial)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, etag, _, _, _ := ProxyRulesSnapshot()
	next := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true }
  ]
}`
	if _, _, err := ApplyProxyRulesRaw(etag, next); err != nil {
		t.Fatalf("ApplyProxyRulesRaw: %v", err)
	}

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodPost, "/proxy-rules/rollback", nil)
	req.Header.Set("X-Tukuyomi-Actor", "ops@example.com")
	req.Header.Set("X-Real-IP", "198.51.100.44")
	c.Request = req

	RollbackProxyRulesHandler(c)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	entries, err := readProxyRulesAudit(20)
	if err != nil {
		t.Fatalf("readProxyRulesAudit: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("entries=%d want=1", len(entries))
	}
	entry := entries[0]
	if entry.Event != "proxy_rules_rollback" {
		t.Fatalf("event=%q", entry.Event)
	}
	if entry.Actor != "ops@example.com" {
		t.Fatalf("actor=%q", entry.Actor)
	}
	if entry.IP != "198.51.100.44" {
		t.Fatalf("ip=%q", entry.IP)
	}
	if entry.RestoredFrom == nil {
		t.Fatal("restored_from should not be nil")
	}
	if entry.RestoredFrom.ETag != etag {
		t.Fatalf("restored_from.etag=%q want=%q", entry.RestoredFrom.ETag, etag)
	}
	if entry.BeforeRaw == entry.AfterRaw {
		t.Fatalf("before/after raw should differ")
	}
}

func TestProxyRulesAuditWriteFailureDoesNotFailApplyOrRollback(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	proxyPath := filepath.Join(tmp, "proxy.json")
	restore := setProxyAuditFileForTest(t, tmp)
	defer restore()

	initial := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true }
  ]
}`
	if err := os.WriteFile(proxyPath, []byte(initial), 0o644); err != nil {
		t.Fatalf("write initial proxy.json: %v", err)
	}
	initConfigDBStoreForTest(t)
	importProxyRuntimeDBForTest(t, initial)
	if err := InitProxyRuntime(proxyPath, 2); err != nil {
		t.Fatalf("InitProxyRuntime: %v", err)
	}
	_, etag, _, _, _ := ProxyRulesSnapshot()
	next := `{
  "upstreams": [
    { "name": "primary", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true }
  ]
}`

	putBody, _ := json.Marshal(map[string]any{"raw": next})
	putRec := httptest.NewRecorder()
	putCtx, _ := gin.CreateTestContext(putRec)
	putReq := httptest.NewRequest(http.MethodPut, "/proxy-rules", bytes.NewReader(putBody))
	putReq.Header.Set("Content-Type", "application/json")
	putReq.Header.Set("If-Match", etag)
	putCtx.Request = putReq
	PutProxyRules(putCtx)
	if putRec.Code != http.StatusOK {
		t.Fatalf("put status=%d body=%s", putRec.Code, putRec.Body.String())
	}

	rollbackRec := httptest.NewRecorder()
	rollbackCtx, _ := gin.CreateTestContext(rollbackRec)
	rollbackCtx.Request = httptest.NewRequest(http.MethodPost, "/proxy-rules/rollback", nil)
	RollbackProxyRulesHandler(rollbackCtx)
	if rollbackRec.Code != http.StatusOK {
		t.Fatalf("rollback status=%d body=%s", rollbackRec.Code, rollbackRec.Body.String())
	}
}

func TestGetProxyRulesAuditHandlerReturnsNewestFirstAndClampsLimit(t *testing.T) {
	gin.SetMode(gin.TestMode)

	tmp := t.TempDir()
	auditPath := filepath.Join(tmp, "proxy-audit.ndjson")
	restore := setProxyAuditFileForTest(t, auditPath)
	defer restore()

	lines := make([][]byte, 0, 105)
	for i := 0; i < 105; i += 1 {
		entry, err := json.Marshal(proxyRulesAuditEntry{
			TS:        "2026-04-01T00:00:00Z",
			Service:   "coraza",
			Event:     "proxy_rules_apply",
			Actor:     "tester",
			PrevETag:  "etag-prev",
			NextETag:  "etag-" + strconv.Itoa(i),
			BeforeRaw: `{"upstreams":[{"name":"primary","url":"http://127.0.0.1:8081","weight":1,"enabled":true}]}`,
			AfterRaw:  `{"upstreams":[{"name":"primary","url":"http://127.0.0.1:8082","weight":1,"enabled":true}]}`,
		})
		if err != nil {
			t.Fatalf("marshal audit entry: %v", err)
		}
		lines = append(lines, append(entry, '\n'))
	}
	if err := os.WriteFile(auditPath, bytes.Join(lines, nil), 0o644); err != nil {
		t.Fatalf("write audit file: %v", err)
	}

	for _, tc := range []struct {
		name      string
		query     string
		wantCount int
		wantFirst string
		wantLast  string
	}{
		{
			name:      "omitted limit defaults to twenty",
			query:     "/proxy-rules/audit",
			wantCount: 20,
			wantFirst: "etag-104",
			wantLast:  "etag-85",
		},
		{
			name:      "invalid limit defaults to twenty",
			query:     "/proxy-rules/audit?limit=nope",
			wantCount: 20,
			wantFirst: "etag-104",
			wantLast:  "etag-85",
		},
		{
			name:      "zero clamps to one",
			query:     "/proxy-rules/audit?limit=0",
			wantCount: 1,
			wantFirst: "etag-104",
			wantLast:  "etag-104",
		},
		{
			name:      "negative clamps to one",
			query:     "/proxy-rules/audit?limit=-5",
			wantCount: 1,
			wantFirst: "etag-104",
			wantLast:  "etag-104",
		},
		{
			name:      "upper bound clamps to hundred",
			query:     "/proxy-rules/audit?limit=200",
			wantCount: 100,
			wantFirst: "etag-104",
			wantLast:  "etag-5",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(rec)
			c.Request = httptest.NewRequest(http.MethodGet, tc.query, nil)

			GetProxyRulesAudit(c)

			if rec.Code != http.StatusOK {
				t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
			}
			var body struct {
				Entries []proxyRulesAuditEntry `json:"entries"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
				t.Fatalf("unmarshal response: %v", err)
			}
			if len(body.Entries) != tc.wantCount {
				t.Fatalf("entries=%d want=%d", len(body.Entries), tc.wantCount)
			}
			if body.Entries[0].NextETag != tc.wantFirst {
				t.Fatalf("first next_etag=%q want=%q", body.Entries[0].NextETag, tc.wantFirst)
			}
			if body.Entries[len(body.Entries)-1].NextETag != tc.wantLast {
				t.Fatalf("last next_etag=%q want=%q", body.Entries[len(body.Entries)-1].NextETag, tc.wantLast)
			}
		})
	}
}

func setProxyAuditFileForTest(t *testing.T, path string) func() {
	t.Helper()
	prev := config.ProxyAuditFile
	config.ProxyAuditFile = path
	return func() {
		config.ProxyAuditFile = prev
	}
}
