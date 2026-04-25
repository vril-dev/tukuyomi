package handler

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
)

type testAdminAuditEntry struct {
	TS      string `json:"ts"`
	Service string `json:"service"`
	Event   string `json:"event"`
	Actor   string `json:"actor"`
	IP      string `json:"ip,omitempty"`
	Count   int    `json:"count"`
}

func TestAdminAuditActorPrefersOperatorIdentity(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tukuyomi-Actor", "alice@example.com")
	c.Request = req

	if got := adminAuditActor(c); got != "alice@example.com" {
		t.Fatalf("actor=%q want=%q", got, "alice@example.com")
	}
}

func TestAdminAuditActorFallsBackToUnknown(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request = req

	if got := adminAuditActor(c); got != "unknown" {
		t.Fatalf("actor=%q", got)
	}
}

func TestAdminAuditActorFallsBackToSessionMarker(t *testing.T) {
	gin.SetMode(gin.TestMode)

	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	c.Request = req
	c.Set("tukuyomi.admin_auth_fallback_actor", "session:browser")

	if got := adminAuditActor(c); got != "session:browser" {
		t.Fatalf("actor=%q", got)
	}
}

func TestParseAdminAuditLimitDefaultsAndClamps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		raw   string
		limit int
	}{
		{name: "empty defaults", raw: "", limit: 20},
		{name: "invalid defaults", raw: "nope", limit: 20},
		{name: "zero clamps low", raw: "0", limit: 1},
		{name: "negative clamps low", raw: "-5", limit: 1},
		{name: "high clamps max", raw: "200", limit: 100},
		{name: "valid preserved", raw: "17", limit: 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := parseAdminAuditLimit(tc.raw); got != tc.limit {
				t.Fatalf("limit=%d want=%d", got, tc.limit)
			}
		})
	}
}

func TestAppendAndReadAdminAuditLatest(t *testing.T) {
	gin.SetMode(gin.TestMode)

	path := filepath.Join(t.TempDir(), "admin-audit.ndjson")
	rec := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(rec)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Tukuyomi-Actor", "alice@example.com")
	req.Header.Set("X-Real-IP", "203.0.113.7")
	c.Request = req

	for i := 1; i <= 3; i += 1 {
		info := newAdminAuditInfo(c, "test_event")
		appendAdminAudit(path, "test_audit_write_error", testAdminAuditEntry{
			TS:      info.TS,
			Service: info.Service,
			Event:   info.Event,
			Actor:   info.Actor,
			IP:      info.IP,
			Count:   i,
		})
	}

	entries, err := readAdminAuditLatest[testAdminAuditEntry](path, 2, "test")
	if err != nil {
		t.Fatalf("readAdminAuditLatest: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("entries=%d want=2", len(entries))
	}
	if entries[0].Count != 3 || entries[1].Count != 2 {
		t.Fatalf("counts=%v", []int{entries[0].Count, entries[1].Count})
	}
	if entries[0].Actor != "alice@example.com" {
		t.Fatalf("actor=%q", entries[0].Actor)
	}
	if entries[0].IP != "203.0.113.7" {
		t.Fatalf("ip=%q", entries[0].IP)
	}
}

func TestAppendAdminAuditLogsWriteFailuresWithoutPanicking(t *testing.T) {
	path := t.TempDir()
	var buf bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&buf)
	defer log.SetOutput(prev)

	appendAdminAudit(path, "test_audit_write_error", map[string]any{
		"event": "test_event",
	})

	if !strings.Contains(buf.String(), `"event":"test_audit_write_error"`) {
		t.Fatalf("log output missing warning event: %s", buf.String())
	}
}

func TestReadAdminAuditLatestMissingFileReturnsEmpty(t *testing.T) {
	entries, err := readAdminAuditLatest[testAdminAuditEntry](filepath.Join(t.TempDir(), "missing.ndjson"), 20, "test")
	if err != nil {
		t.Fatalf("readAdminAuditLatest: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries=%d want=0", len(entries))
	}
}

func TestReadAdminAuditLatestDecodeErrorIsLabeled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.ndjson")
	if err := os.WriteFile(path, []byte("{broken}\n"), 0o644); err != nil {
		t.Fatalf("write broken audit: %v", err)
	}

	_, err := readAdminAuditLatest[testAdminAuditEntry](path, 20, "proxy")
	if err == nil {
		t.Fatal("expected decode error")
	}
	if !strings.Contains(err.Error(), "decode proxy audit entry") {
		t.Fatalf("err=%v", err)
	}
}
