package handler

import (
	"bytes"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLogsStatsSQLiteStoreAggregatesAndIngestsIncrementally(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 942100,
			"path":    "/login",
			"country": "jp",
			"status":  403,
			"req_id":  "req-1",
		},
		{
			"ts":      now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": "920350",
			"path":    "/admin",
			"country": "US",
			"status":  403,
			"req_id":  "req-2",
		},
		{
			"ts":    now.Add(-5 * time.Minute).Format(time.RFC3339Nano),
			"event": "waf_hit_allow",
			"path":  "/allow",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	first := callLogsStats(t, "/tukuyomi-api/logs/stats?hours=6")
	if first.ScannedLines != len(entries) {
		t.Fatalf("first scanned_lines=%d want=%d", first.ScannedLines, len(entries))
	}
	if first.WAFBlock.TotalInScan != 2 {
		t.Fatalf("first total_in_scan=%d want=2", first.WAFBlock.TotalInScan)
	}
	if first.WAFBlock.Last1h != 1 {
		t.Fatalf("first last_1h=%d want=1", first.WAFBlock.Last1h)
	}
	if first.WAFBlock.Last24h != 2 {
		t.Fatalf("first last_24h=%d want=2", first.WAFBlock.Last24h)
	}

	appendNDJSONLine(t, logPath, map[string]any{
		"ts":      now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
		"event":   "waf_block",
		"rule_id": 942100,
		"path":    "/login",
		"country": "JP",
		"status":  403,
		"req_id":  "req-3",
	})

	second := callLogsStats(t, "/tukuyomi-api/logs/stats?hours=6")
	if second.ScannedLines != 1 {
		t.Fatalf("second scanned_lines=%d want=1", second.ScannedLines)
	}
	if second.WAFBlock.TotalInScan != 3 {
		t.Fatalf("second total_in_scan=%d want=3", second.WAFBlock.TotalInScan)
	}
	if second.WAFBlock.Last1h != 2 {
		t.Fatalf("second last_1h=%d want=2", second.WAFBlock.Last1h)
	}
	if second.WAFBlock.Last24h != 3 {
		t.Fatalf("second last_24h=%d want=3", second.WAFBlock.Last24h)
	}
}

func TestLogsStatsSQLiteStoreRetentionPrunesOldEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-40 * 24 * time.Hour).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 942100,
			"path":    "/old",
			"country": "JP",
			"status":  403,
			"req_id":  "req-old",
		},
		{
			"ts":      now.Add(-30 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 920350,
			"path":    "/new",
			"country": "US",
			"status":  403,
			"req_id":  "req-new",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	stats := callLogsStats(t, "/tukuyomi-api/logs/stats?hours=24")
	if stats.WAFBlock.TotalInScan != 1 {
		t.Fatalf("total_in_scan=%d want=1", stats.WAFBlock.TotalInScan)
	}
	read := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=10")
	if len(read.Lines) != 1 {
		t.Fatalf("lines=%d want=1", len(read.Lines))
	}
	if got := anyToString(read.Lines[0]["req_id"]); got != "req-new" {
		t.Fatalf("req_id=%q want=req-new", got)
	}
}

func TestLogsReadUsesSQLiteStoreForWAF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-1",
			"path":    "/a",
			"rule_id": 942100,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":     now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":  "waf_hit_allow",
			"req_id": "req-2",
			"path":   "/b",
		},
		{
			"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-3",
			"path":    "/c",
			"rule_id": 920350,
			"country": "US",
			"status":  403,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	first := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=2")
	if len(first.Lines) != 2 {
		t.Fatalf("first lines=%d want=2", len(first.Lines))
	}
	if got := anyToString(first.Lines[0]["req_id"]); got != "req-2" {
		t.Fatalf("first[0].req_id=%q want=req-2", got)
	}
	if got := anyToString(first.Lines[1]["req_id"]); got != "req-3" {
		t.Fatalf("first[1].req_id=%q want=req-3", got)
	}
	if first.PageStart == nil {
		t.Fatalf("first page_start is nil")
	}

	second := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=2&dir=prev&cursor="+itoa64(*first.PageStart))
	if len(second.Lines) != 1 {
		t.Fatalf("second lines=%d want=1", len(second.Lines))
	}
	if got := anyToString(second.Lines[0]["req_id"]); got != "req-1" {
		t.Fatalf("second[0].req_id=%q want=req-1", got)
	}
}

func TestLogsReadUsesSQLiteStoreCountryFilterPagination(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-jp-1",
			"path":    "/a",
			"rule_id": 942100,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":      now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-us-1",
			"path":    "/b",
			"rule_id": 920350,
			"country": "US",
			"status":  403,
		},
		{
			"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-jp-2",
			"path":    "/c",
			"rule_id": 949110,
			"country": "JP",
			"status":  403,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	first := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=1&country=JP")
	if len(first.Lines) != 1 {
		t.Fatalf("first lines=%d want=1", len(first.Lines))
	}
	if got := anyToString(first.Lines[0]["req_id"]); got != "req-jp-2" {
		t.Fatalf("first[0].req_id=%q want=req-jp-2", got)
	}
	if !first.HasPrev {
		t.Fatal("first HasPrev=false want true")
	}
	if first.PageStart == nil {
		t.Fatal("first page_start is nil")
	}

	second := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=1&dir=prev&country=JP&cursor="+itoa64(*first.PageStart))
	if len(second.Lines) != 1 {
		t.Fatalf("second lines=%d want=1", len(second.Lines))
	}
	if got := anyToString(second.Lines[0]["req_id"]); got != "req-jp-1" {
		t.Fatalf("second[0].req_id=%q want=req-jp-1", got)
	}
}

func TestLogsReadUsesSQLiteStoreFreeTextSearch(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-login",
			"path":    "/admin/login",
			"rule_id": 942100,
			"country": "JP",
			"status":  403,
			"msg":     "SQL injection attempt",
		},
		{
			"ts":      now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-percent-literal",
			"path":    "/percent%literal",
			"rule_id": 949110,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-percent-wildcard",
			"path":    "/percentXliteral",
			"rule_id": 949110,
			"country": "US",
			"status":  403,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	sqlSearch := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=10&q=sql+injection")
	if len(sqlSearch.Lines) != 1 {
		t.Fatalf("sql search lines=%d want=1", len(sqlSearch.Lines))
	}
	if got := anyToString(sqlSearch.Lines[0]["req_id"]); got != "req-login" {
		t.Fatalf("sql search req_id=%q want=req-login", got)
	}

	literalSearch := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&tail=10&q=percent%25literal")
	if len(literalSearch.Lines) != 1 {
		t.Fatalf("literal search lines=%d want=1", len(literalSearch.Lines))
	}
	if got := anyToString(literalSearch.Lines[0]["req_id"]); got != "req-percent-literal" {
		t.Fatalf("literal search req_id=%q want=req-percent-literal", got)
	}
}

func TestLogsReadUsesSQLiteStoreReqIDFilterAcrossPolicyEvents(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":         now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":      "ip_reputation",
			"req_id":     "req-shared",
			"path":       "/login",
			"country":    "JP",
			"status":     403,
			"rule_id":    "UNKNOWN",
			"risk_score": 40,
		},
		{
			"ts":         now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":      "bot_challenge",
			"req_id":     "req-shared",
			"path":       "/login",
			"country":    "JP",
			"status":     403,
			"rule_id":    "UNKNOWN",
			"risk_score": 85,
		},
		{
			"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-shared",
			"path":    "/login",
			"country": "JP",
			"status":  403,
			"rule_id": 942100,
		},
		{
			"ts":      now.Add(-30 * time.Second).Format(time.RFC3339Nano),
			"event":   "rate_limited",
			"req_id":  "req-other",
			"path":    "/login",
			"country": "JP",
			"status":  429,
			"rule_id": "UNKNOWN",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	read := callLogsRead(t, "/tukuyomi-api/logs/read?src=waf&req_id=req-shared")
	if len(read.Lines) != 3 {
		t.Fatalf("lines=%d want=3", len(read.Lines))
	}
	if read.HasPrev || read.HasNext || read.HasMore {
		t.Fatalf("unexpected pagination flags: %+v", read)
	}

	gotEvents := make([]string, 0, len(read.Lines))
	for _, line := range read.Lines {
		if got := anyToString(line["req_id"]); got != "req-shared" {
			t.Fatalf("req_id=%q want=req-shared", got)
		}
		gotEvents = append(gotEvents, anyToString(line["event"]))
	}
	wantEvents := []string{"ip_reputation", "bot_challenge", "waf_block"}
	if strings.Join(gotEvents, ",") != strings.Join(wantEvents, ",") {
		t.Fatalf("events=%v want=%v", gotEvents, wantEvents)
	}
}

func TestLogsDownloadUsesSQLiteStoreForWAF(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-3 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-1",
			"path":    "/a",
			"rule_id": 942100,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":      "invalid-ts",
			"event":   "waf_block",
			"req_id":  "req-invalid",
			"path":    "/invalid",
			"rule_id": 999999,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-2",
			"path":    "/b",
			"rule_id": 920350,
			"country": "US",
			"status":  403,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/download?src=waf", nil)
	LogsDownload(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	gr, err := gzip.NewReader(bytes.NewReader(w.Body.Bytes()))
	if err != nil {
		t.Fatalf("new gzip reader: %v", err)
	}
	defer gr.Close()
	raw, err := io.ReadAll(gr)
	if err != nil {
		t.Fatalf("read gzip payload: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) != 2 {
		t.Fatalf("download lines=%d want=2 payload=%s", len(lines), string(raw))
	}
	if strings.Contains(string(raw), "req-invalid") {
		t.Fatalf("invalid timestamp row should be filtered from download payload: %s", string(raw))
	}
}

func TestLatestWAFBlockEventUsesSQLiteStoreWhenLogFileMissing(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":               now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-1",
			"path":             "/a",
			"method":           "GET",
			"rule_id":          942100,
			"matched_variable": "ARGS:q",
			"matched_value":    "foo",
			"status":           403,
		},
		{
			"ts":               now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":            "waf_block",
			"req_id":           "req-2",
			"path":             "/b",
			"method":           "POST",
			"rule_id":          920350,
			"matched_variable": "ARGS:id",
			"matched_value":    "bar",
			"status":           403,
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}
	if _, err := store.BuildLogsStats(logPath, 6, now); err != nil {
		t.Fatalf("seed sqlite store: %v", err)
	}

	if err := os.Remove(logPath); err != nil {
		t.Fatalf("remove waf log file: %v", err)
	}

	event, err := latestWAFBlockEvent()
	if err != nil {
		t.Fatalf("latestWAFBlockEvent error: %v", err)
	}
	if event.EventID != "req-2" {
		t.Fatalf("event_id=%q want=req-2", event.EventID)
	}
	if event.Path != "/b" {
		t.Fatalf("path=%q want=/b", event.Path)
	}
	if event.RuleID != 920350 {
		t.Fatalf("rule_id=%d want=920350", event.RuleID)
	}
	if event.MatchedVariable != "ARGS:id" {
		t.Fatalf("matched_variable=%q want=ARGS:id", event.MatchedVariable)
	}
	if event.MatchedValue != "bar" {
		t.Fatalf("matched_value=%q want=bar", event.MatchedValue)
	}
}

func TestWAFEventStoreStatusSnapshot(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"req_id":  "req-1",
			"path":    "/a",
			"rule_id": 942100,
			"country": "JP",
			"status":  403,
		},
		{
			"ts":     now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
			"event":  "waf_hit_allow",
			"req_id": "req-2",
			"path":   "/b",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	dbPath := filepath.Join(tmp, "tukuyomi.db")
	if err := InitLogsStatsStore(true, dbPath, 30); err != nil {
		t.Fatalf("init sqlite store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected sqlite store")
	}

	s1, err := store.StatusSnapshot(logPath)
	if err != nil {
		t.Fatalf("status snapshot first call: %v", err)
	}
	if s1.TotalRows != 2 {
		t.Fatalf("total_rows=%d want=2", s1.TotalRows)
	}
	if s1.WAFBlockRows != 1 {
		t.Fatalf("waf_block_rows=%d want=1", s1.WAFBlockRows)
	}
	if s1.DBSizeBytes <= 0 {
		t.Fatalf("db_size_bytes=%d want>0", s1.DBSizeBytes)
	}
	if s1.LastIngestOffset <= 0 {
		t.Fatalf("last_ingest_offset=%d want>0", s1.LastIngestOffset)
	}
	if s1.LastIngestModTime == "" {
		t.Fatal("last_ingest_mod_time is empty")
	}
	if s1.LastSyncScannedLines != len(entries) {
		t.Fatalf("first last_sync_scanned_lines=%d want=%d", s1.LastSyncScannedLines, len(entries))
	}

	s2, err := store.StatusSnapshot(logPath)
	if err != nil {
		t.Fatalf("status snapshot second call: %v", err)
	}
	if s2.LastSyncScannedLines != 0 {
		t.Fatalf("second last_sync_scanned_lines=%d want=0", s2.LastSyncScannedLines)
	}
}

func TestInitLogsStatsStore_DisablesStoreForTests(t *testing.T) {
	tmp := t.TempDir()
	dbPath := filepath.Join(tmp, "tukuyomi.db")

	if err := InitLogsStatsStoreWithBackend("db", "sqlite", dbPath, "", 30); err != nil {
		t.Fatalf("init db backend: %v", err)
	}
	if getLogsStatsStore() == nil {
		t.Fatal("expected sqlite store")
	}

	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable store: %v", err)
	}
	if getLogsStatsStore() != nil {
		t.Fatal("store should be nil after explicit disable")
	}
}

func TestInitLogsStatsStoreWithBackend_FileBackendIsRejected(t *testing.T) {
	err := InitLogsStatsStoreWithBackend("file", "sqlite", "", "", 30)
	if err == nil {
		t.Fatal("expected file backend rejection")
	}
	if !strings.Contains(err.Error(), "storage backend file has been removed") {
		t.Fatalf("unexpected error: %v", err)
	}
	if getLogsStatsStore() != nil {
		t.Fatal("store should be nil after rejected backend switch")
	}
}

func TestInitLogsStatsStoreWithBackend_MySQLRequiresDSN(t *testing.T) {
	err := InitLogsStatsStoreWithBackend("db", "mysql", "", "", 30)
	if err == nil {
		t.Fatal("expected error for missing mysql dsn")
	}
	if !strings.Contains(err.Error(), "requires storage.db_dsn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitLogsStatsStoreWithBackend_PgSQLRequiresDSN(t *testing.T) {
	err := InitLogsStatsStoreWithBackend("db", "pgsql", "", "", 30)
	if err == nil {
		t.Fatal("expected error for missing pgsql dsn")
	}
	if !strings.Contains(err.Error(), "requires storage.db_dsn") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestInitLogsStatsStoreWithBackend_InvalidBackend(t *testing.T) {
	err := InitLogsStatsStoreWithBackend("oracle", "sqlite", "ignored.db", "", 30)
	if err == nil {
		t.Fatal("expected error for invalid storage backend")
	}
	if !strings.Contains(err.Error(), "unsupported storage backend") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestWAFEventStoreSQLDialectStatements(t *testing.T) {
	sqliteStore := &wafEventStore{dbDriver: logStatsDBDriverSQLite}
	if !strings.Contains(sqliteStore.insertWAFEventStmt(), "INSERT OR IGNORE") {
		t.Fatalf("sqlite insert stmt mismatch: %s", sqliteStore.insertWAFEventStmt())
	}
	if !strings.Contains(sqliteStore.upsertIngestStateStmt(), "ON CONFLICT") {
		t.Fatalf("sqlite upsert stmt mismatch: %s", sqliteStore.upsertIngestStateStmt())
	}
	if !strings.Contains(sqliteStore.upsertConfigBlobStmt(), "ON CONFLICT") {
		t.Fatalf("sqlite config blob upsert stmt mismatch: %s", sqliteStore.upsertConfigBlobStmt())
	}

	mysqlStore := &wafEventStore{dbDriver: logStatsDBDriverMySQL}
	if !strings.Contains(mysqlStore.insertWAFEventStmt(), "INSERT IGNORE") {
		t.Fatalf("mysql insert stmt mismatch: %s", mysqlStore.insertWAFEventStmt())
	}
	if !strings.Contains(mysqlStore.upsertIngestStateStmt(), "ON DUPLICATE KEY UPDATE") {
		t.Fatalf("mysql upsert stmt mismatch: %s", mysqlStore.upsertIngestStateStmt())
	}
	if !strings.Contains(mysqlStore.upsertConfigBlobStmt(), "ON DUPLICATE KEY UPDATE") {
		t.Fatalf("mysql config blob upsert stmt mismatch: %s", mysqlStore.upsertConfigBlobStmt())
	}

	pgStore := &wafEventStore{dbDriver: logStatsDBDriverPostgres}
	if !strings.Contains(pgStore.insertWAFEventStmt(), "ON CONFLICT(line_hash) DO NOTHING") {
		t.Fatalf("pgsql insert stmt mismatch: %s", pgStore.insertWAFEventStmt())
	}
	if !strings.Contains(pgStore.upsertIngestStateStmt(), `"offset" = excluded."offset"`) {
		t.Fatalf("pgsql upsert stmt mismatch: %s", pgStore.upsertIngestStateStmt())
	}
	if got := pgStore.bindSQL("SELECT * FROM config_blobs WHERE config_key = ? AND etag = ?"); got != "SELECT * FROM config_blobs WHERE config_key = $1 AND etag = $2" {
		t.Fatalf("pgsql placeholder bind=%q", got)
	}
}

func TestConfigBlobSQLiteRoundTrip(t *testing.T) {
	tmp := t.TempDir()
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

	raw := []byte("ALLOW prefix=/assets methods=GET,HEAD ttl=300\n")
	if err := store.UpsertConfigBlob(cacheConfigBlobKey, raw, "", time.Unix(1700000000, 0).UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	gotRaw, gotETag, found, err := store.GetConfigBlob(cacheConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected config blob to exist")
	}
	if strings.TrimSpace(gotETag) == "" {
		t.Fatal("etag should not be empty")
	}
	if string(gotRaw) != string(raw) {
		t.Fatalf("raw mismatch: got=%q want=%q", string(gotRaw), string(raw))
	}
}

func TestConfigBlobMySQLRoundTrip(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("WAF_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("WAF_TEST_MYSQL_DSN is not set")
	}

	if err := InitLogsStatsStoreWithBackend("db", "mysql", "", dsn, 30); err != nil {
		t.Fatalf("init mysql store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected mysql store")
	}
	if _, err := store.db.Exec(`DELETE FROM config_blobs WHERE config_key = ?`, cacheConfigBlobKey); err != nil {
		t.Fatalf("cleanup config_blob: %v", err)
	}

	raw := []byte("DENY prefix=/tukuyomi-api/ methods=GET,HEAD\n")
	if err := store.UpsertConfigBlob(cacheConfigBlobKey, raw, "", time.Now().UTC()); err != nil {
		t.Fatalf("upsert config blob: %v", err)
	}

	gotRaw, gotETag, found, err := store.GetConfigBlob(cacheConfigBlobKey)
	if err != nil {
		t.Fatalf("get config blob: %v", err)
	}
	if !found {
		t.Fatal("expected config blob to exist")
	}
	if strings.TrimSpace(gotETag) == "" {
		t.Fatal("etag should not be empty")
	}
	if string(gotRaw) != string(raw) {
		t.Fatalf("raw mismatch: got=%q want=%q", string(gotRaw), string(raw))
	}
}

func TestLogsStatsMySQLStoreAggregatesAndIngestsIncrementally(t *testing.T) {
	dsn := strings.TrimSpace(os.Getenv("WAF_TEST_MYSQL_DSN"))
	if dsn == "" {
		t.Skip("WAF_TEST_MYSQL_DSN is not set")
	}

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-8 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 942100,
			"path":    "/mysql-login",
			"country": "JP",
			"status":  403,
			"req_id":  "mysql-req-1",
		},
		{
			"ts":      now.Add(-2 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 920350,
			"path":    "/mysql-admin",
			"country": "US",
			"status":  403,
			"req_id":  "mysql-req-2",
		},
	}

	tmp := t.TempDir()
	logPath := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, logPath, entries)

	restoreLogPath := setWAFLogPathForTest(t, logPath)
	defer restoreLogPath()

	if err := InitLogsStatsStoreWithBackend("db", "mysql", "", dsn, 30); err != nil {
		t.Fatalf("init mysql store: %v", err)
	}
	t.Cleanup(func() {
		_ = InitLogsStatsStore(false, "", 0)
	})

	store := getLogsStatsStore()
	if store == nil {
		t.Fatal("expected mysql store")
	}
	if _, err := store.db.Exec(`TRUNCATE TABLE waf_events`); err != nil {
		t.Fatalf("truncate waf_events: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM ingest_state WHERE source = ?`, logStatsStoreSourceWAF); err != nil {
		t.Fatalf("reset ingest_state: %v", err)
	}

	first := callLogsStats(t, "/tukuyomi-api/logs/stats?hours=6")
	if first.WAFBlock.TotalInScan != 2 {
		t.Fatalf("first total_in_scan=%d want=2", first.WAFBlock.TotalInScan)
	}
	if first.ScannedLines != len(entries) {
		t.Fatalf("first scanned_lines=%d want=%d", first.ScannedLines, len(entries))
	}

	appendNDJSONLine(t, logPath, map[string]any{
		"ts":      now.Add(-1 * time.Minute).Format(time.RFC3339Nano),
		"event":   "waf_block",
		"rule_id": 949110,
		"path":    "/mysql-api",
		"country": "JP",
		"status":  403,
		"req_id":  "mysql-req-3",
	})

	second := callLogsStats(t, "/tukuyomi-api/logs/stats?hours=6")
	if second.WAFBlock.TotalInScan != 3 {
		t.Fatalf("second total_in_scan=%d want=3", second.WAFBlock.TotalInScan)
	}
	if second.ScannedLines != 1 {
		t.Fatalf("second scanned_lines=%d want=1", second.ScannedLines)
	}
}

func callLogsStats(t *testing.T, path string) logsStatsResp {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)

	LogsStats(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out logsStatsResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func appendNDJSONLine(t *testing.T, path string, entry map[string]any) {
	t.Helper()

	line, err := json.Marshal(entry)
	if err != nil {
		t.Fatalf("marshal ndjson entry: %v", err)
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		t.Fatalf("open append file: %v", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		t.Fatalf("append ndjson entry: %v", err)
	}
}

func callLogsRead(t *testing.T, path string) readResp {
	t.Helper()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, path, nil)

	LogsRead(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var out readResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return out
}

func itoa64(v int64) string {
	return fmt.Sprintf("%d", v)
}
