package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
)

func TestLogsStatsAggregatesWAFBlocks(t *testing.T) {
	gin.SetMode(gin.TestMode)

	now := time.Now().UTC()
	entries := []map[string]any{
		{
			"ts":      now.Add(-10 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 942100,
			"path":    "/login",
			"country": "jp",
		},
		{
			"ts":      now.Add(-2 * time.Hour).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": "920350",
			"path":    "/admin",
			"country": "US",
		},
		{
			"ts":      now.Add(-26 * time.Hour).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": 942100,
			"path":    "/old",
			"country": "DE",
		},
		{
			"ts":    now.Add(-15 * time.Minute).Format(time.RFC3339Nano),
			"event": "waf_hit_allow",
			"path":  "/allow",
		},
		{
			"ts":      now.Add(-20 * time.Minute).Format(time.RFC3339Nano),
			"event":   "waf_block",
			"rule_id": nil,
			"path":    "",
			"country": "",
		},
		{
			"ts":      "invalid-ts",
			"event":   "waf_block",
			"rule_id": 999999,
			"path":    "/invalid",
			"country": "CN",
		},
	}

	tmp := t.TempDir()
	path := filepath.Join(tmp, "waf-events.ndjson")
	writeNDJSONFile(t, path, entries)

	restore := setWAFLogPathForTest(t, path)
	defer restore()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/stats?scan=100&hours=6", nil)

	LogsStats(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out logsStatsResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if out.ScannedLines != len(entries) {
		t.Fatalf("scanned_lines=%d want=%d", out.ScannedLines, len(entries))
	}
	if out.RangeHours != 6 {
		t.Fatalf("range_hours=%d want=6", out.RangeHours)
	}

	if out.WAFBlock.TotalInScan != 5 {
		t.Fatalf("total_in_scan=%d want=5", out.WAFBlock.TotalInScan)
	}
	if out.WAFBlock.Last1h != 2 {
		t.Fatalf("last_1h=%d want=2", out.WAFBlock.Last1h)
	}
	if out.WAFBlock.Last24h != 3 {
		t.Fatalf("last_24h=%d want=3", out.WAFBlock.Last24h)
	}

	assertBucketKeys(t, out.WAFBlock.TopRuleIDs24h, []string{"920350", "942100", "UNKNOWN"})
	assertBucketKeys(t, out.WAFBlock.TopPaths24h, []string{"/", "/admin", "/login"})
	assertBucketKeys(t, out.WAFBlock.TopCountries24h, []string{"JP", "UNKNOWN", "US"})

	if len(out.WAFBlock.SeriesHourly) != 6 {
		t.Fatalf("series_hourly length=%d want=6", len(out.WAFBlock.SeriesHourly))
	}

	expectedByHour := map[string]int{}
	for _, ts := range []time.Time{
		now.Add(-10 * time.Minute),
		now.Add(-20 * time.Minute),
		now.Add(-2 * time.Hour),
	} {
		key := ts.UTC().Truncate(time.Hour).Format(time.RFC3339)
		expectedByHour[key]++
	}
	for bucketStart, expectedCount := range expectedByHour {
		gotCount := countByHour(out.WAFBlock.SeriesHourly, bucketStart)
		if gotCount != expectedCount {
			t.Fatalf("series[%s]=%d want=%d", bucketStart, gotCount, expectedCount)
		}
	}
}

func TestLogsStatsMissingLogReturnsEmptyPayload(t *testing.T) {
	gin.SetMode(gin.TestMode)

	path := filepath.Join(t.TempDir(), "missing-waf-events.ndjson")
	restore := setWAFLogPathForTest(t, path)
	defer restore()

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/stats", nil)

	LogsStats(c)

	if w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}

	var out logsStatsResp
	if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
		t.Fatalf("decode response: %v", err)
	}

	if out.ScannedLines != 0 {
		t.Fatalf("scanned_lines=%d want=0", out.ScannedLines)
	}
	if out.RangeHours != defaultStatsRangeHours {
		t.Fatalf("range_hours=%d want=%d", out.RangeHours, defaultStatsRangeHours)
	}
	if out.WAFBlock.TotalInScan != 0 || out.WAFBlock.Last1h != 0 || out.WAFBlock.Last24h != 0 {
		t.Fatalf("unexpected counters: %+v", out.WAFBlock)
	}
	if len(out.WAFBlock.TopRuleIDs24h) != 0 || len(out.WAFBlock.TopPaths24h) != 0 || len(out.WAFBlock.TopCountries24h) != 0 {
		t.Fatalf("expected empty top buckets: %+v", out.WAFBlock)
	}
	if len(out.WAFBlock.SeriesHourly) != defaultStatsRangeHours {
		t.Fatalf("series_hourly length=%d want=%d", len(out.WAFBlock.SeriesHourly), defaultStatsRangeHours)
	}
	for i, point := range out.WAFBlock.SeriesHourly {
		if point.Count != 0 {
			t.Fatalf("series_hourly[%d] count=%d want=0", i, point.Count)
		}
	}
}

func setWAFLogPathForTest(t *testing.T, path string) func() {
	t.Helper()

	oldPath := logFiles["waf"]
	logFiles["waf"] = path

	idxMu.Lock()
	fileIx = map[string]*lineIndex{}
	idxMu.Unlock()

	return func() {
		logFiles["waf"] = oldPath
		idxMu.Lock()
		fileIx = map[string]*lineIndex{}
		idxMu.Unlock()
	}
}

func writeNDJSONFile(t *testing.T, path string, entries []map[string]any) {
	t.Helper()

	buf := make([]byte, 0, len(entries)*128)
	for _, entry := range entries {
		line, err := json.Marshal(entry)
		if err != nil {
			t.Fatalf("marshal ndjson entry: %v", err)
		}
		buf = append(buf, line...)
		buf = append(buf, '\n')
	}
	if err := os.WriteFile(path, buf, 0o644); err != nil {
		t.Fatalf("write ndjson fixture: %v", err)
	}
}

func assertBucketKeys(t *testing.T, got []statsBucket, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("bucket length=%d want=%d (got=%+v)", len(got), len(want), got)
	}
	for i := range want {
		if got[i].Key != want[i] {
			t.Fatalf("bucket[%d].key=%q want=%q", i, got[i].Key, want[i])
		}
	}
}

func countByHour(series []statsSeriesPoint, bucketStart string) int {
	for _, point := range series {
		if point.BucketStart == bucketStart {
			return point.Count
		}
	}
	return -1
}
