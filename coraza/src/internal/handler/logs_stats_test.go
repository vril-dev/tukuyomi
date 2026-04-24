package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestLogsStatsRequiresDBStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable logs db store: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/stats", nil)

	LogsStats(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	if !json.Valid(w.Body.Bytes()) {
		t.Fatalf("expected json response: %s", w.Body.String())
	}
}

func TestLogsReadWAFRequiresDBStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable logs db store: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/read?src=waf&tail=10", nil)

	LogsRead(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
}

func TestLogsDownloadWAFRequiresDBStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	if err := InitLogsStatsStore(false, "", 0); err != nil {
		t.Fatalf("disable logs db store: %v", err)
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/tukuyomi-api/logs/download?src=waf", nil)

	LogsDownload(c)

	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
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
