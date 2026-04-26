package adminaudit

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type testEntry struct {
	Event string `json:"event"`
	Count int    `json:"count"`
}

func TestAppendAndLatestReturnNewestFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.ndjson")
	for i := 1; i <= 3; i++ {
		if err := Append(path, testEntry{Event: "test", Count: i}); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	entries, err := Latest[testEntry](path, 2, "test")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if len(entries) != 2 || entries[0].Count != 3 || entries[1].Count != 2 {
		t.Fatalf("entries=%#v", entries)
	}
}

func TestLatestMissingFileReturnsEmpty(t *testing.T) {
	entries, err := Latest[testEntry](filepath.Join(t.TempDir(), "missing.ndjson"), DefaultLimit, "test")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("entries=%d want=0", len(entries))
	}
}

func TestLatestDecodeErrorIsLabeled(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broken.ndjson")
	if err := os.WriteFile(path, []byte("{broken}\n"), 0o644); err != nil {
		t.Fatalf("write broken audit: %v", err)
	}
	if _, err := Latest[testEntry](path, DefaultLimit, "proxy"); err == nil || !strings.Contains(err.Error(), "decode proxy audit entry") {
		t.Fatalf("err=%v", err)
	}
}

func TestParseLimitClamps(t *testing.T) {
	if got := ParseLimit("0"); got != 1 {
		t.Fatalf("ParseLimit(0)=%d want=1", got)
	}
	if got := ParseLimit("200"); got != MaxLimit {
		t.Fatalf("ParseLimit(200)=%d want=%d", got, MaxLimit)
	}
}
