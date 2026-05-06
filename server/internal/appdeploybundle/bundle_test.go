package appdeploybundle

import (
	"archive/zip"
	"bytes"
	"strings"
	"testing"
)

func TestParseZIPStripsSingleWrapperDirectory(t *testing.T) {
	raw := testZip(t, map[string]string{
		"release/public/index.php": "<?php echo 'ok';",
		"release/config/app.php":   "<?php return [];",
	})

	parsed, err := ParseZIP(raw)
	if err != nil {
		t.Fatalf("ParseZIP: %v", err)
	}
	got := []string{}
	for _, file := range parsed.Files {
		got = append(got, file.Path)
	}
	want := []string{"config/app.php", "public/index.php"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paths=%v want %v", got, want)
	}
	if parsed.FileCount != 2 {
		t.Fatalf("file_count=%d want 2", parsed.FileCount)
	}
	if ValidateRevision(parsed.Revision) == "" || parsed.Revision != parsed.PackageHash {
		t.Fatalf("invalid revision/hash revision=%q hash=%q", parsed.Revision, parsed.PackageHash)
	}
}

func TestParseZIPKeepsMeaningfulTopLevelFiles(t *testing.T) {
	raw := testZip(t, map[string]string{
		"tukuyomi.conf":           "Include rules/*.conf",
		"rules/example.conf":      "SecRuleEngine On",
		"_tukuyomi/metadata.json": "{}",
	})

	parsed, err := ParseZIP(raw)
	if err != nil {
		t.Fatalf("ParseZIP: %v", err)
	}
	got := []string{}
	for _, file := range parsed.Files {
		got = append(got, file.Path)
	}
	want := []string{"_tukuyomi/metadata.json", "rules/example.conf", "tukuyomi.conf"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("paths=%v want %v", got, want)
	}
}

func TestParseZIPPreservePathsKeepsSingleRootPrefix(t *testing.T) {
	raw := testZip(t, map[string]string{
		"public/index.php": "<?php echo 'ok';",
	})

	parsed, err := ParseZIPPreservePaths(raw)
	if err != nil {
		t.Fatalf("ParseZIPPreservePaths: %v", err)
	}
	if len(parsed.Files) != 1 || parsed.Files[0].Path != "public/index.php" {
		t.Fatalf("paths=%v want public/index.php", parsed.Files)
	}
}

func TestParseZIPRejectsUnsafePath(t *testing.T) {
	raw := testZip(t, map[string]string{
		"../escape.php": "bad",
	})

	if _, err := ParseZIP(raw); err == nil {
		t.Fatal("ParseZIP succeeded for unsafe path")
	}
}

func TestParseZIPRejectsDuplicateCleanPath(t *testing.T) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, name := range []string{"app/index.php", "app/./index.php"} {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry: %v", err)
		}
		if _, err := w.Write([]byte("body")); err != nil {
			t.Fatalf("write zip entry: %v", err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}

	if _, err := ParseZIP(buf.Bytes()); err == nil {
		t.Fatal("ParseZIP succeeded for duplicate clean path")
	}
}

func testZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
