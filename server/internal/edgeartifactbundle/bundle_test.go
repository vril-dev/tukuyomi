package edgeartifactbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildParseBundleRoundTrip(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	built, err := BuildBundle([]RuleFile{
		{Path: "rules/b.conf", Kind: "crs_asset", ETag: "b", Body: []byte("SecRule ARGS b")},
		{Path: "rules/a.conf", Kind: "base", ETag: "a", Disabled: true, Body: []byte("SecRule ARGS a")},
	}, now)
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	if built.Revision == "" || built.BundleHash == "" || built.FileCount != 2 {
		t.Fatalf("unexpected build metadata: %+v", built)
	}
	parsed, err := Parse(built.Compressed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Revision != built.Revision || parsed.BundleHash != built.BundleHash || parsed.FileCount != 2 {
		t.Fatalf("parsed metadata mismatch: built=%+v parsed=%+v", built, parsed)
	}
	if parsed.Files[0].Path != "rules/a.conf" || !parsed.Files[0].Disabled || string(parsed.Files[0].Body) != "SecRule ARGS a" {
		t.Fatalf("first parsed file mismatch: %+v", parsed.Files[0])
	}
	if parsed.Files[1].Path != "rules/b.conf" || string(parsed.Files[1].Body) != "SecRule ARGS b" {
		t.Fatalf("second parsed file mismatch: %+v", parsed.Files[1])
	}
}

func TestBuildBundleRevisionIgnoresGeneratedAt(t *testing.T) {
	files := []RuleFile{{Path: "rules/a.conf", Kind: "base", Body: []byte("same")}}
	first, err := BuildBundle(files, time.Unix(1, 0).UTC())
	if err != nil {
		t.Fatalf("first BuildBundle: %v", err)
	}
	second, err := BuildBundle(files, time.Unix(2, 0).UTC())
	if err != nil {
		t.Fatalf("second BuildBundle: %v", err)
	}
	if first.Revision != second.Revision {
		t.Fatalf("revision changed with generated_at: %s != %s", first.Revision, second.Revision)
	}
}

func TestBuildBundleRejectsTraversalPath(t *testing.T) {
	_, err := BuildBundle([]RuleFile{{Path: "../rules/a.conf", Kind: "base", Body: []byte("bad")}}, time.Now())
	if err == nil || !strings.Contains(err.Error(), "path") {
		t.Fatalf("expected path rejection, got %v", err)
	}
}

func TestParseRejectsSymlink(t *testing.T) {
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	manifest := Manifest{
		SchemaVersion: SchemaVersion,
		Files: []FileManifest{{
			Path:        "rules/a.conf",
			ArchivePath: "files/000001.conf",
			Kind:        "base",
			SHA256:      strings.Repeat("0", 64),
			SizeBytes:   0,
		}},
	}
	revision, err := Revision(manifest)
	if err != nil {
		t.Fatalf("Revision: %v", err)
	}
	manifest.BundleRevision = revision
	manifestRaw, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	if err := writeTarFile(tw, "manifest.json", manifestRaw); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "files/000001.conf", Typeflag: tar.TypeSymlink, Linkname: "rules/a.conf"}); err != nil {
		t.Fatalf("write symlink header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	var gzBuf bytes.Buffer
	gw := gzip.NewWriter(&gzBuf)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	_, err = Parse(gzBuf.Bytes())
	if err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
}
