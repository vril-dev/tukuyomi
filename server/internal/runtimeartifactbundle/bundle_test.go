package runtimeartifactbundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBuildParsePHPFPMRuntimeArtifact(t *testing.T) {
	build := buildTestArtifact(t)
	parsed, err := Parse(build.Compressed)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.Revision != build.Revision || parsed.ArtifactHash != build.ArtifactHash {
		t.Fatalf("parsed identity mismatch parsed=%s/%s build=%s/%s", parsed.Revision, parsed.ArtifactHash, build.Revision, build.ArtifactHash)
	}
	if parsed.Manifest.RuntimeFamily != RuntimeFamilyPHPFPM || parsed.Manifest.RuntimeID != "php83" {
		t.Fatalf("unexpected runtime identity: %+v", parsed.Manifest)
	}
	if parsed.Manifest.Target.DistroID != "ubuntu" || parsed.Manifest.Target.DistroVersion != "24.04" {
		t.Fatalf("unexpected target: %+v", parsed.Manifest.Target)
	}
	if parsed.FileCount != 5 {
		t.Fatalf("file_count=%d want 5", parsed.FileCount)
	}
}

func TestParseRejectsUnsafeArchivePath(t *testing.T) {
	build := buildTestArtifact(t)
	parsed, err := Parse(build.Compressed)
	if err != nil {
		t.Fatalf("Parse valid: %v", err)
	}
	parsed.Manifest.Files[0].ArchivePath = "../runtime.json"
	raw, err := json.Marshal(parsed.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	bundle := gzipTarForTest(t, map[string][]byte{
		"manifest.json":   raw,
		"../runtime.json": []byte(`{"runtime_id":"php83","display_name":"PHP 8.3","detected_version":"8.3.30","source":"bundled"}`),
	})
	if _, err := Parse(bundle); err == nil || !strings.Contains(err.Error(), "unsafe archive path") {
		t.Fatalf("Parse unsafe path err=%v", err)
	}
}

func TestParseRejectsSymlinkEntry(t *testing.T) {
	build := buildTestArtifact(t)
	parsed, err := Parse(build.Compressed)
	if err != nil {
		t.Fatalf("Parse valid: %v", err)
	}
	raw, err := json.Marshal(parsed.Manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	if err := tw.WriteHeader(&tar.Header{Name: "manifest.json", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(raw))}); err != nil {
		t.Fatalf("write manifest header: %v", err)
	}
	if _, err := tw.Write(raw); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := tw.WriteHeader(&tar.Header{Name: "runtime.json", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Mode: 0o777}); err != nil {
		t.Fatalf("write symlink header: %v", err)
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	if _, err := Parse(compressed.Bytes()); err == nil || !strings.Contains(err.Error(), "non-regular") {
		t.Fatalf("Parse symlink err=%v", err)
	}
}

func buildTestArtifact(t *testing.T) Build {
	t.Helper()
	build, err := BuildBundle(BuildInput{
		RuntimeFamily:   RuntimeFamilyPHPFPM,
		RuntimeID:       "php83",
		DisplayName:     "PHP 8.3",
		DetectedVersion: "8.3.30",
		Target: TargetKey{
			OS:            "linux",
			Arch:          "amd64",
			KernelVersion: "6.8.0-test",
			DistroID:      "ubuntu",
			DistroIDLike:  "debian",
			DistroVersion: "24.04",
		},
		BuilderVersion: "test-builder",
		BuilderProfile: "ubuntu-24.04-amd64",
		GeneratedAt:    time.Unix(1000, 0).UTC(),
		Files: []File{
			{
				ArchivePath: "runtime.json",
				FileKind:    "metadata",
				Mode:        0o644,
				Body:        []byte(`{"runtime_id":"php83","display_name":"PHP 8.3","detected_version":"8.3.30","source":"bundled"}`),
			},
			{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["core","date"]`)},
			{ArchivePath: "php-fpm", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "php", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
			{ArchivePath: "rootfs/usr/bin/php", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-binary")},
		},
	})
	if err != nil {
		t.Fatalf("BuildBundle: %v", err)
	}
	return build
}

func gzipTarForTest(t *testing.T, files map[string][]byte) []byte {
	t.Helper()
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for name, body := range files {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatalf("write header: %v", err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatalf("write body: %v", err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatalf("close tar: %v", err)
	}
	var compressed bytes.Buffer
	gw := gzip.NewWriter(&compressed)
	if _, err := gw.Write(tarBuf.Bytes()); err != nil {
		t.Fatalf("write gzip: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("close gzip: %v", err)
	}
	return compressed.Bytes()
}
