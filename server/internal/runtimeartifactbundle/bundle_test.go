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
	if parsed.FileCount != 7 {
		t.Fatalf("file_count=%d want 7", parsed.FileCount)
	}
}

func TestBuildParsePSGIRuntimeArtifact(t *testing.T) {
	cases := []struct {
		runtimeID       string
		displayName     string
		detectedVersion string
	}{
		{runtimeID: "perl536", displayName: "Perl 5.36", detectedVersion: "v5.36.0"},
		{runtimeID: "perl538", displayName: "Perl 5.38", detectedVersion: "v5.38.5"},
		{runtimeID: "perl540", displayName: "Perl 5.40", detectedVersion: "v5.40.0"},
	}
	for _, tc := range cases {
		t.Run(tc.runtimeID, func(t *testing.T) {
			build, err := BuildBundle(BuildInput{
				RuntimeFamily:   RuntimeFamilyPSGI,
				RuntimeID:       tc.runtimeID,
				DisplayName:     tc.displayName,
				DetectedVersion: tc.detectedVersion,
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
						Body:        []byte(`{"runtime_id":"` + tc.runtimeID + `","display_name":"` + tc.displayName + `","detected_version":"` + tc.detectedVersion + `","perl_path":"data/psgi/binaries/` + tc.runtimeID + `/perl","starman_path":"data/psgi/binaries/` + tc.runtimeID + `/starman","source":"bundled"}`),
					},
					{ArchivePath: "modules.json", FileKind: "metadata", Mode: 0o644, Body: []byte(`["plack","starman"]`)},
					{ArchivePath: "perl", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
					{ArchivePath: "starman", FileKind: "binary", Mode: 0o755, Body: []byte("#!/bin/sh\n")},
					{ArchivePath: "rootfs/usr/bin/perl", FileKind: "rootfs", Mode: 0o755, Body: []byte("perl-binary")},
					{ArchivePath: "rootfs/usr/bin/starman", FileKind: "rootfs", Mode: 0o755, Body: []byte("starman-binary")},
					{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
				},
			})
			if err != nil {
				t.Fatalf("BuildBundle: %v", err)
			}
			parsed, err := Parse(build.Compressed)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if parsed.Manifest.RuntimeFamily != RuntimeFamilyPSGI || parsed.Manifest.RuntimeID != tc.runtimeID {
				t.Fatalf("unexpected runtime identity: %+v", parsed.Manifest)
			}
			if parsed.FileCount != 7 {
				t.Fatalf("file_count=%d want 7", parsed.FileCount)
			}
		})
	}
}

func TestBuildRejectsIncompleteRuntimeRootFS(t *testing.T) {
	_, err := BuildBundle(BuildInput{
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
			{ArchivePath: "rootfs/.dockerenv", FileKind: "rootfs", Mode: 0o755, Body: nil},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "dynamic loader") {
		t.Fatalf("BuildBundle incomplete rootfs err=%v", err)
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
			{ArchivePath: "rootfs/usr/local/sbin/php-fpm", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-fpm-binary")},
			{ArchivePath: "rootfs/usr/bin/php", FileKind: "rootfs", Mode: 0o755, Body: []byte("php-binary")},
			{ArchivePath: "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", FileKind: "rootfs", Mode: 0o755, Body: []byte("loader")},
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
