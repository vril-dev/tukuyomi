package center

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRuntimeArtifactFilesFromDirectoryDoesNotSkipAfterRootFSSymlinkDir(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "php85")
	for _, dir := range []string{
		filepath.Join(runtimeDir, "rootfs", "usr", "bin"),
		filepath.Join(runtimeDir, "rootfs", "usr", "lib", "x86_64-linux-gnu"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		"runtime.json":       `{"runtime_id":"php85","display_name":"PHP 8.5","detected_version":"8.5.5"}`,
		"modules.json":       `["core"]`,
		"php-fpm":            "#!/bin/sh\n",
		"php":                "#!/bin/sh\n",
		"rootfs/.dockerenv":  "",
		"rootfs/usr/bin/php": "php-binary",
		"rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": "loader",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if name == "php-fpm" || name == "php" || stringsHasExecutablePayload(name) {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(runtimeDir, filepath.FromSlash(name)), []byte(body), mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.Symlink("usr/bin", filepath.Join(runtimeDir, "rootfs", "bin")); err != nil {
		t.Fatalf("symlink rootfs/bin: %v", err)
	}

	got, err := runtimeArtifactFilesFromDirectory(runtimeDir)
	if err != nil {
		t.Fatalf("runtimeArtifactFilesFromDirectory: %v", err)
	}
	paths := map[string]bool{}
	for _, file := range got {
		paths[file.ArchivePath] = true
	}
	for _, want := range []string{
		"rootfs/.dockerenv",
		"rootfs/usr/bin/php",
		"rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
	} {
		if !paths[want] {
			t.Fatalf("missing %s after symlink directory; paths=%v", want, paths)
		}
	}
}

func TestRuntimeArtifactFilesFromDirectoryStoresSymlinkAsHardlink(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "perl540")
	for _, dir := range []string{
		filepath.Join(runtimeDir, "rootfs", "usr", "local", "bin"),
		filepath.Join(runtimeDir, "rootfs", "usr", "lib", "x86_64-linux-gnu"),
		filepath.Join(runtimeDir, "rootfs", "lib"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		"runtime.json":                 `{"runtime_id":"perl540","display_name":"Perl 5.40","detected_version":"v5.40.0"}`,
		"modules.json":                 `["plack"]`,
		"perl":                         "#!/bin/sh\n",
		"starman":                      "#!/bin/sh\n",
		"rootfs/usr/local/bin/perl":    "perl-binary",
		"rootfs/usr/local/bin/starman": "starman-binary",
		"rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2": "loader",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if name == "perl" || name == "starman" || stringsHasExecutablePayload(name) || name == "rootfs/usr/local/bin/perl" || name == "rootfs/usr/local/bin/starman" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(runtimeDir, filepath.FromSlash(name)), []byte(body), mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.Symlink("../usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", filepath.Join(runtimeDir, "rootfs", "lib", "ld-linux-x86-64.so.2")); err != nil {
		t.Fatalf("symlink loader: %v", err)
	}

	got, err := runtimeArtifactFilesFromDirectory(runtimeDir)
	if err != nil {
		t.Fatalf("runtimeArtifactFilesFromDirectory: %v", err)
	}
	for _, file := range got {
		if file.ArchivePath != "rootfs/lib/ld-linux-x86-64.so.2" {
			continue
		}
		if file.LinkTarget != "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2" {
			t.Fatalf("LinkTarget=%q", file.LinkTarget)
		}
		if len(file.Body) != 0 {
			t.Fatalf("symlink body was copied into artifact input")
		}
		return
	}
	t.Fatalf("symlink file was not included")
}

func TestRuntimeArtifactFilesFromDirectoryResolvesSymlinkedParentDirectory(t *testing.T) {
	runtimeDir := filepath.Join(t.TempDir(), "perl540")
	for _, dir := range []string{
		filepath.Join(runtimeDir, "rootfs", "usr", "local", "bin"),
		filepath.Join(runtimeDir, "rootfs", "usr", "bin"),
		filepath.Join(runtimeDir, "rootfs", "etc", "alternatives"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	files := map[string]string{
		"runtime.json":                        `{"runtime_id":"perl540","display_name":"Perl 5.40","detected_version":"v5.40.0"}`,
		"modules.json":                        `["plack"]`,
		"perl":                                "#!/bin/sh\n",
		"starman":                             "#!/bin/sh\n",
		"rootfs/usr/local/bin/perl":           "perl-binary",
		"rootfs/usr/local/bin/starman":        "starman-binary",
		"rootfs/usr/bin/more":                 "more-binary",
		"rootfs/usr/bin/ld-linux-x86-64.so.2": "loader",
	}
	for name, body := range files {
		mode := os.FileMode(0o644)
		if name == "perl" || name == "starman" || stringsHasExecutablePayload(name) || name == "rootfs/usr/local/bin/perl" || name == "rootfs/usr/local/bin/starman" || name == "rootfs/usr/bin/more" || name == "rootfs/usr/bin/ld-linux-x86-64.so.2" {
			mode = 0o755
		}
		if err := os.WriteFile(filepath.Join(runtimeDir, filepath.FromSlash(name)), []byte(body), mode); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	if err := os.Symlink("usr/bin", filepath.Join(runtimeDir, "rootfs", "bin")); err != nil {
		t.Fatalf("symlink bin: %v", err)
	}
	if err := os.Symlink("/bin/more", filepath.Join(runtimeDir, "rootfs", "etc", "alternatives", "pager")); err != nil {
		t.Fatalf("symlink pager: %v", err)
	}

	got, err := runtimeArtifactFilesFromDirectory(runtimeDir)
	if err != nil {
		t.Fatalf("runtimeArtifactFilesFromDirectory: %v", err)
	}
	for _, file := range got {
		if file.ArchivePath != "rootfs/etc/alternatives/pager" {
			continue
		}
		if file.LinkTarget != "rootfs/usr/bin/more" {
			t.Fatalf("LinkTarget=%q want rootfs/usr/bin/more", file.LinkTarget)
		}
		if _, err := buildRuntimeArtifactFromDirectory(runtimeDir, centerRuntimeBuildExecution{
			RuntimeFamily: RuntimeFamilyPSGI,
			RuntimeID:     "perl540",
			Target: RuntimeTargetKey{
				OS:            "linux",
				Arch:          "amd64",
				KernelVersion: "6.8.0-test",
				DistroID:      "ubuntu",
				DistroVersion: "24.04",
			},
		}, "test"); err != nil {
			t.Fatalf("buildRuntimeArtifactFromDirectory: %v", err)
		}
		return
	}
	t.Fatalf("symlink through parent symlink was not included")
}

func stringsHasExecutablePayload(name string) bool {
	switch name {
	case "rootfs/usr/bin/php", "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2", "rootfs/usr/local/bin/perl", "rootfs/usr/local/bin/starman":
		return true
	default:
		return false
	}
}
