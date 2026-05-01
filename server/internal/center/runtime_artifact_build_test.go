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

func stringsHasExecutablePayload(name string) bool {
	switch name {
	case "rootfs/usr/bin/php", "rootfs/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2":
		return true
	default:
		return false
	}
}
