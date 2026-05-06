package center

import (
	"errors"
	"strings"
	"testing"

	"tukuyomi/internal/appdeploybundle"
)

func TestNormalizeAppDeployRootsAllowsSourceRoot(t *testing.T) {
	roots, raw, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
		RootID:         "source_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/vhosts/app",
		PackagePrefix:  ".",
		TargetSubpath:  ".",
		RuntimeSubpath: "public",
		Required:       true,
	}})
	if err != nil {
		t.Fatalf("normalizeAppDeployRoots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("len(roots)=%d want 1", len(roots))
	}
	root := roots[0]
	if root.SourcePath != "data/vhosts/app" {
		t.Fatalf("SourcePath=%q want data/vhosts/app", root.SourcePath)
	}
	if root.PackagePrefix != "" || root.TargetSubpath != "" {
		t.Fatalf("package/target=%q/%q want empty", root.PackagePrefix, root.TargetSubpath)
	}
	if root.RuntimeSubpath != "public" {
		t.Fatalf("RuntimeSubpath=%q want public", root.RuntimeSubpath)
	}
	if !strings.Contains(raw, `"source_path":"data/vhosts/app"`) || !strings.Contains(raw, `"runtime_subpath":"public"`) {
		t.Fatalf("normalized roots JSON omitted source/runtime subpath: %s", raw)
	}
}

func TestNormalizeAppDeployRootsRejectsUnsafeSourcePath(t *testing.T) {
	for _, sourcePath := range []string{"/srv/app", "etc", "data"} {
		_, _, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
			RootID:        "source_root",
			RuntimeField:  "document_root",
			SourcePath:    sourcePath,
			PackagePrefix: ".",
			TargetSubpath: ".",
			Required:      true,
		}})
		if !errors.Is(err, ErrAppDeployInvalid) {
			t.Fatalf("source_path=%q err=%v want ErrAppDeployInvalid", sourcePath, err)
		}
	}
}

func TestAppDeployFilesForParsedPackageAllowsRootPackagePrefix(t *testing.T) {
	roots, _, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
		RootID:         "source_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/vhosts/app",
		PackagePrefix:  "",
		TargetSubpath:  "",
		RuntimeSubpath: "public",
		Required:       true,
	}})
	if err != nil {
		t.Fatalf("normalizeAppDeployRoots: %v", err)
	}
	files, err := appDeployFilesForParsedPackage(appdeploybundle.Parsed{Files: []appdeploybundle.File{
		{Path: "artisan", SHA256: strings.Repeat("a", 64), SizeBytes: 1, Mode: 0o644},
		{Path: "public/index.php", SHA256: strings.Repeat("b", 64), SizeBytes: 2, Mode: 0o644},
	}}, roots)
	if err != nil {
		t.Fatalf("appDeployFilesForParsedPackage: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("len(files)=%d want 2", len(files))
	}
	for _, file := range files {
		if file.RootID != "source_root" {
			t.Fatalf("file %q RootID=%q want source_root", file.Path, file.RootID)
		}
	}
}
