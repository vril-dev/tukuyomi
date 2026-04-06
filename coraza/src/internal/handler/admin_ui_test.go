package handler

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadAdminUIAssetFallsBackToPlaceholder(t *testing.T) {
	uiFS := fstest.MapFS{
		"placeholder.html": {Data: []byte("<html>placeholder</html>")},
	}

	raw, resolvedPath, placeholder, err := readAdminUIAsset(uiFS, "missing.js")
	if err != nil {
		t.Fatalf("readAdminUIAsset returned error: %v", err)
	}
	if !placeholder {
		t.Fatal("expected placeholder fallback")
	}
	if resolvedPath != "placeholder.html" {
		t.Fatalf("resolvedPath=%q want=%q", resolvedPath, "placeholder.html")
	}
	if string(raw) != "<html>placeholder</html>" {
		t.Fatalf("raw=%q want placeholder html", string(raw))
	}
}

func TestReadAdminUIAssetReturnsExistingAsset(t *testing.T) {
	uiFS := fstest.MapFS{
		"index.html":       {Data: []byte("<html>real</html>")},
		"assets/app.js":    {Data: []byte("console.log('ok')")},
		"placeholder.html": {Data: []byte("<html>placeholder</html>")},
	}

	raw, resolvedPath, placeholder, err := readAdminUIAsset(uiFS, "assets/app.js")
	if err != nil {
		t.Fatalf("readAdminUIAsset returned error: %v", err)
	}
	if placeholder {
		t.Fatal("did not expect placeholder fallback")
	}
	if resolvedPath != "assets/app.js" {
		t.Fatalf("resolvedPath=%q want=%q", resolvedPath, "assets/app.js")
	}
	if !strings.Contains(string(raw), "console.log") {
		t.Fatalf("unexpected asset payload: %q", string(raw))
	}
}
