package adminui

import (
	"strings"
	"testing"
	"testing/fstest"
)

func TestReadAssetFallsBackToPlaceholder(t *testing.T) {
	uiFS := fstest.MapFS{
		"placeholder.html": {Data: []byte("<html>placeholder</html>")},
	}

	raw, resolvedPath, placeholder, err := ReadAsset(uiFS, "missing.js")
	if err != nil {
		t.Fatalf("ReadAsset returned error: %v", err)
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

func TestReadAssetReturnsExistingAsset(t *testing.T) {
	uiFS := fstest.MapFS{
		"index.html":       {Data: []byte("<html>real</html>")},
		"assets/app.js":    {Data: []byte("console.log('ok')")},
		"placeholder.html": {Data: []byte("<html>placeholder</html>")},
	}

	raw, resolvedPath, placeholder, err := ReadAsset(uiFS, "assets/app.js")
	if err != nil {
		t.Fatalf("ReadAsset returned error: %v", err)
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
