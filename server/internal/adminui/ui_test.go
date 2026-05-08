package adminui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/gin-gonic/gin"
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

func TestRegisterRoutesMarksHTMLFallbackNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	uiFS := fstest.MapFS{
		"index.html":       {Data: []byte("<html>real</html>")},
		"placeholder.html": {Data: []byte("<html>placeholder</html>")},
	}
	r := gin.New()
	RegisterRoutes(r, Options{FS: uiFS, BasePath: "/tukuyomi-ui"})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-ui/login", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusOK, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q want no-store", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x-content-type-options=%q want nosniff", got)
	}
}

func TestRegisterRoutesMarksAccessDeniedNoStore(t *testing.T) {
	gin.SetMode(gin.TestMode)
	uiFS := fstest.MapFS{
		"index.html": {Data: []byte("<html>real</html>")},
	}
	r := gin.New()
	RegisterRoutes(r, Options{
		FS:          uiFS,
		BasePath:    "/tukuyomi-ui",
		CheckAccess: func(*http.Request) bool { return false },
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/tukuyomi-ui/login", nil)
	r.ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d body=%s", rec.Code, http.StatusForbidden, rec.Body.String())
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("cache-control=%q want no-store", got)
	}
	if got := rec.Header().Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("x-content-type-options=%q want nosniff", got)
	}
}
