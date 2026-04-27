package proxyerror

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResponseZeroValueWritesBadGateway(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "http://example.test/app", nil)
	rec := httptest.NewRecorder()

	Response{}.Write(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusBadGateway {
		t.Fatalf("unexpected status: %d", res.StatusCode)
	}
	if !strings.Contains(string(body), "Bad Gateway") {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestResponseWritesCustomHTMLForHTMLRequests(t *testing.T) {
	tmp := t.TempDir()
	htmlPath := filepath.Join(tmp, "proxy-error.html")
	htmlBody := "<html><body><h1>maintenance</h1></body></html>"
	if err := os.WriteFile(htmlPath, []byte(htmlBody), 0o644); err != nil {
		t.Fatalf("write html: %v", err)
	}
	resp, err := New(Config{HTMLFile: htmlPath})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/app", nil)
	req.Header.Set("Accept", "text/html")
	rec := httptest.NewRecorder()
	resp.Write(rec, req)

	res := rec.Result()
	body, _ := io.ReadAll(res.Body)
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("unexpected status: %d", res.StatusCode)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "text/html") {
		t.Fatalf("unexpected content-type: %q", ct)
	}
	if string(body) != htmlBody {
		t.Fatalf("unexpected body: %q", string(body))
	}
}

func TestResponseRedirectsOnlySafeMethods(t *testing.T) {
	resp, err := New(Config{RedirectURL: "/maintenance"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, method := range []string{http.MethodGet, http.MethodHead} {
		req := httptest.NewRequest(method, "http://example.test/app", nil)
		rec := httptest.NewRecorder()
		resp.Write(rec, req)
		res := rec.Result()
		res.Body.Close()
		if res.StatusCode != http.StatusFound {
			t.Fatalf("%s unexpected status: %d", method, res.StatusCode)
		}
		if got := res.Header.Get("Location"); got != "/maintenance" {
			t.Fatalf("%s unexpected location: %q", method, got)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "http://example.test/app", nil)
	rec := httptest.NewRecorder()
	resp.Write(rec, req)
	res := rec.Result()
	res.Body.Close()
	if res.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("POST unexpected status: %d", res.StatusCode)
	}
	if got := res.Header.Get("Location"); got != "" {
		t.Fatalf("POST unexpected location: %q", got)
	}
}

func TestNewRejectsInvalidConfiguration(t *testing.T) {
	tmp := t.TempDir()
	htmlPath := filepath.Join(tmp, "proxy-error.html")
	if err := os.WriteFile(htmlPath, []byte("body"), 0o644); err != nil {
		t.Fatalf("write html: %v", err)
	}

	cases := []struct {
		name string
		cfg  Config
	}{
		{
			name: "exclusive",
			cfg:  Config{HTMLFile: htmlPath, RedirectURL: "/maintenance"},
		},
		{
			name: "unsupported scheme",
			cfg:  Config{RedirectURL: "javascript:alert(1)"},
		},
		{
			name: "relative without slash",
			cfg:  Config{RedirectURL: "maintenance"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := New(tc.cfg); err == nil {
				t.Fatal("expected error")
			}
		})
	}
}
