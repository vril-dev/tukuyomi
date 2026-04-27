package botchallenge

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWriteHTMLChallengeIncludesTelemetryWriter(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("Accept", "text/html")

	Write(rec, req, Decision{
		Status:            http.StatusTooManyRequests,
		CookieName:        "__bot_ok",
		BrowserCookieName: "__bot_js",
		Token:             "token",
		TTLSeconds:        60,
	})

	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusTooManyRequests)
	}
	body := rec.Body.String()
	for _, want := range []string{"__bot_ok", "__bot_js", "navigator.webdriver"} {
		if !strings.Contains(body, want) {
			t.Fatalf("body missing %q:\n%s", want, body)
		}
	}
}

func TestWriteJSONChallengeWhenHTMLNotAccepted(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "https://example.test/", nil)
	req.Header.Set("Accept", "application/json")

	Write(rec, req, Decision{Status: http.StatusForbidden})
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status=%d want=%d", rec.Code, http.StatusForbidden)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Fatalf("content-type=%q", got)
	}
}
