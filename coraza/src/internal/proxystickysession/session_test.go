package proxystickysession

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCookieBuildsAndParsesSignedID(t *testing.T) {
	now := time.Now().UTC()
	cfg := Config{
		Enabled:    true,
		CookieName: "tky_lb_site_api",
		TTLSeconds: 60,
		Path:       "/",
		SameSite:   "strict",
	}

	cookie := Cookie(cfg, "blue|west", now)
	if cookie == nil {
		t.Fatal("cookie was not built")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("same_site=%v want strict", cookie.SameSite)
	}
	got, ok := ParseValue(cookie.Name, cookie.Value, now)
	if !ok {
		t.Fatal("cookie should parse")
	}
	if got != "blue|west" {
		t.Fatalf("sticky_id=%q want blue|west", got)
	}
}

func TestRequestIDRejectsInvalidCookie(t *testing.T) {
	now := time.Now().UTC()
	cfg := Config{Enabled: true, CookieName: "tky_lb_site_api", TTLSeconds: 60}

	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.AddCookie(&http.Cookie{Name: cfg.CookieName, Value: strings.Repeat("x", MaxCookieBytes+1)})
	if _, ok := RequestID(req, cfg, now); ok {
		t.Fatal("oversized cookie should be rejected")
	}

	value := BuildValue(cfg.CookieName, "blue", now)
	if _, ok := ParseValue(cfg.CookieName, value, now); ok {
		t.Fatal("expired cookie should be rejected")
	}
	if _, ok := ParseValue(cfg.CookieName, value+"x", now); ok {
		t.Fatal("tampered cookie should be rejected")
	}
}

func TestHTTPOnlyDefault(t *testing.T) {
	if !HTTPOnly(Config{}) {
		t.Fatal("default HTTPOnly should be true")
	}
	disabled := false
	if HTTPOnly(Config{HTTPOnly: &disabled}) {
		t.Fatal("explicit false HTTPOnly should be honored")
	}
}
