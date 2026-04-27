package requestmeta

import (
	"net/http"
	"testing"
)

func TestClientIPFromHeaders(t *testing.T) {
	if got := ClientIPFromHeaders(" 203.0.113.10 ", "198.51.100.1", "127.0.0.1"); got != "203.0.113.10" {
		t.Fatalf("real ip=%q", got)
	}
	if got := ClientIPFromHeaders("", " 198.51.100.1, 198.51.100.2 ", "127.0.0.1"); got != "198.51.100.1" {
		t.Fatalf("forwarded ip=%q", got)
	}
	if got := ClientIPFromHeaders("", "", " 127.0.0.1 "); got != "127.0.0.1" {
		t.Fatalf("fallback ip=%q", got)
	}
}

func TestClientIPFromHTTP(t *testing.T) {
	req, err := http.NewRequest(http.MethodGet, "http://example.test/", nil)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.RemoteAddr = "127.0.0.1:12345"
	if got := ClientIPFromHTTP(req); got != "127.0.0.1" {
		t.Fatalf("remote addr ip=%q", got)
	}
	req.Header.Set("X-Forwarded-For", "198.51.100.10, 198.51.100.11")
	if got := ClientIPFromHTTP(req); got != "198.51.100.10" {
		t.Fatalf("forwarded ip=%q", got)
	}
}
