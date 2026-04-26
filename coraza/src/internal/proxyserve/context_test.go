package proxyserve

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestContextJSONWritesPlainHTTPResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx := New(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))

	ctx.JSON(http.StatusTeapot, map[string]string{"error": "short"})

	res := rec.Result()
	res.Body.Close()
	if res.StatusCode != http.StatusTeapot {
		t.Fatalf("status=%d want %d", res.StatusCode, http.StatusTeapot)
	}
	if ct := res.Header.Get("Content-Type"); !strings.Contains(ct, "application/json") {
		t.Fatalf("content-type=%q want json", ct)
	}
	if body := rec.Body.String(); !strings.Contains(body, `"error":"short"`) {
		t.Fatalf("body=%q want error payload", body)
	}
}

func TestContextAbortWithStatusWritesPlainHTTPResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	ctx := New(rec, httptest.NewRequest(http.MethodGet, "http://example.test/", nil))

	ctx.AbortWithStatus(http.StatusForbidden)

	res := rec.Result()
	res.Body.Close()
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d want %d", res.StatusCode, http.StatusForbidden)
	}
}
