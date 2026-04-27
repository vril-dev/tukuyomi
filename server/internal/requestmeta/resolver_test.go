package requestmeta

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestNewDefaultResolversBuiltins(t *testing.T) {
	resolvers := NewDefaultResolvers(func() string { return "header" }, nil)
	if len(resolvers) != 2 {
		t.Fatalf("resolver count=%d want=2", len(resolvers))
	}
	if got := resolvers[0].Name(); got != "header_country" {
		t.Fatalf("resolver[0]=%q want=%q", got, "header_country")
	}
	if got := resolvers[1].Name(); got != "mmdb_country" {
		t.Fatalf("resolver[1]=%q want=%q", got, "mmdb_country")
	}
}

func TestRunResolversResolvesCountryFromHeader(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	req.Header.Set("X-Country-Code", "jp")

	ctx := NewResolverContext("10.0.0.1")
	if err := RunResolvers(req, NewDefaultResolvers(func() string { return "header" }, nil), ctx); err != nil {
		t.Fatalf("RunResolvers() error: %v", err)
	}
	if ctx.Country != "JP" {
		t.Fatalf("country=%q want=%q", ctx.Country, "JP")
	}
	if ctx.CountrySource != CountrySourceHeader {
		t.Fatalf("countrySource=%q want=%q", ctx.CountrySource, CountrySourceHeader)
	}
}

func TestRunResolversRejectsNilContext(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	if err := RunResolvers(req, nil, nil); err == nil {
		t.Fatal("expected error for nil resolver context")
	}
}

func TestRunResolversResolvesCountryFromMMDBLookup(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/demo", nil)
	ctx := NewResolverContext("203.0.113.9")
	lookup := func(clientIP string) (string, bool, error) {
		if clientIP != "203.0.113.9" {
			t.Fatalf("lookup ip=%q want=%q", clientIP, "203.0.113.9")
		}
		return "JP", true, nil
	}

	if err := RunResolvers(req, NewDefaultResolvers(func() string { return "mmdb" }, lookup), ctx); err != nil {
		t.Fatalf("RunResolvers() error: %v", err)
	}
	if ctx.Country != "JP" {
		t.Fatalf("country=%q want=%q", ctx.Country, "JP")
	}
	if ctx.CountrySource != CountrySourceMMDB {
		t.Fatalf("countrySource=%q want=%q", ctx.CountrySource, CountrySourceMMDB)
	}
}
