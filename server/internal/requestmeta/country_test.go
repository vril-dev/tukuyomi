package requestmeta

import "testing"

func TestNormalizeCountryCode(t *testing.T) {
	if got := NormalizeCountryCode(" jp "); got != "JP" {
		t.Fatalf("country=%q want JP", got)
	}
	if got := NormalizeCountryCode("-"); got != "UNKNOWN" {
		t.Fatalf("country=%q want UNKNOWN", got)
	}
}

func TestCountryFilter(t *testing.T) {
	if got := NormalizeCountryFilter("all"); got != "" {
		t.Fatalf("all filter=%q want empty", got)
	}
	filter := NormalizeCountryFilter("jp")
	if !CountryMatchesFilter("JP", filter) {
		t.Fatal("expected JP to match JP filter")
	}
	if CountryMatchesFilter("US", filter) {
		t.Fatal("did not expect US to match JP filter")
	}
}
