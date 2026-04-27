package requestmeta

import (
	"strings"
	"testing"
)

func TestParseGeoIPConfigAcceptsCountryEdition(t *testing.T) {
	raw := []byte(`
# comment
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-Country GeoLite2-City
`)
	summary, err := ParseGeoIPConfig(raw)
	if err != nil {
		t.Fatalf("ParseGeoIPConfig() error: %v", err)
	}
	if got, want := summary.SupportedCountryEdition, "GeoLite2-Country"; got != want {
		t.Fatalf("supported edition=%q want=%q", got, want)
	}
	if len(summary.EditionIDs) != 2 {
		t.Fatalf("edition ids=%v want two entries", summary.EditionIDs)
	}
}

func TestParseGeoIPConfigRejectsWithoutSupportedCountryEdition(t *testing.T) {
	raw := []byte(`
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-City
`)
	_, err := ParseGeoIPConfig(raw)
	if err == nil {
		t.Fatal("expected error for config without supported country edition")
	}
}

func TestRenderGeoIPConfigForCountryEditionFiltersNonCountryEditions(t *testing.T) {
	raw := []byte(`
# keep comments
AccountID 12345
LicenseKey secret
EditionIDs GeoLite2-ASN GeoLite2-City GeoLite2-Country
ProductIDs GeoLite2-ASN
`)
	out, err := RenderGeoIPConfigForCountryEdition(raw, "GeoLite2-Country")
	if err != nil {
		t.Fatalf("RenderGeoIPConfigForCountryEdition: %v", err)
	}
	text := string(out)
	for _, want := range []string{"AccountID 12345", "LicenseKey secret", "EditionIDs GeoLite2-Country"} {
		if !strings.Contains(text, want) {
			t.Fatalf("rendered config missing %q:\n%s", want, text)
		}
	}
	for _, blocked := range []string{"GeoLite2-ASN", "GeoLite2-City", "ProductIDs"} {
		if strings.Contains(text, blocked) {
			t.Fatalf("rendered config still contains %q:\n%s", blocked, text)
		}
	}
}
