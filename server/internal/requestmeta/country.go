package requestmeta

import "strings"

const (
	CountrySourceUnknown = "unknown"
	CountrySourceHeader  = "header"
	CountrySourceMMDB    = "mmdb"
)

func NormalizeCountryCode(raw string) string {
	v := strings.TrimSpace(strings.ToUpper(raw))
	switch v {
	case "", "-", "N/A", "NULL":
		return "UNKNOWN"
	default:
		return v
	}
}

func NormalizeCountryFilter(raw string) string {
	v := strings.TrimSpace(strings.ToUpper(raw))
	if v == "" || v == "ALL" {
		return ""
	}
	return NormalizeCountryCode(v)
}

func NormalizeCountryFromAny(raw any) string {
	s, _ := raw.(string)
	return NormalizeCountryCode(s)
}

func CountryMatchesFilter(raw any, filter string) bool {
	if filter == "" {
		return true
	}
	return NormalizeCountryFromAny(raw) == filter
}
