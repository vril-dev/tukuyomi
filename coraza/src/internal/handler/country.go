package handler

import "strings"

func normalizeCountryFilter(raw string) string {
	v := strings.TrimSpace(strings.ToUpper(raw))
	if v == "" || v == "ALL" {
		return ""
	}

	return normalizeCountryCode(v)
}

func normalizeCountryCode(raw string) string {
	v := strings.TrimSpace(strings.ToUpper(raw))
	switch v {
	case "", "-", "N/A", "NULL":
		return "UNKNOWN"
	default:
		return v
	}
}

func normalizeCountryFromAny(raw any) string {
	s, _ := raw.(string)
	return normalizeCountryCode(s)
}

func countryMatchesFilter(raw any, filter string) bool {
	if filter == "" {
		return true
	}

	return normalizeCountryFromAny(raw) == filter
}
