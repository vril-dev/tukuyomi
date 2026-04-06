package handler

import (
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

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

func requestCountryCode(c *gin.Context) string {
	if c == nil || c.Request == nil {
		return "UNKNOWN"
	}
	if !trustedForwardedHeaders(c) {
		return "UNKNOWN"
	}

	for _, name := range config.CountryHeaderNames {
		raw := strings.TrimSpace(c.GetHeader(name))
		if raw == "" {
			continue
		}
		return normalizeCountryCode(raw)
	}

	return "UNKNOWN"
}
