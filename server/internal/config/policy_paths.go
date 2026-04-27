package config

import (
	"os"
	"path/filepath"
	"strings"
)

const (
	DefaultBypassFilePath          = "conf/waf-bypass.json"
	LegacyDefaultBypassFilePath    = "conf/waf.bypass"
	DefaultCountryBlockFilePath    = "conf/country-block.json"
	LegacyDefaultCountryBlockPath  = "conf/country-block.conf"
	DefaultCacheRulesFilePath      = "conf/cache-rules.json"
	LegacyDefaultCacheRulesPath    = "conf/cache.conf"
	DefaultUpstreamRuntimeFilePath = "conf/upstream-runtime.json"
	DefaultBaseRuleAssetPath       = "tukuyomi.conf"
)

func LegacyCompatPath(configuredPath, defaultPath, legacyDefaultPath string) string {
	if normalizeCompatPath(configuredPath) != normalizeCompatPath(defaultPath) {
		return ""
	}
	return strings.TrimSpace(legacyDefaultPath)
}

func ResolveReadablePolicyPath(primaryPath, legacyPath string) string {
	primary := strings.TrimSpace(primaryPath)
	if primary == "" {
		return ""
	}
	if pathExists(primary) {
		return primary
	}
	legacy := strings.TrimSpace(legacyPath)
	if legacy != "" && pathExists(legacy) {
		return legacy
	}
	return primary
}

func NormalizeBaseRuleAssetSpec(raw string) string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		normalized := NormalizeBaseRuleAssetPath(part)
		if normalized == "" {
			continue
		}
		out = append(out, normalized)
	}
	return strings.Join(out, ",")
}

func NormalizeBaseRuleAssetPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(raw))
	if clean == "." {
		return ""
	}
	return clean
}

func normalizeCompatPath(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	return filepath.Clean(path)
}

func pathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}
