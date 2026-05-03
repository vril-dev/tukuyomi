package configbundle

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"tukuyomi/internal/crsselection"
)

const (
	SchemaVersion = 1
	DefaultName   = "config-bundle.json"
	MaxBytes      = 8 * 1024 * 1024

	DomainAdminUsers           = "admin_users"
	DomainProxy                = "proxy"
	DomainSites                = "sites"
	DomainRuntimeApps          = "runtime_apps"
	DomainPHPRuntimeInventory  = "php_runtime_inventory"
	DomainPSGIRuntimeInventory = "psgi_runtime_inventory"
	DomainScheduledTasks       = "scheduled_tasks"
	DomainUpstreamRuntime      = "upstream_runtime"
	DomainCRSDisabled          = "crs_disabled"
	DomainCacheStore           = "cache_store"
	DomainCacheRules           = "cache_rules"
	DomainCountryBlock         = "country_block"
	DomainRateLimit            = "rate_limit"
	DomainBotDefense           = "bot_defense"
	DomainSemantic             = "semantic"
	DomainIPReputation         = "ip_reputation"
	DomainNotifications        = "notifications"
	DomainWAFBypass            = "waf_bypass"
)

type Bundle struct {
	SchemaVersion int                        `json:"schema_version"`
	GeneratedAt   string                     `json:"generated_at,omitempty"`
	Source        string                     `json:"source,omitempty"`
	Bootstrap     Bootstrap                  `json:"bootstrap,omitempty"`
	Domains       map[string]json.RawMessage `json:"domains"`
}

type Bootstrap struct {
	AppConfig json.RawMessage `json:"app_config,omitempty"`
}

var legacySeedDomains = map[string]string{
	"admin-users.json":            DomainAdminUsers,
	"proxy.json":                  DomainProxy,
	"sites.json":                  DomainSites,
	"vhosts.json":                 DomainRuntimeApps,
	"php-runtime-inventory.json":  DomainPHPRuntimeInventory,
	"psgi-runtime-inventory.json": DomainPSGIRuntimeInventory,
	"scheduled-tasks.json":        DomainScheduledTasks,
	"upstream-runtime.json":       DomainUpstreamRuntime,
	"crs-disabled.conf":           DomainCRSDisabled,
	"cache-store.json":            DomainCacheStore,
	"cache-rules.json":            DomainCacheRules,
	"country-block.json":          DomainCountryBlock,
	"rate-limit.json":             DomainRateLimit,
	"bot-defense.json":            DomainBotDefense,
	"semantic.json":               DomainSemantic,
	"ip-reputation.json":          DomainIPReputation,
	"notifications.json":          DomainNotifications,
	"waf-bypass.json":             DomainWAFBypass,
}

var knownDomains = map[string]struct{}{
	DomainAdminUsers:           {},
	DomainProxy:                {},
	DomainSites:                {},
	DomainRuntimeApps:          {},
	DomainPHPRuntimeInventory:  {},
	DomainPSGIRuntimeInventory: {},
	DomainScheduledTasks:       {},
	DomainUpstreamRuntime:      {},
	DomainCRSDisabled:          {},
	DomainCacheStore:           {},
	DomainCacheRules:           {},
	DomainCountryBlock:         {},
	DomainRateLimit:            {},
	DomainBotDefense:           {},
	DomainSemantic:             {},
	DomainIPReputation:         {},
	DomainNotifications:        {},
	DomainWAFBypass:            {},
}

func New(source string, generatedAt time.Time) Bundle {
	b := Bundle{
		SchemaVersion: SchemaVersion,
		Source:        strings.TrimSpace(source),
		Domains:       map[string]json.RawMessage{},
	}
	if !generatedAt.IsZero() {
		b.GeneratedAt = generatedAt.UTC().Format(time.RFC3339Nano)
	}
	return b
}

func Decode(raw []byte) (Bundle, error) {
	if len(raw) > MaxBytes {
		return Bundle{}, fmt.Errorf("config bundle exceeds %d bytes", MaxBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var b Bundle
	if err := dec.Decode(&b); err != nil {
		return Bundle{}, fmt.Errorf("decode config bundle: %w", err)
	}
	if err := dec.Decode(&struct{}{}); err == nil {
		return Bundle{}, fmt.Errorf("invalid config bundle: multiple JSON values")
	} else if err != io.EOF {
		return Bundle{}, fmt.Errorf("invalid config bundle: %w", err)
	}
	if err := Validate(b); err != nil {
		return Bundle{}, err
	}
	return b, nil
}

func LoadFile(path string) (Bundle, error) {
	raw, err := readBoundedFile(path, MaxBytes)
	if err != nil {
		return Bundle{}, err
	}
	return Decode(raw)
}

func Validate(b Bundle) error {
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported config bundle schema_version %d", b.SchemaVersion)
	}
	if b.Domains == nil {
		return fmt.Errorf("config bundle domains is required")
	}
	for domain, raw := range b.Domains {
		if _, ok := knownDomains[domain]; !ok {
			return fmt.Errorf("unknown config bundle domain %q", domain)
		}
		if len(raw) == 0 {
			return fmt.Errorf("config bundle domain %q is empty", domain)
		}
		if !json.Valid(raw) {
			return fmt.Errorf("config bundle domain %q contains invalid JSON", domain)
		}
	}
	if len(b.Bootstrap.AppConfig) > 0 && !json.Valid(b.Bootstrap.AppConfig) {
		return fmt.Errorf("config bundle bootstrap.app_config contains invalid JSON")
	}
	return nil
}

func Marshal(b Bundle) ([]byte, error) {
	if err := Validate(b); err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func SetDomainRaw(b *Bundle, domain string, raw []byte) error {
	if b == nil {
		return fmt.Errorf("config bundle is nil")
	}
	domain = strings.TrimSpace(domain)
	if _, ok := knownDomains[domain]; !ok {
		return fmt.Errorf("unknown config bundle domain %q", domain)
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return fmt.Errorf("config bundle domain %q is empty", domain)
	}
	if !json.Valid(raw) {
		return fmt.Errorf("config bundle domain %q contains invalid JSON", domain)
	}
	if b.Domains == nil {
		b.Domains = map[string]json.RawMessage{}
	}
	b.Domains[domain] = append(json.RawMessage(nil), raw...)
	return nil
}

func SetBootstrapAppConfigRaw(b *Bundle, raw []byte) error {
	if b == nil {
		return fmt.Errorf("config bundle is nil")
	}
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		b.Bootstrap.AppConfig = nil
		return nil
	}
	if !json.Valid(raw) {
		return fmt.Errorf("config bundle bootstrap.app_config contains invalid JSON")
	}
	b.Bootstrap.AppConfig = append(json.RawMessage(nil), raw...)
	return nil
}

func DomainForLegacySeed(seedName string) (string, bool) {
	clean := filepath.Base(strings.TrimSpace(seedName))
	domain, ok := legacySeedDomains[clean]
	return domain, ok
}

func (b Bundle) LegacySeedRaw(seedName string) ([]byte, bool, error) {
	domain, ok := DomainForLegacySeed(seedName)
	if !ok {
		return nil, false, nil
	}
	raw, ok := b.Domains[domain]
	if !ok {
		return nil, false, nil
	}
	if domain == DomainCRSDisabled {
		converted, err := crsDisabledSeedRaw(raw)
		if err != nil {
			return nil, false, err
		}
		return converted, true, nil
	}
	return append([]byte(nil), raw...), true, nil
}

func KnownDomainNames() []string {
	out := make([]string, 0, len(knownDomains))
	for domain := range knownDomains {
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}

func crsDisabledSeedRaw(raw []byte) ([]byte, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 || bytes.Equal(raw, []byte("null")) {
		return []byte{}, nil
	}
	if len(raw) > 0 && raw[0] == '"' {
		var text string
		if err := json.Unmarshal(raw, &text); err != nil {
			return nil, fmt.Errorf("decode crs_disabled text: %w", err)
		}
		return []byte(text), nil
	}
	var names []string
	if err := json.Unmarshal(raw, &names); err != nil {
		return nil, fmt.Errorf("decode crs_disabled names: %w", err)
	}
	return crsselection.SerializeDisabled(names), nil
}

func readBoundedFile(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	limited := io.LimitReader(f, limit+1)
	raw, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("config bundle exceeds %d bytes", limit)
	}
	return raw, nil
}
