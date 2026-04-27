package proxyheaders

import (
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

const (
	ModeAuto   = "auto"
	ModeManual = "manual"
	ModeOff    = "off"

	SourceURL = "https://owasp.org/www-project-secure-headers/ci/headers_remove.json"
)

var headerNamePattern = regexp.MustCompile("^[!#$%&'*+\\-.^_`|~0-9A-Za-z]+$")

type Config struct {
	Mode         string   `json:"mode,omitempty"`
	CustomRemove []string `json:"custom_remove,omitempty"`
	CustomKeep   []string `json:"custom_keep,omitempty"`
	DebugLog     bool     `json:"debug_log,omitempty"`
}

type CatalogData struct {
	LastUpdateUTC string
	Headers       []string
	HeaderSet     map[string]struct{}
}

type Policy struct {
	Mode      string
	DebugLog  bool
	RemoveSet map[string]struct{}
}

type Surface string

const (
	SurfaceLive        Surface = "live_proxy_response"
	SurfaceCacheStore  Surface = "cache_store"
	SurfaceCacheReplay Surface = "cache_replay"
)

type ProcessingPlan struct {
	FeatureSanitize bool
	HardSafety      bool
}

func (p ProcessingPlan) NeedsHeaderIteration() bool {
	return p.FeatureSanitize || p.HardSafety
}

type FilterOptions struct {
	ExtraRemove map[string]struct{}
	Request     *http.Request
	Surface     string
	Log         func(FilterLog)
}

type FilterLog struct {
	Policy  Policy
	Removed []string
	Request *http.Request
	Surface string
}

type FilterResult struct {
	Header        http.Header
	PolicyRemoved []string
	Changed       bool
}

func NormalizeConfig(in Config) Config {
	out := in
	out.Mode = strings.ToLower(strings.TrimSpace(out.Mode))
	if out.Mode == "" {
		out.Mode = ModeAuto
	}
	out.CustomRemove = NormalizeNameList(out.CustomRemove)
	out.CustomKeep = NormalizeNameList(out.CustomKeep)
	return out
}

func NormalizeNameList(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, raw := range in {
		next := CanonicalName(raw)
		if strings.TrimSpace(raw) == "" {
			next = ""
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil
	}
	return out
}

func CanonicalName(raw string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	return http.CanonicalHeaderKey(value)
}

func ValidateConfig(cfg Config) error {
	switch cfg.Mode {
	case ModeAuto, ModeManual, ModeOff:
	default:
		return fmt.Errorf("response_header_sanitize.mode must be one of auto|manual|off")
	}
	if err := ValidateNames(cfg.CustomRemove, "response_header_sanitize.custom_remove"); err != nil {
		return err
	}
	if err := ValidateNames(cfg.CustomKeep, "response_header_sanitize.custom_keep"); err != nil {
		return err
	}
	return nil
}

func ValidateNames(in []string, field string) error {
	for _, name := range in {
		if name == "" {
			return fmt.Errorf("%s must not contain blank header names", field)
		}
		if !headerNamePattern.MatchString(name) {
			return fmt.Errorf("%s contains invalid header name %q", field, name)
		}
	}
	return nil
}

func BuildPolicy(cfg Config) Policy {
	policy := Policy{
		Mode:     cfg.Mode,
		DebugLog: cfg.DebugLog,
	}
	switch cfg.Mode {
	case ModeAuto:
		policy.RemoveSet = CloneNameSet(EmbeddedCatalog.HeaderSet)
		for _, name := range cfg.CustomKeep {
			delete(policy.RemoveSet, name)
		}
	case ModeManual:
		policy.RemoveSet = map[string]struct{}{}
	case ModeOff:
		policy.RemoveSet = map[string]struct{}{}
	default:
		return policy
	}
	for _, name := range cfg.CustomRemove {
		policy.RemoveSet[name] = struct{}{}
	}
	if len(policy.RemoveSet) == 0 {
		policy.RemoveSet = nil
	}
	return policy
}

func CloneNameSet(in map[string]struct{}) map[string]struct{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]struct{}, len(in))
	for name := range in {
		out[name] = struct{}{}
	}
	return out
}

func NameSet(names ...string) map[string]struct{} {
	out := make(map[string]struct{}, len(names))
	for _, raw := range names {
		name := CanonicalName(raw)
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func Plan(surface Surface, policy Policy) ProcessingPlan {
	plan := ProcessingPlan{
		FeatureSanitize: len(policy.RemoveSet) > 0,
	}
	switch surface {
	case SurfaceCacheStore, SurfaceCacheReplay:
		plan.HardSafety = true
	}
	return plan
}

func FilterHeaders(in http.Header, policy Policy, opts FilterOptions) FilterResult {
	if in == nil {
		return FilterResult{Header: make(http.Header), Changed: true}
	}

	changed := false
	var policyRemoved map[string]struct{}
	for key := range in {
		name := http.CanonicalHeaderKey(key)
		if name != key {
			changed = true
		}
		if _, ok := opts.ExtraRemove[name]; ok {
			changed = true
			continue
		}
		if _, ok := policy.RemoveSet[name]; ok {
			changed = true
			if policyRemoved == nil {
				policyRemoved = make(map[string]struct{}, 1)
			}
			policyRemoved[name] = struct{}{}
			continue
		}
	}

	removed := SetNames(policyRemoved)
	emitLog(policy, removed, opts)
	if !changed {
		return FilterResult{
			Header:        in,
			PolicyRemoved: removed,
		}
	}

	out := make(http.Header, len(in))
	for key, vals := range in {
		name := http.CanonicalHeaderKey(key)
		if _, ok := opts.ExtraRemove[name]; ok {
			continue
		}
		if _, ok := policy.RemoveSet[name]; ok {
			continue
		}
		out[name] = append(out[name], vals...)
	}
	return FilterResult{
		Header:        out,
		PolicyRemoved: removed,
		Changed:       true,
	}
}

func SetNames(in map[string]struct{}) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	for name := range in {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func emitLog(policy Policy, removed []string, opts FilterOptions) {
	if opts.Log == nil || !policy.DebugLog || len(removed) == 0 {
		return
	}
	opts.Log(FilterLog{
		Policy:  policy,
		Removed: removed,
		Request: opts.Request,
		Surface: strings.TrimSpace(opts.Surface),
	})
}

func MustBuildCatalogData(lastUpdateUTC string, headers []string) CatalogData {
	headers = NormalizeNameList(headers)
	if err := ValidateNames(headers, "embedded response header sanitize catalog"); err != nil {
		panic(fmt.Sprintf("validate embedded response header sanitize catalog: %v", err))
	}
	return CatalogData{
		LastUpdateUTC: lastUpdateUTC,
		Headers:       headers,
		HeaderSet:     NameSet(headers...),
	}
}
