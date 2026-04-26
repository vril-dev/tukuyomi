package semanticprovider

import (
	"context"
	"regexp"
	"strings"
	"time"
)

const (
	NameBuiltinAttackFamily = "builtin_attack_family"
	DefaultTimeoutMS        = 25
	MaxExcerptBytes         = 512
)

var (
	patternSQL = regexp.MustCompile(`\bunion\b[\s\W]{0,24}\bselect\b|\binformation_schema\b|\bselect\b[\s\W]{0,24}\bfrom\b`)
	patternXSS = regexp.MustCompile(`<\s*script|javascript:|onerror\s*=|onload\s*=`)
	patternLFI = regexp.MustCompile(`\.\./|\.\.\\|/etc/passwd|boot\.ini`)
	patternCmd = regexp.MustCompile(`(/bin/sh|cmd\.exe|powershell|wget|curl|bash|sh)\b`)
)

type Config struct {
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

type Input struct {
	RequestID       string   `json:"request_id,omitempty"`
	ActorKey        string   `json:"actor_key,omitempty"`
	PathClass       string   `json:"path_class,omitempty"`
	TargetClass     string   `json:"target_class,omitempty"`
	SurfaceClass    string   `json:"surface_class,omitempty"`
	BaseScore       int      `json:"base_score,omitempty"`
	StatefulScore   int      `json:"stateful_score,omitempty"`
	BaseReasons     []string `json:"base_reasons,omitempty"`
	StatefulReasons []string `json:"stateful_reasons,omitempty"`
	QueryHash       string   `json:"query_hash,omitempty"`
	FormHash        string   `json:"form_hash,omitempty"`
	JSONHash        string   `json:"json_hash,omitempty"`
	BodyHash        string   `json:"body_hash,omitempty"`
	HeaderHash      string   `json:"header_hash,omitempty"`
	QueryExcerpt    string   `json:"query_excerpt,omitempty"`
	FormExcerpt     string   `json:"form_excerpt,omitempty"`
	JSONExcerpt     string   `json:"json_excerpt,omitempty"`
	BodyExcerpt     string   `json:"body_excerpt,omitempty"`
	HeaderExcerpt   string   `json:"header_excerpt,omitempty"`
}

type Output struct {
	Name         string   `json:"name"`
	ScoreDelta   int      `json:"score_delta"`
	ReasonCodes  []string `json:"reason_codes,omitempty"`
	AttackFamily string   `json:"attack_family,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
}

type Provider interface {
	Name() string
	Evaluate(context.Context, Input) (Output, error)
}

type Runtime struct {
	Config Config
	Impl   Provider
}

type familyScore struct {
	name     string
	evidence int
	reasons  []string
}

type builtinAttackFamilyProvider struct{}

func NormalizeConfig(cfg Config) (Config, error) {
	cfg.Name = strings.ToLower(strings.TrimSpace(cfg.Name))
	if cfg.Name == "" {
		cfg.Name = NameBuiltinAttackFamily
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = DefaultTimeoutMS
	}
	if !cfg.Enabled {
		cfg.Name = ""
		cfg.TimeoutMS = 0
		return cfg, nil
	}
	switch cfg.Name {
	case NameBuiltinAttackFamily:
	default:
		return Config{}, configError("provider.name must be builtin_attack_family")
	}
	if cfg.TimeoutMS < 1 || cfg.TimeoutMS > 250 {
		return Config{}, configError("provider.timeout_ms must be between 1 and 250")
	}
	return cfg, nil
}

type configError string

func (e configError) Error() string {
	return string(e)
}

func BuildRuntime(cfg Config) *Runtime {
	if !cfg.Enabled {
		return nil
	}
	switch cfg.Name {
	case NameBuiltinAttackFamily:
		return &Runtime{
			Config: cfg,
			Impl:   builtinAttackFamilyProvider{},
		}
	default:
		return nil
	}
}

func Evaluate(rt *Runtime, in Input) *Output {
	if rt == nil || rt.Impl == nil {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(rt.Config.TimeoutMS)*time.Millisecond)
	defer cancel()

	out, err := rt.Impl.Evaluate(ctx, in)
	if err != nil || out.ScoreDelta <= 0 {
		return nil
	}
	out.Name = rt.Impl.Name()
	out.ReasonCodes = unique(out.ReasonCodes)
	return &out
}

func (builtinAttackFamilyProvider) Name() string {
	return NameBuiltinAttackFamily
}

func (builtinAttackFamilyProvider) Evaluate(_ context.Context, in Input) (Output, error) {
	families := map[string]*familyScore{
		"sql_injection":     {name: "sql_injection"},
		"xss":               {name: "xss"},
		"path_traversal":    {name: "path_traversal"},
		"command_injection": {name: "command_injection"},
		"recon_escalation":  {name: "recon_escalation"},
	}
	addEvidence := func(family, reason string, points int) {
		entry := families[family]
		if entry == nil || points <= 0 {
			return
		}
		entry.evidence += points
		entry.reasons = append(entry.reasons, reason)
	}

	combined := strings.Join(nonEmpty(in.QueryExcerpt, in.FormExcerpt, in.JSONExcerpt, in.BodyExcerpt, in.HeaderExcerpt), "\n")
	for _, reason := range in.BaseReasons {
		switch {
		case strings.Contains(reason, "sql_union_select"), strings.Contains(reason, "sql_boolean_chain"), strings.Contains(reason, "sql_meta_keyword"):
			addEvidence("sql_injection", "provider:evidence:semantic_sql", 2)
		case strings.Contains(reason, "xss_pattern"):
			addEvidence("xss", "provider:evidence:semantic_xss", 2)
		case strings.Contains(reason, "path_traversal"):
			addEvidence("path_traversal", "provider:evidence:semantic_path_traversal", 2)
		case strings.Contains(reason, "command_chain"):
			addEvidence("command_injection", "provider:evidence:semantic_command", 2)
		case strings.Contains(reason, "comment_obfuscation"), strings.Contains(reason, "high_encoding_density"):
			addEvidence("sql_injection", "provider:evidence:obfuscation", 1)
			addEvidence("xss", "provider:evidence:obfuscation", 1)
		}
	}
	for _, reason := range in.StatefulReasons {
		switch reason {
		case "stateful:admin_after_suspicious_activity", "stateful:sensitive_path_after_suspicious_activity", "stateful:sudden_target_sensitivity_shift", "stateful:rapid_surface_shift":
			addEvidence("recon_escalation", "provider:evidence:stateful_sequence", 2)
		}
	}
	if patternSQL.MatchString(combined) {
		addEvidence("sql_injection", "provider:evidence:normalized_text", 1)
	}
	if patternXSS.MatchString(combined) {
		addEvidence("xss", "provider:evidence:normalized_text", 1)
	}
	if patternLFI.MatchString(combined) {
		addEvidence("path_traversal", "provider:evidence:normalized_text", 1)
	}
	if patternCmd.MatchString(combined) {
		addEvidence("command_injection", "provider:evidence:normalized_text", 1)
	}
	if in.TargetClass == "admin_management" || in.TargetClass == "account_security" {
		for _, family := range []string{"sql_injection", "xss", "path_traversal", "command_injection"} {
			if families[family].evidence > 0 {
				addEvidence(family, "provider:evidence:sensitive_target", 1)
			}
		}
	}
	if in.TargetClass == "admin_management" && in.StatefulScore > 0 {
		addEvidence("recon_escalation", "provider:evidence:admin_target", 1)
	}

	best := bestFamily(families)
	if best == nil || best.evidence < 3 {
		return Output{}, nil
	}

	confidence := "medium"
	scoreDelta := 1
	switch {
	case best.evidence >= 5:
		confidence = "high"
		scoreDelta = 3
	case best.evidence >= 4:
		confidence = "high"
		scoreDelta = 2
	default:
		confidence = "medium"
		scoreDelta = 1
	}

	return Output{
		ScoreDelta:   scoreDelta,
		ReasonCodes:  append([]string{"provider:attack_family:" + best.name}, unique(best.reasons)...),
		AttackFamily: best.name,
		Confidence:   confidence,
	}, nil
}

func bestFamily(families map[string]*familyScore) *familyScore {
	var best *familyScore
	order := []string{"sql_injection", "xss", "path_traversal", "command_injection", "recon_escalation"}
	for _, name := range order {
		current := families[name]
		if current == nil || current.evidence <= 0 {
			continue
		}
		if best == nil || current.evidence > best.evidence {
			best = current
		}
	}
	return best
}

func unique(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := map[string]struct{}{}
	for _, raw := range in {
		next := strings.TrimSpace(raw)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	return out
}

func nonEmpty(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
