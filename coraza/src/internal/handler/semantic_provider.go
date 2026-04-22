package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
	"time"
)

const (
	semanticProviderNameBuiltinAttackFamily = "builtin_attack_family"
	defaultSemanticProviderTimeoutMS        = 25
	maxSemanticProviderExcerptBytes         = 512
)

var (
	semanticProviderPatternSQL = regexp.MustCompile(`\bunion\b[\s\W]{0,24}\bselect\b|\binformation_schema\b|\bselect\b[\s\W]{0,24}\bfrom\b`)
	semanticProviderPatternXSS = regexp.MustCompile(`<\s*script|javascript:|onerror\s*=|onload\s*=`)
	semanticProviderPatternLFI = regexp.MustCompile(`\.\./|\.\.\\|/etc/passwd|boot\.ini`)
	semanticProviderPatternCmd = regexp.MustCompile(`(/bin/sh|cmd\.exe|powershell|wget|curl|bash|sh)\b`)
)

type semanticProviderConfig struct {
	Enabled   bool   `json:"enabled"`
	Name      string `json:"name,omitempty"`
	TimeoutMS int    `json:"timeout_ms,omitempty"`
}

type semanticProviderInput struct {
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

type semanticProviderOutput struct {
	Name         string   `json:"name"`
	ScoreDelta   int      `json:"score_delta"`
	ReasonCodes  []string `json:"reason_codes,omitempty"`
	AttackFamily string   `json:"attack_family,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
}

type semanticProvider interface {
	Name() string
	Evaluate(context.Context, semanticProviderInput) (semanticProviderOutput, error)
}

type semanticProviderRuntime struct {
	Config semanticProviderConfig
	Impl   semanticProvider
}

type semanticProviderFamilyScore struct {
	name     string
	evidence int
	reasons  []string
}

type builtinAttackFamilySemanticProvider struct{}

func normalizeSemanticProviderConfig(cfg semanticProviderConfig) (semanticProviderConfig, error) {
	cfg.Name = strings.ToLower(strings.TrimSpace(cfg.Name))
	if cfg.Name == "" {
		cfg.Name = semanticProviderNameBuiltinAttackFamily
	}
	if cfg.TimeoutMS <= 0 {
		cfg.TimeoutMS = defaultSemanticProviderTimeoutMS
	}
	if !cfg.Enabled {
		cfg.Name = ""
		cfg.TimeoutMS = 0
		return cfg, nil
	}
	switch cfg.Name {
	case semanticProviderNameBuiltinAttackFamily:
	default:
		return semanticProviderConfig{}, errSemanticProviderConfig("provider.name must be builtin_attack_family")
	}
	if cfg.TimeoutMS < 1 || cfg.TimeoutMS > 250 {
		return semanticProviderConfig{}, errSemanticProviderConfig("provider.timeout_ms must be between 1 and 250")
	}
	return cfg, nil
}

func errSemanticProviderConfig(message string) error {
	return &semanticProviderConfigError{message: message}
}

type semanticProviderConfigError struct {
	message string
}

func (e *semanticProviderConfigError) Error() string {
	if e == nil {
		return ""
	}
	return e.message
}

func buildSemanticProviderRuntime(cfg semanticProviderConfig) *semanticProviderRuntime {
	if !cfg.Enabled {
		return nil
	}
	switch cfg.Name {
	case semanticProviderNameBuiltinAttackFamily:
		return &semanticProviderRuntime{
			Config: cfg,
			Impl:   builtinAttackFamilySemanticProvider{},
		}
	default:
		return nil
	}
}

func evaluateSemanticProvider(rt *semanticProviderRuntime, in semanticProviderInput) *semanticProviderOutput {
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

func newSemanticProviderInput(
	r *http.Request,
	requestID string,
	telemetry *semanticTelemetry,
	bodyChunk []byte,
	baseScore, statefulScore int,
	baseSignals, statefulSignals []semanticSignal,
) semanticProviderInput {
	in := semanticProviderInput{
		RequestID:       strings.TrimSpace(requestID),
		BaseScore:       baseScore,
		StatefulScore:   statefulScore,
		BaseReasons:     semanticReasons(baseSignals),
		StatefulReasons: semanticReasons(statefulSignals),
	}
	if telemetry != nil {
		in.ActorKey = telemetry.Context.ActorKey
		in.PathClass = telemetry.Context.PathClass
		in.TargetClass = telemetry.Context.TargetClass
		in.SurfaceClass = telemetry.Context.SurfaceClass
		in.QueryHash = telemetry.Fingerprints.QueryHash
		in.FormHash = telemetry.Fingerprints.FormHash
		in.JSONHash = telemetry.Fingerprints.JSONHash
		in.BodyHash = telemetry.Fingerprints.BodyHash
		in.HeaderHash = telemetry.Fingerprints.HeaderHash
	}
	if r != nil && r.URL != nil {
		in.QueryExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(r.URL.RawQuery))
	}
	contentType := ""
	if r != nil {
		contentType = semanticNormalizedContentType(r.Header.Get("Content-Type"))
		in.HeaderExcerpt = boundedSemanticProviderExcerpt(semanticHeaderExcerpt(r.Header))
	}
	if len(bodyChunk) > 0 {
		switch {
		case contentType == "application/x-www-form-urlencoded":
			in.FormExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(string(bodyChunk)))
		case contentType == "application/json", strings.HasSuffix(contentType, "+json"), semanticLooksLikeJSON(bodyChunk):
			in.JSONExcerpt = boundedSemanticProviderExcerpt(semanticJSONExcerpt(bodyChunk))
		default:
			in.BodyExcerpt = boundedSemanticProviderExcerpt(normalizeSemanticFingerprintText(string(bodyChunk)))
		}
	}
	return in
}

func boundedSemanticProviderExcerpt(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= maxSemanticProviderExcerptBytes {
		return raw
	}
	return raw[:maxSemanticProviderExcerptBytes]
}

func semanticHeaderExcerpt(header http.Header) string {
	if header == nil {
		return ""
	}
	parts := make([]string, 0, 3)
	for _, name := range []string{"User-Agent", "Referer", "Content-Type"} {
		value := strings.TrimSpace(header.Get(name))
		if value == "" {
			continue
		}
		parts = append(parts, strings.ToLower(name)+"="+normalizeSemanticFingerprintText(value))
	}
	return strings.Join(parts, "\n")
}

func semanticJSONExcerpt(body []byte) string {
	var payload any
	if err := json.Unmarshal(body, &payload); err != nil {
		return normalizeSemanticFingerprintText(string(body))
	}
	return semanticCanonicalJSONFingerprint(payload, 0)
}

func (builtinAttackFamilySemanticProvider) Name() string {
	return semanticProviderNameBuiltinAttackFamily
}

func (builtinAttackFamilySemanticProvider) Evaluate(_ context.Context, in semanticProviderInput) (semanticProviderOutput, error) {
	families := map[string]*semanticProviderFamilyScore{
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

	combined := strings.Join(nonEmptyStrings(in.QueryExcerpt, in.FormExcerpt, in.JSONExcerpt, in.BodyExcerpt, in.HeaderExcerpt), "\n")
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
	if semanticProviderPatternSQL.MatchString(combined) {
		addEvidence("sql_injection", "provider:evidence:normalized_text", 1)
	}
	if semanticProviderPatternXSS.MatchString(combined) {
		addEvidence("xss", "provider:evidence:normalized_text", 1)
	}
	if semanticProviderPatternLFI.MatchString(combined) {
		addEvidence("path_traversal", "provider:evidence:normalized_text", 1)
	}
	if semanticProviderPatternCmd.MatchString(combined) {
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

	best := semanticBestProviderFamily(families)
	if best == nil || best.evidence < 3 {
		return semanticProviderOutput{}, nil
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

	return semanticProviderOutput{
		ScoreDelta:   scoreDelta,
		ReasonCodes:  append([]string{"provider:attack_family:" + best.name}, unique(best.reasons)...),
		AttackFamily: best.name,
		Confidence:   confidence,
	}, nil
}

func semanticBestProviderFamily(families map[string]*semanticProviderFamilyScore) *semanticProviderFamilyScore {
	var best *semanticProviderFamilyScore
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

func semanticProviderOutputSignals(out semanticProviderOutput) []semanticSignal {
	if out.ScoreDelta <= 0 {
		return nil
	}
	reason := "provider:" + strings.TrimSpace(out.AttackFamily)
	if reason == "provider:" {
		reason = "provider:" + strings.TrimSpace(out.Name)
	}
	return []semanticSignal{{
		Reason: reason,
		Score:  out.ScoreDelta,
	}}
}

func nonEmptyStrings(values ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
