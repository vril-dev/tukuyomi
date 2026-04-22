package cacheconf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"tukuyomi/internal/policyhost"
)

func ToDTO(rs *Ruleset) RulesFile {
	out := RulesFile{
		Default: ScopeDTO{Rules: rulesToDTO(rsRules(rs))},
	}
	if rs == nil || len(rs.Hosts) == 0 {
		return out
	}

	keys := make([]string, 0, len(rs.Hosts))
	for host := range rs.Hosts {
		keys = append(keys, host)
	}
	sort.Strings(keys)
	out.Hosts = make(map[string]ScopeDTO, len(keys))
	for _, host := range keys {
		out.Hosts[host] = ScopeDTO{Rules: rulesToDTO(rs.Hosts[host])}
	}
	return out
}

func rulesToDTO(in []Rule) []RuleDTO {
	if len(in) == 0 {
		return []RuleDTO{}
	}

	out := make([]RuleDTO, 0, len(in))
	for _, r := range in {
		m := Match{}
		switch {
		case r.Exact != "":
			m = Match{Type: "exact", Value: r.Exact}
		case r.Prefix != "":
			m = Match{Type: "prefix", Value: r.Prefix}
		case r.Regex != nil:
			m = Match{Type: "regex", Value: r.Regex.String()}
		}
		methods := make([]string, 0, len(r.Methods))
		for k := range r.Methods {
			methods = append(methods, strings.ToUpper(k))
		}
		if len(methods) == 0 {
			methods = []string{"GET", "HEAD"}
		} else {
			sort.Strings(methods)
		}
		out = append(out, RuleDTO{
			Kind:    strings.ToUpper(r.Kind),
			Match:   m,
			Methods: methods,
			TTL:     r.TTL,
			Vary:    append([]string(nil), r.Vary...),
		})
	}

	return out
}

func FromDTO(file RulesFile) (*Ruleset, []error) {
	rs := &Ruleset{}
	var errs []error

	defaultRules, defaultErrs := rulesFromDTO(file.Default.Rules, "default.rules")
	if len(defaultErrs) > 0 {
		errs = append(errs, defaultErrs...)
	} else {
		rs.Rules = defaultRules
	}

	if len(file.Hosts) > 0 {
		keys := make([]string, 0, len(file.Hosts))
		for host := range file.Hosts {
			keys = append(keys, host)
		}
		sort.Strings(keys)

		rs.Hosts = make(map[string][]Rule, len(keys))
		for _, rawHost := range keys {
			hostKey, err := policyhost.NormalizePattern(rawHost)
			if err != nil {
				errs = append(errs, fmt.Errorf("hosts[%q]: %v", rawHost, err))
				continue
			}
			if _, exists := rs.Hosts[hostKey]; exists {
				errs = append(errs, fmt.Errorf("hosts[%q]: duplicate normalized host scope %q", rawHost, hostKey))
				continue
			}
			hostRules, hostErrs := rulesFromDTO(file.Hosts[rawHost].Rules, fmt.Sprintf("hosts[%q].rules", rawHost))
			if len(hostErrs) > 0 {
				errs = append(errs, hostErrs...)
				continue
			}
			rs.Hosts[hostKey] = hostRules
		}
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return rs, nil
}

func rulesFromDTO(dtos []RuleDTO, scope string) ([]Rule, []error) {
	if len(dtos) == 0 {
		return nil, nil
	}

	var errs []error
	out := make([]Rule, 0, len(dtos))
	for i, d := range dtos {
		r := Rule{Kind: strings.ToUpper(d.Kind), TTL: d.TTL, Vary: append([]string(nil), d.Vary...)}
		prefix := fmt.Sprintf("%s[%d]", scope, i)
		if r.Kind != "ALLOW" && r.Kind != "DENY" {
			errs = append(errs, fmt.Errorf("%s: kind must be ALLOW or DENY", prefix))
		}

		switch strings.ToLower(d.Match.Type) {
		case "prefix":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("%s: prefix value required", prefix))
			}
			r.Prefix = d.Match.Value
		case "regex":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("%s: regex value required", prefix))
			} else {
				re, err := regexp.Compile(d.Match.Value)
				if err != nil {
					errs = append(errs, fmt.Errorf("%s: invalid regex: %v", prefix, err))
				} else {
					r.Regex = re
				}
			}
		case "exact":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("%s: exact value required", prefix))
			}
			r.Exact = d.Match.Value
		default:
			errs = append(errs, fmt.Errorf("%s: match.type must be prefix|regex|exact", prefix))
		}

		r.Methods = map[string]bool{}
		if len(d.Methods) == 0 {
			r.Methods["GET"] = true
			r.Methods["HEAD"] = true
		} else {
			for _, m := range d.Methods {
				mu := strings.ToUpper(strings.TrimSpace(m))
				if mu == "" {
					continue
				}
				switch mu {
				case "GET", "HEAD":
					r.Methods[mu] = true
				default:
					errs = append(errs, fmt.Errorf("%s: unsupported method %q (only GET/HEAD)", prefix, mu))
				}
			}
		}

		if r.TTL < 0 {
			errs = append(errs, fmt.Errorf("%s: ttl must be >= 0", prefix))
		}

		out = append(out, r)
	}

	if len(errs) > 0 {
		return nil, errs
	}
	return out, nil
}

func RulesetToLines(rs *Ruleset) []string {
	if rs == nil {
		return nil
	}

	lines := make([]string, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		parts := []string{strings.ToUpper(r.Kind)}
		if r.Exact != "" {
			parts = append(parts, "exact="+r.Exact)
		}
		if r.Prefix != "" {
			parts = append(parts, "prefix="+r.Prefix)
		}
		if r.Regex != nil {
			parts = append(parts, "regex="+r.Regex.String())
		}
		if len(r.Methods) > 0 {
			ms := make([]string, 0, len(r.Methods))
			for k := range r.Methods {
				ms = append(ms, strings.ToUpper(k))
			}
			sort.Strings(ms)
			parts = append(parts, "methods="+strings.Join(ms, ","))
		}
		if r.TTL > 0 {
			parts = append(parts, fmt.Sprintf("ttl=%d", r.TTL))
		}
		if len(r.Vary) > 0 {
			parts = append(parts, "vary="+strings.Join(r.Vary, ","))
		}
		lines = append(lines, strings.Join(parts, " "))
	}

	return lines
}

func RulesetToJSON(rs *Ruleset) ([]byte, error) {
	if rs == nil {
		rs = &Ruleset{}
	}
	out, err := json.MarshalIndent(ToDTO(rs), "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func ComputeETag(b []byte) string {
	h := sha256.Sum256(b)
	return `W/"sha256:` + hex.EncodeToString(h[:]) + `"`
}

func rsRules(rs *Ruleset) []Rule {
	if rs == nil {
		return nil
	}
	return rs.Rules
}
