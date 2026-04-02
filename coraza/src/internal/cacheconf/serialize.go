package cacheconf

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

func ToDTO(rs *Ruleset) []RuleDTO {
	if rs == nil {
		return nil
	}

	out := make([]RuleDTO, 0, len(rs.Rules))
	for _, r := range rs.Rules {
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
			Vary:    r.Vary,
		})
	}

	return out
}

func FromDTO(dtos []RuleDTO) (*Ruleset, []error) {
	var errs []error
	rs := &Ruleset{}
	for i, d := range dtos {
		r := Rule{Kind: strings.ToUpper(d.Kind), TTL: d.TTL, Vary: d.Vary}
		if r.Kind != "ALLOW" && r.Kind != "DENY" {
			errs = append(errs, fmt.Errorf("rules[%d]: kind must be ALLOW or DENY", i))
		}

		switch strings.ToLower(d.Match.Type) {
		case "prefix":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("rules[%d]: prefix value required", i))
			}
			r.Prefix = d.Match.Value
		case "regex":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("rules[%d]: regex value required", i))
			} else {
				re, err := regexp.Compile(d.Match.Value)
				if err != nil {
					errs = append(errs, fmt.Errorf("rules[%d]: invalid regex: %v", i, err))
				} else {
					r.Regex = re
				}
			}
		case "exact":
			if d.Match.Value == "" {
				errs = append(errs, fmt.Errorf("rules[%d]: exact value required", i))
			}
			r.Exact = d.Match.Value
		default:
			errs = append(errs, fmt.Errorf("rules[%d]: match.type must be prefix|regex|exact", i))
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
					errs = append(errs, fmt.Errorf("rules[%d]: unsupported method %q (only GET/HEAD)", i, mu))
				}
			}
		}

		if r.TTL < 0 {
			errs = append(errs, fmt.Errorf("rules[%d]: ttl must be >= 0", i))
		}

		rs.Rules = append(rs.Rules, r)
	}

	if len(errs) > 0 {
		return nil, errs
	}

	return rs, nil
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

func ComputeETag(b []byte) string {
	h := sha256.Sum256(b)
	return `W/"sha256:` + hex.EncodeToString(h[:]) + `"`
}
