package cacheconf

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"tukuyomi/internal/policyhost"
)

type Rule struct {
	Kind    string
	Prefix  string
	Regex   *regexp.Regexp
	Exact   string
	Methods map[string]bool
	TTL     int
	Vary    []string
}

type Ruleset struct {
	Rules []Rule
	Hosts map[string][]Rule
}

func Load(path string) (*Ruleset, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadFromBytes(b)
}

func LoadFromString(s string) (*Ruleset, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return &Ruleset{}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		return loadJSON(trimmed)
	}

	sc := bufio.NewScanner(strings.NewReader(s))

	return parseScanner(sc)
}

func LoadFromBytes(b []byte) (*Ruleset, error) {
	return LoadFromString(string(b))
}

func parseScanner(sc *bufio.Scanner) (*Ruleset, error) {
	rs := &Ruleset{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}

		r := Rule{Kind: strings.ToUpper(fields[0]), TTL: 600}
		for _, opt := range fields[1:] {
			kv := strings.SplitN(opt, "=", 2)
			if len(kv) != 2 {
				continue
			}

			k := strings.ToLower(kv[0])
			v := kv[1]
			switch k {
			case "prefix":
				r.Prefix = v
			case "regex":
				if re, err := regexp.Compile(v); err == nil {
					r.Regex = re
				}
			case "exact":
				r.Exact = v
			case "methods":
				r.Methods = map[string]bool{}
				for _, m := range strings.Split(v, ",") {
					r.Methods[strings.ToUpper(strings.TrimSpace(m))] = true
				}
			case "ttl":
				if t, err := strconv.Atoi(v); err == nil {
					r.TTL = t
				}
			case "vary":
				r.Vary = splitTrim(v, ",")
			}
		}
		rs.Rules = append(rs.Rules, r)
	}
	return rs, sc.Err()
}

func loadJSON(raw string) (*Ruleset, error) {
	var payload struct {
		Default *ScopeDTO            `json:"default"`
		Hosts   *map[string]ScopeDTO `json:"hosts"`
		Rules   *[]RuleDTO           `json:"rules"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&payload); err != nil {
		return nil, err
	}
	if payload.Rules != nil && (payload.Default != nil || payload.Hosts != nil) {
		return nil, fmt.Errorf("cache rules JSON must use either legacy rules or canonical default/hosts, not both")
	}
	file := RulesFile{}
	if payload.Default != nil {
		file.Default = *payload.Default
	}
	if payload.Hosts != nil {
		file.Hosts = *payload.Hosts
	}
	if payload.Rules != nil {
		file.Default = ScopeDTO{Rules: *payload.Rules}
	}
	rs, errs := FromDTO(file)
	if len(errs) > 0 {
		return nil, joinValidationErrors(errs)
	}
	if rs == nil {
		return &Ruleset{}, nil
	}
	return rs, nil
}

func joinValidationErrors(errs []error) error {
	if len(errs) == 0 {
		return nil
	}
	msgs := make([]string, 0, len(errs))
	for _, err := range errs {
		msgs = append(msgs, err.Error())
	}
	return errors.New(strings.Join(msgs, "; "))
}

func (rs *Ruleset) Match(reqHost string, tls bool, method, path string) (*Rule, bool) {
	m := strings.ToUpper(method)
	rules := rs.Rules
	if len(rs.Hosts) > 0 {
		for _, candidate := range policyhost.Candidates(reqHost, tls) {
			if scoped, ok := rs.Hosts[candidate]; ok {
				rules = scoped
				break
			}
		}
	}
	for i := range rules {
		r := &rules[i]
		if len(r.Methods) > 0 && !r.Methods[m] {
			continue
		}

		switch {
		case r.Exact != "" && path == r.Exact:
			return r, r.Kind == "ALLOW"
		case r.Prefix != "" && strings.HasPrefix(path, r.Prefix):
			return r, r.Kind == "ALLOW"
		case r.Regex != nil && r.Regex.MatchString(path):
			return r, r.Kind == "ALLOW"
		}
	}

	return nil, false
}

func RuleCount(rs *Ruleset) int {
	if rs == nil {
		return 0
	}
	total := len(rs.Rules)
	for _, scoped := range rs.Hosts {
		total += len(scoped)
	}
	return total
}

func splitTrim(s, sep string) []string {
	if s == "" {
		return nil
	}

	parts := strings.Split(s, sep)
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}

	return out
}
