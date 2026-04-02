package cacheconf

import (
	"bufio"
	"os"
	"regexp"
	"strconv"
	"strings"
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

type Ruleset struct{ Rules []Rule }

func Load(path string) (*Ruleset, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rs := &Ruleset{}
	sc := bufio.NewScanner(f)
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

func LoadFromString(s string) (*Ruleset, error) {
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

func (rs *Ruleset) Match(method, path string) (*Rule, bool) {
	m := strings.ToUpper(method)
	for i := range rs.Rules {
		r := &rs.Rules[i]
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
