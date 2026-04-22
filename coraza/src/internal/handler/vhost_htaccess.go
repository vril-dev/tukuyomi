package handler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

type VhostOverrideImportReport struct {
	OverrideFileName     string   `json:"override_file_name,omitempty"`
	Found                bool     `json:"found"`
	ImportedRewriteRules int      `json:"imported_rewrite_rules,omitempty"`
	ImportedAccessRules  int      `json:"imported_access_rules,omitempty"`
	ImportedBasicAuth    bool     `json:"imported_basic_auth,omitempty"`
	Messages             []string `json:"messages,omitempty"`
}

type vhostHtaccessImport struct {
	RewriteRules []VhostRewriteRule
	AccessRules  []VhostAccessRule
	Messages     []string
	BasicAuth    bool
}

func cloneVhostOverrideImportReports(in map[string]VhostOverrideImportReport) map[string]VhostOverrideImportReport {
	if len(in) == 0 {
		return map[string]VhostOverrideImportReport{}
	}
	out := make(map[string]VhostOverrideImportReport, len(in))
	for key, report := range in {
		cp := report
		cp.Messages = append([]string(nil), report.Messages...)
		out[key] = cp
	}
	return out
}

func importVhostOverrideFiles(cfg VhostConfigFile) (VhostConfigFile, map[string]VhostOverrideImportReport, error) {
	out := cloneVhostConfigFile(cfg)
	reports := make(map[string]VhostOverrideImportReport, len(out.Vhosts))
	for i, vhost := range out.Vhosts {
		merged, report, err := importSingleVhostOverride(vhost)
		if err != nil {
			return VhostConfigFile{}, nil, err
		}
		out.Vhosts[i] = merged
		reports[merged.GeneratedTarget] = report
	}
	return out, reports, nil
}

func importSingleVhostOverride(vhost VhostConfig) (VhostConfig, VhostOverrideImportReport, error) {
	report := VhostOverrideImportReport{
		OverrideFileName: vhost.OverrideFileName,
	}
	overridePath := filepath.Join(vhost.DocumentRoot, vhost.OverrideFileName)
	body, found, err := readFileMaybe(overridePath)
	if err != nil {
		return VhostConfig{}, VhostOverrideImportReport{}, fmt.Errorf("vhost %q override %q: %w", vhost.Name, vhost.OverrideFileName, err)
	}
	report.Found = found
	if !found {
		return vhost, report, nil
	}
	imported, err := parseHtaccessSubset(vhost.DocumentRoot, vhost.OverrideFileName, string(body))
	if err != nil {
		return VhostConfig{}, VhostOverrideImportReport{}, fmt.Errorf("vhost %q override %q: %w", vhost.Name, vhost.OverrideFileName, err)
	}
	vhost.RewriteRules = append(vhost.RewriteRules, imported.RewriteRules...)
	vhost.AccessRules = append(vhost.AccessRules, imported.AccessRules...)
	report.ImportedRewriteRules = len(imported.RewriteRules)
	report.ImportedAccessRules = len(imported.AccessRules)
	report.ImportedBasicAuth = imported.BasicAuth
	report.Messages = append(report.Messages, imported.Messages...)
	return vhost, report, nil
}

func parseHtaccessSubset(docroot string, overrideFileName string, raw string) (vhostHtaccessImport, error) {
	var imported vhostHtaccessImport
	var authType string
	authRealm := "Restricted"
	authUserFile := ""
	requireAllUsers := false
	var requireUsers []string
	rewriteEnabled := true

	scanner := bufio.NewScanner(strings.NewReader(raw))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields, err := splitHtaccessDirectiveFields(line)
		if err != nil {
			return vhostHtaccessImport{}, fmt.Errorf("line %d: %w", lineNo, err)
		}
		if len(fields) == 0 {
			continue
		}
		directive := strings.ToLower(fields[0])
		args := fields[1:]
		switch directive {
		case "rewriteengine":
			if len(args) != 1 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: RewriteEngine expects On or Off", lineNo)
			}
			rewriteEnabled = strings.EqualFold(args[0], "on")
		case "rewriterule":
			if !rewriteEnabled {
				imported.Messages = append(imported.Messages, fmt.Sprintf("line %d: RewriteRule ignored because RewriteEngine is Off", lineNo))
				continue
			}
			if len(args) < 2 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: RewriteRule requires pattern and substitution", lineNo)
			}
			rule, messages, err := convertHtaccessRewriteRule(args[0], args[1], strings.Join(args[2:], " "))
			if err != nil {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: %w", lineNo, err)
			}
			imported.RewriteRules = append(imported.RewriteRules, rule)
			imported.Messages = append(imported.Messages, messages...)
		case "rewritecond", "rewritebase", "options", "satisfy", "order":
			imported.Messages = append(imported.Messages, fmt.Sprintf("line %d: unsupported directive %s was ignored", lineNo, fields[0]))
		case "authtype":
			if len(args) != 1 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: AuthType expects a single value", lineNo)
			}
			authType = strings.ToLower(strings.TrimSpace(args[0]))
		case "authname":
			if len(args) == 0 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: AuthName requires a realm", lineNo)
			}
			authRealm = strings.TrimSpace(strings.Join(args, " "))
		case "authuserfile":
			if len(args) != 1 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: AuthUserFile requires a single path", lineNo)
			}
			authUserFile = strings.TrimSpace(args[0])
		case "require":
			if len(args) == 0 {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: Require needs arguments", lineNo)
			}
			head := strings.ToLower(args[0])
			switch head {
			case "valid-user":
				requireAllUsers = true
			case "user":
				if len(args) < 2 {
					return vhostHtaccessImport{}, fmt.Errorf("line %d: Require user needs at least one username", lineNo)
				}
				requireUsers = append(requireUsers, args[1:]...)
			case "all":
				if len(args) != 2 {
					return vhostHtaccessImport{}, fmt.Errorf("line %d: Require all expects granted or denied", lineNo)
				}
				switch strings.ToLower(args[1]) {
				case "granted":
					imported.AccessRules = append(imported.AccessRules, VhostAccessRule{PathPattern: "/", Action: "allow"})
				case "denied":
					imported.AccessRules = append(imported.AccessRules, VhostAccessRule{PathPattern: "/", Action: "deny"})
				default:
					imported.Messages = append(imported.Messages, fmt.Sprintf("line %d: unsupported Require all mode %q was ignored", lineNo, args[1]))
				}
			case "ip":
				cidrs, err := normalizeHtaccessAddressList(args[1:])
				if err != nil {
					return vhostHtaccessImport{}, fmt.Errorf("line %d: %w", lineNo, err)
				}
				imported.AccessRules = append(imported.AccessRules, VhostAccessRule{PathPattern: "/", Action: "allow", CIDRs: cidrs})
			default:
				imported.Messages = append(imported.Messages, fmt.Sprintf("line %d: unsupported Require mode %q was ignored", lineNo, args[0]))
			}
		case "allow", "deny":
			if len(args) < 2 || !strings.EqualFold(args[0], "from") {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: %s expects 'from ...'", lineNo, fields[0])
			}
			cidrs, err := normalizeHtaccessAddressList(args[1:])
			if err != nil {
				return vhostHtaccessImport{}, fmt.Errorf("line %d: %w", lineNo, err)
			}
			imported.AccessRules = append(imported.AccessRules, VhostAccessRule{
				PathPattern: "/",
				Action:      strings.ToLower(directive),
				CIDRs:       cidrs,
			})
		default:
			imported.Messages = append(imported.Messages, fmt.Sprintf("line %d: unsupported directive %s was ignored", lineNo, fields[0]))
		}
	}
	if err := scanner.Err(); err != nil {
		return vhostHtaccessImport{}, err
	}

	if authUserFile != "" || requireAllUsers || len(requireUsers) > 0 || authType != "" {
		if authType != "basic" {
			return vhostHtaccessImport{}, fmt.Errorf("basic auth import requires AuthType Basic")
		}
		auth, messages, err := buildHtaccessBasicAuth(docroot, authUserFile, authRealm, requireAllUsers, requireUsers)
		if err != nil {
			return vhostHtaccessImport{}, err
		}
		imported.AccessRules = append(imported.AccessRules, VhostAccessRule{
			PathPattern: "/",
			Action:      "allow",
			BasicAuth:   auth,
		})
		imported.BasicAuth = true
		imported.Messages = append(imported.Messages, messages...)
	}

	return imported, nil
}

func splitHtaccessDirectiveFields(line string) ([]string, error) {
	var out []string
	var current strings.Builder
	var quote rune
	escaped := false
	for _, r := range line {
		switch {
		case escaped:
			current.WriteRune(r)
			escaped = false
		case quote != 0:
			switch r {
			case '\\':
				escaped = true
			case quote:
				quote = 0
			default:
				current.WriteRune(r)
			}
		default:
			switch r {
			case '\'', '"':
				quote = r
			case ' ', '\t':
				if current.Len() > 0 {
					out = append(out, current.String())
					current.Reset()
				}
			default:
				current.WriteRune(r)
			}
		}
	}
	if quote != 0 {
		return nil, fmt.Errorf("unterminated quoted string")
	}
	if current.Len() > 0 {
		out = append(out, current.String())
	}
	return out, nil
}

func convertHtaccessRewriteRule(pattern string, replacement string, rawFlags string) (VhostRewriteRule, []string, error) {
	rule := VhostRewriteRule{
		Pattern:     normalizeHtaccessRewritePattern(pattern),
		Replacement: normalizeHtaccessRewriteReplacement(replacement),
		Flag:        "break",
	}
	var messages []string
	flags := parseHtaccessRewriteFlags(rawFlags)
	for _, flag := range flags {
		key, value := splitHtaccessRewriteFlag(flag)
		switch key {
		case "l", "end":
			rule.Flag = "break"
		case "r":
			switch value {
			case "", "302", "307", "308":
				rule.Flag = "redirect"
			case "301":
				rule.Flag = "permanent"
			default:
				messages = append(messages, fmt.Sprintf("rewrite flag %q was ignored", flag))
			}
		case "qsa":
			rule.PreserveQuery = true
		case "":
		default:
			messages = append(messages, fmt.Sprintf("rewrite flag %q was ignored", flag))
		}
	}
	if rule.Pattern == "" {
		return VhostRewriteRule{}, nil, fmt.Errorf("RewriteRule pattern is required")
	}
	if replacement == "-" {
		return VhostRewriteRule{}, nil, fmt.Errorf("RewriteRule substitution '-' is not supported")
	}
	return rule, messages, nil
}

func parseHtaccessRewriteFlags(raw string) []string {
	raw = strings.TrimSpace(raw)
	raw = strings.TrimPrefix(raw, "[")
	raw = strings.TrimSuffix(raw, "]")
	if raw == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func splitHtaccessRewriteFlag(flag string) (string, string) {
	idx := strings.Index(flag, "=")
	if idx < 0 {
		return strings.ToLower(strings.TrimSpace(flag)), ""
	}
	return strings.ToLower(strings.TrimSpace(flag[:idx])), strings.TrimSpace(flag[idx+1:])
}

func normalizeHtaccessRewritePattern(pattern string) string {
	pattern = strings.TrimSpace(pattern)
	switch {
	case pattern == "":
		return ""
	case strings.HasPrefix(pattern, "^/"), strings.HasPrefix(pattern, "/"):
		return pattern
	case strings.HasPrefix(pattern, "^"):
		return "^/" + strings.TrimPrefix(pattern, "^")
	default:
		return "^/" + pattern
	}
}

func normalizeHtaccessRewriteReplacement(replacement string) string {
	replacement = strings.TrimSpace(replacement)
	switch {
	case replacement == "":
		return ""
	case strings.HasPrefix(replacement, "/"):
		return replacement
	case strings.HasPrefix(strings.ToLower(replacement), "http://"), strings.HasPrefix(strings.ToLower(replacement), "https://"):
		return replacement
	default:
		return "/" + replacement
	}
}

func normalizeHtaccessAddressList(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, fmt.Errorf("address list is empty")
	}
	if len(values) == 1 && strings.EqualFold(values[0], "all") {
		return nil, nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if strings.Contains(value, "/") {
			out = append(out, value)
			continue
		}
		if strings.Contains(value, ":") {
			out = append(out, value+"/128")
			continue
		}
		out = append(out, value+"/32")
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("address list is empty")
	}
	return out, nil
}

func buildHtaccessBasicAuth(docroot string, userFile string, realm string, requireAllUsers bool, requireUsers []string) (*VhostBasicAuth, []string, error) {
	if strings.TrimSpace(userFile) == "" {
		return nil, nil, fmt.Errorf("AuthUserFile is required for basic auth import")
	}
	users, messages, err := loadHtaccessUsers(docroot, userFile)
	if err != nil {
		return nil, nil, err
	}
	selected := make([]VhostBasicAuthUser, 0, len(users))
	if requireAllUsers || len(requireUsers) == 0 {
		for _, user := range users {
			selected = append(selected, user)
		}
	} else {
		seen := make(map[string]struct{}, len(requireUsers))
		for _, username := range requireUsers {
			username = strings.TrimSpace(username)
			if username == "" {
				continue
			}
			if _, ok := seen[username]; ok {
				continue
			}
			seen[username] = struct{}{}
			found := false
			for _, user := range users {
				if user.Username == username {
					selected = append(selected, user)
					found = true
					break
				}
			}
			if !found {
				messages = append(messages, fmt.Sprintf("Require user %q was not found in %s", username, userFile))
			}
		}
	}
	if len(selected) == 0 {
		return nil, nil, fmt.Errorf("basic auth import found no supported bcrypt users in %s", userFile)
	}
	return &VhostBasicAuth{
		Realm: strings.TrimSpace(realm),
		Users: selected,
	}, messages, nil
}

func loadHtaccessUsers(docroot string, userFile string) ([]VhostBasicAuthUser, []string, error) {
	resolved := userFile
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(docroot, userFile)
	}
	body, err := os.ReadFile(resolved)
	if err != nil {
		return nil, nil, fmt.Errorf("read AuthUserFile %q: %w", userFile, err)
	}
	var users []VhostBasicAuthUser
	var messages []string
	scanner := bufio.NewScanner(strings.NewReader(string(body)))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			messages = append(messages, fmt.Sprintf("AuthUserFile %s line %d was ignored because it is not username:hash", userFile, lineNo))
			continue
		}
		username := strings.TrimSpace(line[:idx])
		hash := strings.TrimSpace(line[idx+1:])
		if username == "" || hash == "" {
			messages = append(messages, fmt.Sprintf("AuthUserFile %s line %d was ignored because it is incomplete", userFile, lineNo))
			continue
		}
		if _, err := bcrypt.Cost([]byte(hash)); err != nil {
			messages = append(messages, fmt.Sprintf("AuthUserFile %s line %d was ignored because only bcrypt hashes are supported", userFile, lineNo))
			continue
		}
		users = append(users, VhostBasicAuthUser{
			Username:     username,
			PasswordHash: hash,
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, nil, err
	}
	return users, messages, nil
}
