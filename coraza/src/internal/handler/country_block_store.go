package handler

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"tukuyomi/internal/policyhost"
)

var (
	countryBlockMu         sync.RWMutex
	countryBlockPath       string
	countryBlockLegacyPath string
	countryBlockActivePath string
	countryBlockState      = compiledCountryBlock{
		Raw: countryBlockFile{Default: countryBlockScope{BlockedCountries: []string{}}},
	}
)

type countryBlockScope struct {
	BlockedCountries []string `json:"blocked_countries"`
}

type countryBlockFile struct {
	Default countryBlockScope            `json:"default"`
	Hosts   map[string]countryBlockScope `json:"hosts,omitempty"`
}

type compiledCountryBlock struct {
	Raw     countryBlockFile
	Default map[string]struct{}
	Hosts   map[string]map[string]struct{}
}

func InitCountryBlock(path, legacy string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("country block path is empty")
	}
	legacy = strings.TrimSpace(legacy)
	countryBlockMu.Lock()
	countryBlockPath = target
	countryBlockLegacyPath = legacy
	countryBlockActivePath = ""
	countryBlockMu.Unlock()

	if store := getLogsStatsStore(); store != nil {
		raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(countryBlockConfigBlobKey), normalizeCountryBlockPolicyRaw, "country block rules")
		if err != nil {
			return fmt.Errorf("read country block config db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized country block config missing in db; run make db-import before removing seed files")
		}
		return applyCountryBlockPolicyRaw(raw)
	}

	if err := ensureCountryBlockFile(target, legacy); err != nil {
		return err
	}

	return ReloadCountryBlock()
}

func GetCountryBlockPath() string {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()

	return countryBlockPath
}

func GetCountryBlockActivePath() string {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()

	return countryBlockActivePath
}

func GetBlockedCountries() []string {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()

	return flattenCountryBlockCodes(countryBlockState.Raw)
}

func GetCountryBlockFile() countryBlockFile {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()
	return cloneCountryBlockFile(countryBlockState.Raw)
}

func IsCountryBlocked(reqHost string, tls bool, country string) bool {
	code := normalizeCountryCode(country)

	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()
	for _, candidate := range policyhost.Candidates(reqHost, tls) {
		if hostCodes, ok := countryBlockState.Hosts[candidate]; ok {
			_, blocked := hostCodes[code]
			return blocked
		}
	}
	_, ok := countryBlockState.Default[code]
	return ok
}

func ReloadCountryBlock() error {
	path := GetCountryBlockPath()
	if path == "" {
		return fmt.Errorf("country block path is empty")
	}

	readPath := resolveCountryBlockLoadPath()
	raw, err := os.ReadFile(readPath)
	if err != nil {
		return err
	}

	file, err := ParseCountryBlockRaw(string(raw))
	if err != nil {
		return err
	}

	countryBlockMu.Lock()
	countryBlockState = compileCountryBlock(file)
	countryBlockActivePath = readPath
	countryBlockMu.Unlock()

	return nil
}

func ParseCountryBlockRaw(raw string) (countryBlockFile, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return countryBlockFile{Default: countryBlockScope{BlockedCountries: []string{}}}, nil
	}
	if strings.HasPrefix(trimmed, "{") {
		return parseCountryBlockJSON(trimmed)
	}

	sc := bufio.NewScanner(strings.NewReader(raw))
	seen := map[string]struct{}{}
	out := make([]string, 0, 16)
	lineNo := 0

	for sc.Scan() {
		lineNo++
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) != 1 {
			return countryBlockFile{}, fmt.Errorf("line %d: expected one country code per line", lineNo)
		}

		code, err := validateCountryCode(parts[0])
		if err != nil {
			return countryBlockFile{}, fmt.Errorf("line %d: %w", lineNo, err)
		}

		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	if err := sc.Err(); err != nil {
		return countryBlockFile{}, err
	}

	sort.Strings(out)
	return countryBlockFile{Default: countryBlockScope{BlockedCountries: out}}, nil
}

func parseCountryBlockJSON(raw string) (countryBlockFile, error) {
	var file struct {
		Default          *countryBlockScope           `json:"default,omitempty"`
		Hosts            map[string]countryBlockScope `json:"hosts,omitempty"`
		BlockedCountries []string                     `json:"blocked_countries,omitempty"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return countryBlockFile{}, err
	}
	if len(file.BlockedCountries) > 0 && (file.Default != nil || len(file.Hosts) > 0) {
		return countryBlockFile{}, fmt.Errorf("blocked_countries is legacy-only; use default.blocked_countries with hosts")
	}
	next := countryBlockFile{Default: countryBlockScope{BlockedCountries: []string{}}}
	if len(file.BlockedCountries) > 0 {
		codes, err := normalizeCountryCodes(file.BlockedCountries, "blocked_countries")
		if err != nil {
			return countryBlockFile{}, err
		}
		next.Default.BlockedCountries = codes
		return next, nil
	}
	if file.Default != nil {
		codes, err := normalizeCountryCodes(file.Default.BlockedCountries, "default.blocked_countries")
		if err != nil {
			return countryBlockFile{}, err
		}
		next.Default.BlockedCountries = codes
	}
	if len(file.Hosts) == 0 {
		return next, nil
	}
	next.Hosts = make(map[string]countryBlockScope, len(file.Hosts))
	for rawHost, scope := range file.Hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return countryBlockFile{}, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		codes, err := normalizeCountryCodes(scope.BlockedCountries, fmt.Sprintf("hosts[%q].blocked_countries", rawHost))
		if err != nil {
			return countryBlockFile{}, err
		}
		next.Hosts[hostKey] = countryBlockScope{BlockedCountries: codes}
	}
	return next, nil
}

func validateCountryCode(raw string) (string, error) {
	code := normalizeCountryCode(raw)
	if code == "UNKNOWN" {
		return code, nil
	}
	if len(code) != 2 {
		return "", fmt.Errorf("country code must be ISO-3166 alpha-2 (e.g. JP, US)")
	}
	for _, r := range code {
		if r < 'A' || r > 'Z' {
			return "", fmt.Errorf("invalid country code: %s", code)
		}
	}
	return code, nil
}

func MarshalCountryBlockJSON(file countryBlockFile) ([]byte, error) {
	file = cloneCountryBlockFile(file)
	if file.Default.BlockedCountries == nil {
		file.Default.BlockedCountries = []string{}
	}
	out, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func resolveCountryBlockLoadPath() string {
	countryBlockMu.RLock()
	primary := countryBlockPath
	legacy := countryBlockLegacyPath
	countryBlockMu.RUnlock()

	if _, err := os.Stat(primary); err == nil {
		return primary
	}
	if strings.TrimSpace(legacy) != "" {
		if _, err := os.Stat(legacy); err == nil {
			return legacy
		}
	}
	return primary
}

func ensureCountryBlockFile(path, legacy string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if strings.TrimSpace(legacy) != "" {
		if _, err := os.Stat(legacy); err == nil {
			return nil
		}
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if strings.HasSuffix(strings.ToLower(path), ".json") {
		payload, err := MarshalCountryBlockJSON(countryBlockFile{Default: countryBlockScope{BlockedCountries: []string{}}})
		if err != nil {
			return err
		}
		return os.WriteFile(path, payload, 0o644)
	}
	return os.WriteFile(path, []byte("# one country code per line (JP, US, UNKNOWN)\n"), 0o644)
}

func normalizeCountryCodes(rawCodes []string, field string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(rawCodes))
	for i, code := range rawCodes {
		normalized, err := validateCountryCode(code)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: %w", field, i, err)
		}
		if _, ok := seen[normalized]; ok {
			continue
		}
		seen[normalized] = struct{}{}
		out = append(out, normalized)
	}
	sort.Strings(out)
	return out, nil
}

func compileCountryBlock(file countryBlockFile) compiledCountryBlock {
	rt := compiledCountryBlock{
		Raw:     cloneCountryBlockFile(file),
		Default: make(map[string]struct{}, len(file.Default.BlockedCountries)),
	}
	for _, code := range file.Default.BlockedCountries {
		rt.Default[code] = struct{}{}
	}
	if len(file.Hosts) == 0 {
		return rt
	}
	rt.Hosts = make(map[string]map[string]struct{}, len(file.Hosts))
	for host, scope := range file.Hosts {
		next := make(map[string]struct{}, len(scope.BlockedCountries))
		for _, code := range scope.BlockedCountries {
			next[code] = struct{}{}
		}
		rt.Hosts[host] = next
	}
	return rt
}

func cloneCountryBlockFile(in countryBlockFile) countryBlockFile {
	out := countryBlockFile{
		Default: countryBlockScope{BlockedCountries: append([]string(nil), in.Default.BlockedCountries...)},
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]countryBlockScope, len(in.Hosts))
		for host, scope := range in.Hosts {
			out.Hosts[host] = countryBlockScope{BlockedCountries: append([]string(nil), scope.BlockedCountries...)}
		}
	}
	return out
}

func cloneCompiledCountryBlock(in compiledCountryBlock) compiledCountryBlock {
	out := compiledCountryBlock{
		Raw:     cloneCountryBlockFile(in.Raw),
		Default: make(map[string]struct{}, len(in.Default)),
	}
	for code := range in.Default {
		out.Default[code] = struct{}{}
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]map[string]struct{}, len(in.Hosts))
		for host, codes := range in.Hosts {
			next := make(map[string]struct{}, len(codes))
			for code := range codes {
				next[code] = struct{}{}
			}
			out.Hosts[host] = next
		}
	}
	return out
}

func flattenCountryBlockCodes(file countryBlockFile) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(file.Default.BlockedCountries))
	for _, code := range file.Default.BlockedCountries {
		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	for _, scope := range file.Hosts {
		for _, code := range scope.BlockedCountries {
			if _, ok := seen[code]; ok {
				continue
			}
			seen[code] = struct{}{}
			out = append(out, code)
		}
	}
	sort.Strings(out)
	return out
}
