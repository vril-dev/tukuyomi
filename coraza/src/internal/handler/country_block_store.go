package handler

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
)

var (
	countryBlockMu      sync.RWMutex
	countryBlockPath    string
	blockedCountryCodes = map[string]struct{}{}
)

func InitCountryBlock(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("country block path is empty")
	}
	if err := ensureCountryBlockFile(target); err != nil {
		return err
	}

	countryBlockMu.Lock()
	countryBlockPath = target
	countryBlockMu.Unlock()

	return ReloadCountryBlock()
}

func GetCountryBlockPath() string {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()

	return countryBlockPath
}

func GetBlockedCountries() []string {
	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()

	out := make([]string, 0, len(blockedCountryCodes))
	for code := range blockedCountryCodes {
		out = append(out, code)
	}
	sort.Strings(out)
	return out
}

func IsCountryBlocked(country string) bool {
	code := normalizeCountryCode(country)

	countryBlockMu.RLock()
	defer countryBlockMu.RUnlock()
	_, ok := blockedCountryCodes[code]
	return ok
}

func ReloadCountryBlock() error {
	path := GetCountryBlockPath()
	if path == "" {
		return fmt.Errorf("country block path is empty")
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	codes, err := ParseCountryBlockRaw(string(raw))
	if err != nil {
		return err
	}

	next := make(map[string]struct{}, len(codes))
	for _, code := range codes {
		next[code] = struct{}{}
	}

	countryBlockMu.Lock()
	blockedCountryCodes = next
	countryBlockMu.Unlock()

	return nil
}

func ParseCountryBlockRaw(raw string) ([]string, error) {
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
			return nil, fmt.Errorf("line %d: expected one country code per line", lineNo)
		}

		code := normalizeCountryCode(parts[0])
		if code == "UNKNOWN" {
			if _, ok := seen[code]; !ok {
				seen[code] = struct{}{}
				out = append(out, code)
			}
			continue
		}
		if len(code) != 2 {
			return nil, fmt.Errorf("line %d: country code must be ISO-3166 alpha-2 (e.g. JP, US)", lineNo)
		}
		for _, r := range code {
			if r < 'A' || r > 'Z' {
				return nil, fmt.Errorf("line %d: invalid country code: %s", lineNo, code)
			}
		}

		if _, ok := seen[code]; ok {
			continue
		}
		seen[code] = struct{}{}
		out = append(out, code)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}

	sort.Strings(out)
	return out, nil
}

func ensureCountryBlockFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, []byte("# one country code per line (JP, US, UNKNOWN)\n"), 0o644)
}
