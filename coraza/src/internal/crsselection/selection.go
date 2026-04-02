package crsselection

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func NormalizeName(name string) string {
	return filepath.Base(strings.TrimSpace(name))
}

func ParseDisabled(raw string) map[string]struct{} {
	out := map[string]struct{}{}
	sc := bufio.NewScanner(strings.NewReader(raw))
	for sc.Scan() {
		line := sc.Text()
		if i := strings.Index(line, "#"); i >= 0 {
			line = line[:i]
		}
		name := NormalizeName(line)
		if name == "" {
			continue
		}
		out[name] = struct{}{}
	}
	return out
}

func LoadDisabledFile(path string) (map[string]struct{}, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]struct{}{}, nil
		}
		return nil, err
	}
	return ParseDisabled(string(b)), nil
}

func FilterEnabledPaths(paths []string, disabled map[string]struct{}) []string {
	if len(disabled) == 0 {
		out := make([]string, len(paths))
		copy(out, paths)
		return out
	}

	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if _, off := disabled[NormalizeName(p)]; off {
			continue
		}
		out = append(out, p)
	}
	return out
}

func BuildDisabledFromEnabled(allPaths []string, enabledNames []string) ([]string, error) {
	allByName := map[string]struct{}{}
	for _, p := range allPaths {
		allByName[NormalizeName(p)] = struct{}{}
	}

	enabled := map[string]struct{}{}
	for _, n := range enabledNames {
		name := NormalizeName(n)
		if name == "" {
			continue
		}
		if _, ok := allByName[name]; !ok {
			return nil, fmt.Errorf("unknown CRS rule: %s", n)
		}
		enabled[name] = struct{}{}
	}

	disabled := make([]string, 0, len(allByName))
	for name := range allByName {
		if _, ok := enabled[name]; ok {
			continue
		}
		disabled = append(disabled, name)
	}
	sort.Strings(disabled)
	return disabled, nil
}

func SerializeDisabled(disabledNames []string) []byte {
	lines := []string{
		"# crs-disabled.conf - Disabled CRS rule filenames",
		"# One filename per line. Empty means all CRS rules are enabled.",
		"# Example: REQUEST-913-SCANNER-DETECTION.conf",
		"",
	}
	lines = append(lines, disabledNames...)
	return []byte(strings.Join(lines, "\n") + "\n")
}
