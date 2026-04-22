package waf

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/crsselection"
)

var WAF coraza.WAF
var baseMu sync.RWMutex
var overrideMu sync.RWMutex
var overrideWAFs = map[string]coraza.WAF{}

func GetBaseWAF() coraza.WAF {
	baseMu.RLock()
	defer baseMu.RUnlock()
	return WAF
}

func setBaseWAF(w coraza.WAF) {
	baseMu.Lock()
	WAF = w
	baseMu.Unlock()
}

func getCachedOverrideWAF(rule string) (coraza.WAF, bool) {
	overrideMu.RLock()
	w, ok := overrideWAFs[rule]
	overrideMu.RUnlock()

	return w, ok
}

func setCachedOverrideWAF(rule string, w coraza.WAF) (coraza.WAF, bool) {
	overrideMu.Lock()
	if existing, ok := overrideWAFs[rule]; ok {
		overrideMu.Unlock()
		return existing, false
	}
	overrideWAFs[rule] = w
	overrideMu.Unlock()

	return w, true
}

func InvalidateOverrideWAF(rule string) {
	rule = strings.TrimSpace(rule)
	if rule == "" {
		return
	}
	overrideMu.Lock()
	delete(overrideWAFs, rule)
	overrideMu.Unlock()
}

func buildWAF(files []string) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDebugLogger(debuglog.Default().WithLevel(debuglog.LevelInfo)).
		WithErrorCallback(func(m types.MatchedRule) {
			log.Printf("[WAF] Blocked: URI=%s, MSG=%s", m.URI(), m.MatchedDatas())
		})

	for _, file := range files {
		file = strings.TrimSpace(file)
		if file == "" {
			continue
		}
		cfg = cfg.WithDirectivesFromFile(file)
		log.Printf("[WAF] Loaded rules from: %s", file)
	}

	return coraza.NewWAF(cfg)
}

func discoverCRSRuleFiles(setupFile, rulesDir string) ([]string, error) {
	if setupFile == "" {
		return nil, errors.New("paths.crs_setup_file is empty")
	}
	if rulesDir == "" {
		return nil, errors.New("paths.crs_rules_dir is empty")
	}
	if _, err := os.Stat(setupFile); err != nil {
		return nil, fmt.Errorf("CRS setup file not found: %s: %w", setupFile, err)
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, fmt.Errorf("failed to read CRS rules dir %s: %w", rulesDir, err)
	}

	setupPath := filepath.Clean(setupFile)
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() {
			continue
		}

		name := e.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".conf") {
			continue
		}
		if strings.HasSuffix(strings.ToLower(name), ".conf.example") {
			continue
		}

		full := filepath.Join(rulesDir, name)
		if filepath.Clean(full) == setupPath {
			continue
		}
		out = append(out, full)
	}

	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no CRS rule files found in %s", rulesDir)
	}

	return out, nil
}

func composeInitialRuleFiles(baseRuleSpec string, crsEnabled bool, crsSetupFile, crsRulesDir, crsDisabledFile string) ([]string, error) {
	disabled := map[string]struct{}{}
	if crsEnabled {
		var err error
		disabled, err = crsselection.LoadDisabledFile(crsDisabledFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load CRS disabled file %s: %w", crsDisabledFile, err)
		}
	}

	return composeInitialRuleFilesWithDisabledSet(baseRuleSpec, crsEnabled, crsSetupFile, crsRulesDir, disabled)
}

func composeInitialRuleFilesWithDisabledSet(baseRuleSpec string, crsEnabled bool, crsSetupFile, crsRulesDir string, crsDisabled map[string]struct{}) ([]string, error) {
	files := make([]string, 0, 32)
	seen := map[string]struct{}{}
	appendUnique := func(path string) {
		path = strings.TrimSpace(path)
		if path == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		files = append(files, path)
	}

	if crsEnabled {
		crsFiles, err := discoverCRSRuleFiles(crsSetupFile, crsRulesDir)
		if err != nil {
			return nil, err
		}
		crsFiles = crsselection.FilterEnabledPaths(crsFiles, crsDisabled)
		appendUnique(crsSetupFile)
		for _, f := range crsFiles {
			appendUnique(f)
		}
	}

	for _, f := range splitRuleFiles(baseRuleSpec) {
		appendUnique(f)
	}
	if len(files) == 0 {
		return nil, errors.New("no rule files configured")
	}

	return files, nil
}

func splitRuleFiles(raw string) []string {
	parts := strings.Split(raw, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, p)
	}

	return out
}

func InitWAF() {
	initialFiles, err := composeInitialRuleFiles(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		config.CRSDisabledFile,
	)
	if err != nil {
		log.Fatalf("failed to prepare initial WAF rules: %v", err)
	}

	base, err := buildWAF(initialFiles)
	if err != nil {
		log.Fatalf("failed to initialize WAF: %v", err)
	}
	setBaseWAF(base)

	if err := bypassconf.Init(config.BypassFile, config.LegacyCompatPath(config.BypassFile, config.DefaultBypassFilePath, config.LegacyDefaultBypassFilePath)); err != nil {
		log.Printf("[BYPASS][INIT][ERR] %v (path=%s)", err, config.BypassFile)
	} else {
		log.Printf("[BYPASS][INIT] configured=%s active=%s", bypassconf.GetPath(), bypassconf.GetActivePath())
	}
}

func PrepareInitialRuleFiles() ([]string, error) {
	return composeInitialRuleFiles(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		config.CRSDisabledFile,
	)
}

func DiscoverCRSRuleFiles() ([]string, error) {
	return discoverCRSRuleFiles(config.CRSSetupFile, config.CRSRulesDir)
}

func ValidateWithCRSSelection(enabledRuleNames []string) error {
	crsFiles, err := DiscoverCRSRuleFiles()
	if err != nil {
		return err
	}

	disabledNames, err := crsselection.BuildDisabledFromEnabled(crsFiles, enabledRuleNames)
	if err != nil {
		return err
	}
	disabled := make(map[string]struct{}, len(disabledNames))
	for _, name := range disabledNames {
		disabled[name] = struct{}{}
	}

	files, err := composeInitialRuleFilesWithDisabledSet(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		disabled,
	)
	if err != nil {
		return err
	}

	_, err = buildWAF(files)
	return err
}

func ValidateWithRuleOverride(targetPath string, raw []byte) error {
	target := filepath.Clean(strings.TrimSpace(targetPath))
	if target == "" {
		return errors.New("rule path is empty")
	}

	files, err := PrepareInitialRuleFiles()
	if err != nil {
		return err
	}

	replaced := false
	for i, f := range files {
		if filepath.Clean(f) != target {
			continue
		}

		dir := filepath.Dir(target)
		tmp, err := os.CreateTemp(dir, ".rule-validate.*.conf")
		if err != nil {
			// Some deployments mount rule files read-only for the runtime UID.
			// Fall back to /tmp so validation can still run.
			tmp, err = os.CreateTemp("", ".rule-validate.*.conf")
			if err != nil {
				return err
			}
		}
		tmpPath := tmp.Name()
		if _, err := tmp.Write(raw); err != nil {
			tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		if err := tmp.Sync(); err != nil {
			tmp.Close()
			_ = os.Remove(tmpPath)
			return err
		}
		if err := tmp.Close(); err != nil {
			_ = os.Remove(tmpPath)
			return err
		}
		defer os.Remove(tmpPath)
		files[i] = tmpPath
		replaced = true
		break
	}
	if !replaced {
		return fmt.Errorf("rule file %s is not part of active rule set", targetPath)
	}

	_, err = buildWAF(files)
	return err
}

func ReloadBaseWAF() error {
	files, err := PrepareInitialRuleFiles()
	if err != nil {
		return err
	}
	base, err := buildWAF(files)
	if err != nil {
		return err
	}
	setBaseWAF(base)
	log.Printf("[WAF] Reloaded base rules (%d files)", len(files))
	return nil
}

func GetWAFForExtraRule(extraRule string) (coraza.WAF, error) {
	rule := strings.TrimSpace(extraRule)
	if rule == "" {
		return GetBaseWAF(), nil
	}

	if w, ok := getCachedOverrideWAF(rule); ok {
		return w, nil
	}

	w, err := buildWAF([]string{rule})
	if err != nil {
		return nil, fmt.Errorf("failed to load extra rule %q: %w", rule, err)
	}

	var inserted bool
	w, inserted = setCachedOverrideWAF(rule, w)
	if inserted {
		log.Printf("[BYPASS][RULE] loaded extra rules from: %s", rule)
	}

	return w, nil
}

func ValidateStandaloneRule(rulePath string, raw []byte) error {
	dir := filepath.Dir(strings.TrimSpace(rulePath))
	tmp, err := os.CreateTemp(dir, ".override-validate.*.conf")
	if err != nil {
		tmp, err = os.CreateTemp("", ".override-validate.*.conf")
		if err != nil {
			return err
		}
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	defer os.Remove(tmpPath)

	_, err = buildWAF([]string{tmpPath})
	return err
}
