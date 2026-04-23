package waf

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/corazawaf/coraza/v3/types"

	"tukuyomi/internal/config"
	"tukuyomi/internal/crsselection"
)

var WAF coraza.WAF
var baseMu sync.RWMutex
var overrideMu sync.RWMutex
var overrideWAFs = map[string]overrideWAFCacheEntry{}

type overrideWAFCacheEntry struct {
	w    coraza.WAF
	etag string
}

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

func getCachedOverrideWAF(rule string, etag string) (coraza.WAF, bool) {
	overrideMu.RLock()
	entry, ok := overrideWAFs[rule]
	overrideMu.RUnlock()
	if !ok {
		return nil, false
	}
	if strings.TrimSpace(etag) != "" && entry.etag != etag {
		return nil, false
	}

	return entry.w, true
}

func setCachedOverrideWAF(rule string, etag string, w coraza.WAF) (coraza.WAF, bool) {
	overrideMu.Lock()
	if existing, ok := overrideWAFs[rule]; ok && (strings.TrimSpace(etag) == "" || existing.etag == etag) {
		overrideMu.Unlock()
		return existing.w, false
	}
	overrideWAFs[rule] = overrideWAFCacheEntry{w: w, etag: etag}
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
	return buildWAFWithRoot(files, nil)
}

func buildWAFWithRoot(files []string, root fs.FS) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDebugLogger(debuglog.Default().WithLevel(debuglog.LevelInfo)).
		WithErrorCallback(func(m types.MatchedRule) {
			log.Printf("[WAF] Blocked: URI=%s, MSG=%s", m.URI(), m.MatchedDatas())
		})
	if root != nil {
		cfg = cfg.WithRootFS(root)
	}

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

func buildWAFWithDirectives(raw []byte) (coraza.WAF, error) {
	cfg := coraza.NewWAFConfig().
		WithDebugLogger(debuglog.Default().WithLevel(debuglog.LevelInfo)).
		WithErrorCallback(func(m types.MatchedRule) {
			log.Printf("[WAF] Blocked: URI=%s, MSG=%s", m.URI(), m.MatchedDatas())
		}).
		WithDirectives(string(raw))

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

func composeInitialRuleFilesFromAssets(bundle RuleAssetBundle, baseRuleSpec string, crsEnabled bool, crsSetupFile, crsRulesDir string, crsDisabled map[string]struct{}) ([]string, error) {
	files := make([]string, 0, 32)
	seen := map[string]struct{}{}
	assetSet := make(map[string]struct{}, len(bundle.Assets))
	for _, asset := range bundle.Assets {
		assetSet[normalizeRuleAssetPath(asset.Path)] = struct{}{}
	}
	appendUnique := func(path string) {
		path = normalizeRuleAssetPath(path)
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
		crsFiles, err := discoverCRSRuleFilesFromAssets(bundle, crsSetupFile, crsRulesDir)
		if err != nil {
			return nil, err
		}
		crsFiles = crsselection.FilterEnabledPaths(crsFiles, crsDisabled)
		setup := normalizeRuleAssetPath(crsSetupFile)
		if _, ok := assetSet[setup]; !ok {
			return nil, fmt.Errorf("CRS setup asset not found in DB: %s", crsSetupFile)
		}
		appendUnique(setup)
		for _, f := range crsFiles {
			appendUnique(f)
		}
	}

	for _, f := range splitRuleFiles(baseRuleSpec) {
		path := normalizeRuleAssetPath(f)
		if _, ok := assetSet[path]; !ok {
			return nil, fmt.Errorf("base rule asset not found in DB: %s", f)
		}
		appendUnique(path)
	}
	if len(files) == 0 {
		return nil, errors.New("no rule assets configured")
	}

	return files, nil
}

func discoverCRSRuleFilesFromAssets(bundle RuleAssetBundle, setupFile, rulesDir string) ([]string, error) {
	setupPath := normalizeRuleAssetPath(setupFile)
	rulesPrefix := strings.TrimSuffix(normalizeRuleAssetPath(rulesDir), "/") + "/"
	if setupPath == "" {
		return nil, errors.New("paths.crs_setup_file is empty")
	}
	if strings.TrimSpace(rulesDir) == "" {
		return nil, errors.New("paths.crs_rules_dir is empty")
	}

	hasSetup := false
	out := []string{}
	for _, asset := range bundle.Assets {
		p := normalizeRuleAssetPath(asset.Path)
		if p == setupPath {
			hasSetup = true
			continue
		}
		if !strings.HasPrefix(p, rulesPrefix) {
			continue
		}
		name := filepath.Base(p)
		if !strings.HasSuffix(strings.ToLower(name), ".conf") {
			continue
		}
		if strings.HasSuffix(strings.ToLower(name), ".conf.example") {
			continue
		}
		out = append(out, p)
	}
	if !hasSetup {
		return nil, fmt.Errorf("CRS setup asset not found in DB: %s", setupFile)
	}
	sort.Strings(out)
	if len(out) == 0 {
		return nil, fmt.Errorf("no CRS rule assets found in DB under %s", rulesDir)
	}
	return out, nil
}

func normalizeRuleAssetPath(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	clean := filepath.ToSlash(filepath.Clean(raw))
	if clean == "." {
		return ""
	}
	return clean
}

func loadRuleAssetBundle() (RuleAssetBundle, bool, error) {
	provider := currentRuleAssetProvider()
	if provider == nil {
		return RuleAssetBundle{}, false, nil
	}
	return provider()
}

func prepareInitialRuleSet() ([]string, fs.FS, error) {
	bundle, found, err := loadRuleAssetBundle()
	if err != nil {
		return nil, nil, err
	}
	if found {
		disabled := map[string]struct{}{}
		if config.CRSEnable {
			disabled, err = loadCRSDisabledSelection(config.CRSDisabledFile)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to load CRS disabled selection: %w", err)
			}
		}
		files, err := composeInitialRuleFilesFromAssets(bundle, config.RulesFile, config.CRSEnable, config.CRSSetupFile, config.CRSRulesDir, disabled)
		if err != nil {
			return nil, nil, err
		}
		return files, newMemoryRuleFS(bundle.Assets), nil
	}

	files, err := composeInitialRuleFiles(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		config.CRSDisabledFile,
	)
	return files, nil, err
}

func prepareInitialRuleSetWithDisabled(disabled map[string]struct{}) ([]string, fs.FS, error) {
	bundle, found, err := loadRuleAssetBundle()
	if err != nil {
		return nil, nil, err
	}
	if found {
		files, err := composeInitialRuleFilesFromAssets(bundle, config.RulesFile, config.CRSEnable, config.CRSSetupFile, config.CRSRulesDir, disabled)
		if err != nil {
			return nil, nil, err
		}
		return files, newMemoryRuleFS(bundle.Assets), nil
	}
	files, err := composeInitialRuleFilesWithDisabledSet(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		disabled,
	)
	return files, nil, err
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
	initialFiles, root, err := prepareInitialRuleSet()
	if err != nil {
		log.Fatalf("failed to prepare initial WAF rules: %v", err)
	}

	base, err := buildWAFWithRoot(initialFiles, root)
	if err != nil {
		log.Fatalf("failed to initialize WAF: %v", err)
	}
	setBaseWAF(base)
}

func PrepareInitialRuleFiles() ([]string, error) {
	if bundle, found, err := loadRuleAssetBundle(); err != nil {
		return nil, err
	} else if found {
		disabled := map[string]struct{}{}
		if config.CRSEnable {
			disabled, err = loadCRSDisabledSelection(config.CRSDisabledFile)
			if err != nil {
				return nil, fmt.Errorf("failed to load CRS disabled selection: %w", err)
			}
		}
		return composeInitialRuleFilesFromAssets(bundle, config.RulesFile, config.CRSEnable, config.CRSSetupFile, config.CRSRulesDir, disabled)
	}
	return composeInitialRuleFiles(
		config.RulesFile,
		config.CRSEnable,
		config.CRSSetupFile,
		config.CRSRulesDir,
		config.CRSDisabledFile,
	)
}

func loadCRSDisabledSelection(path string) (map[string]struct{}, error) {
	if provider := currentCRSDisabledProvider(); provider != nil {
		disabled, found, err := provider()
		if err != nil || found {
			return disabled, err
		}
	}
	return crsselection.LoadDisabledFile(path)
}

func DiscoverCRSRuleFiles() ([]string, error) {
	if bundle, found, err := loadRuleAssetBundle(); err != nil {
		return nil, err
	} else if found {
		return discoverCRSRuleFilesFromAssets(bundle, config.CRSSetupFile, config.CRSRulesDir)
	}
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

	files, root, err := prepareInitialRuleSetWithDisabled(disabled)
	if err != nil {
		return err
	}

	_, err = buildWAFWithRoot(files, root)
	return err
}

func ValidateWithRuleOverride(targetPath string, raw []byte) error {
	target := filepath.Clean(strings.TrimSpace(targetPath))
	if target == "" {
		return errors.New("rule path is empty")
	}

	if bundle, found, err := loadRuleAssetBundle(); err != nil {
		return err
	} else if found {
		targetAsset := normalizeRuleAssetPath(target)
		replaced := false
		for i := range bundle.Assets {
			if normalizeRuleAssetPath(bundle.Assets[i].Path) != targetAsset {
				continue
			}
			bundle.Assets[i].Raw = append([]byte(nil), raw...)
			replaced = true
			break
		}
		if !replaced {
			return fmt.Errorf("rule asset %s is not part of active rule set", targetPath)
		}
		disabled := map[string]struct{}{}
		if config.CRSEnable {
			disabled, err = loadCRSDisabledSelection(config.CRSDisabledFile)
			if err != nil {
				return fmt.Errorf("failed to load CRS disabled selection: %w", err)
			}
		}
		files, err := composeInitialRuleFilesFromAssets(bundle, config.RulesFile, config.CRSEnable, config.CRSSetupFile, config.CRSRulesDir, disabled)
		if err != nil {
			return err
		}
		_, err = buildWAFWithRoot(files, newMemoryRuleFS(bundle.Assets))
		return err
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
	files, root, err := prepareInitialRuleSet()
	if err != nil {
		return err
	}
	base, err := buildWAFWithRoot(files, root)
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

	if loader := currentOverrideRuleLoader(); loader != nil {
		source, found, err := loader(rule)
		if err != nil {
			return nil, fmt.Errorf("failed to load extra rule %q from DB: %w", rule, err)
		}
		if found {
			etag := strings.TrimSpace(source.ETag)
			if w, ok := getCachedOverrideWAF(rule, etag); ok {
				return w, nil
			}
			w, err := buildWAFWithDirectives(source.Raw)
			if err != nil {
				return nil, fmt.Errorf("failed to load extra rule %q from DB: %w", rule, err)
			}
			var inserted bool
			w, inserted = setCachedOverrideWAF(rule, etag, w)
			if inserted {
				log.Printf("[BYPASS][RULE] loaded extra rules from DB: %s", rule)
			}
			return w, nil
		}
	}

	if w, ok := getCachedOverrideWAF(rule, ""); ok {
		return w, nil
	}

	w, err := buildWAF([]string{rule})
	if err != nil {
		return nil, fmt.Errorf("failed to load extra rule %q: %w", rule, err)
	}

	var inserted bool
	w, inserted = setCachedOverrideWAF(rule, "", w)
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
