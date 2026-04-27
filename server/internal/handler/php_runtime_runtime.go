package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

var (
	defaultDisabledPHPRuntimeModules = []string{}
	defaultPHPRuntimeInventoryRaw    = "{}\n"
)

type phpRuntimeConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetPHPRuntimes(c *gin.Context) {
	raw, etag, cfg, rollbackDepth := PHPRuntimeInventorySnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"runtimes":       cfg,
		"materialized":   PHPRuntimeMaterializationSnapshot(),
		"processes":      PHPRuntimeProcessSnapshot(),
		"rollback_depth": rollbackDepth,
	})
}

func ValidatePHPRuntimes(c *gin.Context) {
	var in phpRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidatePHPRuntimeInventoryRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"runtimes": cfg,
	})
}

func PutPHPRuntimes(c *gin.Context) {
	var in phpRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyPHPRuntimeInventoryRaw(ifMatch, in.Raw)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": conflict.CurrentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"etag":     etag,
		"runtimes": cfg,
	})
}

func RollbackPHPRuntimes(c *gin.Context) {
	etag, cfg, restored, err := RollbackPHPRuntimeInventory()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot"})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"runtimes":      cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}

func UpPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := StartPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}

func DownPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := StopPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}

func ReloadPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := ReloadPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}

type phpRuntimeInventoryStateFile struct {
	Runtimes         []PHPRuntimeRecord `json:"runtimes,omitempty"`
	explicitRuntimes bool
}

type PHPRuntimeInventoryFile struct {
	Runtimes []PHPRuntimeRecord `json:"runtimes,omitempty"`
}

type PHPRuntimeRecord struct {
	RuntimeID              string   `json:"runtime_id,omitempty"`
	DisplayName            string   `json:"display_name,omitempty"`
	DetectedVersion        string   `json:"detected_version,omitempty"`
	BinaryPath             string   `json:"binary_path,omitempty"`
	CLIBinaryPath          string   `json:"cli_binary_path,omitempty"`
	Modules                []string `json:"modules,omitempty"`
	DefaultDisabledModules []string `json:"default_disabled_modules,omitempty"`
	Available              bool     `json:"available"`
	AvailabilityMessage    string   `json:"availability_message,omitempty"`
	RunUser                string   `json:"run_user,omitempty"`
	RunGroup               string   `json:"run_group,omitempty"`
	Source                 string   `json:"source,omitempty"`
	SHA256                 string   `json:"sha256,omitempty"`
}

type phpRuntimeInventoryPreparedConfig struct {
	state phpRuntimeInventoryStateFile
	cfg   PHPRuntimeInventoryFile
	raw   string
	etag  string
}

type phpRuntimeInventoryRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	state         phpRuntimeInventoryStateFile
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	phpRuntimeInventoryMu sync.RWMutex
	phpRuntimeInventoryRt *phpRuntimeInventoryRuntime
)

func InitPHPRuntimeInventoryRuntime(path string, rollbackMax int) error {
	cfgPath := strings.TrimSpace(path)
	if cfgPath == "" {
		cfgPath = "data/php-fpm/inventory.json"
	}
	if store := getLogsStatsStore(); store != nil {
		prepared, rec, found, err := store.loadActivePHPRuntimeInventoryPreparedConfig(cfgPath)
		if err != nil {
			return fmt.Errorf("read php runtime inventory db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized php runtime inventory config missing in db; run make db-import before removing seed files")
		}
		rt := &phpRuntimeInventoryRuntime{
			configPath:    cfgPath,
			raw:           prepared.raw,
			etag:          rec.ETag,
			state:         prepared.state,
			rollbackMax:   clampProxyRollbackMax(rollbackMax),
			rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
		}
		phpRuntimeInventoryMu.Lock()
		phpRuntimeInventoryRt = rt
		phpRuntimeInventoryMu.Unlock()
		return refreshPHPRuntimeMaterializationAfterInventoryInit()
	}

	rawBytes, _, err := readFileMaybe(cfgPath)
	if err != nil {
		return fmt.Errorf("read php runtime inventory (%s): %w", cfgPath, err)
	}
	raw := string(rawBytes)
	if strings.TrimSpace(raw) == "" {
		raw = defaultPHPRuntimeInventoryRaw
	}
	prepared, err := preparePHPRuntimeInventoryRaw(raw, cfgPath)
	if err != nil {
		return fmt.Errorf("invalid php runtime inventory (%s): %w", cfgPath, err)
	}
	rt := &phpRuntimeInventoryRuntime{
		configPath:    cfgPath,
		raw:           prepared.raw,
		etag:          prepared.etag,
		state:         prepared.state,
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	phpRuntimeInventoryMu.Lock()
	phpRuntimeInventoryRt = rt
	phpRuntimeInventoryMu.Unlock()
	return refreshPHPRuntimeMaterializationAfterInventoryInit()
}

func refreshPHPRuntimeMaterializationAfterInventoryInit() error {
	if vhostRuntimeInstance() == nil {
		return nil
	}
	if err := RefreshPHPRuntimeMaterialization(); err != nil {
		return fmt.Errorf("materialize php runtime config: %w", err)
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		return fmt.Errorf("reconcile php runtime supervisor: %w", err)
	}
	return nil
}

func phpRuntimeInventoryInstance() *phpRuntimeInventoryRuntime {
	phpRuntimeInventoryMu.RLock()
	defer phpRuntimeInventoryMu.RUnlock()
	return phpRuntimeInventoryRt
}

func PHPRuntimeInventorySnapshot() (raw string, etag string, cfg PHPRuntimeInventoryFile, rollbackDepth int) {
	rt := phpRuntimeInventoryInstance()
	if rt == nil {
		cfg, err := buildPHPRuntimeInventoryConfig(phpRuntimeInventoryStateFile{}, currentPHPRuntimeInventoryPath())
		if err != nil {
			cfg = PHPRuntimeInventoryFile{}
		}
		return defaultPHPRuntimeInventoryRaw, bypassconf.ComputeETag([]byte(defaultPHPRuntimeInventoryRaw)), clonePHPRuntimeInventoryFile(cfg), 0
	}
	rt.mu.RLock()
	raw = rt.raw
	etag = rt.etag
	state := rt.state
	rollbackDepth = len(rt.rollbackStack)
	configPath := rt.configPath
	rt.mu.RUnlock()
	cfg, err := buildPHPRuntimeInventoryConfig(state, configPath)
	if err != nil {
		cfg = PHPRuntimeInventoryFile{}
	}
	return raw, etag, clonePHPRuntimeInventoryFile(cfg), rollbackDepth
}

func ValidatePHPRuntimeInventoryRaw(raw string) (PHPRuntimeInventoryFile, error) {
	prepared, err := preparePHPRuntimeInventoryRaw(raw, currentPHPRuntimeInventoryPath())
	if err != nil {
		return PHPRuntimeInventoryFile{}, err
	}
	if err := validateVhostConfigFile(currentVhostConfig(), prepared.cfg); err != nil {
		return PHPRuntimeInventoryFile{}, err
	}
	return clonePHPRuntimeInventoryFile(prepared.cfg), nil
}

func ApplyPHPRuntimeInventoryRaw(ifMatch string, raw string) (string, PHPRuntimeInventoryFile, error) {
	rt := phpRuntimeInventoryInstance()
	if rt == nil {
		return "", PHPRuntimeInventoryFile{}, fmt.Errorf("php runtime inventory is not initialized")
	}
	prepared, err := preparePHPRuntimeInventoryRaw(raw, rt.configPath)
	if err != nil {
		return "", PHPRuntimeInventoryFile{}, err
	}
	if err := validateVhostConfigFile(currentVhostConfig(), prepared.cfg); err != nil {
		return "", PHPRuntimeInventoryFile{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", PHPRuntimeInventoryFile{}, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevState := rt.state
	nextETag := prepared.etag
	dbStore, err := requireConfigDBStore()
	if err != nil {
		return "", PHPRuntimeInventoryFile{}, err
	}
	rec, err := dbStore.writePHPRuntimeInventoryPreparedConfigVersion(ifMatch, prepared, configVersionSourceApply, "", "php runtime inventory update", 0)
	if err != nil {
		return "", PHPRuntimeInventoryFile{}, err
	}
	nextETag = rec.ETag
	rt.raw = prepared.raw
	rt.etag = nextETag
	rt.state = prepared.state
	if err := refreshPHPRuntimeMaterializationWithConfig(prepared.cfg, currentVhostConfig()); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPHPRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		return "", PHPRuntimeInventoryFile{}, err
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPHPRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		prevCfg, _ := buildPHPRuntimeInventoryConfig(prevState, rt.configPath)
		_ = refreshPHPRuntimeMaterializationWithConfig(prevCfg, currentVhostConfig())
		_ = ReconcilePHPRuntimeSupervisor()
		return "", PHPRuntimeInventoryFile{}, err
	}
	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rt.etag, clonePHPRuntimeInventoryFile(prepared.cfg), nil
}

func RollbackPHPRuntimeInventory() (string, PHPRuntimeInventoryFile, proxyRollbackEntry, error) {
	rt := phpRuntimeInventoryInstance()
	if rt == nil {
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, fmt.Errorf("php runtime inventory is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := preparePHPRuntimeInventoryRaw(entry.Raw, rt.configPath)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	if err := validateVhostConfigFile(currentVhostConfig(), prepared.cfg); err != nil {
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevState := rt.state
	nextETag := prepared.etag
	dbStore, err := requireConfigDBStore()
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	rec, err := dbStore.writePHPRuntimeInventoryPreparedConfigVersion(rt.etag, prepared, configVersionSourceRollback, "", "php runtime inventory rollback", 0)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	nextETag = rec.ETag

	rt.raw = prepared.raw
	rt.etag = nextETag
	rt.state = prepared.state
	if err := refreshPHPRuntimeMaterializationWithConfig(prepared.cfg, currentVhostConfig()); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPHPRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPHPRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		prevCfg, _ := buildPHPRuntimeInventoryConfig(prevState, rt.configPath)
		_ = refreshPHPRuntimeMaterializationWithConfig(prevCfg, currentVhostConfig())
		_ = ReconcilePHPRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", PHPRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	return rt.etag, clonePHPRuntimeInventoryFile(prepared.cfg), entry, nil
}

func currentPHPRuntimeInventoryConfig() PHPRuntimeInventoryFile {
	rt := phpRuntimeInventoryInstance()
	if rt != nil {
		rt.mu.RLock()
		state := rt.state
		configPath := rt.configPath
		rt.mu.RUnlock()
		cfg, err := buildPHPRuntimeInventoryConfig(state, configPath)
		if err == nil {
			return clonePHPRuntimeInventoryFile(cfg)
		}
		return PHPRuntimeInventoryFile{}
	}
	cfg, err := buildPHPRuntimeInventoryConfig(phpRuntimeInventoryStateFile{}, currentPHPRuntimeInventoryPath())
	if err == nil {
		return clonePHPRuntimeInventoryFile(cfg)
	}
	return PHPRuntimeInventoryFile{}
}

func preparePHPRuntimeInventoryRaw(raw string, inventoryPath string) (phpRuntimeInventoryPreparedConfig, error) {
	state, err := parsePHPRuntimeInventoryRaw(raw)
	if err != nil {
		return phpRuntimeInventoryPreparedConfig{}, err
	}
	return preparePHPRuntimeInventoryState(state, inventoryPath)
}

func preparePHPRuntimeInventoryState(state phpRuntimeInventoryStateFile, inventoryPath string) (phpRuntimeInventoryPreparedConfig, error) {
	cfg, err := buildPHPRuntimeInventoryConfig(state, inventoryPath)
	if err != nil {
		return phpRuntimeInventoryPreparedConfig{}, err
	}
	normalizedRaw := marshalPHPRuntimeInventoryStateRaw(state)
	return phpRuntimeInventoryPreparedConfig{
		state: state,
		cfg:   cfg,
		raw:   normalizedRaw,
		etag:  bypassconf.ComputeETag([]byte(normalizedRaw)),
	}, nil
}

func parsePHPRuntimeInventoryRaw(raw string) (phpRuntimeInventoryStateFile, error) {
	var in struct {
		PHPEnabled json.RawMessage `json:"php_enabled"`
		Runtimes   json.RawMessage `json:"runtimes"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return phpRuntimeInventoryStateFile{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return phpRuntimeInventoryStateFile{}, fmt.Errorf("invalid json")
	}
	state := phpRuntimeInventoryStateFile{}
	if in.Runtimes != nil {
		state.explicitRuntimes = true
		if strings.TrimSpace(string(in.Runtimes)) != "null" {
			if err := json.Unmarshal(in.Runtimes, &state.Runtimes); err != nil {
				return phpRuntimeInventoryStateFile{}, fmt.Errorf("runtimes must be an array")
			}
		}
	}
	return state, nil
}

func phpRuntimeInventoryStateFromConfig(cfg PHPRuntimeInventoryFile) phpRuntimeInventoryStateFile {
	return phpRuntimeInventoryStateFile{
		Runtimes:         clonePHPRuntimeInventoryFile(cfg).Runtimes,
		explicitRuntimes: true,
	}
}

func marshalPHPRuntimeInventoryStateRaw(state phpRuntimeInventoryStateFile) string {
	if !state.explicitRuntimes {
		return defaultPHPRuntimeInventoryRaw
	}
	return mustJSON(struct {
		Runtimes []PHPRuntimeRecord `json:"runtimes"`
	}{
		Runtimes: clonePHPRuntimeInventoryFile(PHPRuntimeInventoryFile{Runtimes: state.Runtimes}).Runtimes,
	})
}

func normalizePHPRuntimeInventoryFile(in PHPRuntimeInventoryFile) PHPRuntimeInventoryFile {
	out := PHPRuntimeInventoryFile{
		Runtimes: make([]PHPRuntimeRecord, 0, len(in.Runtimes)),
	}
	for _, runtime := range in.Runtimes {
		runtime.RuntimeID = normalizeConfigToken(runtime.RuntimeID)
		runtime.DisplayName = strings.TrimSpace(runtime.DisplayName)
		runtime.DetectedVersion = strings.TrimSpace(runtime.DetectedVersion)
		runtime.BinaryPath = strings.TrimSpace(runtime.BinaryPath)
		runtime.CLIBinaryPath = strings.TrimSpace(runtime.CLIBinaryPath)
		runtime.Modules = normalizePHPRuntimeModules(runtime.Modules)
		runtime.DefaultDisabledModules = normalizePHPRuntimeDisabledModules(runtime.DefaultDisabledModules, runtime.Modules)
		runtime.AvailabilityMessage = strings.TrimSpace(runtime.AvailabilityMessage)
		runtime.RunUser = strings.TrimSpace(runtime.RunUser)
		runtime.RunGroup = strings.TrimSpace(runtime.RunGroup)
		runtime.Source = normalizePHPRuntimeSource(runtime.Source)
		runtime.SHA256 = ""
		if runtime.DisplayName == "" {
			switch {
			case runtime.DetectedVersion != "":
				runtime.DisplayName = runtime.DetectedVersion
			case runtime.RuntimeID != "":
				runtime.DisplayName = runtime.RuntimeID
			}
		}
		out.Runtimes = append(out.Runtimes, runtime)
	}
	return out
}

func validatePHPRuntimeInventoryFile(cfg PHPRuntimeInventoryFile) error {
	seen := make(map[string]struct{}, len(cfg.Runtimes))
	for i, runtime := range cfg.Runtimes {
		field := fmt.Sprintf("runtimes[%d]", i)
		if runtime.RuntimeID == "" {
			return fmt.Errorf("%s.runtime_id is required", field)
		}
		if !isValidConfigToken(runtime.RuntimeID) {
			return fmt.Errorf("%s.runtime_id must contain only [a-z0-9._-]", field)
		}
		if _, exists := seen[runtime.RuntimeID]; exists {
			return fmt.Errorf("%s.runtime_id duplicates %q", field, runtime.RuntimeID)
		}
		seen[runtime.RuntimeID] = struct{}{}
		if runtime.BinaryPath == "" {
			return fmt.Errorf("%s.binary_path is required", field)
		}
		if runtime.RunUser != "" && !isValidRuntimePrincipalToken(runtime.RunUser) {
			return fmt.Errorf("%s.run_user must contain only [A-Za-z0-9._-]", field)
		}
		if runtime.RunGroup != "" && !isValidRuntimePrincipalToken(runtime.RunGroup) {
			return fmt.Errorf("%s.run_group must contain only [A-Za-z0-9._-]", field)
		}
		switch runtime.Source {
		case "", "bundled":
		default:
			return fmt.Errorf("%s.source must be empty or bundled", field)
		}
		if err := validatePHPRuntimeDefaultDisabledModules(runtime, field); err != nil {
			return err
		}
	}
	return nil
}

func clonePHPRuntimeInventoryFile(in PHPRuntimeInventoryFile) PHPRuntimeInventoryFile {
	out := PHPRuntimeInventoryFile{
		Runtimes: make([]PHPRuntimeRecord, 0, len(in.Runtimes)),
	}
	for _, runtime := range in.Runtimes {
		cloned := runtime
		if len(runtime.Modules) > 0 {
			cloned.Modules = append([]string(nil), runtime.Modules...)
		}
		if len(runtime.DefaultDisabledModules) > 0 {
			cloned.DefaultDisabledModules = append([]string(nil), runtime.DefaultDisabledModules...)
		}
		out.Runtimes = append(out.Runtimes, cloned)
	}
	return out
}

func findPHPRuntimeRecordIndex(cfg PHPRuntimeInventoryFile, runtimeID string) int {
	for i, runtime := range cfg.Runtimes {
		if runtime.RuntimeID == runtimeID {
			return i
		}
	}
	return -1
}

func hasAvailablePHPRuntime(cfg PHPRuntimeInventoryFile) bool {
	for _, runtime := range cfg.Runtimes {
		if runtime.Available {
			return true
		}
	}
	return false
}

func currentVhostReferencesForRuntime(runtimeID string) []string {
	runtimeID = normalizeConfigToken(runtimeID)
	cfg := currentVhostConfig()
	names := make([]string, 0)
	for _, vhost := range cfg.Vhosts {
		if normalizeConfigToken(vhost.RuntimeID) == runtimeID {
			names = append(names, vhost.Name)
		}
	}
	sort.Strings(names)
	return names
}

func phpRuntimeRootDirFromInventoryPath(inventoryPath string) string {
	base := strings.TrimSpace(inventoryPath)
	if base == "" {
		base = "data/php-fpm/inventory.json"
	}
	return filepath.Clean(filepath.Dir(base))
}

func normalizePHPRuntimeSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case "", "bundled":
		return "bundled"
	default:
		return source
	}
}

func detectPHPRuntimeAvailability(binaryPath string, modules []string) (bool, string) {
	if ok, message := validatePHPRuntimeBinaryPath(binaryPath); !ok {
		return false, message
	}
	if len(modules) == 0 {
		return false, "module manifest not found or empty"
	}
	return true, ""
}

func validatePHPRuntimeBinaryPath(binaryPath string) (bool, string) {
	binaryPath = strings.TrimSpace(binaryPath)
	if binaryPath == "" {
		return false, "binary_path is empty"
	}
	info, err := os.Stat(binaryPath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, "binary not found"
		}
		return false, err.Error()
	}
	if info.IsDir() {
		return false, "binary path points to a directory"
	}
	if info.Mode()&0o111 == 0 {
		return false, "binary is not executable"
	}
	return true, ""
}

func readPHPRuntimeModuleManifest(binaryPath string) ([]string, error) {
	manifestPath := filepath.Join(filepath.Dir(strings.TrimSpace(binaryPath)), "modules.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("module manifest not found")
		}
		return nil, err
	}
	var modules []string
	if err := json.Unmarshal(raw, &modules); err != nil {
		return nil, fmt.Errorf("module manifest is invalid json")
	}
	modules = normalizePHPRuntimeModules(modules)
	if len(modules) == 0 {
		return nil, fmt.Errorf("module manifest is empty")
	}
	return modules, nil
}

func normalizePHPRuntimeModules(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, module := range in {
		module = strings.ToLower(strings.TrimSpace(module))
		if module == "" {
			continue
		}
		if !isValidRuntimePrincipalToken(module) {
			continue
		}
		if _, exists := seen[module]; exists {
			continue
		}
		seen[module] = struct{}{}
		out = append(out, module)
	}
	return out
}

func normalizePSGIRuntimeModules(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, module := range in {
		module = strings.ToLower(strings.TrimSpace(module))
		if module == "" {
			continue
		}
		if !isValidPerlModuleName(module) {
			continue
		}
		if _, exists := seen[module]; exists {
			continue
		}
		seen[module] = struct{}{}
		out = append(out, module)
	}
	return out
}

func isValidPerlModuleName(module string) bool {
	if module == "" || len(module) > 256 {
		return false
	}
	parts := strings.Split(module, "::")
	for _, part := range parts {
		if part == "" {
			return false
		}
		for i, r := range part {
			switch {
			case r >= 'a' && r <= 'z':
			case r == '_':
			case i > 0 && r >= '0' && r <= '9':
			default:
				return false
			}
		}
	}
	return true
}

func normalizePHPRuntimeDisabledModules(in []string, available []string) []string {
	if len(in) == 0 || len(available) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(available))
	for _, module := range available {
		allowed[module] = struct{}{}
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, module := range in {
		module = strings.ToLower(strings.TrimSpace(module))
		if module == "" {
			continue
		}
		if _, ok := allowed[module]; !ok {
			continue
		}
		if _, exists := seen[module]; exists {
			continue
		}
		seen[module] = struct{}{}
		out = append(out, module)
	}
	return out
}

func validatePHPRuntimeDefaultDisabledModules(runtime PHPRuntimeRecord, field string) error {
	if len(runtime.DefaultDisabledModules) == 0 {
		return nil
	}
	available := make(map[string]struct{}, len(runtime.Modules))
	for _, module := range runtime.Modules {
		available[module] = struct{}{}
	}
	for i, module := range runtime.DefaultDisabledModules {
		if _, ok := available[module]; !ok {
			return fmt.Errorf("%s.default_disabled_modules[%d] references unknown module %q", field, i, module)
		}
	}
	return nil
}

type phpRuntimeArtifactManifest struct {
	RuntimeID              string   `json:"runtime_id,omitempty"`
	DisplayName            string   `json:"display_name,omitempty"`
	DetectedVersion        string   `json:"detected_version,omitempty"`
	BinaryPath             string   `json:"binary_path,omitempty"`
	CLIBinaryPath          string   `json:"cli_binary_path,omitempty"`
	DefaultDisabledModules []string `json:"default_disabled_modules,omitempty"`
	RunUser                string   `json:"run_user,omitempty"`
	RunGroup               string   `json:"run_group,omitempty"`
	Source                 string   `json:"source,omitempty"`
}

func buildPHPRuntimeInventoryConfig(state phpRuntimeInventoryStateFile, inventoryPath string) (PHPRuntimeInventoryFile, error) {
	var runtimes []PHPRuntimeRecord
	var err error
	if state.explicitRuntimes {
		runtimes = clonePHPRuntimeInventoryFile(PHPRuntimeInventoryFile{Runtimes: state.Runtimes}).Runtimes
		for i := range runtimes {
			runtimes[i].Available, runtimes[i].AvailabilityMessage = detectPHPRuntimeAvailability(runtimes[i].BinaryPath, runtimes[i].Modules)
		}
	} else {
		runtimes, err = discoverPHPRuntimesFromDisk(inventoryPath)
		if err != nil {
			return PHPRuntimeInventoryFile{}, err
		}
	}
	cfg := normalizePHPRuntimeInventoryFile(PHPRuntimeInventoryFile{
		Runtimes: runtimes,
	})
	if err := validatePHPRuntimeInventoryFile(cfg); err != nil {
		return PHPRuntimeInventoryFile{}, err
	}
	return cfg, nil
}

func discoverPHPRuntimesFromDisk(inventoryPath string) ([]PHPRuntimeRecord, error) {
	root := filepath.Join(phpRuntimeRootDirFromInventoryPath(inventoryPath), "binaries")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read php runtime binaries dir (%s): %w", root, err)
	}
	out := make([]PHPRuntimeRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runtime, err := readPHPRuntimeArtifactManifest(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, runtime)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuntimeID < out[j].RuntimeID
	})
	return out, nil
}

func readPHPRuntimeArtifactManifest(runtimeDir string) (PHPRuntimeRecord, error) {
	runtimeDir = filepath.Clean(strings.TrimSpace(runtimeDir))
	if runtimeDir == "" {
		return PHPRuntimeRecord{}, fmt.Errorf("php runtime dir is empty")
	}
	runtimeID := normalizeConfigToken(filepath.Base(runtimeDir))
	record := PHPRuntimeRecord{
		RuntimeID:              runtimeID,
		DisplayName:            defaultDisplayNameForRuntimeID(runtimeID),
		BinaryPath:             filepath.ToSlash(filepath.Join(runtimeDir, "php-fpm")),
		CLIBinaryPath:          filepath.ToSlash(filepath.Join(runtimeDir, "php")),
		DefaultDisabledModules: append([]string(nil), defaultDisabledPHPRuntimeModules...),
		Source:                 "bundled",
	}
	manifestPath := filepath.Join(runtimeDir, "runtime.json")
	if raw, err := os.ReadFile(manifestPath); err == nil {
		var meta phpRuntimeArtifactManifest
		if err := json.Unmarshal(raw, &meta); err != nil {
			return PHPRuntimeRecord{}, fmt.Errorf("parse php runtime manifest (%s): %w", manifestPath, err)
		}
		if id := normalizeConfigToken(meta.RuntimeID); id != "" {
			record.RuntimeID = id
		}
		if display := strings.TrimSpace(meta.DisplayName); display != "" {
			record.DisplayName = display
		}
		record.DetectedVersion = strings.TrimSpace(meta.DetectedVersion)
		if binaryPath := strings.TrimSpace(meta.BinaryPath); binaryPath != "" {
			record.BinaryPath = binaryPath
		}
		if cliBinaryPath := strings.TrimSpace(meta.CLIBinaryPath); cliBinaryPath != "" {
			record.CLIBinaryPath = cliBinaryPath
		}
		record.DefaultDisabledModules = normalizePHPRuntimeModules(meta.DefaultDisabledModules)
		record.RunUser = strings.TrimSpace(meta.RunUser)
		record.RunGroup = strings.TrimSpace(meta.RunGroup)
		record.Source = normalizePHPRuntimeSource(meta.Source)
	} else if !os.IsNotExist(err) {
		return PHPRuntimeRecord{}, fmt.Errorf("read php runtime manifest (%s): %w", manifestPath, err)
	}
	modules, err := readPHPRuntimeModuleManifest(record.BinaryPath)
	if err != nil {
		record.Modules = nil
		record.DefaultDisabledModules = nil
		record.Available = false
		record.AvailabilityMessage = err.Error()
	} else {
		record.Modules = modules
		if len(record.DefaultDisabledModules) == 0 {
			record.DefaultDisabledModules = append([]string(nil), defaultDisabledPHPRuntimeModules...)
		}
		record.DefaultDisabledModules = normalizePHPRuntimeDisabledModules(record.DefaultDisabledModules, record.Modules)
		record.Available, record.AvailabilityMessage = detectPHPRuntimeAvailability(record.BinaryPath, record.Modules)
	}
	if record.DisplayName == "" {
		record.DisplayName = defaultDisplayNameForRuntimeID(record.RuntimeID)
	}
	if record.DisplayName == "" {
		record.DisplayName = record.RuntimeID
	}
	return record, nil
}

func defaultDisplayNameForRuntimeID(runtimeID string) string {
	switch runtimeID {
	case "php83":
		return "PHP 8.3"
	case "php84":
		return "PHP 8.4"
	case "php85":
		return "PHP 8.5"
	default:
		return ""
	}
}

func isValidRuntimePrincipalToken(value string) bool {
	if strings.TrimSpace(value) == "" {
		return false
	}
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '.', r == '_', r == '-':
		default:
			return false
		}
	}
	return true
}

func rollbackPersistedPHPRuntimeInventory(path string, store *wafEventStore, expectedETag string, state phpRuntimeInventoryStateFile, raw string) error {
	if store == nil {
		return errConfigDBStoreRequired
	}
	prepared, err := preparePHPRuntimeInventoryState(state, path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(raw) != "" {
		prepared.raw = strings.TrimSpace(raw)
	}
	_, err = store.writePHPRuntimeInventoryPreparedConfigVersion(expectedETag, prepared, configVersionSourceRollback, "", "php runtime inventory rollback after failed apply", 0)
	return err
}

func (rt *phpRuntimeInventoryRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if rt.rollbackMax <= 0 {
		rt.rollbackMax = clampProxyRollbackMax(rt.rollbackMax)
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[len(rt.rollbackStack)-rt.rollbackMax:]...)
	}
}

var defaultPSGIRuntimeInventoryRaw = "{}\n"

type psgiRuntimeConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetPSGIRuntimes(c *gin.Context) {
	raw, etag, cfg, rollbackDepth := PSGIRuntimeInventorySnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"runtimes":       cfg,
		"materialized":   PSGIRuntimeMaterializationSnapshot(),
		"processes":      PSGIRuntimeProcessSnapshot(),
		"rollback_depth": rollbackDepth,
	})
}

func ValidatePSGIRuntimes(c *gin.Context) {
	var in psgiRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidatePSGIRuntimeInventoryRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"runtimes": cfg,
	})
}

func PutPSGIRuntimes(c *gin.Context) {
	var in psgiRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyPSGIRuntimeInventoryRaw(ifMatch, in.Raw)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": conflict.CurrentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"etag":     etag,
		"runtimes": cfg,
	})
}

func RollbackPSGIRuntimes(c *gin.Context) {
	etag, cfg, restored, err := RollbackPSGIRuntimeInventory()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot"})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"runtimes":      cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}

func UpPSGIProcessHandler(c *gin.Context) {
	appName := runtimeAppNameParam(c)
	if err := StartPSGIProcess(appName); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"runtime_app_name": normalizeConfigToken(appName),
		"vhost_name":       normalizeConfigToken(appName),
		"processes":        PSGIRuntimeProcessSnapshot(),
	})
}

func DownPSGIProcessHandler(c *gin.Context) {
	appName := runtimeAppNameParam(c)
	if err := StopPSGIProcess(appName); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"runtime_app_name": normalizeConfigToken(appName),
		"vhost_name":       normalizeConfigToken(appName),
		"processes":        PSGIRuntimeProcessSnapshot(),
	})
}

func ReloadPSGIProcessHandler(c *gin.Context) {
	appName := runtimeAppNameParam(c)
	if err := ReloadPSGIProcess(appName); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":               true,
		"runtime_app_name": normalizeConfigToken(appName),
		"vhost_name":       normalizeConfigToken(appName),
		"processes":        PSGIRuntimeProcessSnapshot(),
	})
}

func runtimeAppNameParam(c *gin.Context) string {
	if c == nil {
		return ""
	}
	if value := strings.TrimSpace(c.Param("runtime_app_name")); value != "" {
		return value
	}
	return strings.TrimSpace(c.Param("vhost_name"))
}

type psgiRuntimeInventoryStateFile struct {
	Runtimes         []PSGIRuntimeRecord `json:"runtimes,omitempty"`
	explicitRuntimes bool
}

type PSGIRuntimeInventoryFile struct {
	Runtimes []PSGIRuntimeRecord `json:"runtimes,omitempty"`
}

type PSGIRuntimeRecord struct {
	RuntimeID           string   `json:"runtime_id,omitempty"`
	DisplayName         string   `json:"display_name,omitempty"`
	DetectedVersion     string   `json:"detected_version,omitempty"`
	PerlPath            string   `json:"perl_path,omitempty"`
	StarmanPath         string   `json:"starman_path,omitempty"`
	Modules             []string `json:"modules,omitempty"`
	Available           bool     `json:"available"`
	AvailabilityMessage string   `json:"availability_message,omitempty"`
	RunUser             string   `json:"run_user,omitempty"`
	RunGroup            string   `json:"run_group,omitempty"`
	Source              string   `json:"source,omitempty"`
	SHA256              string   `json:"sha256,omitempty"`
}

type psgiRuntimeInventoryPreparedConfig struct {
	state psgiRuntimeInventoryStateFile
	cfg   PSGIRuntimeInventoryFile
	raw   string
	etag  string
}

type psgiRuntimeInventoryRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	state         psgiRuntimeInventoryStateFile
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	psgiRuntimeInventoryMu sync.RWMutex
	psgiRuntimeInventoryRt *psgiRuntimeInventoryRuntime
)

func InitPSGIRuntimeInventoryRuntime(path string, rollbackMax int) error {
	cfgPath := strings.TrimSpace(path)
	if cfgPath == "" {
		cfgPath = "data/psgi/inventory.json"
	}
	if store := getLogsStatsStore(); store != nil {
		prepared, rec, found, err := store.loadActivePSGIRuntimeInventoryPreparedConfig(cfgPath)
		if err != nil {
			return fmt.Errorf("read psgi runtime inventory db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized psgi runtime inventory config missing in db; run make db-import before removing seed files")
		}
		rt := &psgiRuntimeInventoryRuntime{
			configPath:    cfgPath,
			raw:           prepared.raw,
			etag:          rec.ETag,
			state:         prepared.state,
			rollbackMax:   clampProxyRollbackMax(rollbackMax),
			rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
		}
		psgiRuntimeInventoryMu.Lock()
		psgiRuntimeInventoryRt = rt
		psgiRuntimeInventoryMu.Unlock()
		return refreshPSGIRuntimeMaterializationAfterInventoryInit()
	}

	rawBytes, _, err := readFileMaybe(cfgPath)
	if err != nil {
		return fmt.Errorf("read psgi runtime inventory (%s): %w", cfgPath, err)
	}
	raw := string(rawBytes)
	if strings.TrimSpace(raw) == "" {
		raw = defaultPSGIRuntimeInventoryRaw
	}
	prepared, err := preparePSGIRuntimeInventoryRaw(raw, cfgPath)
	if err != nil {
		return fmt.Errorf("invalid psgi runtime inventory (%s): %w", cfgPath, err)
	}
	rt := &psgiRuntimeInventoryRuntime{
		configPath:    cfgPath,
		raw:           prepared.raw,
		etag:          prepared.etag,
		state:         prepared.state,
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	psgiRuntimeInventoryMu.Lock()
	psgiRuntimeInventoryRt = rt
	psgiRuntimeInventoryMu.Unlock()
	return refreshPSGIRuntimeMaterializationAfterInventoryInit()
}

func refreshPSGIRuntimeMaterializationAfterInventoryInit() error {
	if vhostRuntimeInstance() == nil {
		return nil
	}
	if err := RefreshPSGIRuntimeMaterialization(); err != nil {
		return fmt.Errorf("materialize psgi runtime config: %w", err)
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		return fmt.Errorf("reconcile psgi runtime supervisor: %w", err)
	}
	return nil
}

func psgiRuntimeInventoryInstance() *psgiRuntimeInventoryRuntime {
	psgiRuntimeInventoryMu.RLock()
	defer psgiRuntimeInventoryMu.RUnlock()
	return psgiRuntimeInventoryRt
}

func PSGIRuntimeInventorySnapshot() (raw string, etag string, cfg PSGIRuntimeInventoryFile, rollbackDepth int) {
	rt := psgiRuntimeInventoryInstance()
	if rt == nil {
		cfg, err := buildPSGIRuntimeInventoryConfig(psgiRuntimeInventoryStateFile{}, currentPSGIRuntimeInventoryPath())
		if err != nil {
			cfg = PSGIRuntimeInventoryFile{}
		}
		return defaultPSGIRuntimeInventoryRaw, bypassconf.ComputeETag([]byte(defaultPSGIRuntimeInventoryRaw)), clonePSGIRuntimeInventoryFile(cfg), 0
	}
	rt.mu.RLock()
	raw = rt.raw
	etag = rt.etag
	state := rt.state
	rollbackDepth = len(rt.rollbackStack)
	configPath := rt.configPath
	rt.mu.RUnlock()
	cfg, err := buildPSGIRuntimeInventoryConfig(state, configPath)
	if err != nil {
		cfg = PSGIRuntimeInventoryFile{}
	}
	return raw, etag, clonePSGIRuntimeInventoryFile(cfg), rollbackDepth
}

func ValidatePSGIRuntimeInventoryRaw(raw string) (PSGIRuntimeInventoryFile, error) {
	prepared, err := preparePSGIRuntimeInventoryRaw(raw, currentPSGIRuntimeInventoryPath())
	if err != nil {
		return PSGIRuntimeInventoryFile{}, err
	}
	if err := validateVhostConfigFileWithInventories(currentVhostConfig(), currentPHPRuntimeInventoryConfig(), prepared.cfg); err != nil {
		return PSGIRuntimeInventoryFile{}, err
	}
	return clonePSGIRuntimeInventoryFile(prepared.cfg), nil
}

func ApplyPSGIRuntimeInventoryRaw(ifMatch string, raw string) (string, PSGIRuntimeInventoryFile, error) {
	rt := psgiRuntimeInventoryInstance()
	if rt == nil {
		return "", PSGIRuntimeInventoryFile{}, fmt.Errorf("psgi runtime inventory is not initialized")
	}
	prepared, err := preparePSGIRuntimeInventoryRaw(raw, rt.configPath)
	if err != nil {
		return "", PSGIRuntimeInventoryFile{}, err
	}
	if err := validateVhostConfigFileWithInventories(currentVhostConfig(), currentPHPRuntimeInventoryConfig(), prepared.cfg); err != nil {
		return "", PSGIRuntimeInventoryFile{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", PSGIRuntimeInventoryFile{}, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevState := rt.state
	nextETag := prepared.etag
	dbStore, err := requireConfigDBStore()
	if err != nil {
		return "", PSGIRuntimeInventoryFile{}, err
	}
	rec, err := dbStore.writePSGIRuntimeInventoryPreparedConfigVersion(ifMatch, prepared, configVersionSourceApply, "", "psgi runtime inventory update", 0)
	if err != nil {
		return "", PSGIRuntimeInventoryFile{}, err
	}
	nextETag = rec.ETag
	rt.raw = prepared.raw
	rt.etag = nextETag
	rt.state = prepared.state
	if err := refreshPSGIRuntimeMaterializationWithConfig(prepared.cfg, currentVhostConfig()); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPSGIRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		return "", PSGIRuntimeInventoryFile{}, err
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPSGIRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		prevCfg, _ := buildPSGIRuntimeInventoryConfig(prevState, rt.configPath)
		_ = refreshPSGIRuntimeMaterializationWithConfig(prevCfg, currentVhostConfig())
		_ = ReconcilePSGIRuntimeSupervisor()
		return "", PSGIRuntimeInventoryFile{}, err
	}
	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rt.etag, clonePSGIRuntimeInventoryFile(prepared.cfg), nil
}

func RollbackPSGIRuntimeInventory() (string, PSGIRuntimeInventoryFile, proxyRollbackEntry, error) {
	rt := psgiRuntimeInventoryInstance()
	if rt == nil {
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, fmt.Errorf("psgi runtime inventory is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := preparePSGIRuntimeInventoryRaw(entry.Raw, rt.configPath)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	if err := validateVhostConfigFileWithInventories(currentVhostConfig(), currentPHPRuntimeInventoryConfig(), prepared.cfg); err != nil {
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevState := rt.state
	nextETag := prepared.etag
	dbStore, err := requireConfigDBStore()
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	rec, err := dbStore.writePSGIRuntimeInventoryPreparedConfigVersion(rt.etag, prepared, configVersionSourceRollback, "", "psgi runtime inventory rollback", 0)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	nextETag = rec.ETag

	rt.raw = prepared.raw
	rt.etag = nextETag
	rt.state = prepared.state
	if err := refreshPSGIRuntimeMaterializationWithConfig(prepared.cfg, currentVhostConfig()); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPSGIRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.state = prevState
		_ = rollbackPersistedPSGIRuntimeInventory(rt.configPath, dbStore, nextETag, prevState, prevRaw)
		prevCfg, _ := buildPSGIRuntimeInventoryConfig(prevState, rt.configPath)
		_ = refreshPSGIRuntimeMaterializationWithConfig(prevCfg, currentVhostConfig())
		_ = ReconcilePSGIRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", PSGIRuntimeInventoryFile{}, proxyRollbackEntry{}, err
	}
	return rt.etag, clonePSGIRuntimeInventoryFile(prepared.cfg), entry, nil
}

func currentPSGIRuntimeInventoryConfig() PSGIRuntimeInventoryFile {
	rt := psgiRuntimeInventoryInstance()
	if rt != nil {
		rt.mu.RLock()
		state := rt.state
		configPath := rt.configPath
		rt.mu.RUnlock()
		cfg, err := buildPSGIRuntimeInventoryConfig(state, configPath)
		if err == nil {
			return clonePSGIRuntimeInventoryFile(cfg)
		}
		return PSGIRuntimeInventoryFile{}
	}
	cfg, err := buildPSGIRuntimeInventoryConfig(psgiRuntimeInventoryStateFile{}, currentPSGIRuntimeInventoryPath())
	if err == nil {
		return clonePSGIRuntimeInventoryFile(cfg)
	}
	return PSGIRuntimeInventoryFile{}
}

func preparePSGIRuntimeInventoryRaw(raw string, inventoryPath string) (psgiRuntimeInventoryPreparedConfig, error) {
	state, err := parsePSGIRuntimeInventoryRaw(raw)
	if err != nil {
		return psgiRuntimeInventoryPreparedConfig{}, err
	}
	return preparePSGIRuntimeInventoryState(state, inventoryPath)
}

func preparePSGIRuntimeInventoryState(state psgiRuntimeInventoryStateFile, inventoryPath string) (psgiRuntimeInventoryPreparedConfig, error) {
	cfg, err := buildPSGIRuntimeInventoryConfig(state, inventoryPath)
	if err != nil {
		return psgiRuntimeInventoryPreparedConfig{}, err
	}
	normalizedRaw := marshalPSGIRuntimeInventoryStateRaw(state)
	return psgiRuntimeInventoryPreparedConfig{
		state: state,
		cfg:   cfg,
		raw:   normalizedRaw,
		etag:  bypassconf.ComputeETag([]byte(normalizedRaw)),
	}, nil
}

func parsePSGIRuntimeInventoryRaw(raw string) (psgiRuntimeInventoryStateFile, error) {
	var in struct {
		Runtimes json.RawMessage `json:"runtimes"`
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return psgiRuntimeInventoryStateFile{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return psgiRuntimeInventoryStateFile{}, fmt.Errorf("invalid json")
	}
	state := psgiRuntimeInventoryStateFile{}
	if in.Runtimes != nil {
		state.explicitRuntimes = true
		if strings.TrimSpace(string(in.Runtimes)) != "null" {
			if err := json.Unmarshal(in.Runtimes, &state.Runtimes); err != nil {
				return psgiRuntimeInventoryStateFile{}, fmt.Errorf("runtimes must be an array")
			}
		}
	}
	return state, nil
}

func psgiRuntimeInventoryStateFromConfig(cfg PSGIRuntimeInventoryFile) psgiRuntimeInventoryStateFile {
	return psgiRuntimeInventoryStateFile{
		Runtimes:         clonePSGIRuntimeInventoryFile(cfg).Runtimes,
		explicitRuntimes: true,
	}
}

func marshalPSGIRuntimeInventoryStateRaw(state psgiRuntimeInventoryStateFile) string {
	if !state.explicitRuntimes {
		return defaultPSGIRuntimeInventoryRaw
	}
	return mustJSON(struct {
		Runtimes []PSGIRuntimeRecord `json:"runtimes"`
	}{
		Runtimes: clonePSGIRuntimeInventoryFile(PSGIRuntimeInventoryFile{Runtimes: state.Runtimes}).Runtimes,
	})
}

func normalizePSGIRuntimeInventoryFile(in PSGIRuntimeInventoryFile) PSGIRuntimeInventoryFile {
	out := PSGIRuntimeInventoryFile{
		Runtimes: make([]PSGIRuntimeRecord, 0, len(in.Runtimes)),
	}
	for _, runtime := range in.Runtimes {
		runtime.RuntimeID = normalizeConfigToken(runtime.RuntimeID)
		runtime.DisplayName = strings.TrimSpace(runtime.DisplayName)
		runtime.DetectedVersion = strings.TrimSpace(runtime.DetectedVersion)
		runtime.PerlPath = strings.TrimSpace(runtime.PerlPath)
		runtime.StarmanPath = strings.TrimSpace(runtime.StarmanPath)
		runtime.Modules = normalizePSGIRuntimeModules(runtime.Modules)
		runtime.AvailabilityMessage = strings.TrimSpace(runtime.AvailabilityMessage)
		runtime.RunUser = strings.TrimSpace(runtime.RunUser)
		runtime.RunGroup = strings.TrimSpace(runtime.RunGroup)
		runtime.Source = normalizePSGIRuntimeSource(runtime.Source)
		runtime.SHA256 = ""
		if runtime.DisplayName == "" {
			switch {
			case runtime.DetectedVersion != "":
				runtime.DisplayName = runtime.DetectedVersion
			case runtime.RuntimeID != "":
				runtime.DisplayName = runtime.RuntimeID
			}
		}
		out.Runtimes = append(out.Runtimes, runtime)
	}
	return out
}

func validatePSGIRuntimeInventoryFile(cfg PSGIRuntimeInventoryFile) error {
	seen := make(map[string]struct{}, len(cfg.Runtimes))
	for i, runtime := range cfg.Runtimes {
		field := fmt.Sprintf("runtimes[%d]", i)
		if runtime.RuntimeID == "" {
			return fmt.Errorf("%s.runtime_id is required", field)
		}
		if !isValidConfigToken(runtime.RuntimeID) {
			return fmt.Errorf("%s.runtime_id must contain only [a-z0-9._-]", field)
		}
		if _, exists := seen[runtime.RuntimeID]; exists {
			return fmt.Errorf("%s.runtime_id duplicates %q", field, runtime.RuntimeID)
		}
		seen[runtime.RuntimeID] = struct{}{}
		if runtime.PerlPath == "" {
			return fmt.Errorf("%s.perl_path is required", field)
		}
		if runtime.StarmanPath == "" {
			return fmt.Errorf("%s.starman_path is required", field)
		}
		if runtime.RunUser != "" && !isValidRuntimePrincipalToken(runtime.RunUser) {
			return fmt.Errorf("%s.run_user must contain only [A-Za-z0-9._-]", field)
		}
		if runtime.RunGroup != "" && !isValidRuntimePrincipalToken(runtime.RunGroup) {
			return fmt.Errorf("%s.run_group must contain only [A-Za-z0-9._-]", field)
		}
		switch runtime.Source {
		case "", "bundled":
		default:
			return fmt.Errorf("%s.source must be empty or bundled", field)
		}
	}
	return nil
}

func clonePSGIRuntimeInventoryFile(in PSGIRuntimeInventoryFile) PSGIRuntimeInventoryFile {
	out := PSGIRuntimeInventoryFile{
		Runtimes: make([]PSGIRuntimeRecord, 0, len(in.Runtimes)),
	}
	for _, runtime := range in.Runtimes {
		cloned := runtime
		if len(runtime.Modules) > 0 {
			cloned.Modules = append([]string(nil), runtime.Modules...)
		}
		out.Runtimes = append(out.Runtimes, cloned)
	}
	return out
}

func findPSGIRuntimeRecordIndex(cfg PSGIRuntimeInventoryFile, runtimeID string) int {
	for i, runtime := range cfg.Runtimes {
		if runtime.RuntimeID == runtimeID {
			return i
		}
	}
	return -1
}

func currentVhostReferencesForPSGIRuntime(runtimeID string) []string {
	runtimeID = normalizeConfigToken(runtimeID)
	cfg := currentVhostConfig()
	names := make([]string, 0)
	for _, vhost := range cfg.Vhosts {
		if normalizeConfigToken(vhost.RuntimeID) == runtimeID && normalizeConfigToken(vhost.Mode) == "psgi" {
			names = append(names, vhost.Name)
		}
	}
	sort.Strings(names)
	return names
}

func psgiRuntimeRootDirFromInventoryPath(inventoryPath string) string {
	base := strings.TrimSpace(inventoryPath)
	if base == "" {
		base = "data/psgi/inventory.json"
	}
	return filepath.Clean(filepath.Dir(base))
}

func normalizePSGIRuntimeSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case "", "bundled":
		return "bundled"
	default:
		return source
	}
}

func detectPSGIRuntimeAvailability(perlPath string, starmanPath string, modules []string) (bool, string) {
	if ok, message := validatePHPRuntimeBinaryPath(perlPath); !ok {
		return false, "perl: " + message
	}
	if ok, message := validatePHPRuntimeBinaryPath(starmanPath); !ok {
		return false, "starman: " + message
	}
	if len(modules) == 0 {
		return false, "module manifest not found or empty"
	}
	return true, ""
}

func readPSGIRuntimeModuleManifest(perlPath string) ([]string, error) {
	manifestPath := filepath.Join(filepath.Dir(strings.TrimSpace(perlPath)), "modules.json")
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("module manifest not found")
		}
		return nil, err
	}
	var modules []string
	if err := json.Unmarshal(raw, &modules); err != nil {
		return nil, fmt.Errorf("module manifest is invalid json")
	}
	modules = normalizePSGIRuntimeModules(modules)
	if len(modules) == 0 {
		return nil, fmt.Errorf("module manifest is empty")
	}
	return modules, nil
}

type psgiRuntimeArtifactManifest struct {
	RuntimeID       string `json:"runtime_id,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	DetectedVersion string `json:"detected_version,omitempty"`
	PerlPath        string `json:"perl_path,omitempty"`
	StarmanPath     string `json:"starman_path,omitempty"`
	RunUser         string `json:"run_user,omitempty"`
	RunGroup        string `json:"run_group,omitempty"`
	Source          string `json:"source,omitempty"`
}

func buildPSGIRuntimeInventoryConfig(state psgiRuntimeInventoryStateFile, inventoryPath string) (PSGIRuntimeInventoryFile, error) {
	var runtimes []PSGIRuntimeRecord
	var err error
	if state.explicitRuntimes {
		runtimes = clonePSGIRuntimeInventoryFile(PSGIRuntimeInventoryFile{Runtimes: state.Runtimes}).Runtimes
		for i := range runtimes {
			runtimes[i].Available, runtimes[i].AvailabilityMessage = detectPSGIRuntimeAvailability(runtimes[i].PerlPath, runtimes[i].StarmanPath, runtimes[i].Modules)
		}
	} else {
		runtimes, err = discoverPSGIRuntimesFromDisk(inventoryPath)
		if err != nil {
			return PSGIRuntimeInventoryFile{}, err
		}
	}
	cfg := normalizePSGIRuntimeInventoryFile(PSGIRuntimeInventoryFile{
		Runtimes: runtimes,
	})
	if err := validatePSGIRuntimeInventoryFile(cfg); err != nil {
		return PSGIRuntimeInventoryFile{}, err
	}
	return cfg, nil
}

func discoverPSGIRuntimesFromDisk(inventoryPath string) ([]PSGIRuntimeRecord, error) {
	root := filepath.Join(psgiRuntimeRootDirFromInventoryPath(inventoryPath), "binaries")
	entries, err := os.ReadDir(root)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read psgi runtime binaries dir (%s): %w", root, err)
	}
	out := make([]PSGIRuntimeRecord, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		runtime, err := readPSGIRuntimeArtifactManifest(filepath.Join(root, entry.Name()))
		if err != nil {
			return nil, err
		}
		out = append(out, runtime)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].RuntimeID < out[j].RuntimeID
	})
	return out, nil
}

func readPSGIRuntimeArtifactManifest(runtimeDir string) (PSGIRuntimeRecord, error) {
	runtimeDir = filepath.Clean(strings.TrimSpace(runtimeDir))
	if runtimeDir == "" {
		return PSGIRuntimeRecord{}, fmt.Errorf("psgi runtime dir is empty")
	}
	runtimeID := normalizeConfigToken(filepath.Base(runtimeDir))
	record := PSGIRuntimeRecord{
		RuntimeID:   runtimeID,
		DisplayName: defaultDisplayNameForPSGIRuntimeID(runtimeID),
		PerlPath:    filepath.ToSlash(filepath.Join(runtimeDir, "perl")),
		StarmanPath: filepath.ToSlash(filepath.Join(runtimeDir, "starman")),
		Source:      "bundled",
	}
	manifestPath := filepath.Join(runtimeDir, "runtime.json")
	if raw, err := os.ReadFile(manifestPath); err == nil {
		var meta psgiRuntimeArtifactManifest
		if err := json.Unmarshal(raw, &meta); err != nil {
			return PSGIRuntimeRecord{}, fmt.Errorf("parse psgi runtime manifest (%s): %w", manifestPath, err)
		}
		if id := normalizeConfigToken(meta.RuntimeID); id != "" {
			record.RuntimeID = id
		}
		if display := strings.TrimSpace(meta.DisplayName); display != "" {
			record.DisplayName = display
		}
		record.DetectedVersion = strings.TrimSpace(meta.DetectedVersion)
		if perlPath := strings.TrimSpace(meta.PerlPath); perlPath != "" {
			record.PerlPath = perlPath
		}
		if starmanPath := strings.TrimSpace(meta.StarmanPath); starmanPath != "" {
			record.StarmanPath = starmanPath
		}
		record.RunUser = strings.TrimSpace(meta.RunUser)
		record.RunGroup = strings.TrimSpace(meta.RunGroup)
		record.Source = normalizePSGIRuntimeSource(meta.Source)
	} else if !os.IsNotExist(err) {
		return PSGIRuntimeRecord{}, fmt.Errorf("read psgi runtime manifest (%s): %w", manifestPath, err)
	}
	modules, err := readPSGIRuntimeModuleManifest(record.PerlPath)
	if err != nil {
		record.Modules = nil
		record.Available = false
		record.AvailabilityMessage = err.Error()
	} else {
		record.Modules = modules
		record.Available, record.AvailabilityMessage = detectPSGIRuntimeAvailability(record.PerlPath, record.StarmanPath, record.Modules)
	}
	if record.DisplayName == "" {
		record.DisplayName = defaultDisplayNameForPSGIRuntimeID(record.RuntimeID)
	}
	if record.DisplayName == "" {
		record.DisplayName = record.RuntimeID
	}
	return record, nil
}

func defaultDisplayNameForPSGIRuntimeID(runtimeID string) string {
	if strings.HasPrefix(runtimeID, "perl") && len(runtimeID) == len("perl")+3 {
		return "Perl " + runtimeID[4:5] + "." + runtimeID[5:]
	}
	return ""
}

func currentPSGIRuntimeInventoryPath() string {
	if rt := psgiRuntimeInventoryInstance(); rt != nil {
		rt.mu.RLock()
		defer rt.mu.RUnlock()
		return rt.configPath
	}
	return "data/psgi/inventory.json"
}

func rollbackPersistedPSGIRuntimeInventory(path string, store *wafEventStore, expectedETag string, state psgiRuntimeInventoryStateFile, raw string) error {
	if store == nil {
		return errConfigDBStoreRequired
	}
	prepared, err := preparePSGIRuntimeInventoryState(state, path)
	if err != nil {
		return err
	}
	if strings.TrimSpace(raw) != "" {
		prepared.raw = strings.TrimSpace(raw)
	}
	_, err = store.writePSGIRuntimeInventoryPreparedConfigVersion(expectedETag, prepared, configVersionSourceRollback, "", "psgi runtime inventory rollback after failed apply", 0)
	return err
}

func (rt *psgiRuntimeInventoryRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if rt.rollbackMax <= 0 {
		rt.rollbackMax = clampProxyRollbackMax(rt.rollbackMax)
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[len(rt.rollbackStack)-rt.rollbackMax:]...)
	}
}
