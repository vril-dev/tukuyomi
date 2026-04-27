package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
	"tukuyomi/internal/bypassconf"
)

const defaultVhostConfigRaw = "{\n  \"vhosts\": []\n}\n"

type vhostConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetRuntimeApps(c *gin.Context) {
	raw, etag, cfg, rollbackDepth := VhostConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":              etag,
		"raw":               raw,
		"runtime_apps":      cfg,
		"runtime_status":    VhostRuntimeStatusSnapshot(),
		"materialized":      PHPRuntimeMaterializationSnapshot(),
		"psgi_materialized": PSGIRuntimeMaterializationSnapshot(),
		"rollback_depth":    rollbackDepth,
	})
}

func ValidateRuntimeApps(c *gin.Context) {
	var in vhostConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidateVhostConfigRawWithInventories(in.Raw, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	if err := validatePSGIVhostRuntimePreflight(cfg, currentPSGIRuntimeInventoryConfig()); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	if _, err := prepareProxyRulesRawWithSitesAndVhosts(currentProxyRawConfigRaw(), currentSiteConfig(), cfg); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":           true,
		"messages":     []string{},
		"runtime_apps": cfg,
	})
}

func PutRuntimeApps(c *gin.Context) {
	var in vhostConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyVhostConfigRaw(ifMatch, in.Raw)
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
		"ok":           true,
		"etag":         etag,
		"runtime_apps": cfg,
	})
}

func RollbackRuntimeApps(c *gin.Context) {
	etag, cfg, restored, err := RollbackVhostConfig()
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
		"runtime_apps":  cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}

type VhostConfigFile struct {
	Vhosts []VhostConfig `json:"vhosts,omitempty"`
}

type VhostConfig struct {
	Name         string `json:"name,omitempty"`
	Mode         string `json:"mode,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	ListenPort   int    `json:"listen_port,omitempty"`
	DocumentRoot string `json:"document_root,omitempty"`
	// Deprecated: accepted only to migrate old configs; ignored at runtime.
	OverrideFileName   string             `json:"override_file_name,omitempty"`
	TryFiles           []string           `json:"try_files,omitempty"`
	RewriteRules       []VhostRewriteRule `json:"rewrite_rules,omitempty"`
	AccessRules        []VhostAccessRule  `json:"access_rules,omitempty"`
	BasicAuth          *VhostBasicAuth    `json:"basic_auth,omitempty"`
	PHPValues          map[string]string  `json:"php_value,omitempty"`
	PHPAdminValues     map[string]string  `json:"php_admin_value,omitempty"`
	AppRoot            string             `json:"app_root,omitempty"`
	PSGIFile           string             `json:"psgi_file,omitempty"`
	Workers            int                `json:"workers,omitempty"`
	MaxRequests        int                `json:"max_requests,omitempty"`
	IncludeExtlib      *bool              `json:"include_extlib,omitempty"`
	Env                map[string]string  `json:"env,omitempty"`
	RuntimeID          string             `json:"runtime_id,omitempty"`
	GeneratedTarget    string             `json:"generated_target,omitempty"`
	LinkedUpstreamName string             `json:"linked_upstream_name,omitempty"`
}

type VhostRewriteRule struct {
	Pattern       string `json:"pattern,omitempty"`
	Replacement   string `json:"replacement,omitempty"`
	Flag          string `json:"flag,omitempty"`
	PreserveQuery bool   `json:"preserve_query,omitempty"`
}

type VhostAccessRule struct {
	PathPattern string          `json:"path_pattern,omitempty"`
	Action      string          `json:"action,omitempty"`
	CIDRs       []string        `json:"cidrs,omitempty"`
	BasicAuth   *VhostBasicAuth `json:"basic_auth,omitempty"`
}

type VhostBasicAuth struct {
	Realm string               `json:"realm,omitempty"`
	Users []VhostBasicAuthUser `json:"users,omitempty"`
}

type VhostBasicAuthUser struct {
	Username     string `json:"username,omitempty"`
	PasswordHash string `json:"password_hash,omitempty"`
}

type vhostPreparedConfig struct {
	cfg       VhostConfigFile
	raw       string
	etag      string
	versionID int64
}

type VhostRuntimeStatus struct {
	Degraded  bool   `json:"degraded"`
	LastError string `json:"last_error,omitempty"`
}

type vhostStartupConfigError struct {
	path string
	err  error
}

func (e vhostStartupConfigError) Error() string {
	return fmt.Sprintf("invalid Runtime Apps config (%s): %v", e.path, e.err)
}

func (e vhostStartupConfigError) Unwrap() error {
	return e.err
}

type vhostRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	versionID     int64
	cfg           VhostConfigFile
	loadError     string
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	vhostRuntimeMu sync.RWMutex
	vhostRt        *vhostRuntime
)

func InitVhostRuntime(path string, rollbackMax int) error {
	cfgPath := strings.TrimSpace(path)
	if cfgPath == "" {
		cfgPath = "data/php-fpm/vhosts.json"
	}
	if store := getLogsStatsStore(); store != nil {
		cfg, rec, found, err := store.loadActiveVhostConfig()
		if err != nil {
			return fmt.Errorf("read Runtime Apps config db: %w", err)
		}
		if found {
			prepared, err := prepareVhostConfigRawWithInventories(mustJSON(cfg), currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
			if err != nil {
				return fmt.Errorf("read Runtime Apps config db: %w", err)
			}
			prepared.etag = rec.ETag
			prepared.versionID = rec.VersionID
			rt := newVhostRuntime(cfgPath, prepared.raw, prepared.cfg, "", rollbackMax)
			rt.etag = prepared.etag
			rt.versionID = prepared.versionID
			setVhostRuntime(rt)
			if err := RefreshPHPRuntimeMaterialization(); err != nil {
				return fmt.Errorf("materialize php runtime config: %w", err)
			}
			if err := ReconcilePHPRuntimeSupervisor(); err != nil {
				return fmt.Errorf("reconcile php runtime supervisor: %w", err)
			}
			if err := RefreshPSGIRuntimeMaterialization(); err != nil {
				return fmt.Errorf("materialize psgi runtime config: %w", err)
			}
			if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
				return fmt.Errorf("reconcile psgi runtime supervisor: %w", err)
			}
			return nil
		}
		return fmt.Errorf("normalized Runtime Apps config missing in db; run make db-import before removing seed files")
	}
	rawBytes, _, err := readFileMaybe(cfgPath)
	if err != nil {
		return fmt.Errorf("read Runtime Apps config (%s): %w", cfgPath, err)
	}
	raw := string(rawBytes)
	if strings.TrimSpace(raw) == "" {
		raw = defaultVhostConfigRaw
	}
	prepared, err := prepareVhostConfigRawWithInventories(raw, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
	if err != nil {
		startupErr := vhostStartupConfigError{path: cfgPath, err: err}
		rt := newVhostRuntime(cfgPath, raw, VhostConfigFile{}, "invalid Runtime Apps config: "+err.Error(), rollbackMax)
		setVhostRuntime(rt)
		if err := refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), VhostConfigFile{}); err != nil {
			return fmt.Errorf("materialize isolated php runtime config: %w", err)
		}
		if err := ReconcilePHPRuntimeSupervisor(); err != nil {
			return fmt.Errorf("reconcile isolated php runtime supervisor: %w", err)
		}
		if err := refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), VhostConfigFile{}); err != nil {
			return fmt.Errorf("materialize isolated psgi runtime config: %w", err)
		}
		if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
			return fmt.Errorf("reconcile isolated psgi runtime supervisor: %w", err)
		}
		return startupErr
	}
	if store := getLogsStatsStore(); store != nil {
		rec, err := store.writeVhostConfigVersion("", prepared.cfg, configVersionSourceImport, "", "Runtime Apps file import", 0)
		if err != nil {
			return fmt.Errorf("import Runtime Apps config db: %w", err)
		}
		prepared.etag = rec.ETag
		prepared.versionID = rec.VersionID
	}
	rt := newVhostRuntime(cfgPath, prepared.raw, prepared.cfg, "", rollbackMax)
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	setVhostRuntime(rt)
	if err := RefreshPHPRuntimeMaterialization(); err != nil {
		return fmt.Errorf("materialize php runtime config: %w", err)
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		return fmt.Errorf("reconcile php runtime supervisor: %w", err)
	}
	if err := RefreshPSGIRuntimeMaterialization(); err != nil {
		return fmt.Errorf("materialize psgi runtime config: %w", err)
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		return fmt.Errorf("reconcile psgi runtime supervisor: %w", err)
	}
	return nil
}

func newVhostRuntime(path string, raw string, cfg VhostConfigFile, loadError string, rollbackMax int) *vhostRuntime {
	return &vhostRuntime{
		configPath:    path,
		raw:           raw,
		etag:          bypassconf.ComputeETag([]byte(raw)),
		cfg:           cloneVhostConfigFile(cfg),
		loadError:     strings.TrimSpace(loadError),
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
}

func setVhostRuntime(rt *vhostRuntime) {
	vhostRuntimeMu.Lock()
	vhostRt = rt
	vhostRuntimeMu.Unlock()
}

func IsVhostStartupConfigError(err error) bool {
	var target vhostStartupConfigError
	return errors.As(err, &target)
}

func vhostRuntimeInstance() *vhostRuntime {
	vhostRuntimeMu.RLock()
	defer vhostRuntimeMu.RUnlock()
	return vhostRt
}

func VhostConfigSnapshot() (raw string, etag string, cfg VhostConfigFile, rollbackDepth int) {
	rt := vhostRuntimeInstance()
	if rt == nil {
		return defaultVhostConfigRaw, bypassconf.ComputeETag([]byte(defaultVhostConfigRaw)), VhostConfigFile{}, 0
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.raw, rt.etag, cloneVhostConfigFile(rt.cfg), len(rt.rollbackStack)
}

func VhostRuntimeStatusSnapshot() VhostRuntimeStatus {
	rt := vhostRuntimeInstance()
	if rt == nil {
		return VhostRuntimeStatus{}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	lastErr := strings.TrimSpace(rt.loadError)
	return VhostRuntimeStatus{
		Degraded:  lastErr != "",
		LastError: lastErr,
	}
}

func ValidateVhostConfigRaw(raw string) (VhostConfigFile, error) {
	return ValidateVhostConfigRawWithInventories(raw, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
}

func ValidateVhostConfigRawWithInventory(raw string, inventory PHPRuntimeInventoryFile) (VhostConfigFile, error) {
	return ValidateVhostConfigRawWithInventories(raw, inventory, currentPSGIRuntimeInventoryConfig())
}

func ValidateVhostConfigRawWithInventories(raw string, phpInventory PHPRuntimeInventoryFile, psgiInventory PSGIRuntimeInventoryFile) (VhostConfigFile, error) {
	prepared, err := prepareVhostConfigRawWithInventories(raw, phpInventory, psgiInventory)
	if err != nil {
		return VhostConfigFile{}, err
	}
	return cloneVhostConfigFile(prepared.cfg), nil
}

func validatePSGIVhostRuntimePreflight(cfg VhostConfigFile, psgiInventory PSGIRuntimeInventoryFile) error {
	materialized, _, err := buildPSGIRuntimeMaterializations(psgiInventory, cfg)
	if err != nil {
		return err
	}
	processIDs := make([]string, 0, len(materialized))
	for processID := range materialized {
		processIDs = append(processIDs, processID)
	}
	sort.Strings(processIDs)
	for _, processID := range processIDs {
		mat := materialized[processID]
		identity, err := resolvePSGIRuntimeIdentity(mat)
		if err != nil {
			return err
		}
		if err := validatePSGIApplicationPaths(mat, identity); err != nil {
			return err
		}
	}
	return nil
}

func ApplyVhostConfigRaw(ifMatch string, raw string) (string, VhostConfigFile, error) {
	rt := vhostRuntimeInstance()
	if rt == nil {
		return "", VhostConfigFile{}, fmt.Errorf("vhost runtime is not initialized")
	}
	prepared, err := prepareVhostConfigRawWithInventories(raw, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
	if err != nil {
		return "", VhostConfigFile{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	syncEquivalentVhostDBVersionLocked(rt)
	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag && !configVersionETagSameContent(ifMatch, rt.etag) {
		return "", VhostConfigFile{}, proxyRulesConflictError{CurrentETag: currentConfigVersionETag(vhostConfigDomain, rt.etag)}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	prevCfg := cloneVhostConfigFile(rt.cfg)
	prevLoadError := rt.loadError
	if _, err := prepareProxyRulesRawWithSitesAndVhosts(currentProxyRawConfigRaw(), currentSiteConfig(), prepared.cfg); err != nil {
		return "", VhostConfigFile{}, err
	}
	if err := validatePSGIVhostRuntimePreflight(prepared.cfg, currentPSGIRuntimeInventoryConfig()); err != nil {
		return "", VhostConfigFile{}, err
	}
	nextETag, nextVersionID, err := persistVhostConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceApply, 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", VhostConfigFile{}, proxyRulesConflictError{CurrentETag: currentConfigVersionETag(vhostConfigDomain, rt.etag)}
		}
		return "", VhostConfigFile{}, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneVhostConfigFile(prepared.cfg)
	rt.loadError = ""
	if err := refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		return "", VhostConfigFile{}, err
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		return "", VhostConfigFile{}, err
	}
	if err := refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		return "", VhostConfigFile{}, err
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		return "", VhostConfigFile{}, err
	}
	if err := reloadProxyRuntimeWithSitesAndVhosts(currentSiteConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		return "", VhostConfigFile{}, err
	}
	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rt.etag, cloneVhostConfigFile(rt.cfg), nil
}

func RollbackVhostConfig() (string, VhostConfigFile, proxyRollbackEntry, error) {
	rt := vhostRuntimeInstance()
	if rt == nil {
		return "", VhostConfigFile{}, proxyRollbackEntry{}, fmt.Errorf("vhost runtime is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", VhostConfigFile{}, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := prepareVhostConfigRawWithInventories(entry.Raw, currentPHPRuntimeInventoryConfig(), currentPSGIRuntimeInventoryConfig())
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	prevCfg := cloneVhostConfigFile(rt.cfg)
	prevLoadError := rt.loadError
	if _, err := prepareProxyRulesRawWithSitesAndVhosts(currentProxyRawConfigRaw(), currentSiteConfig(), prepared.cfg); err != nil {
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	restoredVersionID := int64(0)
	if store := getLogsStatsStore(); store != nil {
		if foundID, found, err := store.findConfigVersionIDByETag(vhostConfigDomain, entry.ETag); err == nil && found {
			restoredVersionID = foundID
		}
	}
	nextETag, nextVersionID, err := persistVhostConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceRollback, restoredVersionID)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", VhostConfigFile{}, proxyRollbackEntry{}, proxyRulesConflictError{CurrentETag: currentConfigVersionETag(vhostConfigDomain, rt.etag)}
		}
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID

	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneVhostConfigFile(prepared.cfg)
	rt.loadError = ""
	if err := refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	if err := ReconcilePHPRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	if err := refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	if err := ReconcilePSGIRuntimeSupervisor(); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	if err := reloadProxyRuntimeWithSitesAndVhosts(currentSiteConfig(), prepared.cfg); err != nil {
		rt.raw = prevRaw
		rt.etag = prevETag
		rt.versionID = prevVersionID
		rt.cfg = prevCfg
		rt.loadError = prevLoadError
		if restoredETag, restoredVersionID, restoreErr := persistVhostConfigAuthoritative(rt.configPath, prepared.etag, vhostPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prevCfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		_ = refreshPHPRuntimeMaterializationWithConfig(currentPHPRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePHPRuntimeSupervisor()
		_ = refreshPSGIRuntimeMaterializationWithConfig(currentPSGIRuntimeInventoryConfig(), prevCfg)
		_ = ReconcilePSGIRuntimeSupervisor()
		rt.pushRollbackLocked(entry)
		return "", VhostConfigFile{}, proxyRollbackEntry{}, err
	}
	return rt.etag, cloneVhostConfigFile(rt.cfg), entry, nil
}

func currentVhostConfig() VhostConfigFile {
	rt := vhostRuntimeInstance()
	if rt != nil {
		rt.mu.RLock()
		defer rt.mu.RUnlock()
		return cloneVhostConfigFile(rt.cfg)
	}
	return VhostConfigFile{}
}

func prepareVhostConfigRawWithInventory(raw string, inventory PHPRuntimeInventoryFile) (vhostPreparedConfig, error) {
	return prepareVhostConfigRawWithInventories(raw, inventory, currentPSGIRuntimeInventoryConfig())
}

func prepareVhostConfigRawWithInventories(raw string, phpInventory PHPRuntimeInventoryFile, psgiInventory PSGIRuntimeInventoryFile) (vhostPreparedConfig, error) {
	cfg, err := parseVhostConfigRaw(raw)
	if err != nil {
		return vhostPreparedConfig{}, err
	}
	if err := validateVhostConfigFileWithInventories(cfg, phpInventory, psgiInventory); err != nil {
		return vhostPreparedConfig{}, err
	}
	normalizedRaw := mustJSON(cfg)
	return vhostPreparedConfig{
		cfg:  cfg,
		raw:  normalizedRaw,
		etag: bypassconf.ComputeETag([]byte(normalizedRaw)),
	}, nil
}

func parseVhostConfigRaw(raw string) (VhostConfigFile, error) {
	var in VhostConfigFile
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return VhostConfigFile{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return VhostConfigFile{}, fmt.Errorf("invalid json")
	}
	return normalizeVhostConfigFile(in), nil
}

func normalizeVhostConfigFile(in VhostConfigFile) VhostConfigFile {
	out := VhostConfigFile{
		Vhosts: make([]VhostConfig, 0, len(in.Vhosts)),
	}
	linkedAliases := make(map[string]struct{}, len(in.Vhosts))
	usedGeneratedTargets := make(map[string]struct{}, len(in.Vhosts))
	for _, vhost := range in.Vhosts {
		vhost.Name = strings.TrimSpace(vhost.Name)
		vhost.Mode = normalizeVhostMode(vhost.Mode)
		vhost.Hostname = normalizeRuntimeListenHost(vhost.Hostname)
		vhost.DocumentRoot = strings.TrimSpace(filepath.Clean(strings.TrimSpace(vhost.DocumentRoot)))
		vhost.OverrideFileName = ""
		vhost.TryFiles = normalizeVhostTryFiles(vhost.TryFiles)
		vhost.RewriteRules = normalizeVhostRewriteRules(vhost.RewriteRules)
		vhost.AccessRules = normalizeVhostAccessRules(vhost.AccessRules)
		vhost.BasicAuth = normalizeVhostBasicAuth(vhost.BasicAuth)
		vhost.PHPValues = normalizeVhostINIOverrides(vhost.PHPValues)
		vhost.PHPAdminValues = normalizeVhostINIOverrides(vhost.PHPAdminValues)
		vhost.AppRoot = normalizeOptionalLocalPath(vhost.AppRoot)
		vhost.PSGIFile = normalizeRelativeLocalPath(vhost.PSGIFile)
		vhost.Env = normalizeVhostEnv(vhost.Env)
		vhost.RuntimeID = normalizeConfigToken(vhost.RuntimeID)
		vhost.GeneratedTarget = normalizeConfigToken(vhost.GeneratedTarget)
		vhost.LinkedUpstreamName = normalizeConfigToken(vhost.LinkedUpstreamName)
		if vhost.LinkedUpstreamName != "" {
			linkedAliases[vhost.LinkedUpstreamName] = struct{}{}
		}
		if vhost.GeneratedTarget != "" {
			usedGeneratedTargets[vhost.GeneratedTarget] = struct{}{}
		}
		if vhost.Mode == "static" {
			vhost.RuntimeID = ""
		}
		if vhost.Mode == "psgi" {
			if vhost.Workers == 0 {
				vhost.Workers = 2
			}
			if vhost.MaxRequests == 0 {
				vhost.MaxRequests = 200
			}
			if vhost.IncludeExtlib == nil {
				include := true
				vhost.IncludeExtlib = &include
			}
		}
		out.Vhosts = append(out.Vhosts, vhost)
	}
	for i := range out.Vhosts {
		if out.Vhosts[i].GeneratedTarget != "" {
			continue
		}
		base := slugConfigToken(out.Vhosts[i].Name)
		if base == "" {
			base = "vhost-" + strconv.Itoa(i+1)
		}
		if _, exists := linkedAliases[base]; exists {
			base += generatedTargetConflictSuffix(out.Vhosts[i].Mode)
		}
		out.Vhosts[i].GeneratedTarget = uniqueGeneratedTarget(base, i+1, linkedAliases, usedGeneratedTargets)
		usedGeneratedTargets[out.Vhosts[i].GeneratedTarget] = struct{}{}
	}
	return out
}

func generatedTargetConflictSuffix(mode string) string {
	switch normalizeVhostMode(mode) {
	case "php-fpm":
		return "-php"
	case "psgi":
		return "-psgi"
	case "static":
		return "-static"
	default:
		return "-vhost"
	}
}

func uniqueGeneratedTarget(base string, index int, linkedAliases map[string]struct{}, usedGeneratedTargets map[string]struct{}) string {
	base = normalizeConfigToken(base)
	if base == "" {
		base = "vhost-" + strconv.Itoa(index)
	}
	if !generatedTargetReserved(base, linkedAliases, usedGeneratedTargets) {
		return base
	}
	for suffix := 2; ; suffix++ {
		candidate := base + "-" + strconv.Itoa(suffix)
		if !generatedTargetReserved(candidate, linkedAliases, usedGeneratedTargets) {
			return candidate
		}
	}
}

func generatedTargetReserved(candidate string, linkedAliases map[string]struct{}, usedGeneratedTargets map[string]struct{}) bool {
	if _, exists := linkedAliases[candidate]; exists {
		return true
	}
	_, exists := usedGeneratedTargets[candidate]
	return exists
}

func validateVhostConfigFile(cfg VhostConfigFile, inventory PHPRuntimeInventoryFile) error {
	return validateVhostConfigFileWithInventories(cfg, inventory, currentPSGIRuntimeInventoryConfig())
}

func validateVhostConfigFileWithInventories(cfg VhostConfigFile, phpInventory PHPRuntimeInventoryFile, psgiInventory PSGIRuntimeInventoryFile) error {
	seenNames := make(map[string]struct{}, len(cfg.Vhosts))
	seenUpstreamAliases := make(map[string]struct{}, len(cfg.Vhosts)*2)
	seenListenPairs := make(map[string]struct{}, len(cfg.Vhosts))
	knownPHPRuntimes := make(map[string]struct{}, len(phpInventory.Runtimes))
	for _, runtime := range phpInventory.Runtimes {
		knownPHPRuntimes[runtime.RuntimeID] = struct{}{}
	}
	knownPSGIRuntimes := make(map[string]struct{}, len(psgiInventory.Runtimes))
	for _, runtime := range psgiInventory.Runtimes {
		knownPSGIRuntimes[runtime.RuntimeID] = struct{}{}
	}
	for i, vhost := range cfg.Vhosts {
		field := fmt.Sprintf("vhosts[%d]", i)
		if vhost.Name == "" {
			return fmt.Errorf("%s.name is required", field)
		}
		if _, exists := seenNames[vhost.Name]; exists {
			return fmt.Errorf("%s.name duplicates %q", field, vhost.Name)
		}
		seenNames[vhost.Name] = struct{}{}
		switch vhost.Mode {
		case "static", "php-fpm", "psgi":
		default:
			return fmt.Errorf("%s.mode must be one of: static, php-fpm, psgi", field)
		}
		if err := validateRuntimeListenHost(vhost.Hostname, field+".hostname"); err != nil {
			return err
		}
		if vhost.ListenPort < 1 || vhost.ListenPort > 65535 {
			return fmt.Errorf("%s.listen_port must be between 1 and 65535", field)
		}
		pairKey := runtimeListenEndpoint(vhost.Hostname, vhost.ListenPort)
		if _, exists := seenListenPairs[pairKey]; exists {
			return fmt.Errorf("%s listen target duplicates %q", field, pairKey)
		}
		seenListenPairs[pairKey] = struct{}{}
		if vhost.DocumentRoot == "" || vhost.DocumentRoot == "." {
			return fmt.Errorf("%s.document_root is required", field)
		}
		if err := validateVhostTryFiles(vhost.TryFiles, field); err != nil {
			return err
		}
		if vhost.Mode != "psgi" && vhostTryFilesContainPSGI(vhost.TryFiles) {
			return fmt.Errorf("%s.try_files @psgi requires mode=psgi", field)
		}
		if err := validateVhostRewriteRules(vhost.RewriteRules, field); err != nil {
			return err
		}
		if err := validateVhostAccessRules(vhost.AccessRules, field); err != nil {
			return err
		}
		if err := validateVhostBasicAuth(vhost.BasicAuth, field+".basic_auth"); err != nil {
			return err
		}
		if vhost.GeneratedTarget == "" {
			return fmt.Errorf("%s.generated_target is required", field)
		}
		if !isValidConfigToken(vhost.GeneratedTarget) {
			return fmt.Errorf("%s.generated_target must contain only [a-z0-9._-]", field)
		}
		if _, exists := seenUpstreamAliases[vhost.GeneratedTarget]; exists {
			return fmt.Errorf("%s.generated_target duplicates %q", field, vhost.GeneratedTarget)
		}
		seenUpstreamAliases[vhost.GeneratedTarget] = struct{}{}
		if vhost.LinkedUpstreamName != "" {
			if vhost.LinkedUpstreamName == vhost.GeneratedTarget {
				return fmt.Errorf("%s.linked_upstream_name must differ from generated_target", field)
			}
			if !isValidConfigToken(vhost.LinkedUpstreamName) {
				return fmt.Errorf("%s.linked_upstream_name must contain only [a-z0-9._-]", field)
			}
			if _, exists := seenUpstreamAliases[vhost.LinkedUpstreamName]; exists {
				return fmt.Errorf("%s.linked_upstream_name duplicates %q", field, vhost.LinkedUpstreamName)
			}
			seenUpstreamAliases[vhost.LinkedUpstreamName] = struct{}{}
		}
		if vhost.Mode == "php-fpm" {
			if vhost.RuntimeID == "" {
				return fmt.Errorf("%s.runtime_id is required when mode=php-fpm", field)
			}
			if _, ok := knownPHPRuntimes[vhost.RuntimeID]; !ok {
				return fmt.Errorf("%s.runtime_id references unknown runtime %q", field, vhost.RuntimeID)
			}
			if err := validateVhostINIOverrides(vhost.PHPValues, field+".php_value"); err != nil {
				return err
			}
			if err := validateVhostINIOverrides(vhost.PHPAdminValues, field+".php_admin_value"); err != nil {
				return err
			}
		}
		if vhost.Mode == "psgi" {
			if vhost.RuntimeID == "" {
				return fmt.Errorf("%s.runtime_id is required when mode=psgi", field)
			}
			if _, ok := knownPSGIRuntimes[vhost.RuntimeID]; !ok {
				return fmt.Errorf("%s.runtime_id references unknown psgi runtime %q", field, vhost.RuntimeID)
			}
			if vhost.AppRoot == "" || vhost.AppRoot == "." {
				return fmt.Errorf("%s.app_root is required when mode=psgi", field)
			}
			if vhost.PSGIFile == "" {
				return fmt.Errorf("%s.psgi_file is required when mode=psgi", field)
			}
			if err := validateVhostRelativePath(vhost.PSGIFile); err != nil {
				return fmt.Errorf("%s.psgi_file: %w", field, err)
			}
			if !strings.HasSuffix(strings.ToLower(vhost.PSGIFile), ".psgi") {
				return fmt.Errorf("%s.psgi_file must end with .psgi", field)
			}
			if vhost.Workers < 1 || vhost.Workers > 64 {
				return fmt.Errorf("%s.workers must be between 1 and 64", field)
			}
			if vhost.MaxRequests < 1 || vhost.MaxRequests > 100000 {
				return fmt.Errorf("%s.max_requests must be between 1 and 100000", field)
			}
			if len(vhost.PHPValues) > 0 || len(vhost.PHPAdminValues) > 0 {
				return fmt.Errorf("%s php_value/php_admin_value require mode=php-fpm", field)
			}
			if err := validateVhostEnv(vhost.Env, field+".env"); err != nil {
				return err
			}
		}
		if vhost.Mode == "static" && vhost.RuntimeID != "" {
			return fmt.Errorf("%s.runtime_id must be empty when mode=static", field)
		}
		if vhost.Mode == "static" && (len(vhost.PHPValues) > 0 || len(vhost.PHPAdminValues) > 0) {
			return fmt.Errorf("%s php_value/php_admin_value require mode=php-fpm", field)
		}
		if vhost.Mode != "psgi" && (vhost.AppRoot != "" || vhost.PSGIFile != "" || vhost.Workers != 0 || vhost.MaxRequests != 0 || vhost.IncludeExtlib != nil || len(vhost.Env) > 0) {
			return fmt.Errorf("%s app_root/psgi_file/workers/max_requests/include_extlib/env require mode=psgi", field)
		}
	}
	return nil
}

func cloneVhostConfigFile(in VhostConfigFile) VhostConfigFile {
	out := VhostConfigFile{
		Vhosts: make([]VhostConfig, len(in.Vhosts)),
	}
	for i, vhost := range in.Vhosts {
		cp := vhost
		cp.TryFiles = append([]string(nil), vhost.TryFiles...)
		cp.RewriteRules = append([]VhostRewriteRule(nil), vhost.RewriteRules...)
		cp.AccessRules = cloneVhostAccessRules(vhost.AccessRules)
		cp.BasicAuth = cloneVhostBasicAuth(vhost.BasicAuth)
		cp.PHPValues = cloneStringMap(vhost.PHPValues)
		cp.PHPAdminValues = cloneStringMap(vhost.PHPAdminValues)
		cp.IncludeExtlib = cloneBoolPtr(vhost.IncludeExtlib)
		cp.Env = cloneStringMap(vhost.Env)
		out.Vhosts[i] = cp
	}
	return out
}

func countVhostsByMode(cfg VhostConfigFile, mode string) int {
	mode = normalizeVhostMode(mode)
	count := 0
	for _, vhost := range cfg.Vhosts {
		if normalizeVhostMode(vhost.Mode) == mode {
			count++
		}
	}
	return count
}

func persistVhostConfigAuthoritative(path string, expectedETag string, prepared vhostPreparedConfig, source string, restoredFromVersionID int64) (string, int64, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return "", 0, err
	}
	rec, err := store.writeVhostConfigVersion(expectedETag, prepared.cfg, source, "", "Runtime Apps config update", restoredFromVersionID)
	if err != nil {
		return "", 0, err
	}
	return rec.ETag, rec.VersionID, nil
}

func syncEquivalentVhostDBVersionLocked(rt *vhostRuntime) {
	if rt == nil {
		return
	}
	store := getLogsStatsStore()
	if store == nil {
		return
	}
	rec, found, err := store.loadActiveConfigVersion(vhostConfigDomain)
	if err != nil || !found {
		return
	}
	if rec.ETag == "" || rec.ETag == rt.etag {
		return
	}
	if !configVersionETagSameContent(rec.ETag, rt.etag) {
		return
	}
	rt.etag = rec.ETag
	rt.versionID = rec.VersionID
}

func normalizeVhostMode(v string) string {
	x := strings.ToLower(strings.TrimSpace(v))
	if x == "" {
		return "static"
	}
	return x
}

func normalizeRuntimeListenHost(value string) string {
	host := strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		inner := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		if addr, err := netip.ParseAddr(inner); err == nil {
			return addr.String()
		}
		return inner
	}
	if addr, err := netip.ParseAddr(host); err == nil {
		return addr.String()
	}
	return host
}

func validateRuntimeListenHost(host string, field string) error {
	host = normalizeRuntimeListenHost(host)
	if host == "" {
		return fmt.Errorf("%s is required", field)
	}
	if strings.Contains(host, "://") || strings.Contains(host, "/") || strings.ContainsAny(host, " \t\r\n") {
		return fmt.Errorf("%s must not include scheme, path, or whitespace", field)
	}
	if _, _, err := net.SplitHostPort(host); err == nil {
		return fmt.Errorf("%s must not include a port", field)
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return nil
	}
	if strings.Contains(host, ":") {
		return fmt.Errorf("%s must be a hostname or IP address without a port", field)
	}
	return nil
}

func runtimeListenEndpoint(host string, port int) string {
	return net.JoinHostPort(normalizeRuntimeListenHost(host), strconv.Itoa(port))
}

func normalizeVhostTryFiles(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, entry := range in {
		next := strings.TrimSpace(entry)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateVhostTryFiles(tryFiles []string, field string) error {
	for i, entry := range tryFiles {
		if entry == "" {
			return fmt.Errorf("%s.try_files[%d] must not be empty", field, i)
		}
		if strings.ContainsAny(entry, "\r\n") {
			return fmt.Errorf("%s.try_files[%d] must be a single line", field, i)
		}
		if entry == "@psgi" {
			continue
		}
		if strings.HasPrefix(entry, "$uri") || strings.HasPrefix(entry, "/") {
			continue
		}
		return fmt.Errorf("%s.try_files[%d] must start with $uri or /, or be @psgi", field, i)
	}
	return nil
}

func vhostTryFilesContainPSGI(tryFiles []string) bool {
	for _, entry := range tryFiles {
		if strings.TrimSpace(entry) == "@psgi" {
			return true
		}
	}
	return false
}

func normalizeVhostRewriteRules(in []VhostRewriteRule) []VhostRewriteRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]VhostRewriteRule, 0, len(in))
	for _, rule := range in {
		next := VhostRewriteRule{
			Pattern:       strings.TrimSpace(rule.Pattern),
			Replacement:   strings.TrimSpace(rule.Replacement),
			Flag:          normalizeVhostRewriteFlag(rule.Flag),
			PreserveQuery: rule.PreserveQuery,
		}
		if next.Pattern == "" && next.Replacement == "" && next.Flag == "" && !next.PreserveQuery {
			continue
		}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeVhostRewriteFlag(v string) string {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "", "break":
		return "break"
	case "last", "redirect", "permanent":
		return strings.ToLower(strings.TrimSpace(v))
	default:
		return strings.ToLower(strings.TrimSpace(v))
	}
}

func validateVhostRewriteRules(rules []VhostRewriteRule, field string) error {
	for i, rule := range rules {
		ruleField := fmt.Sprintf("%s.rewrite_rules[%d]", field, i)
		if rule.Pattern == "" {
			return fmt.Errorf("%s.pattern is required", ruleField)
		}
		if strings.ContainsAny(rule.Pattern, "\r\n") {
			return fmt.Errorf("%s.pattern must be a single line", ruleField)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("%s.pattern: %w", ruleField, err)
		}
		if strings.ContainsAny(rule.Replacement, "\r\n") {
			return fmt.Errorf("%s.replacement must be a single line", ruleField)
		}
		switch rule.Flag {
		case "break", "last", "redirect", "permanent":
		default:
			return fmt.Errorf("%s.flag must be one of: break, last, redirect, permanent", ruleField)
		}
	}
	return nil
}

func normalizeVhostAccessRules(in []VhostAccessRule) []VhostAccessRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]VhostAccessRule, 0, len(in))
	for _, rule := range in {
		next := VhostAccessRule{
			PathPattern: normalizeVhostRequestPath(rule.PathPattern),
			Action:      normalizeVhostAccessAction(rule.Action),
			CIDRs:       normalizeCIDRStrings(rule.CIDRs),
			BasicAuth:   normalizeVhostBasicAuth(rule.BasicAuth),
		}
		if strings.TrimSpace(rule.PathPattern) == "" {
			next.PathPattern = ""
		}
		if next.PathPattern == "" && next.Action == "" && len(next.CIDRs) == 0 && next.BasicAuth == nil {
			continue
		}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeVhostAccessAction(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func validateVhostAccessRules(rules []VhostAccessRule, field string) error {
	for i, rule := range rules {
		ruleField := fmt.Sprintf("%s.access_rules[%d]", field, i)
		if rule.PathPattern == "" {
			return fmt.Errorf("%s.path_pattern is required", ruleField)
		}
		if !strings.HasPrefix(rule.PathPattern, "/") {
			return fmt.Errorf("%s.path_pattern must start with '/'", ruleField)
		}
		if strings.ContainsAny(rule.PathPattern, "\r\n") {
			return fmt.Errorf("%s.path_pattern must be a single line", ruleField)
		}
		switch rule.Action {
		case "allow", "deny":
		default:
			return fmt.Errorf("%s.action must be one of: allow, deny", ruleField)
		}
		for j, cidr := range rule.CIDRs {
			if _, err := netip.ParsePrefix(cidr); err != nil {
				return fmt.Errorf("%s.cidrs[%d]: %w", ruleField, j, err)
			}
		}
		if rule.Action == "deny" && rule.BasicAuth != nil {
			return fmt.Errorf("%s.basic_auth cannot be combined with action=deny", ruleField)
		}
		if err := validateVhostBasicAuth(rule.BasicAuth, ruleField+".basic_auth"); err != nil {
			return err
		}
	}
	return nil
}

func normalizeVhostBasicAuth(in *VhostBasicAuth) *VhostBasicAuth {
	if in == nil {
		return nil
	}
	out := &VhostBasicAuth{
		Realm: strings.TrimSpace(in.Realm),
		Users: make([]VhostBasicAuthUser, 0, len(in.Users)),
	}
	if out.Realm == "" {
		out.Realm = "Restricted"
	}
	for _, user := range in.Users {
		next := VhostBasicAuthUser{
			Username:     strings.TrimSpace(user.Username),
			PasswordHash: strings.TrimSpace(user.PasswordHash),
		}
		if next.Username == "" && next.PasswordHash == "" {
			continue
		}
		out.Users = append(out.Users, next)
	}
	if len(out.Users) == 0 {
		return nil
	}
	return out
}

func validateVhostBasicAuth(in *VhostBasicAuth, field string) error {
	if in == nil {
		return nil
	}
	if strings.ContainsAny(in.Realm, "\r\n") {
		return fmt.Errorf("%s.realm must be a single line", field)
	}
	if len(in.Users) == 0 {
		return fmt.Errorf("%s.users must not be empty", field)
	}
	seenUsers := make(map[string]struct{}, len(in.Users))
	for i, user := range in.Users {
		userField := fmt.Sprintf("%s.users[%d]", field, i)
		if user.Username == "" {
			return fmt.Errorf("%s.username is required", userField)
		}
		if strings.ContainsAny(user.Username, ":\r\n") {
			return fmt.Errorf("%s.username must not contain ':' or newlines", userField)
		}
		if _, exists := seenUsers[user.Username]; exists {
			return fmt.Errorf("%s.username duplicates %q", userField, user.Username)
		}
		seenUsers[user.Username] = struct{}{}
		if user.PasswordHash == "" {
			return fmt.Errorf("%s.password_hash is required", userField)
		}
		if _, err := bcrypt.Cost([]byte(user.PasswordHash)); err != nil {
			return fmt.Errorf("%s.password_hash must be a valid bcrypt hash", userField)
		}
	}
	return nil
}

func normalizeVhostINIOverrides(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		nextKey := strings.TrimSpace(key)
		nextValue := strings.TrimSpace(value)
		if nextKey == "" {
			continue
		}
		out[nextKey] = nextValue
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateVhostINIOverrides(in map[string]string, field string) error {
	for key, value := range in {
		if key == "" {
			return fmt.Errorf("%s contains an empty key", field)
		}
		if strings.ContainsAny(key, "[]=\r\n") {
			return fmt.Errorf("%s[%q] has an invalid key", field, key)
		}
		if strings.ContainsAny(value, "\r\n") {
			return fmt.Errorf("%s[%q] must be a single line", field, key)
		}
	}
	return nil
}

func normalizeOptionalLocalPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = filepath.Clean(value)
	if value == "." {
		return ""
	}
	return value
}

func normalizeRelativeLocalPath(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = filepath.ToSlash(filepath.Clean(value))
	if value == "." {
		return ""
	}
	return value
}

func validateVhostRelativePath(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return fmt.Errorf("is required")
	}
	if filepath.IsAbs(value) || strings.HasPrefix(value, "/") {
		return fmt.Errorf("must be relative")
	}
	for _, part := range strings.Split(filepath.ToSlash(value), "/") {
		switch part {
		case "", ".", "..":
			return fmt.Errorf("must not contain empty, '.', or '..' path segments")
		}
	}
	return nil
}

func normalizeVhostEnv(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if key == "" {
			continue
		}
		out[key] = value
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func validateVhostEnv(in map[string]string, field string) error {
	for key, value := range in {
		if key == "" {
			return fmt.Errorf("%s contains an empty key", field)
		}
		if !isValidVhostEnvName(key) {
			return fmt.Errorf("%s[%q] has an invalid name", field, key)
		}
		if strings.ContainsAny(value, "\x00\r\n") {
			return fmt.Errorf("%s[%q] must be a single line without NUL", field, key)
		}
	}
	return nil
}

func isValidVhostEnvName(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		switch {
		case r >= 'A' && r <= 'Z':
		case r >= 'a' && r <= 'z':
		case r == '_':
		case i > 0 && r >= '0' && r <= '9':
		default:
			return false
		}
	}
	return true
}

func cloneVhostAccessRules(in []VhostAccessRule) []VhostAccessRule {
	if len(in) == 0 {
		return nil
	}
	out := make([]VhostAccessRule, len(in))
	for i, rule := range in {
		out[i] = VhostAccessRule{
			PathPattern: rule.PathPattern,
			Action:      rule.Action,
			CIDRs:       append([]string(nil), rule.CIDRs...),
			BasicAuth:   cloneVhostBasicAuth(rule.BasicAuth),
		}
	}
	return out
}

func cloneVhostBasicAuth(in *VhostBasicAuth) *VhostBasicAuth {
	if in == nil {
		return nil
	}
	out := &VhostBasicAuth{
		Realm: in.Realm,
		Users: append([]VhostBasicAuthUser(nil), in.Users...),
	}
	return out
}

func cloneStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func cloneBoolPtr(in *bool) *bool {
	if in == nil {
		return nil
	}
	out := *in
	return &out
}

func normalizeCIDRStrings(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := make([]string, 0, len(in))
	seen := make(map[string]struct{}, len(in))
	for _, entry := range in {
		next := strings.TrimSpace(entry)
		if next == "" {
			continue
		}
		if _, ok := seen[next]; ok {
			continue
		}
		seen[next] = struct{}{}
		out = append(out, next)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func normalizeConfigToken(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func isValidConfigToken(v string) bool {
	if v == "" {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= '0' && r <= '9':
		case r == '.', r == '-', r == '_':
		default:
			return false
		}
	}
	return true
}

func slugConfigToken(v string) string {
	var b strings.Builder
	v = strings.ToLower(strings.TrimSpace(v))
	lastDash := false
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
			lastDash = false
		case r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		case r == '.', r == '_', r == '-':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func (rt *vhostRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if rt.rollbackMax <= 0 {
		rt.rollbackMax = clampProxyRollbackMax(rt.rollbackMax)
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[len(rt.rollbackStack)-rt.rollbackMax:]...)
	}
}
