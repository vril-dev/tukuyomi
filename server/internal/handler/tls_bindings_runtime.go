package handler

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	defaultTLSBindingConfigRaw = "{\n  \"bindings\": []\n}\n"
	tlsBindingConfigBlobKey    = "tls_bindings"
	tlsBindingConfigDomain     = "tls_bindings"
	tlsBindingSchemaVersion    = 1
)

type tlsBindingConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetTLSBindings(c *gin.Context) {
	raw, etag, cfg, statuses, rollbackDepth := TLSBindingConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":                 etag,
		"raw":                  raw,
		"tls_bindings":         cfg,
		"tls_binding_statuses": statuses,
		"rollback_depth":       rollbackDepth,
	})
}

func ValidateTLSBindings(c *gin.Context) {
	var in tlsBindingConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, statuses, err := ValidateTLSBindingConfigRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":                   true,
		"messages":             []string{},
		"tls_bindings":         cfg,
		"tls_binding_statuses": statuses,
	})
}

func PutTLSBindings(c *gin.Context) {
	var in tlsBindingConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, statuses, err := ApplyTLSBindingConfigRaw(ifMatch, in.Raw)
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
		"ok":                   true,
		"etag":                 etag,
		"tls_bindings":         cfg,
		"tls_binding_statuses": statuses,
	})
}

func RollbackTLSBindings(c *gin.Context) {
	etag, cfg, statuses, restored, err := RollbackTLSBindingConfig()
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
		"ok":                   true,
		"etag":                 etag,
		"tls_bindings":         cfg,
		"tls_binding_statuses": statuses,
		"rollback":             true,
		"restored_from":        restored,
	})
}

type TLSBindingConfigFile struct {
	Bindings []TLSBindingConfig `json:"bindings,omitempty"`
}

type TLSBindingConfig struct {
	Name     string            `json:"name,omitempty"`
	Enabled  *bool             `json:"enabled,omitempty"`
	Hosts    []string          `json:"hosts,omitempty"`
	Mode     string            `json:"mode"`
	CertFile string            `json:"cert_file,omitempty"`
	KeyFile  string            `json:"key_file,omitempty"`
	ACME     SiteTLSACMEConfig `json:"acme,omitempty"`
}

type TLSBindingRuntimeStatus struct {
	Name            string   `json:"name"`
	Enabled         bool     `json:"enabled"`
	Hosts           []string `json:"hosts,omitempty"`
	Mode            string   `json:"mode"`
	Status          string   `json:"status"`
	Warning         string   `json:"warning,omitempty"`
	CertNotAfter    string   `json:"cert_not_after,omitempty"`
	ACMEEnvironment string   `json:"acme_environment,omitempty"`
}

type tlsBindingPreparedConfig struct {
	cfg       TLSBindingConfigFile
	raw       string
	etag      string
	versionID int64
	statuses  []TLSBindingRuntimeStatus
	bindings  []siteTLSBinding
}

type tlsBindingRuntimeSnapshot struct {
	raw       string
	etag      string
	versionID int64
	cfg       TLSBindingConfigFile
	statuses  []TLSBindingRuntimeStatus
	bindings  []siteTLSBinding
}

type tlsBindingRuntime struct {
	mu            sync.RWMutex
	configPath    string
	raw           string
	etag          string
	versionID     int64
	cfg           TLSBindingConfigFile
	statuses      []TLSBindingRuntimeStatus
	bindings      []siteTLSBinding
	rollbackMax   int
	rollbackStack []proxyRollbackEntry
}

var (
	tlsBindingRuntimeMu sync.RWMutex
	tlsBindingRt        *tlsBindingRuntime
)

func InitTLSBindingRuntime(path string, rollbackMax int) error {
	cfgPath := strings.TrimSpace(path)
	if cfgPath == "" {
		cfgPath = "conf/tls-bindings.json"
	}
	prepared, err := loadTLSBindingPreparedConfig(cfgPath)
	if err != nil {
		return fmt.Errorf("initialize tls bindings config (%s): %w", cfgPath, err)
	}
	rt := &tlsBindingRuntime{
		configPath:    cfgPath,
		raw:           prepared.raw,
		etag:          prepared.etag,
		versionID:     prepared.versionID,
		cfg:           prepared.cfg,
		statuses:      cloneTLSBindingRuntimeStatuses(prepared.statuses),
		bindings:      cloneSiteTLSBindings(prepared.bindings),
		rollbackMax:   clampProxyRollbackMax(rollbackMax),
		rollbackStack: make([]proxyRollbackEntry, 0, clampProxyRollbackMax(rollbackMax)),
	}
	tlsBindingRuntimeMu.Lock()
	tlsBindingRt = rt
	tlsBindingRuntimeMu.Unlock()
	return nil
}

func loadTLSBindingPreparedConfig(path string) (tlsBindingPreparedConfig, error) {
	store := getLogsStatsStore()
	if store != nil {
		cfg, rec, found, err := store.loadActiveTLSBindingConfig()
		if err != nil || found {
			if err != nil {
				return tlsBindingPreparedConfig{}, err
			}
			prepared, err := prepareTLSBindingConfigRaw(mustJSON(cfg))
			if err != nil {
				return tlsBindingPreparedConfig{}, err
			}
			prepared.etag = rec.ETag
			prepared.versionID = rec.VersionID
			return prepared, nil
		}
		if dbRaw, _, legacyFound, err := store.GetConfigBlob(tlsBindingConfigBlobKey); err != nil {
			return tlsBindingPreparedConfig{}, err
		} else if legacyFound {
			prepared, err := prepareTLSBindingConfigRaw(string(dbRaw))
			if err != nil {
				return tlsBindingPreparedConfig{}, err
			}
			rec, err := store.writeTLSBindingConfigVersion("", prepared.cfg, configVersionSourceImport, "", "legacy tls bindings import", 0)
			if err != nil {
				return tlsBindingPreparedConfig{}, err
			}
			_ = store.DeleteConfigBlob(tlsBindingConfigBlobKey)
			prepared.etag = rec.ETag
			prepared.versionID = rec.VersionID
			return prepared, nil
		}
		if siteCfg, _, siteFound, err := store.loadActiveSiteConfig(); err != nil {
			return tlsBindingPreparedConfig{}, err
		} else if siteFound {
			derived := deriveTLSBindingsFromSites(siteCfg)
			if len(derived.Bindings) > 0 {
				prepared, err := prepareTLSBindingConfigRaw(mustJSON(derived))
				if err != nil {
					return tlsBindingPreparedConfig{}, err
				}
				rec, err := store.writeTLSBindingConfigVersion("", prepared.cfg, configVersionSourceImport, "", "derived from sites tls", 0)
				if err != nil {
					return tlsBindingPreparedConfig{}, err
				}
				prepared.etag = rec.ETag
				prepared.versionID = rec.VersionID
				return prepared, nil
			}
		}
		rawBytes, _, err := readStartupSeedFile(path, startupTLSBindingsSeedName)
		if err != nil {
			return tlsBindingPreparedConfig{}, err
		}
		raw := string(rawBytes)
		if strings.TrimSpace(raw) == "" {
			raw = defaultTLSBindingConfigRaw
		}
		prepared, err := prepareTLSBindingConfigRaw(raw)
		if err != nil {
			return tlsBindingPreparedConfig{}, err
		}
		rec, err = store.writeTLSBindingConfigVersion("", prepared.cfg, configVersionSourceImport, "", "tls bindings seed import", 0)
		if err != nil {
			return tlsBindingPreparedConfig{}, err
		}
		prepared.etag = rec.ETag
		prepared.versionID = rec.VersionID
		return prepared, nil
	}

	rawBytes, _, err := readFileMaybe(path)
	if err != nil {
		return tlsBindingPreparedConfig{}, err
	}
	raw := string(rawBytes)
	if strings.TrimSpace(raw) == "" {
		raw = defaultTLSBindingConfigRaw
	}
	return prepareTLSBindingConfigRaw(raw)
}

func tlsBindingRuntimeInstance() *tlsBindingRuntime {
	tlsBindingRuntimeMu.RLock()
	defer tlsBindingRuntimeMu.RUnlock()
	return tlsBindingRt
}

func TLSBindingConfigSnapshot() (raw string, etag string, cfg TLSBindingConfigFile, statuses []TLSBindingRuntimeStatus, rollbackDepth int) {
	rt := tlsBindingRuntimeInstance()
	if rt == nil {
		return defaultTLSBindingConfigRaw, bypassconf.ComputeETag([]byte(defaultTLSBindingConfigRaw)), TLSBindingConfigFile{}, nil, 0
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return rt.raw, rt.etag, rt.cfg, cloneTLSBindingRuntimeStatuses(rt.statuses), len(rt.rollbackStack)
}

func ValidateTLSBindingConfigRaw(raw string) (TLSBindingConfigFile, []TLSBindingRuntimeStatus, error) {
	prepared, err := prepareTLSBindingConfigRaw(raw)
	if err != nil {
		return TLSBindingConfigFile{}, nil, err
	}
	return prepared.cfg, cloneTLSBindingRuntimeStatuses(prepared.statuses), nil
}

func ApplyTLSBindingConfigRaw(ifMatch string, raw string) (string, TLSBindingConfigFile, []TLSBindingRuntimeStatus, error) {
	rt := tlsBindingRuntimeInstance()
	if rt == nil {
		return "", TLSBindingConfigFile{}, nil, fmt.Errorf("tls binding runtime is not initialized")
	}
	prepared, err := prepareTLSBindingConfigRaw(raw)
	if err != nil {
		return "", TLSBindingConfigFile{}, nil, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag {
		return "", TLSBindingConfigFile{}, nil, proxyRulesConflictError{CurrentETag: rt.etag}
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	nextETag, nextVersionID, err := persistTLSBindingConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceApply, 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", TLSBindingConfigFile{}, nil, proxyRulesConflictError{CurrentETag: rt.etag}
		}
		return "", TLSBindingConfigFile{}, nil, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID
	prev := rt.snapshotLocked()
	rt.applyPreparedLocked(prepared)
	if err := ReloadServerTLSRuntimeForTLSBindings(prepared.cfg, prepared.statuses); err != nil {
		rt.restoreLocked(prev)
		if restoredETag, restoredVersionID, restoreErr := persistTLSBindingConfigAuthoritative(rt.configPath, prepared.etag, tlsBindingPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prev.cfg}, configVersionSourceRollback, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		if restoreErr := ReloadServerTLSRuntimeForTLSBindings(prev.cfg, prev.statuses); restoreErr != nil {
			RecordServerTLSError(fmt.Errorf("failed to restore tls runtime after reload error: %w", restoreErr))
		}
		return "", TLSBindingConfigFile{}, nil, err
	}

	rt.pushRollbackLocked(proxyRollbackEntry{
		Raw:       prevRaw,
		ETag:      prevETag,
		Timestamp: time.Now().UTC().Format(time.RFC3339Nano),
	})
	return rt.etag, rt.cfg, cloneTLSBindingRuntimeStatuses(rt.statuses), nil
}

func RollbackTLSBindingConfig() (string, TLSBindingConfigFile, []TLSBindingRuntimeStatus, proxyRollbackEntry, error) {
	rt := tlsBindingRuntimeInstance()
	if rt == nil {
		return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, fmt.Errorf("tls binding runtime is not initialized")
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if len(rt.rollbackStack) == 0 {
		return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, fmt.Errorf("no rollback snapshot")
	}
	entry := rt.rollbackStack[len(rt.rollbackStack)-1]
	rt.rollbackStack = rt.rollbackStack[:len(rt.rollbackStack)-1]

	prepared, err := prepareTLSBindingConfigRaw(entry.Raw)
	if err != nil {
		rt.pushRollbackLocked(entry)
		return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, err
	}

	prevRaw := rt.raw
	prevETag := rt.etag
	prevVersionID := rt.versionID
	restoredVersionID := int64(0)
	if store := getLogsStatsStore(); store != nil {
		if foundID, found, err := store.findConfigVersionIDByETag(tlsBindingConfigDomain, entry.ETag); err == nil && found {
			restoredVersionID = foundID
		}
	}
	nextETag, nextVersionID, err := persistTLSBindingConfigAuthoritative(rt.configPath, rt.etag, prepared, configVersionSourceRollback, restoredVersionID)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, proxyRulesConflictError{CurrentETag: rt.etag}
		}
		rt.pushRollbackLocked(entry)
		return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, err
	}
	prepared.etag = nextETag
	prepared.versionID = nextVersionID
	prev := rt.snapshotLocked()
	rt.applyPreparedLocked(prepared)
	if err := ReloadServerTLSRuntimeForTLSBindings(prepared.cfg, prepared.statuses); err != nil {
		rt.restoreLocked(prev)
		if restoredETag, restoredVersionID, restoreErr := persistTLSBindingConfigAuthoritative(rt.configPath, prepared.etag, tlsBindingPreparedConfig{raw: prevRaw, etag: prevETag, cfg: prev.cfg}, configVersionSourceApply, prevVersionID); restoreErr == nil {
			rt.etag = restoredETag
			rt.versionID = restoredVersionID
		}
		if restoreErr := ReloadServerTLSRuntimeForTLSBindings(prev.cfg, prev.statuses); restoreErr != nil {
			RecordServerTLSError(fmt.Errorf("failed to restore tls runtime after rollback error: %w", restoreErr))
		}
		rt.pushRollbackLocked(entry)
		return "", TLSBindingConfigFile{}, nil, proxyRollbackEntry{}, err
	}

	return rt.etag, rt.cfg, cloneTLSBindingRuntimeStatuses(rt.statuses), entry, nil
}

func SyncTLSBindingStorage() error {
	store := getLogsStatsStore()
	rt := tlsBindingRuntimeInstance()
	if store == nil || rt == nil {
		return nil
	}
	cfg, rec, found, err := store.loadActiveTLSBindingConfig()
	if err != nil {
		return err
	}
	if !found {
		rt.mu.RLock()
		cfg := cloneTLSBindingConfigFile(rt.cfg)
		rt.mu.RUnlock()
		_, err := store.writeTLSBindingConfigVersion("", cfg, configVersionSourceImport, "", "tls bindings runtime import", 0)
		return err
	}
	prepared, err := prepareTLSBindingConfigRaw(mustJSON(cfg))
	if err != nil {
		return err
	}
	prepared.etag = rec.ETag
	prepared.versionID = rec.VersionID

	rt.mu.Lock()
	defer rt.mu.Unlock()
	if prepared.etag == rt.etag {
		return nil
	}
	prev := rt.snapshotLocked()
	rt.applyPreparedLocked(prepared)
	if err := ReloadServerTLSRuntimeForTLSBindings(prepared.cfg, prepared.statuses); err != nil {
		rt.restoreLocked(prev)
		if restoreErr := ReloadServerTLSRuntimeForTLSBindings(prev.cfg, prev.statuses); restoreErr != nil {
			RecordServerTLSError(fmt.Errorf("failed to restore tls runtime after db sync error: %w", restoreErr))
		}
		return err
	}
	return nil
}

func prepareTLSBindingConfigRaw(raw string) (tlsBindingPreparedConfig, error) {
	cfg, statuses, bindings, err := parseTLSBindingConfigRaw(raw)
	if err != nil {
		return tlsBindingPreparedConfig{}, err
	}
	normalizedRaw := mustJSON(cfg)
	return tlsBindingPreparedConfig{
		cfg:      cfg,
		raw:      normalizedRaw,
		etag:     bypassconf.ComputeETag([]byte(normalizedRaw)),
		statuses: statuses,
		bindings: bindings,
	}, nil
}

func parseTLSBindingConfigRaw(raw string) (TLSBindingConfigFile, []TLSBindingRuntimeStatus, []siteTLSBinding, error) {
	if strings.TrimSpace(raw) == "" {
		raw = defaultTLSBindingConfigRaw
	}
	var in TLSBindingConfigFile
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return TLSBindingConfigFile{}, nil, nil, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return TLSBindingConfigFile{}, nil, nil, fmt.Errorf("invalid json")
	}
	return normalizeAndValidateTLSBindingConfig(in)
}

func normalizeAndValidateTLSBindingConfig(in TLSBindingConfigFile) (TLSBindingConfigFile, []TLSBindingRuntimeStatus, []siteTLSBinding, error) {
	cfg := normalizeTLSBindingConfigFile(in)
	statuses := make([]TLSBindingRuntimeStatus, 0, len(cfg.Bindings))
	bindings := make([]siteTLSBinding, 0, len(cfg.Bindings))
	seenNames := map[string]struct{}{}
	hostOwners := make([]siteHostOwnership, 0)

	for i := range cfg.Bindings {
		bindingCfg := cfg.Bindings[i]
		if _, ok := seenNames[bindingCfg.Name]; ok {
			return TLSBindingConfigFile{}, nil, nil, fmt.Errorf("tls_bindings[%d].name duplicates %q", i, bindingCfg.Name)
		}
		seenNames[bindingCfg.Name] = struct{}{}
		if len(bindingCfg.Hosts) == 0 {
			return TLSBindingConfigFile{}, nil, nil, fmt.Errorf("tls_bindings[%d].hosts is required", i)
		}
		for hostIdx, host := range bindingCfg.Hosts {
			if err := validateProxyRouteHostPattern(host); err != nil {
				return TLSBindingConfigFile{}, nil, nil, fmt.Errorf("tls_bindings[%d].hosts[%d]: %w", i, hostIdx, err)
			}
			for _, owner := range hostOwners {
				if siteHostsOverlap(host, owner.Host) {
					return TLSBindingConfigFile{}, nil, nil, fmt.Errorf("tls_bindings[%d].hosts[%d] overlaps %q owned by tls binding %q", i, hostIdx, owner.Host, owner.SiteName)
				}
			}
			hostOwners = append(hostOwners, siteHostOwnership{SiteName: bindingCfg.Name, Host: host})
		}

		status := TLSBindingRuntimeStatus{
			Name:    bindingCfg.Name,
			Enabled: siteEnabled(bindingCfg.Enabled),
			Hosts:   append([]string(nil), bindingCfg.Hosts...),
			Mode:    bindingCfg.Mode,
			Status:  "disabled",
		}
		if !status.Enabled {
			statuses = append(statuses, status)
			continue
		}

		runtimeBinding, warning, err := validateTLSRuntimeBinding(i, bindingCfg)
		if err != nil {
			return TLSBindingConfigFile{}, nil, nil, err
		}
		status.Status = "covered"
		status.Warning = warning
		status.CertNotAfter = runtimeBinding.NotAfter
		if bindingCfg.Mode == "acme" {
			status.ACMEEnvironment = bindingCfg.ACME.Environment
		}
		statuses = append(statuses, status)
		bindings = append(bindings, runtimeBinding)
	}
	return cfg, statuses, bindings, nil
}

func normalizeTLSBindingConfigFile(in TLSBindingConfigFile) TLSBindingConfigFile {
	if len(in.Bindings) == 0 {
		return TLSBindingConfigFile{}
	}
	out := TLSBindingConfigFile{Bindings: make([]TLSBindingConfig, 0, len(in.Bindings))}
	for i, binding := range in.Bindings {
		next := binding
		next.Name = strings.TrimSpace(next.Name)
		if next.Name == "" {
			next.Name = fmt.Sprintf("tls-%d", i+1)
		}
		next.Hosts = normalizeSiteHosts(next.Hosts)
		next.Mode = normalizeSiteTLSMode(next.Mode)
		next.CertFile = strings.TrimSpace(next.CertFile)
		next.KeyFile = strings.TrimSpace(next.KeyFile)
		next.ACME.Environment = normalizeSiteTLSACMEEnvironment(next.ACME.Environment)
		next.ACME.Email = strings.TrimSpace(next.ACME.Email)
		if next.Mode != "acme" {
			next.ACME = SiteTLSACMEConfig{}
		}
		out.Bindings = append(out.Bindings, next)
	}
	return out
}

func validateTLSRuntimeBinding(index int, binding TLSBindingConfig) (siteTLSBinding, string, error) {
	if !config.ServerTLSEnabled {
		return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d] requires server.tls.enabled=true", index)
	}
	switch binding.Mode {
	case "manual":
		if siteHasWildcardHost(binding.Hosts) && (binding.CertFile == "" || binding.KeyFile == "") {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].manual wildcard hosts require cert_file and key_file", index)
		}
		if binding.CertFile == "" || binding.KeyFile == "" {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].cert_file and tls_bindings[%d].key_file are required for manual mode", index, index)
		}
		cert, leaf, notAfter, err := loadSiteCertificate(binding.CertFile, binding.KeyFile)
		if err != nil {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d] manual certificate load error: %w", index, err)
		}
		for _, host := range binding.Hosts {
			if !siteCertificateCoversHostPattern(leaf, host) {
				return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d] manual certificate does not cover host %q", index, host)
			}
		}
		return siteTLSBinding{Name: binding.Name, Hosts: append([]string(nil), binding.Hosts...), Mode: binding.Mode, Certificate: cert, NotAfter: notAfter}, "", nil
	case "acme":
		if siteHasWildcardHost(binding.Hosts) {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].mode=acme supports exact hosts only", index)
		}
		if host := firstSiteIPAddressHost(binding.Hosts); host != "" {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].mode=acme does not support IP address host %q; use a DNS name or manual certificate", index, host)
		}
		if binding.ACME.Environment != siteTLSACMEEnvironmentProduction && binding.ACME.Environment != siteTLSACMEEnvironmentStaging {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].acme.environment must be production or staging", index)
		}
		if err := validateSiteTLSACMEEmail(binding.ACME.Email); err != nil {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].acme.email %w", index, err)
		}
		return siteTLSBinding{
			Name:        binding.Name,
			Hosts:       append([]string(nil), binding.Hosts...),
			Mode:        binding.Mode,
			ACMEProfile: siteTLSACMEProfileKey(binding.ACME.Environment, binding.ACME.Email),
		}, "", nil
	case "legacy":
		notAfter, warning, err := validateLegacySiteCoverage(binding.Hosts, SiteConfigFile{})
		if err != nil {
			return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].mode=legacy: %w", index, err)
		}
		return siteTLSBinding{Name: binding.Name, Hosts: append([]string(nil), binding.Hosts...), Mode: binding.Mode, NotAfter: notAfter}, warning, nil
	default:
		return siteTLSBinding{}, "", fmt.Errorf("tls_bindings[%d].mode must be manual, acme, or legacy", index)
	}
}

func TLSBindingForHost(host string) siteBindingMatch {
	rt := tlsBindingRuntimeInstance()
	if rt == nil {
		return siteBindingMatch{}
	}
	reqHost := normalizeProxyRequestHost(host)
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	for _, binding := range rt.bindings {
		if siteHostsMatch(binding.Hosts, reqHost) {
			return siteBindingMatch{
				Name:        binding.Name,
				Mode:        binding.Mode,
				ACMEProfile: binding.ACMEProfile,
				Certificate: binding.Certificate,
				NotAfter:    binding.NotAfter,
			}
		}
	}
	return siteBindingMatch{}
}

func EffectiveServerTLSACMEDomains() []string {
	return EffectiveServerTLSACMEDomainsForTLSBindings(currentTLSBindingConfig())
}

func EffectiveServerTLSACMEDomainsForTLSBindings(bindings TLSBindingConfigFile) []string {
	profiles := EffectiveServerTLSACMEProfilesForTLSBindings(bindings)
	var domains []string
	seen := map[string]struct{}{}
	for _, profile := range profiles {
		for _, host := range profile.Domains {
			if _, ok := seen[host]; ok {
				continue
			}
			seen[host] = struct{}{}
			domains = append(domains, host)
		}
	}
	return domains
}

func EffectiveServerTLSACMEProfilesForTLSBindings(bindings TLSBindingConfigFile) []ServerTLSACMEProfile {
	profiles := make([]ServerTLSACMEProfile, 0)
	seenProfiles := map[string]int{}
	seenDomains := map[string]struct{}{}
	for _, binding := range bindings.Bindings {
		if !siteEnabled(binding.Enabled) || binding.Mode != "acme" {
			continue
		}
		environment := normalizeSiteTLSACMEEnvironment(binding.ACME.Environment)
		email := strings.TrimSpace(binding.ACME.Email)
		key := siteTLSACMEProfileKey(environment, email)
		profileIndex, ok := seenProfiles[key]
		if !ok {
			profileIndex = len(profiles)
			seenProfiles[key] = profileIndex
			profiles = append(profiles, ServerTLSACMEProfile{
				Key:         key,
				Environment: environment,
				Email:       email,
			})
		}
		for _, host := range binding.Hosts {
			host = normalizeProxyHostPattern(host)
			if host == "" {
				continue
			}
			if _, ok := seenDomains[host]; ok {
				continue
			}
			seenDomains[host] = struct{}{}
			profiles[profileIndex].Domains = append(profiles[profileIndex].Domains, host)
		}
	}
	return profiles
}

func tlsBindingACMEUsesStaging(bindings TLSBindingConfigFile) bool {
	for _, profile := range EffectiveServerTLSACMEProfilesForTLSBindings(bindings) {
		if profile.Environment == siteTLSACMEEnvironmentStaging {
			return true
		}
	}
	return false
}

func currentTLSBindingConfig() TLSBindingConfigFile {
	rt := tlsBindingRuntimeInstance()
	if rt == nil {
		return TLSBindingConfigFile{}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	return cloneTLSBindingConfigFile(rt.cfg)
}

func deriveTLSBindingsFromSites(sites SiteConfigFile) TLSBindingConfigFile {
	out := TLSBindingConfigFile{}
	for _, site := range sites.Sites {
		if len(site.Hosts) == 0 || !legacySiteTLSShouldBecomeBinding(site) {
			continue
		}
		out.Bindings = append(out.Bindings, TLSBindingConfig{
			Name:     site.Name,
			Enabled:  site.Enabled,
			Hosts:    append([]string(nil), site.Hosts...),
			Mode:     normalizeSiteTLSMode(site.TLS.Mode),
			CertFile: site.TLS.CertFile,
			KeyFile:  site.TLS.KeyFile,
			ACME:     site.TLS.ACME,
		})
	}
	return normalizeTLSBindingConfigFile(out)
}

func legacySiteTLSShouldBecomeBinding(site SiteConfig) bool {
	switch normalizeSiteTLSMode(site.TLS.Mode) {
	case "manual":
		return strings.TrimSpace(site.TLS.CertFile) != "" || strings.TrimSpace(site.TLS.KeyFile) != ""
	case "acme":
		return true
	case "legacy":
		return config.ServerTLSEnabled && strings.TrimSpace(config.ServerTLSCertFile) != "" && strings.TrimSpace(config.ServerTLSKeyFile) != ""
	default:
		return false
	}
}

func cloneTLSBindingConfigFile(in TLSBindingConfigFile) TLSBindingConfigFile {
	if len(in.Bindings) == 0 {
		return TLSBindingConfigFile{}
	}
	out := TLSBindingConfigFile{Bindings: make([]TLSBindingConfig, 0, len(in.Bindings))}
	for _, binding := range in.Bindings {
		next := binding
		if len(binding.Hosts) > 0 {
			next.Hosts = append([]string(nil), binding.Hosts...)
		}
		out.Bindings = append(out.Bindings, next)
	}
	return out
}

func cloneTLSBindingRuntimeStatuses(in []TLSBindingRuntimeStatus) []TLSBindingRuntimeStatus {
	if len(in) == 0 {
		return nil
	}
	out := make([]TLSBindingRuntimeStatus, 0, len(in))
	for _, status := range in {
		next := status
		if len(status.Hosts) > 0 {
			next.Hosts = append([]string(nil), status.Hosts...)
		}
		out = append(out, next)
	}
	return out
}

func (rt *tlsBindingRuntime) snapshotLocked() tlsBindingRuntimeSnapshot {
	return tlsBindingRuntimeSnapshot{
		raw:       rt.raw,
		etag:      rt.etag,
		versionID: rt.versionID,
		cfg:       cloneTLSBindingConfigFile(rt.cfg),
		statuses:  cloneTLSBindingRuntimeStatuses(rt.statuses),
		bindings:  cloneSiteTLSBindings(rt.bindings),
	}
}

func (rt *tlsBindingRuntime) applyPreparedLocked(prepared tlsBindingPreparedConfig) {
	rt.raw = prepared.raw
	rt.etag = prepared.etag
	rt.versionID = prepared.versionID
	rt.cfg = cloneTLSBindingConfigFile(prepared.cfg)
	rt.statuses = cloneTLSBindingRuntimeStatuses(prepared.statuses)
	rt.bindings = cloneSiteTLSBindings(prepared.bindings)
}

func (rt *tlsBindingRuntime) restoreLocked(snapshot tlsBindingRuntimeSnapshot) {
	rt.raw = snapshot.raw
	rt.etag = snapshot.etag
	rt.versionID = snapshot.versionID
	rt.cfg = cloneTLSBindingConfigFile(snapshot.cfg)
	rt.statuses = cloneTLSBindingRuntimeStatuses(snapshot.statuses)
	rt.bindings = cloneSiteTLSBindings(snapshot.bindings)
}

func (rt *tlsBindingRuntime) pushRollbackLocked(entry proxyRollbackEntry) {
	if strings.TrimSpace(entry.Raw) == "" || rt.rollbackMax <= 0 {
		return
	}
	rt.rollbackStack = append(rt.rollbackStack, entry)
	if len(rt.rollbackStack) > rt.rollbackMax {
		trim := len(rt.rollbackStack) - rt.rollbackMax
		rt.rollbackStack = append([]proxyRollbackEntry(nil), rt.rollbackStack[trim:]...)
	}
}

func persistTLSBindingConfigAuthoritative(path string, expectedETag string, prepared tlsBindingPreparedConfig, source string, restoredFromVersionID int64) (string, int64, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return "", 0, err
	}
	rec, err := store.writeTLSBindingConfigVersion(expectedETag, prepared.cfg, source, "", "tls bindings config update", restoredFromVersionID)
	if err != nil {
		return "", 0, err
	}
	return rec.ETag, rec.VersionID, nil
}

func tlsBindingConfigHash(cfg TLSBindingConfigFile) string {
	return configContentHash(mustJSON(normalizeTLSBindingConfigFile(cfg)))
}

func (s *wafEventStore) loadActiveTLSBindingConfig() (TLSBindingConfigFile, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(tlsBindingConfigDomain)
	if err != nil || !found {
		return TLSBindingConfigFile{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadTLSBindingConfigVersion(rec.VersionID)
	if err != nil {
		return TLSBindingConfigFile{}, configVersionRecord{}, false, err
	}
	return normalizeTLSBindingConfigFile(cfg), rec, true, nil
}

func (s *wafEventStore) writeTLSBindingConfigVersion(expectedETag string, cfg TLSBindingConfigFile, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizeTLSBindingConfigFile(cfg)
	return s.writeConfigVersion(
		tlsBindingConfigDomain,
		tlsBindingSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		tlsBindingConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertTLSBindingConfigRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) insertTLSBindingConfigRowsTx(tx *sql.Tx, versionID int64, cfg TLSBindingConfigFile) error {
	for i, binding := range cfg.Bindings {
		enabledSet, enabled := boolPtrToDB(binding.Enabled)
		if _, err := s.txExec(tx, `INSERT INTO sites (version_id, position, name, enabled_set, enabled, default_upstream) VALUES (?, ?, ?, ?, ?, ?)`, versionID, i, binding.Name, enabledSet, enabled, ""); err != nil {
			return err
		}
		for j, host := range binding.Hosts {
			if _, err := s.txExec(tx, `INSERT INTO site_hosts (version_id, site_position, position, host) VALUES (?, ?, ?, ?)`, versionID, i, j, host); err != nil {
				return err
			}
		}
		if _, err := s.txExec(tx, `INSERT INTO site_tls (version_id, site_position, mode, cert_file, key_file, acme_environment, acme_email) VALUES (?, ?, ?, ?, ?, ?, ?)`, versionID, i, binding.Mode, binding.CertFile, binding.KeyFile, binding.ACME.Environment, binding.ACME.Email); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadTLSBindingConfigVersion(versionID int64) (TLSBindingConfigFile, error) {
	rows, err := s.query(`SELECT position, name, enabled_set, enabled FROM sites WHERE version_id = ? ORDER BY position`, versionID)
	if err != nil {
		return TLSBindingConfigFile{}, err
	}
	type bindingRow struct {
		position int
		binding  TLSBindingConfig
	}
	var scanned []bindingRow
	for rows.Next() {
		var position, enabledSet, enabled int
		var binding TLSBindingConfig
		if err := rows.Scan(&position, &binding.Name, &enabledSet, &enabled); err != nil {
			_ = rows.Close()
			return TLSBindingConfigFile{}, err
		}
		binding.Enabled = boolPtrFromDB(enabledSet, enabled)
		scanned = append(scanned, bindingRow{position: position, binding: binding})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return TLSBindingConfigFile{}, err
	}
	if err := rows.Close(); err != nil {
		return TLSBindingConfigFile{}, err
	}

	out := TLSBindingConfigFile{Bindings: make([]TLSBindingConfig, 0, len(scanned))}
	for _, item := range scanned {
		hosts, err := s.loadSiteHosts(versionID, item.position)
		if err != nil {
			return TLSBindingConfigFile{}, err
		}
		tlsCfg, err := s.loadSiteTLS(versionID, item.position)
		if err != nil {
			return TLSBindingConfigFile{}, err
		}
		item.binding.Hosts = hosts
		item.binding.Mode = tlsCfg.Mode
		item.binding.CertFile = tlsCfg.CertFile
		item.binding.KeyFile = tlsCfg.KeyFile
		item.binding.ACME = tlsCfg.ACME
		out.Bindings = append(out.Bindings, item.binding)
	}
	return out, nil
}
