package handler

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	upstreamRuntimeVersion       = "v1"
	upstreamRuntimeConfigBlobKey = "upstream_runtime"
)

var upstreamRuntimeFileMu sync.Mutex

type upstreamAdminState string

const (
	upstreamAdminStateEnabled  upstreamAdminState = "enabled"
	upstreamAdminStateDraining upstreamAdminState = "draining"
	upstreamAdminStateDisabled upstreamAdminState = "disabled"
)

type upstreamRuntimeOverride struct {
	AdminState     *upstreamAdminState `json:"admin_state,omitempty"`
	WeightOverride *int                `json:"weight_override,omitempty"`
}

type upstreamRuntimeFile struct {
	Version  string                             `json:"version"`
	Backends map[string]upstreamRuntimeOverride `json:"backends,omitempty"`
}

type proxyBackendsStatusResponse struct {
	Path      string                  `json:"path"`
	Storage   string                  `json:"storage,omitempty"`
	ETag      string                  `json:"etag"`
	Strategy  string                  `json:"strategy,omitempty"`
	Backends  []upstreamBackendStatus `json:"backends"`
	UpdatedAt string                  `json:"updated_at,omitempty"`
}

type putProxyBackendRuntimeOverrideBody struct {
	AdminState     *string `json:"admin_state,omitempty"`
	WeightOverride *int    `json:"weight_override,omitempty"`
}

func GetProxyBackends(c *gin.Context) {
	resp, err := buildProxyBackendsStatusResponse()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func PutProxyBackendRuntimeOverride(c *gin.Context) {
	var in putProxyBackendRuntimeOverrideBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.AdminState == nil && in.WeightOverride == nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "at least one of admin_state or weight_override is required"})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	backendKey, err := decodeProxyBackendKey(c.Param("backend_key"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	upstreamRuntimeFileMu.Lock()
	defer upstreamRuntimeFileMu.Unlock()

	cfg := currentProxyConfig()
	if !proxyBackendRuntimeOpsSupported(cfg, backendKey) {
		c.JSON(http.StatusNotFound, gin.H{"error": "backend not found"})
		return
	}
	currentRaw, currentETag, file, err := snapshotUpstreamRuntimeFile(cfg)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if ifMatch != currentETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": currentETag})
		return
	}

	override := file.Backends[backendKey]
	if in.AdminState != nil {
		state, err := normalizeUpstreamAdminState(upstreamAdminState(*in.AdminState))
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		override.AdminState = &state
	}
	if in.WeightOverride != nil {
		if *in.WeightOverride <= 0 {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": "weight_override must be > 0"})
			return
		}
		weight := *in.WeightOverride
		override.WeightOverride = &weight
	}
	if file.Backends == nil {
		file.Backends = map[string]upstreamRuntimeOverride{}
	}
	file.Backends[backendKey] = override

	if err := persistAndRefreshUpstreamRuntimeOverrides(cfg, currentRaw, currentETag, file); err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": currentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	resp, err := buildProxyBackendsStatusResponse()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func DeleteProxyBackendRuntimeOverride(c *gin.Context) {
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	backendKey, err := decodeProxyBackendKey(c.Param("backend_key"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	upstreamRuntimeFileMu.Lock()
	defer upstreamRuntimeFileMu.Unlock()

	cfg := currentProxyConfig()
	if !proxyBackendRuntimeOpsSupported(cfg, backendKey) {
		c.JSON(http.StatusNotFound, gin.H{"error": "backend not found"})
		return
	}
	currentRaw, currentETag, file, err := snapshotUpstreamRuntimeFile(cfg)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if ifMatch != currentETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": currentETag})
		return
	}

	if len(file.Backends) > 0 {
		delete(file.Backends, backendKey)
	}
	if err := persistAndRefreshUpstreamRuntimeOverrides(cfg, currentRaw, currentETag, file); err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": currentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	resp, err := buildProxyBackendsStatusResponse()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, resp)
}

func buildProxyBackendsStatusResponse() (proxyBackendsStatusResponse, error) {
	cfg := normalizeProxyRulesConfig(ProxyRulesConfig{})
	health := upstreamHealthStatus{Status: "disabled"}
	if rt := proxyRuntimeInstance(); rt != nil {
		rt.mu.RLock()
		cfg = rt.effectiveCfg
		if rt.health != nil {
			health = rt.health.Snapshot()
		}
		rt.mu.RUnlock()
	}
	_, etag, _, err := snapshotUpstreamRuntimeFile(cfg)
	if err != nil {
		return proxyBackendsStatusResponse{}, err
	}
	backends, updatedAt := buildProxyBackendsSurfaceStatuses(cfg, health.Backends)
	sort.SliceStable(backends, func(i, j int) bool {
		if backends[i].Name != backends[j].Name {
			return backends[i].Name < backends[j].Name
		}
		return backends[i].URL < backends[j].URL
	})
	return proxyBackendsStatusResponse{
		Path:      managedUpstreamRuntimePath(),
		Storage:   upstreamRuntimeStorageLabel(),
		ETag:      etag,
		Strategy:  strings.TrimSpace(cfg.LoadBalancingStrategy),
		Backends:  backends,
		UpdatedAt: updatedAt,
	}, nil
}

func upstreamRuntimeStorageLabel() string {
	if getLogsStatsStore() != nil {
		return "db:" + upstreamRuntimeConfigBlobKey
	}
	path := strings.TrimSpace(managedUpstreamRuntimePath())
	if path == "" {
		return "memory"
	}
	return path
}

func buildProxyBackendsSurfaceStatuses(cfg ProxyRulesConfig, healthBackends []upstreamBackendStatus) ([]upstreamBackendStatus, string) {
	healthByKey := make(map[string]upstreamBackendStatus, len(healthBackends))
	updatedAt := ""
	for _, backend := range healthBackends {
		healthByKey[backend.Key] = backend
		if updatedAt == "" && strings.TrimSpace(backend.CheckedAt) != "" {
			updatedAt = backend.CheckedAt
		}
	}

	visible := proxyBackendsVisibleUpstreams(cfg)
	out := make([]upstreamBackendStatus, 0, len(visible))
	seen := make(map[string]struct{}, len(healthBackends)+len(visible))
	for i, upstream := range visible {
		if proxyUpstreamDiscoveryEnabled(upstream) {
			continue
		}
		target, err := parseProxyUpstreamURL(fmt.Sprintf("backends[%d].url", i), upstream.URL)
		if err != nil {
			continue
		}
		key := proxyBackendLookupKey(upstream.Name, target.String())
		seen[key] = struct{}{}
		if current, ok := healthByKey[key]; ok {
			current.ProviderClass = proxyUpstreamProviderClass(upstream)
			current.ManagedByVhost = strings.TrimSpace(upstream.ManagedByVhost)
			current.RuntimeOpsSupported = proxyUpstreamIsDirect(upstream)
			out = append(out, current)
			continue
		}
		weight := proxyPositiveWeight(upstream.Weight)
		out = append(out, upstreamBackendStatus{
			Key:                 key,
			Name:                upstream.Name,
			URL:                 target.String(),
			ProviderClass:       proxyUpstreamProviderClass(upstream),
			ManagedByVhost:      strings.TrimSpace(upstream.ManagedByVhost),
			RuntimeOpsSupported: false,
			HTTP2Mode:           proxyConfiguredHTTP2Mode(cfg, upstream.HTTP2Mode),
			AdminState:          string(upstreamAdminStateEnabled),
			HealthState:         "unknown",
			ConfiguredWeight:    weight,
			EffectiveWeight:     weight,
			EffectiveSelectable: upstream.Enabled,
			Enabled:             upstream.Enabled,
			Healthy:             false,
			Endpoint:            "",
		})
	}
	for _, backend := range healthBackends {
		if backend.ProviderClass != proxyUpstreamProviderClassDiscovered {
			continue
		}
		if _, ok := seen[backend.Key]; ok {
			continue
		}
		backend.RuntimeOpsSupported = true
		out = append(out, backend)
	}
	return out, updatedAt
}

func decodeProxyBackendKey(raw string) (string, error) {
	decoded, err := url.PathUnescape(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if decoded == "" {
		return "", fmt.Errorf("backend_key is required")
	}
	return decoded, nil
}

func proxyBackendRuntimeOpsSupported(cfg ProxyRulesConfig, key string) bool {
	for i, upstream := range proxyBackendsVisibleUpstreams(cfg) {
		if proxyUpstreamDiscoveryEnabled(upstream) {
			continue
		}
		target, err := parseProxyUpstreamURL(fmt.Sprintf("backends[%d].url", i), upstream.URL)
		if err != nil {
			continue
		}
		if proxyBackendLookupKey(upstream.Name, target.String()) == key {
			return proxyUpstreamIsDirect(upstream)
		}
	}
	if backend, ok := ProxyBackendStatusByKey(key); ok && strings.TrimSpace(backend.Key) != "" {
		return backend.RuntimeOpsSupported
	}
	_, ok := configuredManagedBackendKeys(cfg)[key]
	return ok
}

func persistAndRefreshUpstreamRuntimeOverrides(cfg ProxyRulesConfig, previousRaw string, previousETag string, file upstreamRuntimeFile) error {
	_, _, _, err := persistUpstreamRuntimeFile(cfg, file, previousETag)
	if err != nil {
		return err
	}
	if err := refreshProxyBackendRuntimeOverrides(); err != nil {
		_ = persistUpstreamRuntimeRaw(previousRaw)
		_ = refreshProxyBackendRuntimeOverrides()
		return err
	}
	return nil
}

func managedUpstreamRuntimePath() string {
	if path := strings.TrimSpace(config.UpstreamRuntimeFile); path != "" {
		return path
	}
	if strings.TrimSpace(config.ConfigFile) == "" {
		return ""
	}
	return config.DefaultUpstreamRuntimeFilePath
}

func ParseUpstreamRuntimeRaw(raw string) (upstreamRuntimeFile, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return normalizeUpstreamRuntimeFile(upstreamRuntimeFile{}, nil)
	}
	var file upstreamRuntimeFile
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&file); err != nil {
		return upstreamRuntimeFile{}, err
	}
	if err := dec.Decode(&struct{}{}); err != nil && err != io.EOF {
		return upstreamRuntimeFile{}, fmt.Errorf("invalid json")
	}
	return normalizeUpstreamRuntimeFile(file, nil)
}

func MarshalUpstreamRuntimeJSON(file upstreamRuntimeFile) ([]byte, error) {
	normalized, err := normalizeUpstreamRuntimeFile(file, nil)
	if err != nil {
		return nil, err
	}
	out, err := json.MarshalIndent(normalized, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(out, '\n'), nil
}

func LoadUpstreamRuntimeFile(path string, knownKeys map[string]struct{}) (upstreamRuntimeFile, error) {
	target := strings.TrimSpace(path)
	if target == "" {
		return normalizeUpstreamRuntimeFile(upstreamRuntimeFile{}, nil)
	}
	if err := ensureUpstreamRuntimeFile(target); err != nil {
		return upstreamRuntimeFile{}, err
	}
	raw, err := os.ReadFile(target)
	if err != nil {
		return upstreamRuntimeFile{}, err
	}
	parsed, err := ParseUpstreamRuntimeRaw(string(raw))
	if err != nil {
		return upstreamRuntimeFile{}, err
	}
	normalized, err := normalizeUpstreamRuntimeFile(parsed, knownKeys)
	if err != nil {
		return upstreamRuntimeFile{}, err
	}
	if !reflect.DeepEqual(parsed, normalized) {
		payload, err := MarshalUpstreamRuntimeJSON(normalized)
		if err != nil {
			return upstreamRuntimeFile{}, err
		}
		if err := bypassconf.AtomicWriteWithBackup(target, payload); err != nil {
			return upstreamRuntimeFile{}, err
		}
	}
	return normalized, nil
}

func ensureUpstreamRuntimeFile(path string) error {
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	payload, err := MarshalUpstreamRuntimeJSON(upstreamRuntimeFile{})
	if err != nil {
		return err
	}
	return os.WriteFile(path, payload, 0o644)
}

func loadUpstreamRuntimeOverrides(cfg ProxyRulesConfig) (upstreamRuntimeFile, error) {
	_, _, file, err := snapshotUpstreamRuntimeFile(cfg)
	return file, err
}

func snapshotUpstreamRuntimeFile(cfg ProxyRulesConfig) (string, string, upstreamRuntimeFile, error) {
	path := managedUpstreamRuntimePath()
	knownKeys := configuredManagedBackendKeys(cfg)
	if store := getLogsStatsStore(); store != nil {
		return snapshotUpstreamRuntimeDB(store, path, knownKeys)
	}
	if strings.TrimSpace(path) == "" {
		file, err := normalizeUpstreamRuntimeFile(upstreamRuntimeFile{}, nil)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		payload, err := MarshalUpstreamRuntimeJSON(file)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		raw := string(payload)
		return raw, bypassconf.ComputeETag(payload), file, nil
	}
	file, err := LoadUpstreamRuntimeFile(path, knownKeys)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	payload, err := os.ReadFile(path)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	return string(payload), bypassconf.ComputeETag(payload), file, nil
}

func persistUpstreamRuntimeFile(cfg ProxyRulesConfig, file upstreamRuntimeFile, expectedETag string) (string, string, upstreamRuntimeFile, error) {
	normalized, err := normalizeUpstreamRuntimeFile(file, configuredManagedBackendKeys(cfg))
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	payload, err := MarshalUpstreamRuntimeJSON(normalized)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	store, err := requireConfigDBStore()
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	rec, normalized, err := store.writeUpstreamRuntimeConfigVersion(expectedETag, normalized, configuredManagedBackendKeys(cfg), configVersionSourceApply, "", "upstream runtime update", 0)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	payload, err = MarshalUpstreamRuntimeJSON(normalized)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	return string(payload), rec.ETag, normalized, nil
}

func snapshotUpstreamRuntimeDB(store *wafEventStore, seedPath string, knownKeys map[string]struct{}) (string, string, upstreamRuntimeFile, error) {
	file, rec, found, err := store.loadActiveUpstreamRuntimeConfig(knownKeys)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	if found {
		if upstreamRuntimeConfigHash(file) != rec.ContentHash {
			nextRec, normalized, err := store.writeUpstreamRuntimeConfigVersion(rec.ETag, file, knownKeys, configVersionSourceApply, "", "upstream runtime prune", 0)
			if err != nil {
				return "", "", upstreamRuntimeFile{}, err
			}
			rec = nextRec
			file = normalized
		}
		payload, err := MarshalUpstreamRuntimeJSON(file)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		return string(payload), rec.ETag, file, nil
	}
	if dbRaw, _, legacyFound, err := store.GetConfigBlob(upstreamRuntimeConfigBlobKey); err != nil {
		return "", "", upstreamRuntimeFile{}, err
	} else if legacyFound {
		parsed, err := ParseUpstreamRuntimeRaw(string(dbRaw))
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		rec, normalized, err := store.writeUpstreamRuntimeConfigVersion("", parsed, knownKeys, configVersionSourceImport, "", "legacy upstream runtime import", 0)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		_ = store.DeleteConfigBlob(upstreamRuntimeConfigBlobKey)
		payload, err := MarshalUpstreamRuntimeJSON(normalized)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		return string(payload), rec.ETag, normalized, nil
	}

	return "", "", upstreamRuntimeFile{}, fmt.Errorf("normalized upstream runtime config missing in db; run make db-import before removing seed files")
}

func persistUpstreamRuntimeRaw(raw string) error {
	store, err := requireConfigDBStore()
	if err != nil {
		return err
	}
	file, err := ParseUpstreamRuntimeRaw(raw)
	if err != nil {
		return err
	}
	_, _, err = store.writeUpstreamRuntimeConfigVersion("", file, configuredManagedBackendKeys(currentProxyConfig()), configVersionSourceRollback, "", "upstream runtime restore", 0)
	return err
}

func SyncUpstreamRuntimeStorage() error {
	if getLogsStatsStore() == nil {
		return nil
	}
	if _, _, _, err := snapshotUpstreamRuntimeFile(currentProxyConfig()); err != nil {
		return err
	}
	return refreshProxyBackendRuntimeOverrides()
}

func refreshProxyBackendRuntimeOverrides() error {
	rt := proxyRuntimeInstance()
	if rt == nil || rt.health == nil {
		return nil
	}
	rt.mu.RLock()
	cfg := rt.effectiveCfg
	rt.mu.RUnlock()
	return rt.health.Update(cfg)
}

func configuredManagedBackendKeys(cfg ProxyRulesConfig) map[string]struct{} {
	if proxyConfigHasDiscovery(cfg) {
		return nil
	}
	defs := proxyConfiguredUpstreams(cfg)
	if len(defs) == 0 {
		return nil
	}
	keys := make(map[string]struct{}, len(defs))
	for i, upstream := range defs {
		if !proxyUpstreamIsDirect(upstream) {
			continue
		}
		target, err := parseProxyUpstreamURL(fmt.Sprintf("upstreams[%d].url", i), upstream.URL)
		if err != nil {
			continue
		}
		keys[proxyBackendLookupKey(upstream.Name, target.String())] = struct{}{}
	}
	return keys
}

func normalizeUpstreamRuntimeFile(file upstreamRuntimeFile, knownKeys map[string]struct{}) (upstreamRuntimeFile, error) {
	next := upstreamRuntimeFile{Version: upstreamRuntimeVersion}
	version := strings.ToLower(strings.TrimSpace(file.Version))
	if version != "" && version != upstreamRuntimeVersion {
		return upstreamRuntimeFile{}, fmt.Errorf("version must be %q", upstreamRuntimeVersion)
	}
	if len(file.Backends) == 0 {
		return next, nil
	}
	keys := make([]string, 0, len(file.Backends))
	for rawKey := range file.Backends {
		keys = append(keys, rawKey)
	}
	sort.Strings(keys)
	next.Backends = make(map[string]upstreamRuntimeOverride, len(keys))
	for _, rawKey := range keys {
		key := strings.TrimSpace(rawKey)
		if key == "" {
			return upstreamRuntimeFile{}, fmt.Errorf("backends keys must not be empty")
		}
		if len(knownKeys) > 0 {
			if _, ok := knownKeys[key]; !ok {
				continue
			}
		}
		normalized, err := normalizeUpstreamRuntimeOverride(file.Backends[rawKey], fmt.Sprintf("backends[%q]", rawKey))
		if err != nil {
			return upstreamRuntimeFile{}, err
		}
		if normalized.AdminState == nil && normalized.WeightOverride == nil {
			continue
		}
		next.Backends[key] = normalized
	}
	if len(next.Backends) == 0 {
		next.Backends = nil
	}
	return next, nil
}

func normalizeUpstreamRuntimeOverride(in upstreamRuntimeOverride, field string) (upstreamRuntimeOverride, error) {
	var out upstreamRuntimeOverride
	if in.AdminState != nil {
		state, err := normalizeUpstreamAdminState(*in.AdminState)
		if err != nil {
			return upstreamRuntimeOverride{}, fmt.Errorf("%s.admin_state: %w", field, err)
		}
		out.AdminState = &state
	}
	if in.WeightOverride != nil {
		if *in.WeightOverride <= 0 {
			return upstreamRuntimeOverride{}, fmt.Errorf("%s.weight_override must be > 0", field)
		}
		weight := *in.WeightOverride
		out.WeightOverride = &weight
	}
	return out, nil
}

func normalizeUpstreamAdminState(raw upstreamAdminState) (upstreamAdminState, error) {
	switch upstreamAdminState(strings.ToLower(strings.TrimSpace(string(raw)))) {
	case "", upstreamAdminStateEnabled:
		return upstreamAdminStateEnabled, nil
	case upstreamAdminStateDraining:
		return upstreamAdminStateDraining, nil
	case upstreamAdminStateDisabled:
		return upstreamAdminStateDisabled, nil
	default:
		return "", fmt.Errorf("must be one of: enabled, draining, disabled")
	}
}

func proxyBackendHealthState(cfg ProxyRulesConfig, backend *proxyBackendState) string {
	if backend == nil {
		return "unknown"
	}
	if !proxyHealthCheckEnabled(cfg) && !cfg.PassiveHealthEnabled {
		return "unknown"
	}
	if backend.CheckedAt == "" &&
		backend.LastSuccessAt == "" &&
		backend.LastFailureAt == "" &&
		backend.PassiveFailures == 0 &&
		backend.CircuitState == "" {
		return "unknown"
	}
	if backend.Healthy {
		return "healthy"
	}
	return "unhealthy"
}
