package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

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

func persistUpstreamRuntimeFile(cfg ProxyRulesConfig, file upstreamRuntimeFile) (string, string, upstreamRuntimeFile, error) {
	path := managedUpstreamRuntimePath()
	normalized, err := normalizeUpstreamRuntimeFile(file, configuredManagedBackendKeys(cfg))
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	payload, err := MarshalUpstreamRuntimeJSON(normalized)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	if store := getLogsStatsStore(); store != nil {
		etag := bypassconf.ComputeETag(payload)
		if err := store.UpsertConfigBlob(upstreamRuntimeConfigBlobKey, payload, etag, time.Now().UTC()); err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		return string(payload), etag, normalized, nil
	}
	if strings.TrimSpace(path) != "" {
		if err := ensureUpstreamRuntimeFile(path); err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		if err := bypassconf.AtomicWriteWithBackup(path, payload); err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
	}
	return string(payload), bypassconf.ComputeETag(payload), normalized, nil
}

func snapshotUpstreamRuntimeDB(store *wafEventStore, seedPath string, knownKeys map[string]struct{}) (string, string, upstreamRuntimeFile, error) {
	dbRaw, dbETag, found, err := store.GetConfigBlob(upstreamRuntimeConfigBlobKey)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	if found {
		parsed, err := ParseUpstreamRuntimeRaw(string(dbRaw))
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		normalized, err := normalizeUpstreamRuntimeFile(parsed, knownKeys)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		payload, err := MarshalUpstreamRuntimeJSON(normalized)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		etag := bypassconf.ComputeETag(payload)
		if strings.TrimSpace(dbETag) != "" && string(dbRaw) == string(payload) {
			etag = dbETag
		}
		if strings.TrimSpace(dbETag) == "" || string(dbRaw) != string(payload) {
			if err := store.UpsertConfigBlob(upstreamRuntimeConfigBlobKey, payload, etag, time.Now().UTC()); err != nil {
				return "", "", upstreamRuntimeFile{}, err
			}
		}
		return string(payload), etag, normalized, nil
	}

	var raw []byte
	if strings.TrimSpace(seedPath) != "" {
		fileRaw, _, err := readFileMaybe(seedPath)
		if err != nil {
			return "", "", upstreamRuntimeFile{}, err
		}
		raw = fileRaw
	}
	parsed, err := ParseUpstreamRuntimeRaw(string(raw))
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	normalized, err := normalizeUpstreamRuntimeFile(parsed, knownKeys)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	payload, err := MarshalUpstreamRuntimeJSON(normalized)
	if err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	etag := bypassconf.ComputeETag(payload)
	if err := store.UpsertConfigBlob(upstreamRuntimeConfigBlobKey, payload, etag, time.Now().UTC()); err != nil {
		return "", "", upstreamRuntimeFile{}, err
	}
	return string(payload), etag, normalized, nil
}

func persistUpstreamRuntimeRaw(raw string) error {
	if store := getLogsStatsStore(); store != nil {
		file, err := ParseUpstreamRuntimeRaw(raw)
		if err != nil {
			return err
		}
		payload, err := MarshalUpstreamRuntimeJSON(file)
		if err != nil {
			return err
		}
		return store.UpsertConfigBlob(upstreamRuntimeConfigBlobKey, payload, bypassconf.ComputeETag(payload), time.Now().UTC())
	}
	path := managedUpstreamRuntimePath()
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := ensureUpstreamRuntimeFile(path); err != nil {
		return err
	}
	return bypassconf.AtomicWriteWithBackup(path, []byte(raw))
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
