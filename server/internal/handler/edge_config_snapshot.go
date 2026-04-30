package handler

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	goruntime "runtime"
	"sort"
	"strings"
	"time"

	"tukuyomi/internal/buildinfo"
)

const (
	edgeConfigSnapshotSchemaVersion = 1
	edgeConfigSnapshotMaxBytes      = 2 * 1024 * 1024
)

type edgeConfigSnapshotBuild struct {
	Revision    string
	PayloadHash string
	PayloadRaw  []byte
}

type edgeConfigSnapshotPayload struct {
	SchemaVersion  int                                 `json:"schema_version"`
	ConfigRevision string                              `json:"config_revision"`
	GeneratedAt    string                              `json:"generated_at"`
	DeviceID       string                              `json:"device_id"`
	KeyID          string                              `json:"key_id"`
	GatewayVersion string                              `json:"gateway_version,omitempty"`
	GoVersion      string                              `json:"go_version,omitempty"`
	Domains        map[string]edgeConfigSnapshotDomain `json:"domains"`
	RedactedPaths  []string                            `json:"redacted_paths,omitempty"`
	Warnings       []string                            `json:"warnings,omitempty"`
}

type edgeConfigSnapshotDomain struct {
	ETag  string          `json:"etag,omitempty"`
	Raw   json.RawMessage `json:"raw,omitempty"`
	Error string          `json:"error,omitempty"`
}

type edgeConfigSnapshotRuleAsset struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	ETag      string `json:"etag"`
	Disabled  bool   `json:"disabled"`
	SizeBytes int    `json:"size_bytes"`
}

func buildEdgeConfigSnapshot(identity edgeDeviceIdentityRecord) (edgeConfigSnapshotBuild, error) {
	payload := edgeConfigSnapshotPayload{
		SchemaVersion:  edgeConfigSnapshotSchemaVersion,
		DeviceID:       identity.DeviceID,
		KeyID:          identity.KeyID,
		GatewayVersion: clampEdgeText(buildinfo.Version, 128),
		GoVersion:      clampEdgeText(goruntime.Version(), 64),
		Domains:        map[string]edgeConfigSnapshotDomain{},
	}

	addGatewayConfigSnapshotDomains(&payload)
	payload.RedactedPaths = sortedUniqueStrings(payload.RedactedPaths)
	payload.Warnings = sortedUniqueStrings(payload.Warnings)
	revision, err := edgeConfigSnapshotRevision(payload)
	if err != nil {
		return edgeConfigSnapshotBuild{}, err
	}
	payload.ConfigRevision = revision
	payload.GeneratedAt = time.Now().UTC().Format(time.RFC3339Nano)
	raw, err := json.Marshal(payload)
	if err != nil {
		return edgeConfigSnapshotBuild{}, fmt.Errorf("marshal config snapshot: %w", err)
	}
	if len(raw) > edgeConfigSnapshotMaxBytes {
		return edgeConfigSnapshotBuild{}, fmt.Errorf("config snapshot exceeds %d bytes", edgeConfigSnapshotMaxBytes)
	}
	sum := sha256.Sum256(raw)
	return edgeConfigSnapshotBuild{
		Revision:    revision,
		PayloadHash: hex.EncodeToString(sum[:]),
		PayloadRaw:  raw,
	}, nil
}

func addGatewayConfigSnapshotDomains(payload *edgeConfigSnapshotPayload) {
	if payload == nil {
		return
	}

	if raw, etag, _, err := loadAppConfigStorage(false); err == nil {
		redacted, paths, redactErr := redactAppConfigSnapshotRaw(raw)
		if redactErr != nil {
			payload.addDomainError(appConfigDomain, redactErr)
		} else {
			payload.RedactedPaths = append(payload.RedactedPaths, paths...)
			payload.addRawDomain(appConfigDomain, etag, redacted)
		}
	} else {
		payload.addDomainError(appConfigDomain, err)
	}

	proxyRaw, proxyETag, proxyCfg, _, _ := ProxyRulesSnapshot()
	if strings.TrimSpace(proxyRaw) == "" {
		proxyRaw = mustJSON(normalizeProxyRulesConfig(proxyCfg))
	}
	payload.addRawDomain(proxyConfigDomain, proxyETag, []byte(proxyRaw))

	siteRaw, siteETag, _, _, _ := SiteConfigSnapshot()
	payload.addRawDomain(siteConfigDomain, siteETag, []byte(siteRaw))

	vhostRaw, vhostETag, _, _ := VhostConfigSnapshot()
	payload.addRawDomain(vhostConfigDomain, vhostETag, []byte(vhostRaw))

	phpRaw, phpETag, _, _ := PHPRuntimeInventorySnapshot()
	payload.addRawDomain(phpRuntimeInventoryConfigDomain, phpETag, []byte(phpRaw))

	psgiRaw, psgiETag, _, _ := PSGIRuntimeInventorySnapshot()
	payload.addRawDomain(psgiRuntimeInventoryConfigDomain, psgiETag, []byte(psgiRaw))

	taskRaw, taskETag, _, _, _ := ScheduledTaskConfigSnapshot()
	payload.addRawDomain(scheduledTaskConfigDomain, taskETag, []byte(taskRaw))

	cacheRaw, cacheETag, cacheCfg, _ := ResponseCacheSnapshot()
	if strings.TrimSpace(cacheRaw) == "" {
		cacheRaw = mustJSON(cacheCfg)
	}
	payload.addRawDomain(responseCacheConfigBlobKey, cacheETag, []byte(cacheRaw))

	if raw, etag, _, err := snapshotUpstreamRuntimeFile(proxyCfg); err == nil {
		payload.addRawDomain(upstreamRuntimeConfigDomain, etag, []byte(raw))
	} else {
		payload.addDomainError(upstreamRuntimeConfigDomain, err)
	}

	store := getLogsStatsStore()
	if store == nil {
		payload.Warnings = append(payload.Warnings, "config DB store is not initialized")
		return
	}
	for _, spec := range []policyJSONConfigSpec{
		{Domain: cacheConfigBlobKey},
		{Domain: bypassConfigBlobKey},
		{Domain: countryBlockConfigBlobKey},
		{Domain: rateLimitConfigBlobKey},
		{Domain: botDefenseConfigBlobKey},
		{Domain: semanticConfigBlobKey},
		{Domain: notificationConfigBlobKey},
		{Domain: ipReputationConfigBlobKey},
	} {
		raw, rec, found, err := store.loadActivePolicyJSONConfig(spec)
		if err != nil {
			payload.addDomainError(spec.Domain, err)
			continue
		}
		if found {
			payload.addRawDomain(spec.Domain, rec.ETag, raw)
		}
	}
	if names, rec, found, err := store.loadActiveCRSDisabledConfig(); err != nil {
		payload.addDomainError(crsDisabledConfigDomain, err)
	} else if found {
		payload.addValueDomain(crsDisabledConfigDomain, rec.ETag, map[string]any{"disabled_rules": names})
	}
	if rules, rec, found, err := store.loadActiveManagedOverrideRules(); err != nil {
		payload.addDomainError(overrideRulesConfigDomain, err)
	} else if found {
		out := make([]map[string]any, 0, len(rules))
		for _, rule := range rules {
			out = append(out, map[string]any{
				"name": rule.Name,
				"etag": rule.ETag,
				"raw":  string(rule.Raw),
			})
		}
		payload.addValueDomain(overrideRulesConfigDomain, rec.ETag, out)
	}
	if assets, rec, found, err := store.loadActiveWAFRuleAssets(); err != nil {
		payload.addDomainError(wafRuleAssetsConfigDomain, err)
	} else if found {
		out := make([]edgeConfigSnapshotRuleAsset, 0, len(assets))
		for _, asset := range assets {
			out = append(out, edgeConfigSnapshotRuleAsset{
				Path:      asset.Path,
				Kind:      asset.Kind,
				ETag:      asset.ETag,
				Disabled:  asset.Disabled,
				SizeBytes: len(asset.Raw),
			})
		}
		payload.addValueDomain(wafRuleAssetsConfigDomain, rec.ETag, out)
	}
}

func (p *edgeConfigSnapshotPayload) addRawDomain(name string, etag string, raw []byte) {
	if p == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	compacted, err := compactJSONRaw(raw)
	if err != nil {
		p.addDomainError(name, err)
		return
	}
	p.Domains[name] = edgeConfigSnapshotDomain{
		ETag: strings.TrimSpace(etag),
		Raw:  compacted,
	}
}

func (p *edgeConfigSnapshotPayload) addValueDomain(name string, etag string, value any) {
	if p == nil {
		return
	}
	raw, err := json.Marshal(value)
	if err != nil {
		p.addDomainError(name, err)
		return
	}
	p.addRawDomain(name, etag, raw)
}

func (p *edgeConfigSnapshotPayload) addDomainError(name string, err error) {
	if p == nil || err == nil {
		return
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	p.Domains[name] = edgeConfigSnapshotDomain{Error: clampEdgeText(err.Error(), 512)}
}

func edgeConfigSnapshotRevision(payload edgeConfigSnapshotPayload) (string, error) {
	payload.ConfigRevision = ""
	payload.GeneratedAt = ""
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("marshal config snapshot revision: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func compactJSONRaw(raw []byte) (json.RawMessage, error) {
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	var buf bytes.Buffer
	if err := json.Compact(&buf, raw); err != nil {
		return nil, err
	}
	return append(json.RawMessage(nil), buf.Bytes()...), nil
}

func redactAppConfigSnapshotRaw(raw string) ([]byte, []string, error) {
	var obj any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return nil, nil, err
	}
	paths := []string{}
	for _, path := range []string{
		"admin.session_secret",
		"security_audit.encryption_key",
		"security_audit.hmac_key",
		"fp_tuner.api_key",
		"storage.db_dsn",
	} {
		if redactJSONPath(obj, path) {
			paths = append(paths, "app_config."+path)
		}
	}
	compacted, err := compactJSONRaw(mustMarshalJSON(obj))
	if err != nil {
		return nil, nil, err
	}
	return compacted, paths, nil
}

func redactJSONPath(root any, dotted string) bool {
	parts := strings.Split(strings.TrimSpace(dotted), ".")
	if len(parts) == 0 {
		return false
	}
	current := root
	for i, part := range parts {
		obj, ok := current.(map[string]any)
		if !ok {
			return false
		}
		if i == len(parts)-1 {
			value, found := obj[part]
			if !found {
				return false
			}
			if s, ok := value.(string); ok && s == "" {
				return false
			}
			obj[part] = "[redacted]"
			return true
		}
		next, found := obj[part]
		if !found {
			return false
		}
		current = next
	}
	return false
}

func mustMarshalJSON(v any) []byte {
	raw, err := json.Marshal(v)
	if err != nil {
		return []byte("{}")
	}
	return raw
}

func sortedUniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
