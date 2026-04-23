package handler

import (
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"
)

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

	if err := persistAndRefreshUpstreamRuntimeOverrides(cfg, currentRaw, file); err != nil {
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
	if err := persistAndRefreshUpstreamRuntimeOverrides(cfg, currentRaw, file); err != nil {
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

func persistAndRefreshUpstreamRuntimeOverrides(cfg ProxyRulesConfig, previousRaw string, file upstreamRuntimeFile) error {
	_, _, _, err := persistUpstreamRuntimeFile(cfg, file)
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
