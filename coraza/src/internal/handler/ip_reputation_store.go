package handler

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/policyhost"
)

const (
	ipReputationConfigBlobKey          = "ip_reputation_rules"
	defaultIPReputationRefreshInterval = 15 * time.Minute
	defaultIPReputationRequestTimeout  = 5 * time.Second
	ipReputationDefaultScope           = "default"
)

type ipReputationConfig struct {
	Enabled            bool     `json:"enabled"`
	FeedURLs           []string `json:"feed_urls,omitempty"`
	Allowlist          []string `json:"allowlist,omitempty"`
	Blocklist          []string `json:"blocklist,omitempty"`
	RefreshIntervalSec int      `json:"refresh_interval_sec,omitempty"`
	RequestTimeoutSec  int      `json:"request_timeout_sec,omitempty"`
	BlockStatusCode    int      `json:"block_status_code,omitempty"`
	FailOpen           bool     `json:"fail_open"`
}

type ipReputationFile struct {
	Default ipReputationConfig            `json:"default"`
	Hosts   map[string]ipReputationConfig `json:"hosts,omitempty"`
}

type runtimeIPReputationScope struct {
	Raw   ipReputationConfig
	Store *ipReputationStore
}

type runtimeIPReputationConfig struct {
	Raw     ipReputationFile
	Default runtimeIPReputationScope
	Hosts   map[string]runtimeIPReputationScope
}

type ipReputationScopeSelection struct {
	Raw      ipReputationConfig
	Store    *ipReputationStore
	ScopeKey string
}

type ipReputationStatusSnapshot struct {
	Enabled             bool     `json:"enabled"`
	FeedURLs            []string `json:"feed_urls,omitempty"`
	LastRefreshAt       string   `json:"last_refresh_at,omitempty"`
	LastRefreshError    string   `json:"last_refresh_error,omitempty"`
	EffectiveAllowCount int      `json:"effective_allow_count"`
	EffectiveBlockCount int      `json:"effective_block_count"`
	FeedAllowCount      int      `json:"feed_allow_count"`
	FeedBlockCount      int      `json:"feed_block_count"`
	DynamicPenaltyCount int      `json:"dynamic_penalty_count"`
	BlockStatusCode     int      `json:"block_status_code"`
	FailOpen            bool     `json:"fail_open"`
}

type ipReputationStore struct {
	enabled         bool
	failOpen        bool
	blockStatusCode int
	refreshInterval time.Duration
	requestTimeout  time.Duration
	feedURLs        []string

	mu             sync.RWMutex
	configAllow    []netip.Prefix
	effectiveAllow []netip.Prefix
	staticBlock    []netip.Prefix
	feedAllow      []netip.Prefix
	feedBlock      []netip.Prefix
	activeBlock    []netip.Prefix
	dynamicBlock   map[string]time.Time
	lastRefreshAt  time.Time
	lastRefreshErr string

	ctx    context.Context
	cancel context.CancelFunc
}

var (
	ipReputationMu      sync.RWMutex
	ipReputationPath    string
	ipReputationRuntime *runtimeIPReputationConfig
	ipReputationStoreRT *ipReputationStore
)

func InitIPReputation(path string) error {
	target := strings.TrimSpace(path)
	if target == "" {
		return fmt.Errorf("ip reputation path is empty")
	}
	ipReputationMu.Lock()
	ipReputationPath = target
	ipReputationMu.Unlock()

	if store := getLogsStatsStore(); store != nil {
		raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(ipReputationConfigBlobKey), normalizeIPReputationPolicyRaw, "ip reputation rules")
		if err != nil {
			return fmt.Errorf("read ip reputation config db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized ip reputation config missing in db; run make db-import before removing seed files")
		}
		return applyIPReputationPolicyRaw(raw)
	}

	if err := ensureIPReputationFile(target); err != nil {
		return err
	}
	return ReloadIPReputation()
}

func ReloadIPReputation() error {
	ipReputationMu.RLock()
	path := ipReputationPath
	ipReputationMu.RUnlock()
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("ip reputation path is not initialized")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	rt, err := ValidateIPReputationRaw(string(raw))
	if err != nil {
		return err
	}

	ipReputationMu.Lock()
	defer ipReputationMu.Unlock()
	closeRuntimeIPReputation(ipReputationRuntime)
	ipReputationRuntime = &rt
	ipReputationStoreRT = rt.Default.Store
	return nil
}

func ValidateIPReputationRaw(raw string) (runtimeIPReputationConfig, error) {
	return buildIPReputationRuntimeFromRaw([]byte(raw))
}

func IPReputationStatus() ipReputationStatusSnapshot {
	ipReputationMu.RLock()
	rt := ipReputationRuntime
	ipReputationMu.RUnlock()
	if rt == nil || rt.Default.Store == nil {
		return ipReputationStatusSnapshot{}
	}
	status := rt.Default.Store.Status(rt.Raw.Default)
	status.Enabled = ipReputationEnabled(rt.Raw)
	return status
}

func GetIPReputationConfig() ipReputationFile {
	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	if ipReputationRuntime == nil {
		return ipReputationFile{}
	}
	return cloneIPReputationFile(ipReputationRuntime.Raw)
}

func EvaluateIPReputation(ip string) (bool, int) {
	blocked, status, _ := EvaluateIPReputationForHost("", false, ip)
	return blocked, status
}

func ApplyIPReputationPenalty(ip string, ttl time.Duration, now time.Time) bool {
	return ApplyIPReputationPenaltyForHost("", false, ip, ttl, now)
}

func currentIPReputationStore() *ipReputationStore {
	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	return ipReputationStoreRT
}

func EvaluateIPReputationForRequest(r *http.Request, ip string) (bool, int, string) {
	return EvaluateIPReputationForHost(requestHostPattern(r), requestUsesTLS(r), ip)
}

func EvaluateIPReputationForHost(host string, tls bool, ip string) (bool, int, string) {
	scope := selectIPReputationScope(currentIPReputationRuntime(), host, tls)
	if scope.Store == nil {
		return false, http.StatusForbidden, ipReputationDefaultScope
	}
	return scope.Store.IsBlocked(ip), scope.Store.BlockStatusCode(), scope.ScopeKey
}

func ApplyIPReputationPenaltyForRequest(r *http.Request, ip string, ttl time.Duration, now time.Time) bool {
	return ApplyIPReputationPenaltyForHost(requestHostPattern(r), requestUsesTLS(r), ip, ttl, now)
}

func ApplyIPReputationPenaltyForHost(host string, tls bool, ip string, ttl time.Duration, now time.Time) bool {
	scope := selectIPReputationScope(currentIPReputationRuntime(), host, tls)
	if scope.Store == nil {
		return false
	}
	return scope.Store.ApplyPenalty(ip, ttl, now)
}

func ApplyIPReputationPenaltyForScope(scopeKey, ip string, ttl time.Duration, now time.Time) bool {
	scope := selectIPReputationScopeByKey(currentIPReputationRuntime(), scopeKey)
	if scope.Store == nil {
		return false
	}
	return scope.Store.ApplyPenalty(ip, ttl, now)
}

func IPReputationStatusForHost(host string, tls bool) ipReputationStatusSnapshot {
	scope := selectIPReputationScope(currentIPReputationRuntime(), host, tls)
	if scope.Store == nil {
		return ipReputationStatusSnapshot{}
	}
	return scope.Store.Status(scope.Raw)
}

func currentIPReputationRuntime() *runtimeIPReputationConfig {
	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	return ipReputationRuntime
}

func requestHostPattern(r *http.Request) string {
	if r == nil {
		return ""
	}
	return r.Host
}

func requestUsesTLS(r *http.Request) bool {
	return r != nil && r.TLS != nil
}

func selectIPReputationScope(rt *runtimeIPReputationConfig, host string, tls bool) ipReputationScopeSelection {
	if rt == nil {
		return ipReputationScopeSelection{ScopeKey: ipReputationDefaultScope}
	}
	for _, candidate := range policyhost.Candidates(host, tls) {
		if scope, ok := rt.Hosts[candidate]; ok {
			return ipReputationScopeSelection{
				Raw:      scope.Raw,
				Store:    scope.Store,
				ScopeKey: candidate,
			}
		}
	}
	return ipReputationScopeSelection{
		Raw:      rt.Default.Raw,
		Store:    rt.Default.Store,
		ScopeKey: ipReputationDefaultScope,
	}
}

func selectIPReputationScopeByKey(rt *runtimeIPReputationConfig, scopeKey string) ipReputationScopeSelection {
	scope := strings.TrimSpace(scopeKey)
	if scope == "" || scope == ipReputationDefaultScope {
		return selectIPReputationScope(rt, "", false)
	}
	if rt == nil {
		return ipReputationScopeSelection{ScopeKey: ipReputationDefaultScope}
	}
	if hostScope, ok := rt.Hosts[scope]; ok {
		return ipReputationScopeSelection{
			Raw:      hostScope.Raw,
			Store:    hostScope.Store,
			ScopeKey: scope,
		}
	}
	return selectIPReputationScope(rt, "", false)
}

func GetIPReputation(c *gin.Context) {
	path := GetIPReputationPath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(ipReputationConfigBlobKey), normalizeIPReputationPolicyRaw, "ip reputation rules")
		if err != nil {
			respondConfigBlobDBError(c, "ip-reputation db read failed", err)
			return
		}
		if found {
			rt, parseErr := ValidateIPReputationRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "ip-reputation db rows parse failed", parseErr)
				return
			}
			savedAt = configVersionSavedAt(rec)
			c.JSON(http.StatusOK, gin.H{
				"etag":     rec.ETag,
				"raw":      string(dbRaw),
				"config":   rt.Raw,
				"status":   IPReputationStatus(),
				"saved_at": savedAt,
			})
			return
		}
	}
	var cfg ipReputationFile
	if ipReputationRuntime != nil {
		cfg = ipReputationRuntime.Raw
	}
	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      string(raw),
		"config":   cfg,
		"status":   IPReputationStatus(),
		"saved_at": savedAt,
	})
}

func ValidateIPReputation(c *gin.Context) {
	var in struct {
		Raw string `json:"raw"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	rt, err := ValidateIPReputationRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "config": rt.Raw})
}

func PutIPReputation(c *gin.Context) {
	path := GetIPReputationPath()
	store := getLogsStatsStore()

	var in struct {
		Raw string `json:"raw"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if _, err := ValidateIPReputationRaw(in.Raw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	normalizedRaw, err := normalizeIPReputationPolicyRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	if store != nil {
		spec := mustPolicyJSONSpec(ipReputationConfigBlobKey)
		currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeIPReputationPolicyRaw, "ip reputation rules")
		if err != nil {
			respondConfigBlobDBError(c, "ip-reputation db seed failed", err)
			return
		}
		expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
		rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "ip reputation rules update", 0)
		if err != nil {
			if errors.Is(err, errConfigVersionConflict) {
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, ipReputationConfigBlobKey)})
				return
			}
			respondConfigBlobDBError(c, "ip-reputation db update failed", err)
			return
		}
		if err := applyIPReputationPolicyRaw(normalizedRaw); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		c.JSON(http.StatusOK, gin.H{"ok": true, "etag": rec.ETag, "status": IPReputationStatus(), "saved_at": rec.ActivatedAt.Format(time.RFC3339Nano)})
		return
	}

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}
	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := ReloadIPReputation(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadIPReputation()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	now := time.Now().UTC()
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "status": IPReputationStatus(), "saved_at": now.Format(time.RFC3339Nano)})
}

func SyncIPReputationStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(ipReputationConfigBlobKey), normalizeIPReputationPolicyRaw, "ip reputation rules")
	if err != nil || !found {
		return err
	}
	return applyIPReputationPolicyRaw(raw)
}

func GetIPReputationPath() string {
	ipReputationMu.RLock()
	path := ipReputationPath
	ipReputationMu.RUnlock()
	if strings.TrimSpace(path) == "" {
		return config.IPReputationFile
	}
	return path
}

func ensureIPReputationFile(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return err
	}
	defaultRaw := mustJSON(ipReputationConfig{
		Enabled:            false,
		FeedURLs:           nil,
		Allowlist:          nil,
		Blocklist:          nil,
		RefreshIntervalSec: int(defaultIPReputationRefreshInterval / time.Second),
		RequestTimeoutSec:  int(defaultIPReputationRequestTimeout / time.Second),
		BlockStatusCode:    http.StatusForbidden,
		FailOpen:           true,
	})
	return bypassconf.AtomicWriteWithBackup(path, []byte(defaultRaw))
}

func normalizeAndValidateIPReputationConfig(in ipReputationConfig) (ipReputationConfig, error) {
	cfg := in
	cfg.FeedURLs = normalizeStringSlice(cfg.FeedURLs)
	cfg.Allowlist = normalizeStringSlice(cfg.Allowlist)
	cfg.Blocklist = normalizeStringSlice(cfg.Blocklist)
	if cfg.RefreshIntervalSec == 0 {
		cfg.RefreshIntervalSec = int(defaultIPReputationRefreshInterval / time.Second)
	}
	if cfg.RequestTimeoutSec == 0 {
		cfg.RequestTimeoutSec = int(defaultIPReputationRequestTimeout / time.Second)
	}
	if cfg.BlockStatusCode == 0 {
		cfg.BlockStatusCode = http.StatusForbidden
	}
	if cfg.RefreshIntervalSec <= 0 {
		return ipReputationConfig{}, fmt.Errorf("refresh_interval_sec must be > 0")
	}
	if cfg.RequestTimeoutSec <= 0 {
		return ipReputationConfig{}, fmt.Errorf("request_timeout_sec must be > 0")
	}
	if cfg.BlockStatusCode < 400 || cfg.BlockStatusCode > 599 {
		return ipReputationConfig{}, fmt.Errorf("block_status_code must be between 400 and 599")
	}
	if _, err := parseIPPrefixList(cfg.Allowlist); err != nil {
		return ipReputationConfig{}, fmt.Errorf("allowlist: %w", err)
	}
	if _, err := parseIPPrefixList(cfg.Blocklist); err != nil {
		return ipReputationConfig{}, fmt.Errorf("blocklist: %w", err)
	}
	return cfg, nil
}

func buildIPReputationRuntimeFromRaw(raw []byte) (runtimeIPReputationConfig, error) {
	top, err := decodeIPReputationJSONObject(raw)
	if err != nil {
		return runtimeIPReputationConfig{}, err
	}

	if _, hasDefault := top["default"]; !hasDefault {
		if _, hasHosts := top["hosts"]; !hasHosts {
			scope, err := buildRuntimeIPReputationScopeFromRaw(raw)
			if err != nil {
				return runtimeIPReputationConfig{}, err
			}
			return runtimeIPReputationConfig{
				Raw: ipReputationFile{
					Default: cloneIPReputationConfig(scope.Raw),
				},
				Default: scope,
				Hosts:   map[string]runtimeIPReputationScope{},
			}, nil
		}
	}

	for key := range top {
		if key != "default" && key != "hosts" {
			return runtimeIPReputationConfig{}, fmt.Errorf("invalid json")
		}
	}

	defaultObject, err := decodeIPReputationObjectValue(top["default"], "default")
	if err != nil {
		return runtimeIPReputationConfig{}, err
	}
	defaultScope, err := buildRuntimeIPReputationScopeFromRaw(mustMarshalIPReputationObject(defaultObject))
	if err != nil {
		return runtimeIPReputationConfig{}, err
	}

	runtime := runtimeIPReputationConfig{
		Raw: ipReputationFile{
			Default: cloneIPReputationConfig(defaultScope.Raw),
		},
		Default: defaultScope,
		Hosts:   map[string]runtimeIPReputationScope{},
	}

	hosts, err := decodeIPReputationHosts(top["hosts"])
	if err != nil {
		return runtimeIPReputationConfig{}, err
	}
	if len(hosts) == 0 {
		return runtime, nil
	}

	runtime.Raw.Hosts = make(map[string]ipReputationConfig, len(hosts))
	for rawHost, rawScope := range hosts {
		hostKey, err := policyhost.NormalizePattern(rawHost)
		if err != nil {
			return runtimeIPReputationConfig{}, fmt.Errorf("hosts[%q]: %w", rawHost, err)
		}
		hostObject, err := decodeIPReputationObjectValue(rawScope, fmt.Sprintf("hosts[%q]", rawHost))
		if err != nil {
			return runtimeIPReputationConfig{}, err
		}
		mergedObject := mergeIPReputationJSONObject(defaultObject, hostObject)
		scope, err := buildRuntimeIPReputationScopeFromRaw(mustMarshalIPReputationObject(mergedObject))
		if err != nil {
			return runtimeIPReputationConfig{}, err
		}
		runtime.Raw.Hosts[hostKey] = cloneIPReputationConfig(scope.Raw)
		runtime.Hosts[hostKey] = scope
	}

	return runtime, nil
}

func buildRuntimeIPReputationScopeFromRaw(raw []byte) (runtimeIPReputationScope, error) {
	cfg, err := decodeIPReputationConfig(raw)
	if err != nil {
		return runtimeIPReputationScope{}, err
	}
	return buildRuntimeIPReputationScope(cfg)
}

func buildRuntimeIPReputationScope(cfg ipReputationConfig) (runtimeIPReputationScope, error) {
	normalized, err := normalizeAndValidateIPReputationConfig(cfg)
	if err != nil {
		return runtimeIPReputationScope{}, err
	}
	store, err := newIPReputationStore(normalized)
	if err != nil {
		return runtimeIPReputationScope{}, err
	}
	return runtimeIPReputationScope{
		Raw:   normalized,
		Store: store,
	}, nil
}

func decodeIPReputationConfig(raw []byte) (ipReputationConfig, error) {
	var cfg ipReputationConfig
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return ipReputationConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return ipReputationConfig{}, fmt.Errorf("invalid json")
	}
	return cfg, nil
}

func decodeIPReputationJSONObject(raw []byte) (map[string]json.RawMessage, error) {
	var obj map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&obj); err != nil {
		return nil, err
	}
	if obj == nil {
		return nil, fmt.Errorf("ip reputation config must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return obj, nil
}

func decodeIPReputationObjectValue(raw json.RawMessage, field string) (map[string]any, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return map[string]any{}, nil
	}
	var out map[string]any
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("%s must be a JSON object", field)
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func decodeIPReputationHosts(raw json.RawMessage) (map[string]json.RawMessage, error) {
	if len(strings.TrimSpace(string(raw))) == 0 {
		return nil, nil
	}
	var out map[string]json.RawMessage
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	if err := dec.Decode(&out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("hosts must be a JSON object")
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("invalid json")
	}
	return out, nil
}

func mergeIPReputationJSONObject(base, override map[string]any) map[string]any {
	out := cloneIPReputationJSONValue(base).(map[string]any)
	for key, value := range override {
		out[key] = mergeIPReputationJSONValue(out[key], value)
	}
	return out
}

func mergeIPReputationJSONValue(base, override any) any {
	baseObject, baseOK := base.(map[string]any)
	overrideObject, overrideOK := override.(map[string]any)
	if baseOK && overrideOK {
		return mergeIPReputationJSONObject(baseObject, overrideObject)
	}
	return cloneIPReputationJSONValue(override)
}

func cloneIPReputationJSONValue(value any) any {
	switch typed := value.(type) {
	case map[string]any:
		out := make(map[string]any, len(typed))
		for key, item := range typed {
			out[key] = cloneIPReputationJSONValue(item)
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = cloneIPReputationJSONValue(item)
		}
		return out
	default:
		return typed
	}
}

func mustMarshalIPReputationObject(value map[string]any) []byte {
	raw, _ := json.Marshal(value)
	return raw
}

func closeRuntimeIPReputation(rt *runtimeIPReputationConfig) {
	if rt == nil {
		return
	}
	if rt.Default.Store != nil {
		rt.Default.Store.Close()
	}
	for _, scope := range rt.Hosts {
		if scope.Store != nil {
			scope.Store.Close()
		}
	}
}

func cloneIPReputationFile(in ipReputationFile) ipReputationFile {
	out := ipReputationFile{
		Default: cloneIPReputationConfig(in.Default),
	}
	if len(in.Hosts) > 0 {
		out.Hosts = make(map[string]ipReputationConfig, len(in.Hosts))
		for host, cfg := range in.Hosts {
			out.Hosts[host] = cloneIPReputationConfig(cfg)
		}
	}
	return out
}

func cloneIPReputationConfig(in ipReputationConfig) ipReputationConfig {
	out := in
	out.FeedURLs = append([]string(nil), in.FeedURLs...)
	out.Allowlist = append([]string(nil), in.Allowlist...)
	out.Blocklist = append([]string(nil), in.Blocklist...)
	return out
}

func ipReputationEnabled(file ipReputationFile) bool {
	if file.Default.Enabled {
		return true
	}
	for _, scope := range file.Hosts {
		if scope.Enabled {
			return true
		}
	}
	return false
}

func newIPReputationStore(cfg ipReputationConfig) (*ipReputationStore, error) {
	allow, err := parseIPPrefixList(cfg.Allowlist)
	if err != nil {
		return nil, err
	}
	block, err := parseIPPrefixList(cfg.Blocklist)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	store := &ipReputationStore{
		enabled:         cfg.Enabled,
		failOpen:        cfg.FailOpen,
		blockStatusCode: cfg.BlockStatusCode,
		refreshInterval: time.Duration(cfg.RefreshIntervalSec) * time.Second,
		requestTimeout:  time.Duration(cfg.RequestTimeoutSec) * time.Second,
		feedURLs:        append([]string(nil), cfg.FeedURLs...),
		configAllow:     allow,
		effectiveAllow:  allow,
		staticBlock:     block,
		activeBlock:     applyIPAllowlist(block, allow),
		dynamicBlock:    map[string]time.Time{},
		ctx:             ctx,
		cancel:          cancel,
	}
	if store.enabled && len(store.feedURLs) > 0 {
		if err := store.refresh(ctx); err != nil {
			store.lastRefreshErr = err.Error()
		}
		go store.refreshLoop()
	}
	return store, nil
}

func (s *ipReputationStore) Close() {
	if s != nil && s.cancel != nil {
		s.cancel()
	}
}

func (s *ipReputationStore) BlockStatusCode() int {
	if s == nil || s.blockStatusCode == 0 {
		return http.StatusForbidden
	}
	return s.blockStatusCode
}

func (s *ipReputationStore) Enabled() bool {
	return s != nil && s.enabled
}

func (s *ipReputationStore) IsBlocked(ipStr string) bool {
	if s == nil || !s.enabled {
		return false
	}
	return s.isBlockedAt(ipStr, time.Now().UTC())
}

func (s *ipReputationStore) isBlockedAt(ipStr string, now time.Time) bool {
	if s == nil || !s.enabled {
		return false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if containsIPPrefix(s.effectiveAllow, ip) {
		return false
	}
	s.cleanupDynamicLocked(now)
	if until, ok := s.dynamicBlock[ip.Unmap().String()]; ok && now.Before(until) {
		return true
	}
	return containsIPPrefix(s.activeBlock, ip)
}

func (s *ipReputationStore) Status(raw ipReputationConfig) ipReputationStatusSnapshot {
	if s == nil {
		return ipReputationStatusSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	now := time.Now().UTC()
	dynamicPenaltyCount := 0
	for _, until := range s.dynamicBlock {
		if now.Before(until) {
			dynamicPenaltyCount++
		}
	}
	return ipReputationStatusSnapshot{
		Enabled:             s.enabled,
		FeedURLs:            append([]string(nil), raw.FeedURLs...),
		LastRefreshAt:       formatIPReputationOptionalTime(s.lastRefreshAt),
		LastRefreshError:    s.lastRefreshErr,
		EffectiveAllowCount: len(s.effectiveAllow),
		EffectiveBlockCount: len(s.activeBlock),
		FeedAllowCount:      len(s.feedAllow),
		FeedBlockCount:      len(s.feedBlock),
		DynamicPenaltyCount: dynamicPenaltyCount,
		BlockStatusCode:     s.blockStatusCode,
		FailOpen:            s.failOpen,
	}
}

func (s *ipReputationStore) ApplyPenalty(ipStr string, ttl time.Duration, now time.Time) bool {
	if s == nil || !s.enabled || ttl <= 0 {
		return false
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	s.mu.Lock()
	defer s.mu.Unlock()
	if containsIPPrefix(s.effectiveAllow, ip) {
		return false
	}
	s.cleanupDynamicLocked(now)
	key := ip.String()
	until := now.Add(ttl)
	if existing, ok := s.dynamicBlock[key]; ok && existing.After(until) {
		until = existing
	}
	s.dynamicBlock[key] = until
	return true
}

func (s *ipReputationStore) refreshLoop() {
	ticker := time.NewTicker(s.refreshInterval)
	defer ticker.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			_ = s.refresh(s.ctx)
		}
	}
}

func (s *ipReputationStore) refresh(ctx context.Context) error {
	if s == nil || !s.enabled || len(s.feedURLs) == 0 {
		return nil
	}
	mergedAllow := append([]netip.Prefix(nil), s.configAllow...)
	mergedBlock := append([]netip.Prefix(nil), s.staticBlock...)
	successFeeds := 0
	var errs []string
	for _, feedURL := range s.feedURLs {
		res, err := s.loadFeed(ctx, feedURL)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", feedURL, err))
			continue
		}
		successFeeds++
		mergedAllow = append(mergedAllow, res.allow...)
		mergedBlock = append(mergedBlock, res.block...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if successFeeds == 0 && len(errs) > 0 {
		s.lastRefreshErr = strings.Join(errs, "; ")
		s.lastRefreshAt = time.Now().UTC()
		if s.failOpen {
			return fmt.Errorf("%s", s.lastRefreshErr)
		}
		return nil
	}
	s.feedAllow = dedupeIPPrefixes(mergedAllow[len(s.configAllow):])
	s.feedBlock = dedupeIPPrefixes(mergedBlock[len(s.staticBlock):])
	s.recomputeLocked()
	s.lastRefreshAt = time.Now().UTC()
	s.lastRefreshErr = ""
	return nil
}

type ipFeedResult struct {
	allow []netip.Prefix
	block []netip.Prefix
}

func (s *ipReputationStore) loadFeed(ctx context.Context, source string) (ipFeedResult, error) {
	var (
		reader io.ReadCloser
		err    error
	)
	if isHTTPURL(source) {
		client := &http.Client{Timeout: s.requestTimeout}
		req, reqErr := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
		if reqErr != nil {
			return ipFeedResult{}, reqErr
		}
		res, reqErr := client.Do(req)
		if reqErr != nil {
			return ipFeedResult{}, reqErr
		}
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			body, _ := io.ReadAll(io.LimitReader(res.Body, 1024))
			_ = res.Body.Close()
			return ipFeedResult{}, fmt.Errorf("status=%d body=%q", res.StatusCode, strings.TrimSpace(string(body)))
		}
		reader = res.Body
	} else {
		path := source
		if strings.HasPrefix(strings.ToLower(path), "file://") {
			u, parseErr := url.Parse(path)
			if parseErr != nil {
				return ipFeedResult{}, parseErr
			}
			path = u.Path
		}
		reader, err = os.Open(path)
		if err != nil {
			return ipFeedResult{}, err
		}
	}
	defer reader.Close()

	allow := make([]netip.Prefix, 0, 128)
	block := make([]netip.Prefix, 0, 1024)
	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line == "" {
			continue
		}
		action := "deny"
		target := line
		if strings.HasPrefix(target, "!") {
			action = "allow"
			target = strings.TrimSpace(strings.TrimPrefix(target, "!"))
		} else {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				head := strings.ToLower(strings.TrimSpace(parts[0]))
				if head == "allow" || head == "deny" || head == "block" {
					action = head
					target = strings.TrimSpace(parts[1])
				}
			}
		}
		prefix, parseErr := parseIPPrefix(target)
		if parseErr != nil {
			continue
		}
		if action == "allow" {
			allow = append(allow, prefix)
		} else {
			block = append(block, prefix)
		}
	}
	if err := scanner.Err(); err != nil {
		return ipFeedResult{}, err
	}
	return ipFeedResult{
		allow: dedupeIPPrefixes(allow),
		block: dedupeIPPrefixes(block),
	}, nil
}

func (s *ipReputationStore) recomputeLocked() {
	mergedAllow := dedupeIPPrefixes(append(append([]netip.Prefix(nil), s.configAllow...), s.feedAllow...))
	mergedBlock := dedupeIPPrefixes(append(append([]netip.Prefix(nil), s.staticBlock...), s.feedBlock...))
	s.effectiveAllow = mergedAllow
	s.activeBlock = applyIPAllowlist(mergedBlock, mergedAllow)
}

func (s *ipReputationStore) cleanupDynamicLocked(now time.Time) {
	if len(s.dynamicBlock) == 0 {
		return
	}
	for key, until := range s.dynamicBlock {
		if !now.Before(until) {
			delete(s.dynamicBlock, key)
		}
	}
}

func parseIPPrefix(raw string) (netip.Prefix, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return netip.Prefix{}, fmt.Errorf("empty ip/cidr")
	}
	if strings.Contains(value, "/") {
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		return prefix.Masked(), nil
	}
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	bits := 32
	if ip.Is6() {
		bits = 128
	}
	return netip.PrefixFrom(ip.Unmap(), bits), nil
}

func parseIPPrefixList(in []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(in))
	for i, raw := range in {
		prefix, err := parseIPPrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("[%d]: %w", i, err)
		}
		out = append(out, prefix)
	}
	return dedupeIPPrefixes(out), nil
}

func dedupeIPPrefixes(in []netip.Prefix) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, prefix := range in {
		masked := prefix.Masked()
		if slices.Contains(out, masked) {
			continue
		}
		out = append(out, masked)
	}
	return out
}

func containsIPPrefix(prefixes []netip.Prefix, ip netip.Addr) bool {
	addr := ip.Unmap()
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

func applyIPAllowlist(blocklist, allowlist []netip.Prefix) []netip.Prefix {
	if len(blocklist) == 0 {
		return nil
	}
	if len(allowlist) == 0 {
		return append([]netip.Prefix(nil), blocklist...)
	}
	out := make([]netip.Prefix, 0, len(blocklist))
	for _, prefix := range blocklist {
		if containsIPPrefix(allowlist, prefix.Addr()) {
			continue
		}
		out = append(out, prefix)
	}
	return out
}

func isHTTPURL(raw string) bool {
	value := strings.ToLower(strings.TrimSpace(raw))
	return strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://")
}

func formatIPReputationOptionalTime(ts time.Time) string {
	if ts.IsZero() {
		return ""
	}
	return ts.UTC().Format(time.RFC3339Nano)
}

func normalizeStringSlice(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		value := strings.TrimSpace(raw)
		if value != "" {
			out = append(out, value)
		}
	}
	return out
}
