package handler

import (
	"bufio"
	"context"
	"encoding/json"
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
)

const (
	ipReputationConfigBlobKey          = "ip_reputation_rules"
	defaultIPReputationRefreshInterval = 15 * time.Minute
	defaultIPReputationRequestTimeout  = 5 * time.Second
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

type runtimeIPReputationConfig struct {
	Raw ipReputationConfig
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
	if err := ensureIPReputationFile(target); err != nil {
		return err
	}
	ipReputationMu.Lock()
	ipReputationPath = target
	ipReputationMu.Unlock()
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
	store, err := newIPReputationStore(rt.Raw)
	if err != nil {
		return err
	}

	ipReputationMu.Lock()
	defer ipReputationMu.Unlock()
	if ipReputationStoreRT != nil {
		ipReputationStoreRT.Close()
	}
	ipReputationRuntime = &rt
	ipReputationStoreRT = store
	return nil
}

func ValidateIPReputationRaw(raw string) (runtimeIPReputationConfig, error) {
	var in ipReputationConfig
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		return runtimeIPReputationConfig{}, err
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		return runtimeIPReputationConfig{}, fmt.Errorf("invalid json")
	}
	cfg, err := normalizeAndValidateIPReputationConfig(in)
	if err != nil {
		return runtimeIPReputationConfig{}, err
	}
	return runtimeIPReputationConfig{Raw: cfg}, nil
}

func IPReputationStatus() ipReputationStatusSnapshot {
	ipReputationMu.RLock()
	store := ipReputationStoreRT
	rt := ipReputationRuntime
	ipReputationMu.RUnlock()
	if store == nil || rt == nil {
		return ipReputationStatusSnapshot{}
	}
	return store.Status(rt.Raw)
}

func GetIPReputationConfig() ipReputationConfig {
	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	if ipReputationRuntime == nil {
		return ipReputationConfig{}
	}
	return ipReputationRuntime.Raw
}

func EvaluateIPReputation(ip string) (bool, int) {
	store := currentIPReputationStore()
	if store == nil {
		return false, http.StatusForbidden
	}
	return store.IsBlocked(ip), store.BlockStatusCode()
}

func currentIPReputationStore() *ipReputationStore {
	ipReputationMu.RLock()
	defer ipReputationMu.RUnlock()
	return ipReputationStoreRT
}

func GetIPReputation(c *gin.Context) {
	path := GetIPReputationPath()
	raw, _ := os.ReadFile(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(ipReputationConfigBlobKey)
		if err == nil && found {
			if rt, parseErr := ValidateIPReputationRaw(string(dbRaw)); parseErr == nil {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				c.JSON(http.StatusOK, gin.H{
					"etag":   dbETag,
					"raw":    string(dbRaw),
					"config": rt.Raw,
					"status": IPReputationStatus(),
				})
				return
			}
		}
	}
	var cfg ipReputationConfig
	if ipReputationRuntime != nil {
		cfg = ipReputationRuntime.Raw
	}
	c.JSON(http.StatusOK, gin.H{
		"etag":   bypassconf.ComputeETag(raw),
		"raw":    string(raw),
		"config": cfg,
		"status": IPReputationStatus(),
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
	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(ipReputationConfigBlobKey)
		if err == nil && found {
			if _, parseErr := ValidateIPReputationRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

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
	if store != nil {
		if err := store.UpsertConfigBlob(ipReputationConfigBlobKey, []byte(in.Raw), newETag, time.Now().UTC()); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "status": IPReputationStatus()})
}

func SyncIPReputationStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: ipReputationConfigBlobKey,
		Path:      GetIPReputationPath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateIPReputationRaw(raw)
			return err
		},
		Reload:           ReloadIPReputation,
		SkipWriteIfEqual: true,
	})
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
	ip, err := netip.ParseAddr(strings.TrimSpace(ipStr))
	if err != nil {
		return false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if containsIPPrefix(s.effectiveAllow, ip) {
		return false
	}
	return containsIPPrefix(s.activeBlock, ip)
}

func (s *ipReputationStore) Status(raw ipReputationConfig) ipReputationStatusSnapshot {
	if s == nil {
		return ipReputationStatusSnapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return ipReputationStatusSnapshot{
		Enabled:             s.enabled,
		FeedURLs:            append([]string(nil), raw.FeedURLs...),
		LastRefreshAt:       formatIPReputationOptionalTime(s.lastRefreshAt),
		LastRefreshError:    s.lastRefreshErr,
		EffectiveAllowCount: len(s.effectiveAllow),
		EffectiveBlockCount: len(s.activeBlock),
		FeedAllowCount:      len(s.feedAllow),
		FeedBlockCount:      len(s.feedBlock),
		BlockStatusCode:     s.blockStatusCode,
		FailOpen:            s.failOpen,
	}
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

func mustJSON(v any) string {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		panic(err)
	}
	return string(raw)
}
