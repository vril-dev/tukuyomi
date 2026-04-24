package handler

import (
	"bufio"
	"bytes"
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
)

const (
	responseCacheConfigBlobKey           = "cache_store"
	defaultResponseCacheStoreDir         = "cache/response"
	defaultResponseCacheMaxBytes         = int64(2 * 1024 * 1024 * 1024)
	defaultResponseCacheMemoryMaxBytes   = int64(256 * 1024 * 1024)
	defaultResponseCacheMemoryMaxEntries = 4096
	proxyResponseCacheHeader             = "X-Tukuyomi-Cache"
	proxyResponseCacheRequestID          = "X-Request-ID"
)

type responseCacheConfig struct {
	Enabled          bool   `json:"enabled"`
	StoreDir         string `json:"store_dir,omitempty"`
	MaxBytes         int64  `json:"max_bytes,omitempty"`
	MemoryEnabled    bool   `json:"memory_enabled,omitempty"`
	MemoryMaxBytes   int64  `json:"memory_max_bytes,omitempty"`
	MemoryMaxEntries int    `json:"memory_max_entries,omitempty"`
}

type preparedResponseCacheConfig struct {
	cfg  responseCacheConfig
	raw  string
	etag string
}

type responseCacheConfigConflictError struct {
	CurrentETag string
}

func (e responseCacheConfigConflictError) Error() string {
	return "conflict"
}

type responseCacheRuntime struct {
	mu         sync.RWMutex
	configPath string
	raw        string
	etag       string
	cfg        responseCacheConfig
	store      *proxyResponseCacheStore
}

type proxyResponseCacheStore struct {
	mu              sync.Mutex
	enabled         bool
	dir             string
	maxBytes        int64
	currentBytes    int64
	entries         map[string]*proxyResponseCacheEntry
	lru             *list.List
	hits            uint64
	misses          uint64
	stores          uint64
	evictions       uint64
	clears          uint64
	memEnabled      bool
	memMaxBytes     int64
	memMaxEntries   int
	memCurrentBytes int64
	memEntries      map[string]*proxyResponseCacheMemoryEntry
	memLRU          *list.List
	memHits         uint64
	memMisses       uint64
	memStores       uint64
	memEvictions    uint64
}

type proxyResponseCacheEntry struct {
	Key        string
	Status     int
	Header     http.Header
	Size       int64
	ExpiresAt  time.Time
	CreatedAt  time.Time
	AccessedAt time.Time
	BodyPath   string
	element    *list.Element
}

type proxyResponseCacheMemoryEntry struct {
	Key        string
	Body       []byte
	Size       int64
	AccessedAt time.Time
	element    *list.Element
}

type proxyResponseCacheMeta struct {
	Key        string      `json:"key"`
	Status     int         `json:"status"`
	Header     http.Header `json:"header"`
	Size       int64       `json:"size"`
	ExpiresAt  time.Time   `json:"expires_at"`
	CreatedAt  time.Time   `json:"created_at"`
	AccessedAt time.Time   `json:"accessed_at"`
}

type proxyResponseCacheStats struct {
	Enabled          bool   `json:"enabled"`
	StoreDir         string `json:"store_dir"`
	MaxBytes         int64  `json:"max_bytes"`
	SizeBytes        int64  `json:"size_bytes"`
	EntryCount       int    `json:"entry_count"`
	Hits             uint64 `json:"hits_total"`
	Misses           uint64 `json:"misses_total"`
	Stores           uint64 `json:"stores_total"`
	Evictions        uint64 `json:"evictions_total"`
	Clears           uint64 `json:"clears_total"`
	MemoryEnabled    bool   `json:"memory_enabled"`
	MemoryMaxBytes   int64  `json:"memory_max_bytes"`
	MemoryMaxEntries int    `json:"memory_max_entries"`
	MemorySizeBytes  int64  `json:"memory_size_bytes"`
	MemoryEntryCount int    `json:"memory_entry_count"`
	MemoryHits       uint64 `json:"memory_hits_total"`
	MemoryMisses     uint64 `json:"memory_misses_total"`
	MemoryStores     uint64 `json:"memory_stores_total"`
	MemoryEvictions  uint64 `json:"memory_evictions_total"`
}

type proxyResponseCacheClearResult struct {
	ClearedEntries int   `json:"cleared_entries"`
	ClearedBytes   int64 `json:"cleared_bytes"`
}

type proxyCacheStorePutBody struct {
	Enabled          bool   `json:"enabled"`
	StoreDir         string `json:"store_dir"`
	MaxBytes         int64  `json:"max_bytes"`
	MemoryEnabled    bool   `json:"memory_enabled"`
	MemoryMaxBytes   int64  `json:"memory_max_bytes"`
	MemoryMaxEntries int    `json:"memory_max_entries"`
}

type proxyResponseCacheLoadResult struct {
	Entry     proxyResponseCacheEntry
	Body      []byte
	MemoryHit bool
}

type proxyHTTPCacheCaptureWriter struct {
	http.ResponseWriter
	status   int
	size     int64
	bodySize int64
	tmpFile  *os.File
	tmpPath  string
	tmpErr   error
}

var (
	responseCacheRuntimeMu sync.RWMutex
	responseCacheRt        *responseCacheRuntime
)

func InitResponseCacheRuntime(path string) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return fmt.Errorf("cache store config path is required")
	}
	var raw []byte
	var dbETag string
	if store := getLogsStatsStore(); store != nil {
		dbRaw, rec, found, err := loadRuntimeResponseCacheConfig(store)
		if err != nil {
			return fmt.Errorf("read response cache config from db: %w", err)
		}
		if !found {
			return fmt.Errorf("normalized response cache config missing in db; run make db-import before removing seed files")
		}
		raw = dbRaw
		dbETag = rec.ETag
	}
	if len(raw) == 0 {
		fileRaw, err := os.ReadFile(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return fmt.Errorf("read cache store config (%s): %w", path, err)
			}
			cfg := normalizeResponseCacheConfig(responseCacheConfig{})
			encoded, err := marshalResponseCacheConfig(cfg)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			if err := bypassconf.AtomicWriteWithBackup(path, encoded); err != nil {
				return err
			}
			raw = encoded
		} else {
			raw = fileRaw
		}
	}

	prepared, err := prepareResponseCacheRaw(string(raw))
	if err != nil {
		return fmt.Errorf("invalid cache store config (%s): %w", path, err)
	}
	if dbETag == "" {
		dbETag = prepared.etag
	}
	store, err := newProxyResponseCacheStore(prepared.cfg)
	if err != nil {
		return fmt.Errorf("build response cache: %w", err)
	}

	responseCacheRuntimeMu.Lock()
	responseCacheRt = &responseCacheRuntime{
		configPath: path,
		raw:        prepared.raw,
		etag:       dbETag,
		cfg:        prepared.cfg,
		store:      store,
	}
	responseCacheRuntimeMu.Unlock()
	return nil
}

func currentResponseCacheRuntime() *responseCacheRuntime {
	responseCacheRuntimeMu.RLock()
	defer responseCacheRuntimeMu.RUnlock()
	return responseCacheRt
}

func ResponseCacheSnapshot() (raw string, etag string, cfg responseCacheConfig, stats proxyResponseCacheStats) {
	rt := currentResponseCacheRuntime()
	if rt == nil {
		cfg = normalizeResponseCacheConfig(responseCacheConfig{})
		return "", "", cfg, proxyResponseCacheStats{
			Enabled:  cfg.Enabled,
			StoreDir: cfg.StoreDir,
			MaxBytes: cfg.MaxBytes,
		}
	}
	rt.mu.RLock()
	defer rt.mu.RUnlock()
	stats = proxyResponseCacheStats{
		Enabled:          rt.cfg.Enabled,
		StoreDir:         rt.cfg.StoreDir,
		MaxBytes:         rt.cfg.MaxBytes,
		MemoryEnabled:    rt.cfg.MemoryEnabled,
		MemoryMaxBytes:   rt.cfg.MemoryMaxBytes,
		MemoryMaxEntries: rt.cfg.MemoryMaxEntries,
	}
	if rt.store != nil {
		stats = rt.store.Snapshot()
	}
	return rt.raw, rt.etag, rt.cfg, stats
}

func ValidateResponseCacheRaw(raw string) (responseCacheConfig, error) {
	prepared, err := prepareResponseCacheRaw(raw)
	if err != nil {
		return responseCacheConfig{}, err
	}
	return prepared.cfg, nil
}

func ApplyResponseCacheRaw(ifMatch string, raw string) (string, responseCacheConfig, error) {
	rt := currentResponseCacheRuntime()
	if rt == nil {
		return "", responseCacheConfig{}, fmt.Errorf("response cache runtime is not initialized")
	}
	prepared, err := prepareResponseCacheRaw(raw)
	if err != nil {
		return "", responseCacheConfig{}, err
	}

	rt.mu.Lock()
	defer rt.mu.Unlock()

	if ifMatch = strings.TrimSpace(ifMatch); ifMatch != "" && ifMatch != rt.etag && ifMatch != bypassconf.ComputeETag([]byte(rt.raw)) {
		return "", responseCacheConfig{}, responseCacheConfigConflictError{CurrentETag: rt.etag}
	}

	prevETag := rt.etag
	prevStats := proxyResponseCacheStats{}
	if rt.store != nil {
		prevStats = rt.store.Snapshot()
	}

	store, err := requireConfigDBStore()
	if err != nil {
		return "", responseCacheConfig{}, err
	}
	candidateStore, err := newProxyResponseCacheStore(prepared.cfg)
	if err != nil {
		return "", responseCacheConfig{}, err
	}
	expectedETag := responseCacheExpectedETag(ifMatch, rt.raw, rt.etag)
	rec, cfg, err := store.writeResponseCacheConfigVersion(expectedETag, prepared.cfg, configVersionSourceApply, "", "response cache config update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			return "", responseCacheConfig{}, responseCacheConfigConflictError{CurrentETag: policyConfigConflictETag(store, responseCacheConfigBlobKey)}
		}
		return "", responseCacheConfig{}, err
	}
	prepared.cfg = cfg
	rt.store = candidateStore
	nextETag := rec.ETag

	rt.raw = prepared.raw
	rt.etag = nextETag
	rt.cfg = prepared.cfg

	if prevStats.StoreDir != "" && prevStats.StoreDir != prepared.cfg.StoreDir {
		log.Printf("[CACHE] switched internal cache dir from %s to %s", prevStats.StoreDir, prepared.cfg.StoreDir)
	}
	if prevETag != nextETag {
		log.Printf("[CACHE] internal cache config applied enabled=%t store_dir=%s max_bytes=%d", prepared.cfg.Enabled, prepared.cfg.StoreDir, prepared.cfg.MaxBytes)
	}

	return rt.etag, rt.cfg, nil
}

func ClearResponseCache() (proxyResponseCacheClearResult, error) {
	rt := currentResponseCacheRuntime()
	if rt == nil || rt.store == nil {
		return proxyResponseCacheClearResult{}, fmt.Errorf("response cache runtime is not initialized")
	}
	rt.mu.RLock()
	store := rt.store
	rt.mu.RUnlock()
	return store.Clear()
}

func SyncResponseCacheStoreStorage() error {
	rt := currentResponseCacheRuntime()
	path := ""
	if rt != nil {
		rt.mu.RLock()
		path = rt.configPath
		rt.mu.RUnlock()
	}
	if path == "" {
		return nil
	}
	if store := getLogsStatsStore(); store != nil {
		raw, rec, found, err := loadRuntimeResponseCacheConfig(store)
		if err != nil || !found {
			return err
		}
		prepared, err := prepareResponseCacheRaw(string(raw))
		if err != nil {
			return err
		}
		rt.mu.Lock()
		defer rt.mu.Unlock()
		if rt.store == nil {
			rt.store, err = newProxyResponseCacheStore(prepared.cfg)
			if err != nil {
				return err
			}
		} else if err := rt.store.Reconfigure(prepared.cfg); err != nil {
			return err
		}
		rt.raw = prepared.raw
		rt.etag = rec.ETag
		rt.cfg = prepared.cfg
		return nil
	}
	return nil
}

func GetResponseCacheStore(c *gin.Context) {
	raw, etag, cfg, stats := ResponseCacheSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":  etag,
		"raw":   raw,
		"store": cfg,
		"stats": stats,
	})
}

func ValidateResponseCacheStore(c *gin.Context) {
	var in struct {
		Raw string `json:"raw"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidateResponseCacheRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "store": cfg})
}

func PutResponseCacheStore(c *gin.Context) {
	ifMatch := c.GetHeader("If-Match")
	var in proxyCacheStorePutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	raw, err := marshalResponseCacheConfig(normalizeResponseCacheConfig(responseCacheConfig{
		Enabled:          in.Enabled,
		StoreDir:         in.StoreDir,
		MaxBytes:         in.MaxBytes,
		MemoryEnabled:    in.MemoryEnabled,
		MemoryMaxBytes:   in.MemoryMaxBytes,
		MemoryMaxEntries: in.MemoryMaxEntries,
	}))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	etag, cfg, err := ApplyResponseCacheRaw(ifMatch, string(raw))
	if err != nil {
		var conflictErr responseCacheConfigConflictError
		if errors.As(err, &conflictErr) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": conflictErr.CurrentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": etag, "store": cfg})
}

func ClearResponseCacheStore(c *gin.Context) {
	result, err := ClearResponseCache()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "clear": result})
}

func ServeProxyWithCache(c *gin.Context) {
	if c == nil || c.Request == nil {
		return
	}
	ServeProxyWithCacheHTTP(c.Writer, c.Request)
}

func ServeProxyWithCacheHTTP(w http.ResponseWriter, r *http.Request) {
	if w == nil || r == nil {
		return
	}
	rt := currentResponseCacheRuntime()
	if rt == nil {
		ServeProxy(w, r)
		return
	}

	rt.mu.RLock()
	cfg := rt.cfg
	store := rt.store
	rt.mu.RUnlock()

	rs := cacheconf.Get()
	if !cfg.Enabled || store == nil || rs == nil {
		ServeProxy(w, r)
		return
	}
	if shouldBypassProxyResponseCache(r) {
		ServeProxy(w, r)
		return
	}

	rule, allow := rs.Match(r.Host, r.TLS != nil, r.Method, r.URL.Path)
	if !allow || rule == nil {
		ServeProxy(w, r)
		return
	}

	key := proxyResponseCacheKey(r, proxyEffectiveResponseCacheVary(rule.Vary))
	if cached, ok := store.Load(key); ok {
		if err := writeProxyCachedResponse(w, r, cached.Entry, cached.Body); err == nil {
			return
		}
		store.removeByKey(key)
	}

	tmpFile, tmpPath, err := store.NewTempBodyFile()
	if err != nil {
		ServeProxy(w, r)
		return
	}
	cw := &proxyHTTPCacheCaptureWriter{
		ResponseWriter: w,
		tmpFile:        tmpFile,
		tmpPath:        tmpPath,
	}
	cw.Header().Set(proxyResponseCacheHeader, "MISS")
	ServeProxy(cw, r)

	headerSnapshot := cw.Header().Clone()
	statusCode := cw.Status()
	bodySize := cw.bodySize
	_ = cw.closeTemp()

	if cw.tmpErr != nil || r.Method != http.MethodGet || !shouldStoreProxyResponse(statusCode, headerSnapshot) {
		store.DiscardTemp(tmpPath)
		return
	}
	headerSnapshot = sanitizeProxyCachedResponseHeader(headerSnapshot, r, proxyResponseHeaderPolicySurfaceCacheStore)
	ttl := rule.TTL
	if ttl <= 0 {
		ttl = 600
	}
	if err := store.Store(key, ttl, statusCode, headerSnapshot, tmpPath, bodySize); err != nil {
		store.DiscardTemp(tmpPath)
	}
}

func prepareResponseCacheRaw(raw string) (preparedResponseCacheConfig, error) {
	var cfg responseCacheConfig
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return preparedResponseCacheConfig{}, err
	}
	cfg = normalizeResponseCacheConfig(cfg)
	if err := validateResponseCacheConfig(cfg); err != nil {
		return preparedResponseCacheConfig{}, err
	}
	outRaw, err := marshalResponseCacheConfig(cfg)
	if err != nil {
		return preparedResponseCacheConfig{}, err
	}
	return preparedResponseCacheConfig{
		cfg:  cfg,
		raw:  string(outRaw),
		etag: bypassconf.ComputeETag(outRaw),
	}, nil
}

func normalizeResponseCacheConfig(cfg responseCacheConfig) responseCacheConfig {
	out := cfg
	out.StoreDir = strings.TrimSpace(out.StoreDir)
	if out.StoreDir == "" {
		out.StoreDir = defaultResponseCacheStoreDir
	}
	if out.MaxBytes == 0 {
		out.MaxBytes = defaultResponseCacheMaxBytes
	}
	if out.MemoryEnabled {
		if out.MemoryMaxBytes == 0 {
			out.MemoryMaxBytes = defaultResponseCacheMemoryMaxBytes
		}
		if out.MemoryMaxEntries == 0 {
			out.MemoryMaxEntries = defaultResponseCacheMemoryMaxEntries
		}
	}
	return out
}

func validateResponseCacheConfig(cfg responseCacheConfig) error {
	if strings.TrimSpace(cfg.StoreDir) == "" {
		return fmt.Errorf("cache.store_dir is required")
	}
	if cfg.MaxBytes < 0 {
		return fmt.Errorf("cache.max_bytes must be >= 0")
	}
	if cfg.MemoryMaxBytes < 0 {
		return fmt.Errorf("cache.memory_max_bytes must be >= 0")
	}
	if cfg.MemoryMaxEntries < 0 {
		return fmt.Errorf("cache.memory_max_entries must be >= 0")
	}
	if cfg.Enabled && cfg.MaxBytes <= 0 {
		return fmt.Errorf("cache.max_bytes must be > 0 when enabled=true")
	}
	if !cfg.Enabled {
		return nil
	}
	if cfg.MemoryEnabled {
		if cfg.MemoryMaxBytes <= 0 {
			return fmt.Errorf("cache.memory_max_bytes must be > 0 when memory_enabled=true")
		}
		if cfg.MemoryMaxEntries <= 0 {
			return fmt.Errorf("cache.memory_max_entries must be > 0 when memory_enabled=true")
		}
	}
	if err := os.MkdirAll(cfg.StoreDir, 0o755); err != nil {
		return fmt.Errorf("prepare cache.store_dir: %w", err)
	}
	return nil
}

func marshalResponseCacheConfig(cfg responseCacheConfig) ([]byte, error) {
	raw, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func mustReadFile(path string) []byte {
	raw, _ := os.ReadFile(path)
	return raw
}

func newProxyResponseCacheStore(cfg responseCacheConfig) (*proxyResponseCacheStore, error) {
	s := &proxyResponseCacheStore{
		entries:    make(map[string]*proxyResponseCacheEntry),
		lru:        list.New(),
		memEntries: make(map[string]*proxyResponseCacheMemoryEntry),
		memLRU:     list.New(),
	}
	if err := s.Reconfigure(cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *proxyResponseCacheStore) Reconfigure(cfg responseCacheConfig) error {
	cfg = normalizeResponseCacheConfig(cfg)
	if err := validateResponseCacheConfig(cfg); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !cfg.Enabled {
		s.enabled = false
		s.dir = cfg.StoreDir
		s.maxBytes = cfg.MaxBytes
		s.entries = make(map[string]*proxyResponseCacheEntry)
		s.currentBytes = 0
		s.lru = list.New()
		s.resetMemoryLocked(cfg)
		return nil
	}
	entries, currentBytes, lru, err := loadProxyResponseCacheEntries(cfg)
	if err != nil {
		return err
	}
	s.enabled = cfg.Enabled
	s.dir = cfg.StoreDir
	s.maxBytes = cfg.MaxBytes
	s.entries = entries
	s.currentBytes = currentBytes
	s.lru = lru
	s.resetMemoryLocked(cfg)
	s.enforceLimitLocked(0)
	return nil
}

func (s *proxyResponseCacheStore) Snapshot() proxyResponseCacheStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	return proxyResponseCacheStats{
		Enabled:          s.enabled,
		StoreDir:         s.dir,
		MaxBytes:         s.maxBytes,
		SizeBytes:        s.currentBytes,
		EntryCount:       len(s.entries),
		Hits:             s.hits,
		Misses:           s.misses,
		Stores:           s.stores,
		Evictions:        s.evictions,
		Clears:           s.clears,
		MemoryEnabled:    s.memEnabled,
		MemoryMaxBytes:   s.memMaxBytes,
		MemoryMaxEntries: s.memMaxEntries,
		MemorySizeBytes:  s.memCurrentBytes,
		MemoryEntryCount: len(s.memEntries),
		MemoryHits:       s.memHits,
		MemoryMisses:     s.memMisses,
		MemoryStores:     s.memStores,
		MemoryEvictions:  s.memEvictions,
	}
}

func (s *proxyResponseCacheStore) Load(key string) (proxyResponseCacheLoadResult, bool) {
	now := time.Now().UTC()
	s.mu.Lock()
	if !s.enabled {
		s.mu.Unlock()
		return proxyResponseCacheLoadResult{}, false
	}
	entry, ok := s.entries[key]
	if !ok {
		s.misses++
		if s.memEnabled {
			s.memMisses++
		}
		s.mu.Unlock()
		return proxyResponseCacheLoadResult{}, false
	}
	if !entry.ExpiresAt.After(now) {
		s.removeEntryLocked(entry)
		s.misses++
		if s.memEnabled {
			s.memMisses++
		}
		s.mu.Unlock()
		return proxyResponseCacheLoadResult{}, false
	}
	if memEntry, ok := s.memEntries[key]; ok {
		entry.AccessedAt = now
		memEntry.AccessedAt = now
		if entry.element != nil {
			s.lru.MoveToBack(entry.element)
		}
		if memEntry.element != nil {
			s.memLRU.MoveToBack(memEntry.element)
		}
		s.hits++
		s.memHits++
		result := proxyResponseCacheLoadResult{
			Entry:     cloneProxyResponseCacheEntry(entry),
			Body:      append([]byte(nil), memEntry.Body...),
			MemoryHit: true,
		}
		s.mu.Unlock()
		return result, true
	}
	entryClone := cloneProxyResponseCacheEntry(entry)
	memEnabled := s.memEnabled
	s.mu.Unlock()

	body, err := os.ReadFile(entryClone.BodyPath)
	if err != nil {
		s.mu.Lock()
		if current, ok := s.entries[key]; ok && current.BodyPath == entryClone.BodyPath {
			s.removeEntryLocked(current)
		}
		s.misses++
		if memEnabled {
			s.memMisses++
		}
		s.mu.Unlock()
		return proxyResponseCacheLoadResult{}, false
	}

	s.mu.Lock()
	current, ok := s.entries[key]
	if !ok || current.BodyPath != entryClone.BodyPath || !current.ExpiresAt.After(time.Now().UTC()) {
		if ok && !current.ExpiresAt.After(time.Now().UTC()) {
			s.removeEntryLocked(current)
		}
		s.misses++
		if memEnabled {
			s.memMisses++
		}
		s.mu.Unlock()
		return proxyResponseCacheLoadResult{}, false
	}
	now = time.Now().UTC()
	current.AccessedAt = now
	if current.element != nil {
		s.lru.MoveToBack(current.element)
	}
	s.hits++
	if s.memEnabled {
		s.memMisses++
		s.storeMemoryLocked(key, body, now)
	}
	result := proxyResponseCacheLoadResult{
		Entry:     cloneProxyResponseCacheEntry(current),
		Body:      append([]byte(nil), body...),
		MemoryHit: false,
	}
	s.mu.Unlock()
	return result, true
}

func (s *proxyResponseCacheStore) NewTempBodyFile() (*os.File, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := os.MkdirAll(s.dir, 0o755); err != nil {
		return nil, "", err
	}
	f, err := os.CreateTemp(s.dir, ".tukuyomi-cache-body-*")
	if err != nil {
		return nil, "", err
	}
	return f, f.Name(), nil
}

func (s *proxyResponseCacheStore) DiscardTemp(path string) {
	if strings.TrimSpace(path) != "" {
		_ = os.Remove(path)
	}
}

func (s *proxyResponseCacheStore) Store(key string, ttl int, status int, header http.Header, bodyPath string, bodySize int64) error {
	if strings.TrimSpace(bodyPath) == "" || ttl <= 0 {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.enabled {
		_ = os.Remove(bodyPath)
		return nil
	}
	if s.maxBytes > 0 && bodySize > s.maxBytes {
		_ = os.Remove(bodyPath)
		return nil
	}
	now := time.Now().UTC()
	hash := proxyResponseCacheHash(key)
	finalBodyPath := filepath.Join(s.dir, hash+".body")
	finalMetaPath := filepath.Join(s.dir, hash+".json")
	if existing, ok := s.entries[key]; ok {
		s.removeEntryLocked(existing)
	}
	s.evictExpiredLocked(now)
	s.enforceLimitLocked(bodySize)
	meta := proxyResponseCacheMeta{
		Key:        key,
		Status:     status,
		Header:     cloneProxyHeader(header),
		Size:       bodySize,
		ExpiresAt:  now.Add(time.Duration(ttl) * time.Second),
		CreatedAt:  now,
		AccessedAt: now,
	}
	if err := moveProxyResponseCacheFile(bodyPath, finalBodyPath); err != nil {
		_ = os.Remove(bodyPath)
		return err
	}
	if err := writeProxyResponseCacheMeta(finalMetaPath, meta); err != nil {
		_ = os.Remove(finalBodyPath)
		return err
	}
	entry := &proxyResponseCacheEntry{
		Key:        meta.Key,
		Status:     meta.Status,
		Header:     cloneProxyHeader(meta.Header),
		Size:       meta.Size,
		ExpiresAt:  meta.ExpiresAt,
		CreatedAt:  meta.CreatedAt,
		AccessedAt: meta.AccessedAt,
		BodyPath:   finalBodyPath,
	}
	entry.element = s.lru.PushBack(entry.Key)
	s.entries[key] = entry
	s.currentBytes += entry.Size
	s.stores++
	if s.memEnabled {
		if body, err := os.ReadFile(finalBodyPath); err == nil {
			s.storeMemoryLocked(key, body, now)
		}
	}
	return nil
}

func (s *proxyResponseCacheStore) Clear() (proxyResponseCacheClearResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	result := proxyResponseCacheClearResult{ClearedEntries: len(s.entries), ClearedBytes: s.currentBytes}
	for _, entry := range s.entries {
		_ = os.Remove(entry.BodyPath)
		_ = os.Remove(proxyResponseCacheMetaPath(entry.BodyPath))
	}
	s.entries = make(map[string]*proxyResponseCacheEntry)
	s.lru.Init()
	s.currentBytes = 0
	s.clearMemoryLocked()
	s.clears++
	if s.enabled {
		if err := os.MkdirAll(s.dir, 0o755); err != nil {
			return result, err
		}
	}
	return result, nil
}

func (s *proxyResponseCacheStore) removeByKey(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if entry, ok := s.entries[key]; ok {
		s.removeEntryLocked(entry)
	}
}

func loadProxyResponseCacheEntries(cfg responseCacheConfig) (map[string]*proxyResponseCacheEntry, int64, *list.List, error) {
	entries := make(map[string]*proxyResponseCacheEntry)
	lru := list.New()
	if err := os.MkdirAll(cfg.StoreDir, 0o755); err != nil {
		return nil, 0, nil, err
	}
	matches, err := filepath.Glob(filepath.Join(cfg.StoreDir, "*.json"))
	if err != nil {
		return nil, 0, nil, err
	}
	now := time.Now().UTC()
	loaded := make([]*proxyResponseCacheEntry, 0, len(matches))
	var currentBytes int64
	for _, metaPath := range matches {
		meta, err := readProxyResponseCacheMeta(metaPath)
		if err != nil {
			_ = os.Remove(metaPath)
			continue
		}
		if !meta.ExpiresAt.After(now) {
			_ = os.Remove(metaPath)
			_ = os.Remove(strings.TrimSuffix(metaPath, ".json") + ".body")
			continue
		}
		bodyPath := strings.TrimSuffix(metaPath, ".json") + ".body"
		if _, err := os.Stat(bodyPath); err != nil {
			_ = os.Remove(metaPath)
			continue
		}
		entry := &proxyResponseCacheEntry{
			Key:        meta.Key,
			Status:     meta.Status,
			Header:     cloneProxyHeader(meta.Header),
			Size:       meta.Size,
			ExpiresAt:  meta.ExpiresAt,
			CreatedAt:  meta.CreatedAt,
			AccessedAt: meta.AccessedAt,
			BodyPath:   bodyPath,
		}
		loaded = append(loaded, entry)
	}
	sort.Slice(loaded, func(i, j int) bool { return loaded[i].AccessedAt.Before(loaded[j].AccessedAt) })
	for _, entry := range loaded {
		entry.element = lru.PushBack(entry.Key)
		entries[entry.Key] = entry
		currentBytes += entry.Size
	}
	return entries, currentBytes, lru, nil
}

func readProxyResponseCacheMeta(path string) (proxyResponseCacheMeta, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return proxyResponseCacheMeta{}, err
	}
	var meta proxyResponseCacheMeta
	if err := json.Unmarshal(raw, &meta); err != nil {
		return proxyResponseCacheMeta{}, err
	}
	return meta, nil
}

func writeProxyResponseCacheMeta(path string, meta proxyResponseCacheMeta) error {
	raw, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tukuyomi-cache-meta-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(raw); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
		return err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return os.Rename(tmpPath, path)
}

func proxyResponseCacheMetaPath(bodyPath string) string {
	return strings.TrimSuffix(bodyPath, ".body") + ".json"
}

func proxyResponseCacheHash(key string) string {
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:])
}

func (s *proxyResponseCacheStore) removeEntryLocked(entry *proxyResponseCacheEntry) {
	if entry == nil {
		return
	}
	delete(s.entries, entry.Key)
	if entry.element != nil {
		s.lru.Remove(entry.element)
	}
	s.currentBytes -= entry.Size
	if s.currentBytes < 0 {
		s.currentBytes = 0
	}
	s.removeMemoryByKeyLocked(entry.Key)
	_ = os.Remove(entry.BodyPath)
	_ = os.Remove(proxyResponseCacheMetaPath(entry.BodyPath))
}

func (s *proxyResponseCacheStore) evictExpiredLocked(now time.Time) {
	for _, entry := range s.entries {
		if !entry.ExpiresAt.After(now) {
			s.removeEntryLocked(entry)
			s.evictions++
		}
	}
}

func (s *proxyResponseCacheStore) enforceLimitLocked(additional int64) {
	if s.maxBytes <= 0 {
		return
	}
	for s.currentBytes+additional > s.maxBytes && s.lru.Len() > 0 {
		front := s.lru.Front()
		if front == nil {
			break
		}
		key, _ := front.Value.(string)
		entry := s.entries[key]
		if entry == nil {
			s.lru.Remove(front)
			continue
		}
		s.removeEntryLocked(entry)
		s.evictions++
	}
}

func cloneProxyResponseCacheEntry(entry *proxyResponseCacheEntry) proxyResponseCacheEntry {
	if entry == nil {
		return proxyResponseCacheEntry{}
	}
	return proxyResponseCacheEntry{
		Key:        entry.Key,
		Status:     entry.Status,
		Header:     cloneProxyHeader(entry.Header),
		Size:       entry.Size,
		ExpiresAt:  entry.ExpiresAt,
		CreatedAt:  entry.CreatedAt,
		AccessedAt: entry.AccessedAt,
		BodyPath:   entry.BodyPath,
	}
}

func cloneProxyHeader(in http.Header) http.Header {
	out := make(http.Header, len(in))
	for k, vals := range in {
		out[k] = append([]string(nil), vals...)
	}
	return out
}

func (s *proxyResponseCacheStore) resetMemoryLocked(cfg responseCacheConfig) {
	s.memEnabled = cfg.MemoryEnabled
	s.memMaxBytes = cfg.MemoryMaxBytes
	s.memMaxEntries = cfg.MemoryMaxEntries
	s.memCurrentBytes = 0
	s.memEntries = make(map[string]*proxyResponseCacheMemoryEntry)
	s.memLRU = list.New()
}

func (s *proxyResponseCacheStore) clearMemoryLocked() {
	s.memEntries = make(map[string]*proxyResponseCacheMemoryEntry)
	s.memLRU.Init()
	s.memCurrentBytes = 0
}

func (s *proxyResponseCacheStore) removeMemoryByKeyLocked(key string) {
	memEntry, ok := s.memEntries[key]
	if !ok {
		return
	}
	delete(s.memEntries, key)
	if memEntry.element != nil {
		s.memLRU.Remove(memEntry.element)
	}
	s.memCurrentBytes -= memEntry.Size
	if s.memCurrentBytes < 0 {
		s.memCurrentBytes = 0
	}
}

func (s *proxyResponseCacheStore) enforceMemoryLimitLocked(additional int64) {
	if !s.memEnabled || s.memMaxBytes <= 0 || s.memMaxEntries <= 0 {
		return
	}
	for (s.memCurrentBytes+additional > s.memMaxBytes || len(s.memEntries) >= s.memMaxEntries) && s.memLRU.Len() > 0 {
		front := s.memLRU.Front()
		if front == nil {
			break
		}
		key, _ := front.Value.(string)
		memEntry := s.memEntries[key]
		if memEntry == nil {
			s.memLRU.Remove(front)
			continue
		}
		s.removeMemoryByKeyLocked(key)
		s.memEvictions++
	}
}

func (s *proxyResponseCacheStore) storeMemoryLocked(key string, body []byte, accessedAt time.Time) {
	if !s.memEnabled || s.memMaxBytes <= 0 || s.memMaxEntries <= 0 {
		return
	}
	size := int64(len(body))
	if size > s.memMaxBytes {
		s.removeMemoryByKeyLocked(key)
		return
	}
	if existing, ok := s.memEntries[key]; ok {
		s.removeMemoryByKeyLocked(existing.Key)
	}
	s.enforceMemoryLimitLocked(size)
	entry := &proxyResponseCacheMemoryEntry{
		Key:        key,
		Body:       append([]byte(nil), body...),
		Size:       size,
		AccessedAt: accessedAt,
	}
	entry.element = s.memLRU.PushBack(entry.Key)
	s.memEntries[key] = entry
	s.memCurrentBytes += size
	s.memStores++
}

func shouldBypassProxyResponseCache(r *http.Request) bool {
	if r == nil {
		return true
	}
	if proxyUpgradeType(r.Header) != "" || strings.TrimSpace(r.Header.Get("Upgrade")) != "" {
		return true
	}
	switch r.Method {
	case http.MethodGet, http.MethodHead:
	default:
		return true
	}
	if strings.TrimSpace(r.Header.Get("Authorization")) != "" {
		return true
	}
	if strings.TrimSpace(r.Header.Get("Cookie")) != "" {
		return true
	}
	cacheControl := strings.ToLower(strings.Join(r.Header.Values("Cache-Control"), ","))
	if strings.Contains(cacheControl, "no-cache") || strings.Contains(cacheControl, "no-store") {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(r.Header.Get("Pragma")), "no-cache")
}

func shouldStoreProxyResponse(status int, header http.Header) bool {
	switch status {
	case http.StatusOK, http.StatusNonAuthoritativeInfo, http.StatusNoContent, http.StatusPartialContent, http.StatusMovedPermanently, http.StatusFound, http.StatusNotFound, http.StatusGone:
	default:
		return false
	}
	if len(header.Values("Set-Cookie")) > 0 {
		return false
	}
	cacheControl := strings.ToLower(strings.Join(header.Values("Cache-Control"), ","))
	if strings.Contains(cacheControl, "no-store") || strings.Contains(cacheControl, "private") {
		return false
	}
	return strings.TrimSpace(header.Get("Vary")) != "*"
}

func proxyResponseCacheKey(r *http.Request, vary []string) string {
	method := r.Method
	if method == http.MethodHead {
		method = http.MethodGet
	}
	var b strings.Builder
	b.WriteString(method)
	b.WriteByte('\n')
	b.WriteString(strings.ToLower(strings.TrimSpace(r.Host)))
	b.WriteByte('\n')
	if r.URL != nil {
		b.WriteString(r.URL.RequestURI())
	}
	for _, headerName := range vary {
		name := http.CanonicalHeaderKey(strings.TrimSpace(headerName))
		b.WriteByte('\n')
		b.WriteString(name)
		b.WriteByte(':')
		b.WriteString(strings.Join(r.Header.Values(name), ","))
	}
	return b.String()
}

func writeProxyCachedResponse(w http.ResponseWriter, r *http.Request, entry proxyResponseCacheEntry, bodyBytes []byte) error {
	dst := w.Header()
	reqID := dst.Get(proxyResponseCacheRequestID)
	for k := range dst {
		dst.Del(k)
	}
	for k, vals := range sanitizeProxyCachedResponseHeader(entry.Header, r, proxyResponseHeaderPolicySurfaceCacheReplay) {
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
	if reqID != "" {
		dst.Set(proxyResponseCacheRequestID, reqID)
	}
	if hit, rid := proxyContextWAFDebug(r.Context()); hit && currentProxyConfig().ExposeWAFDebugHeaders {
		dst.Set("X-WAF-Hit", "1")
		if rid != "" {
			dst.Set("X-WAF-RuleIDs", rid)
		}
	}
	dst.Set(proxyResponseCacheHeader, "HIT")
	w.WriteHeader(entry.Status)
	if r.Method == http.MethodHead || entry.Status == http.StatusNoContent {
		return nil
	}
	if bodyBytes != nil {
		_, err := copyProxyResponseBody(w, bytes.NewReader(bodyBytes))
		return err
	}
	body, err := os.Open(entry.BodyPath)
	if err != nil {
		return err
	}
	defer body.Close()
	_, err = copyProxyResponseBody(w, body)
	return err
}

func copyProxyResponseBody(dst io.Writer, src io.Reader) (int64, error) {
	buf := make([]byte, 32*1024)
	var written int64
	for {
		nr, readErr := src.Read(buf)
		if nr > 0 {
			nw, writeErr := dst.Write(buf[:nr])
			written += int64(nw)
			if writeErr != nil {
				return written, writeErr
			}
			if nw != nr {
				return written, io.ErrShortWrite
			}
		}
		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				return written, nil
			}
			return written, readErr
		}
	}
}

func moveProxyResponseCacheFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		_ = out.Close()
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Remove(src)
}

func (w *proxyHTTPCacheCaptureWriter) WriteHeader(status int) {
	if w == nil {
		return
	}
	if w.status != 0 {
		return
	}
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *proxyHTTPCacheCaptureWriter) Write(data []byte) (int, error) {
	if w == nil {
		return 0, http.ErrHandlerTimeout
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.tmpFile != nil {
		if _, err := w.tmpFile.Write(data); err != nil && w.tmpErr == nil {
			w.tmpErr = err
		}
	}
	n, err := w.ResponseWriter.Write(data)
	w.size += int64(n)
	w.bodySize += int64(n)
	return n, err
}

func (w *proxyHTTPCacheCaptureWriter) WriteString(s string) (int, error) {
	if w == nil {
		return 0, http.ErrHandlerTimeout
	}
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	if w.tmpFile != nil {
		if _, err := w.tmpFile.WriteString(s); err != nil && w.tmpErr == nil {
			w.tmpErr = err
		}
	}
	n, err := io.WriteString(w.ResponseWriter, s)
	w.size += int64(n)
	w.bodySize += int64(n)
	return n, err
}

func (w *proxyHTTPCacheCaptureWriter) ReadFrom(r io.Reader) (int64, error) {
	if w == nil || r == nil {
		return 0, nil
	}
	if rf, ok := w.ResponseWriter.(io.ReaderFrom); ok {
		if w.status == 0 {
			w.WriteHeader(http.StatusOK)
		}
		src := r
		if w.tmpFile != nil {
			src = io.TeeReader(r, w.tmpFile)
		}
		n, err := rf.ReadFrom(src)
		w.size += n
		w.bodySize += n
		return n, err
	}
	return copyProxyResponseBody(w, r)
}

func (w *proxyHTTPCacheCaptureWriter) Status() int {
	if w == nil {
		return 0
	}
	if w.status != 0 {
		return w.status
	}
	if statusWriter, ok := w.ResponseWriter.(interface{ Status() int }); ok {
		return statusWriter.Status()
	}
	return 0
}

func (w *proxyHTTPCacheCaptureWriter) Size() int {
	if w == nil {
		return 0
	}
	if w.size > 0 {
		if w.size > int64(^uint(0)>>1) {
			return int(^uint(0) >> 1)
		}
		return int(w.size)
	}
	if sizeWriter, ok := w.ResponseWriter.(interface{ Size() int }); ok {
		return sizeWriter.Size()
	}
	return 0
}

func (w *proxyHTTPCacheCaptureWriter) Flush() {
	if flusher, ok := w.ResponseWriter.(http.Flusher); ok {
		flusher.Flush()
	}
}

func (w *proxyHTTPCacheCaptureWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := w.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, errors.New("hijacker not supported")
	}
	return hijacker.Hijack()
}

func (w *proxyHTTPCacheCaptureWriter) Push(target string, opts *http.PushOptions) error {
	pusher, ok := w.ResponseWriter.(http.Pusher)
	if !ok {
		return http.ErrNotSupported
	}
	return pusher.Push(target, opts)
}

func (w *proxyHTTPCacheCaptureWriter) closeTemp() error {
	if w.tmpFile == nil {
		return nil
	}
	err := w.tmpFile.Close()
	w.tmpFile = nil
	return err
}
