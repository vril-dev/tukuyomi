package handler

import (
	"bytes"
	"container/list"
	"context"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
)

const (
	responseCacheModeOff    = "off"
	responseCacheModeMemory = "memory"

	responseCacheStatusHeader = "X-Tukuyomi-Cache-Status"
	responseCacheStatusBypass = "BYPASS"
	responseCacheStatusMiss   = "MISS"
	responseCacheStatusHit    = "HIT"
)

const ctxKeyCachePlan ctxKey = "response_cache_plan"

type responseCachePlan struct {
	Key        string
	TTL        time.Duration
	Vary       []string
	StoreBody  bool
	RequestURI string
}

type responseCacheEntry struct {
	key        string
	statusCode int
	header     http.Header
	body       []byte
	storedAt   time.Time
	expiresAt  time.Time
}

type responseCacheRuntime struct {
	mu           sync.Mutex
	mode         string
	maxEntries   int
	maxBodyBytes int64
	entries      map[string]*list.Element
	lru          list.List

	hits      atomic.Uint64
	misses    atomic.Uint64
	stores    atomic.Uint64
	bypasses  atomic.Uint64
	evictions atomic.Uint64
}

type responseCacheStatus struct {
	Mode         string `json:"mode"`
	Enabled      bool   `json:"enabled"`
	MaxEntries   int    `json:"max_entries"`
	MaxBodyBytes int64  `json:"max_body_bytes"`
	EntryCount   int    `json:"entry_count"`
	Hits         uint64 `json:"hits"`
	Misses       uint64 `json:"misses"`
	Stores       uint64 `json:"stores"`
	Bypasses     uint64 `json:"bypasses"`
	Evictions    uint64 `json:"evictions"`
}

var localResponseCache = newResponseCacheRuntime()

func newResponseCacheRuntime() *responseCacheRuntime {
	return &responseCacheRuntime{
		mode:    responseCacheModeOff,
		entries: map[string]*list.Element{},
	}
}

func ConfigureResponseCache() {
	localResponseCache.configure(
		config.ResponseCacheMode,
		config.ResponseCacheMaxEntries,
		config.ResponseCacheMaxBodyBytes,
	)
}

func InvalidateResponseCache() {
	localResponseCache.invalidate()
}

func GetResponseCacheStatus() responseCacheStatus {
	return localResponseCache.status()
}

func (c *responseCacheRuntime) configure(mode string, maxEntries int, maxBodyBytes int64) {
	normalizedMode := strings.ToLower(strings.TrimSpace(mode))
	switch normalizedMode {
	case "", responseCacheModeOff:
		normalizedMode = responseCacheModeOff
	case responseCacheModeMemory:
		normalizedMode = responseCacheModeMemory
	default:
		log.Printf("[CACHE][WARN] unsupported response cache mode %q, fallback=off", normalizedMode)
		normalizedMode = responseCacheModeOff
	}

	if maxEntries < 0 {
		maxEntries = 0
	}
	if maxBodyBytes < 0 {
		maxBodyBytes = 0
	}

	c.mu.Lock()
	c.mode = normalizedMode
	c.maxEntries = maxEntries
	c.maxBodyBytes = maxBodyBytes
	c.entries = map[string]*list.Element{}
	c.lru.Init()
	c.mu.Unlock()

	c.hits.Store(0)
	c.misses.Store(0)
	c.stores.Store(0)
	c.bypasses.Store(0)
	c.evictions.Store(0)
}

func (c *responseCacheRuntime) invalidate() {
	c.mu.Lock()
	c.entries = map[string]*list.Element{}
	c.lru.Init()
	c.mu.Unlock()
}

func (c *responseCacheRuntime) status() responseCacheStatus {
	c.mu.Lock()
	entryCount := len(c.entries)
	mode := c.mode
	maxEntries := c.maxEntries
	maxBodyBytes := c.maxBodyBytes
	c.mu.Unlock()

	return responseCacheStatus{
		Mode:         mode,
		Enabled:      mode == responseCacheModeMemory && maxEntries > 0 && maxBodyBytes > 0,
		MaxEntries:   maxEntries,
		MaxBodyBytes: maxBodyBytes,
		EntryCount:   entryCount,
		Hits:         c.hits.Load(),
		Misses:       c.misses.Load(),
		Stores:       c.stores.Load(),
		Bypasses:     c.bypasses.Load(),
		Evictions:    c.evictions.Load(),
	}
}

func (c *responseCacheRuntime) enabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode == responseCacheModeMemory && c.maxEntries > 0 && c.maxBodyBytes > 0
}

func (c *responseCacheRuntime) maxBodyBytesLimit() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.maxBodyBytes
}

func (c *responseCacheRuntime) lookup(plan *responseCachePlan) (*responseCacheEntry, bool) {
	if plan == nil {
		return nil, false
	}

	now := time.Now().UTC()
	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[plan.Key]
	if !ok {
		c.misses.Add(1)
		return nil, false
	}

	entry := elem.Value.(*responseCacheEntry)
	if !entry.expiresAt.After(now) {
		c.removeLocked(elem)
		c.misses.Add(1)
		return nil, false
	}

	c.lru.MoveToFront(elem)
	c.hits.Add(1)
	return cloneResponseCacheEntry(entry), true
}

func (c *responseCacheRuntime) store(plan *responseCachePlan, res *http.Response, body []byte, ttl time.Duration) bool {
	if plan == nil || res == nil || ttl <= 0 {
		return false
	}

	now := time.Now().UTC()
	entry := &responseCacheEntry{
		key:        plan.Key,
		statusCode: res.StatusCode,
		header:     cloneCacheableResponseHeaders(res.Header),
		body:       append([]byte(nil), body...),
		storedAt:   now,
		expiresAt:  now.Add(ttl),
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	c.cleanupExpiredLocked(now)
	if elem, ok := c.entries[plan.Key]; ok {
		elem.Value = entry
		c.lru.MoveToFront(elem)
	} else {
		elem := c.lru.PushFront(entry)
		c.entries[plan.Key] = elem
	}
	for len(c.entries) > c.maxEntries {
		c.removeLocked(c.lru.Back())
	}

	c.stores.Add(1)
	return true
}

func (c *responseCacheRuntime) removeLocked(elem *list.Element) {
	if elem == nil {
		return
	}
	entry, _ := elem.Value.(*responseCacheEntry)
	if entry != nil {
		delete(c.entries, entry.key)
	}
	c.lru.Remove(elem)
	c.evictions.Add(1)
}

func (c *responseCacheRuntime) cleanupExpiredLocked(now time.Time) {
	for elem := c.lru.Back(); elem != nil; {
		prev := elem.Prev()
		entry, _ := elem.Value.(*responseCacheEntry)
		if entry == nil || !entry.expiresAt.After(now) {
			c.removeLocked(elem)
		}
		elem = prev
	}
}

func (c *responseCacheRuntime) recordBypass() {
	c.bypasses.Add(1)
}

func buildResponseCachePlan(req *http.Request) *responseCachePlan {
	if !localResponseCache.enabled() {
		return nil
	}
	if req == nil || req.URL == nil {
		localResponseCache.recordBypass()
		return nil
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		localResponseCache.recordBypass()
		return nil
	}
	if strings.HasPrefix(req.URL.Path, config.APIBasePath) {
		localResponseCache.recordBypass()
		return nil
	}
	if strings.TrimSpace(req.Header.Get("Authorization")) != "" {
		localResponseCache.recordBypass()
		return nil
	}
	if strings.TrimSpace(req.Header.Get("Cookie")) != "" {
		localResponseCache.recordBypass()
		return nil
	}
	if strings.TrimSpace(req.Header.Get("Range")) != "" {
		localResponseCache.recordBypass()
		return nil
	}
	if strings.TrimSpace(req.Header.Get("Upgrade")) != "" {
		localResponseCache.recordBypass()
		return nil
	}

	rs := cacheconf.Get()
	if rs == nil {
		localResponseCache.recordBypass()
		return nil
	}

	rule, allow := rs.Match(req.Method, req.URL.Path)
	if !allow || rule == nil {
		localResponseCache.recordBypass()
		return nil
	}

	ttl := rule.TTL
	if ttl <= 0 {
		ttl = 600
	}

	return &responseCachePlan{
		Key:        responseCacheKey(req, rule.Vary),
		TTL:        time.Duration(ttl) * time.Second,
		Vary:       append([]string(nil), rule.Vary...),
		StoreBody:  req.Method == http.MethodGet,
		RequestURI: req.URL.RequestURI(),
	}
}

func responseCacheKey(req *http.Request, vary []string) string {
	host := strings.ToLower(strings.TrimSpace(req.Host))
	if host == "" {
		host = strings.ToLower(strings.TrimSpace(req.URL.Host))
	}

	var b strings.Builder
	b.WriteString("GET\n")
	b.WriteString(host)
	b.WriteByte('\n')
	b.WriteString(req.URL.RequestURI())
	for _, name := range vary {
		canonical := http.CanonicalHeaderKey(strings.TrimSpace(name))
		if canonical == "" {
			continue
		}
		b.WriteByte('\n')
		b.WriteString(canonical)
		b.WriteByte('=')
		b.WriteString(strings.TrimSpace(req.Header.Get(canonical)))
	}

	return b.String()
}

func setResponseCacheContext(c *gin.Context, plan *responseCachePlan) {
	if c == nil || plan == nil {
		return
	}
	ctx := context.WithValue(c.Request.Context(), ctxKeyCachePlan, plan)
	c.Request = c.Request.WithContext(ctx)
}

func responseCachePlanFromContext(ctx context.Context) *responseCachePlan {
	if ctx == nil {
		return nil
	}
	plan, _ := ctx.Value(ctxKeyCachePlan).(*responseCachePlan)
	return plan
}

func applyResponseCache(res *http.Response) {
	if !localResponseCache.enabled() || res == nil || res.Request == nil || res.Header == nil {
		return
	}

	plan := responseCachePlanFromContext(res.Request.Context())
	if plan == nil {
		res.Header.Set(responseCacheStatusHeader, responseCacheStatusBypass)
		return
	}

	status := responseCacheStatusMiss
	ttl, ok := responseCacheTTLForStatus(plan, res.StatusCode)
	if !ok || hasSetCookie(res.Header) {
		localResponseCache.recordBypass()
		res.Header.Set(responseCacheStatusHeader, responseCacheStatusBypass)
		return
	}

	bodyBytes, storeOK, err := cacheResponseBody(res, localResponseCache.maxBodyBytesLimit())
	if err != nil {
		localResponseCache.recordBypass()
		log.Printf("[CACHE][WARN] response cache body read failed: %v", err)
		res.Header.Set(responseCacheStatusHeader, responseCacheStatusBypass)
		return
	}
	if !storeOK {
		localResponseCache.recordBypass()
		res.Header.Set(responseCacheStatusHeader, responseCacheStatusBypass)
		return
	}
	if !plan.StoreBody {
		res.Header.Set(responseCacheStatusHeader, status)
		return
	}

	localResponseCache.store(plan, res, bodyBytes, ttl)
	res.Header.Set(responseCacheStatusHeader, status)
}

func cacheResponseBody(res *http.Response, maxBytes int64) ([]byte, bool, error) {
	if res == nil || res.Body == nil {
		return nil, false, nil
	}
	if maxBytes <= 0 {
		return nil, false, nil
	}

	limited := io.LimitReader(res.Body, maxBytes+1)
	bodyBytes, err := io.ReadAll(limited)
	if err != nil {
		return nil, false, err
	}
	if int64(len(bodyBytes)) > maxBytes {
		res.Body = io.NopCloser(io.MultiReader(bytes.NewReader(bodyBytes), res.Body))
		return nil, false, nil
	}

	res.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	return bodyBytes, true, nil
}

func responseCacheTTLForStatus(plan *responseCachePlan, status int) (time.Duration, bool) {
	if plan == nil {
		return 0, false
	}

	switch status {
	case http.StatusOK, http.StatusMovedPermanently, http.StatusFound:
		return plan.TTL, true
	case http.StatusNotFound:
		return time.Minute, true
	default:
		return 0, false
	}
}

func hasSetCookie(h http.Header) bool {
	if h == nil {
		return false
	}
	return len(h.Values("Set-Cookie")) > 0
}

func cloneCacheableResponseHeaders(src http.Header) http.Header {
	if src == nil {
		return http.Header{}
	}
	dst := src.Clone()
	dst.Del("Set-Cookie")
	dst.Del("X-WAF-Hit")
	dst.Del("X-WAF-RuleIDs")
	dst.Del("X-Request-ID")
	dst.Del("Age")
	return dst
}

func cloneResponseCacheEntry(src *responseCacheEntry) *responseCacheEntry {
	if src == nil {
		return nil
	}
	return &responseCacheEntry{
		key:        src.key,
		statusCode: src.statusCode,
		header:     src.header.Clone(),
		body:       append([]byte(nil), src.body...),
		storedAt:   src.storedAt,
		expiresAt:  src.expiresAt,
	}
}

func tryServeCachedResponse(c *gin.Context, plan *responseCachePlan, reqID, clientIP, country string, wafHit bool, ruleIDs string, startedAt time.Time) bool {
	if c == nil || plan == nil {
		return false
	}

	entry, ok := localResponseCache.lookup(plan)
	if !ok {
		return false
	}

	writeCachedResponse(c, entry, wafHit, ruleIDs)
	emitOperationalAccessLogs(operationalLogEntry{
		Timestamp:      time.Now().UTC(),
		RequestID:      reqID,
		IP:             clientIP,
		Country:        country,
		Method:         c.Request.Method,
		Path:           requestPath(c.Request),
		Query:          c.Request.URL.RawQuery,
		UserAgent:      c.Request.UserAgent(),
		Status:         entry.statusCode,
		UpstreamStatus: strconv.Itoa(entry.statusCode),
		Duration:       time.Since(startedAt),
		WAFHit:         wafHit,
		WAFRules:       ruleIDs,
		Event:          "cache_hit",
	})

	return true
}

func writeCachedResponse(c *gin.Context, entry *responseCacheEntry, wafHit bool, ruleIDs string) {
	if c == nil || entry == nil {
		return
	}

	header := c.Writer.Header()
	for k, values := range entry.header {
		header.Del(k)
		for _, value := range values {
			header.Add(k, value)
		}
	}
	header.Set(responseCacheStatusHeader, responseCacheStatusHit)
	ageSeconds := int(time.Since(entry.storedAt).Seconds())
	if ageSeconds < 0 {
		ageSeconds = 0
	}
	header.Set("Age", strconv.Itoa(ageSeconds))
	addCurrentWAFHitHeaders(header, c.Request, wafHit, ruleIDs)
	if wafHit {
		emitWAFHitAllowEvent(c.Request, entry.statusCode)
	}

	c.Status(entry.statusCode)
	if c.Request.Method != http.MethodHead {
		_, _ = c.Writer.Write(entry.body)
	}
}
