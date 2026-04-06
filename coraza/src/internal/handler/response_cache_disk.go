package handler

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type responseCacheDiskRecord struct {
	Key        string      `json:"key"`
	StatusCode int         `json:"status_code"`
	Header     http.Header `json:"header"`
	Body       []byte      `json:"body"`
	StoredAt   time.Time   `json:"stored_at"`
	ExpiresAt  time.Time   `json:"expires_at"`
	StaleUntil time.Time   `json:"stale_until"`
	RefreshAt  time.Time   `json:"refresh_at"`
}

func (c *responseCacheRuntime) diskEnabled() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.mode == responseCacheModeDisk && c.storePath != ""
}

func (c *responseCacheRuntime) diskPath(key string) string {
	c.mu.Lock()
	dir := c.storePath
	c.mu.Unlock()
	return responseCacheDiskPath(dir, key)
}

func responseCacheDiskPath(dir, key string) string {
	sum := sha256.Sum256([]byte(key))
	return filepath.Join(dir, hex.EncodeToString(sum[:])+".json")
}

func (c *responseCacheRuntime) persistDiskEntry(entry *responseCacheEntry) error {
	if entry == nil || entry.diskPath == "" {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(entry.diskPath), 0o755); err != nil {
		return err
	}

	record := responseCacheDiskRecord{
		Key:        entry.key,
		StatusCode: entry.statusCode,
		Header:     entry.header,
		Body:       entry.body,
		StoredAt:   entry.storedAt,
		ExpiresAt:  entry.expiresAt,
		StaleUntil: entry.staleUntil,
		RefreshAt:  entry.refreshAt,
	}

	payload, err := json.Marshal(record)
	if err != nil {
		return err
	}

	tmpPath := entry.diskPath + ".tmp"
	if err := os.WriteFile(tmpPath, payload, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmpPath, entry.diskPath); err != nil {
		_ = os.Remove(tmpPath)
		return err
	}
	return nil
}

func (c *responseCacheRuntime) deleteDiskEntry(entry *responseCacheEntry) {
	if entry == nil || entry.diskPath == "" {
		return
	}
	if err := os.Remove(entry.diskPath); err == nil {
		c.diskBytes.Add(-entry.bodyBytes)
	}
}

func (c *responseCacheRuntime) clearDiskEntries(storePath string) {
	storePath = strings.TrimSpace(storePath)
	if storePath == "" {
		return
	}
	if err := os.RemoveAll(storePath); err != nil {
		log.Printf("[CACHE][WARN] disk cache clear failed: %v", err)
		return
	}
	if err := os.MkdirAll(storePath, 0o755); err != nil {
		log.Printf("[CACHE][WARN] disk cache re-init failed: %v", err)
	}
}

func (c *responseCacheRuntime) restoreDiskEntries() {
	c.mu.Lock()
	storePath := c.storePath
	maxEntries := c.maxEntries
	c.mu.Unlock()

	storePath = strings.TrimSpace(storePath)
	if storePath == "" {
		return
	}
	if err := os.MkdirAll(storePath, 0o755); err != nil {
		log.Printf("[CACHE][WARN] disk cache init failed: %v", err)
		return
	}

	dirEntries, err := os.ReadDir(storePath)
	if err != nil {
		log.Printf("[CACHE][WARN] disk cache load failed: %v", err)
		return
	}

	now := time.Now().UTC()
	var restored []*responseCacheEntry

	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() || filepath.Ext(dirEntry.Name()) != ".json" {
			continue
		}

		path := filepath.Join(storePath, dirEntry.Name())
		payload, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[CACHE][WARN] disk cache read failed for %s: %v", path, err)
			continue
		}

		var record responseCacheDiskRecord
		if err := json.Unmarshal(payload, &record); err != nil {
			log.Printf("[CACHE][WARN] disk cache decode failed for %s: %v", path, err)
			continue
		}

		entry := &responseCacheEntry{
			key:        record.Key,
			statusCode: record.StatusCode,
			header:     record.Header.Clone(),
			body:       nil,
			bodyBytes:  int64(len(record.Body)),
			storedAt:   record.StoredAt,
			expiresAt:  record.ExpiresAt,
			staleUntil: record.StaleUntil,
			refreshAt:  record.RefreshAt,
			diskPath:   path,
		}

		if entry.key == "" || !entry.staleUntil.After(now) {
			_ = os.Remove(path)
			continue
		}
		restored = append(restored, entry)
	}

	sort.Slice(restored, func(i, j int) bool {
		return restored[i].storedAt.After(restored[j].storedAt)
	})

	c.mu.Lock()
	defer c.mu.Unlock()

	c.entries = map[string]*list.Element{}
	c.lru.Init()
	c.diskBytes.Store(0)
	for _, entry := range restored {
		elem := c.lru.PushBack(entry)
		c.entries[entry.key] = elem
		c.diskBytes.Add(entry.bodyBytes)
	}
	for len(c.entries) > maxEntries {
		c.removeLocked(c.lru.Back())
	}
}

func (c *responseCacheRuntime) hydrateEntry(entry *responseCacheEntry) (*responseCacheEntry, bool) {
	if entry == nil {
		return nil, false
	}
	if entry.diskPath == "" || entry.body != nil {
		return entry, true
	}

	payload, err := os.ReadFile(entry.diskPath)
	if err != nil {
		log.Printf("[CACHE][WARN] disk cache hydrate read failed for %s: %v", entry.diskPath, err)
		return nil, false
	}

	var record responseCacheDiskRecord
	if err := json.Unmarshal(payload, &record); err != nil {
		log.Printf("[CACHE][WARN] disk cache hydrate decode failed for %s: %v", entry.diskPath, err)
		return nil, false
	}

	hydrated := cloneResponseCacheEntry(entry)
	hydrated.body = append([]byte(nil), record.Body...)
	hydrated.bodyBytes = int64(len(record.Body))
	if hydrated.header == nil || len(hydrated.header) == 0 {
		hydrated.header = record.Header.Clone()
	}
	return hydrated, true
}

func (c *responseCacheRuntime) evictKey(key string) {
	if strings.TrimSpace(key) == "" {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	elem, ok := c.entries[key]
	if !ok {
		return
	}
	c.removeLocked(elem)
}
