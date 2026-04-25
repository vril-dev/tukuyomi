package handler

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	defaultAdminAuditLimit = 20
	maxAdminAuditLimit     = 100
)

// Shared admin audit helpers are intended to be reused by additional
// configuration surfaces over time: bypass rules, country block, rate limit,
// bot defense, semantic rules, and cache rules.
type adminAuditInfo struct {
	TS      string `json:"ts"`
	Service string `json:"service"`
	Event   string `json:"event"`
	Actor   string `json:"actor"`
	IP      string `json:"ip,omitempty"`
}

func newAdminAuditInfo(c *gin.Context, event string) adminAuditInfo {
	info := adminAuditInfo{
		TS:      time.Now().UTC().Format(time.RFC3339Nano),
		Service: "coraza",
		Event:   strings.TrimSpace(event),
		Actor:   adminAuditActor(c),
	}
	if c != nil {
		info.IP = requestClientIP(c)
	}
	return info
}

func adminAuditActor(c *gin.Context) string {
	if c == nil {
		return "unknown"
	}
	if actor := strings.TrimSpace(c.GetHeader("X-Tukuyomi-Actor")); actor != "" {
		return actor
	}
	if actor := strings.TrimSpace(c.GetString("tukuyomi.admin_auth_fallback_actor")); actor != "" {
		return actor
	}
	return "unknown"
}

func appendAdminAudit(path string, writeErrorEvent string, entry any) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		emitAdminAuditWriteError(path, writeErrorEvent, err)
		return
	}

	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		emitAdminAuditWriteError(path, writeErrorEvent, err)
		return
	}
	defer f.Close()

	b, err := json.Marshal(entry)
	if err != nil {
		emitAdminAuditWriteError(path, writeErrorEvent, err)
		return
	}
	if _, err := f.Write(append(b, '\n')); err != nil {
		emitAdminAuditWriteError(path, writeErrorEvent, err)
	}
}

func readAdminAuditLatest[T any](path string, limit int, decodeLabel string) ([]T, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []T{}, nil
		}
		return nil, err
	}

	entries := make([]T, 0)
	for _, chunk := range bytesSplitKeep(raw, '\n') {
		line := strings.TrimSpace(string(trimLastNewline(chunk)))
		if line == "" {
			continue
		}
		var entry T
		if err := json.Unmarshal([]byte(line), &entry); err != nil {
			return nil, fmt.Errorf("decode %s audit entry: %w", decodeLabel, err)
		}
		entries = append(entries, entry)
	}

	limit = clampAdminAuditLimit(limit)
	if len(entries) == 0 {
		return []T{}, nil
	}

	start := 0
	if len(entries) > limit {
		start = len(entries) - limit
	}
	out := make([]T, 0, len(entries)-start)
	for i := len(entries) - 1; i >= start; i -= 1 {
		out = append(out, entries[i])
	}
	return out, nil
}

func parseAdminAuditLimit(raw string) int {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultAdminAuditLimit
	}
	limit, err := strconv.Atoi(raw)
	if err != nil {
		return defaultAdminAuditLimit
	}
	return clampAdminAuditLimit(limit)
}

func clampAdminAuditLimit(limit int) int {
	if limit < 1 {
		return 1
	}
	if limit > maxAdminAuditLimit {
		return maxAdminAuditLimit
	}
	return limit
}

func emitAdminAuditWriteError(path string, writeErrorEvent string, err error) {
	emitJSONLog(map[string]any{
		"ts":      time.Now().UTC().Format(time.RFC3339Nano),
		"service": "coraza",
		"level":   "WARN",
		"event":   writeErrorEvent,
		"path":    path,
		"error":   err.Error(),
	})
}
