package handler

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const slowRequestThreshold = time.Second

type operationalLogEntry struct {
	Timestamp      time.Time
	RequestID      string
	IP             string
	Country        string
	Method         string
	Path           string
	Query          string
	UserAgent      string
	Status         int
	UpstreamStatus string
	Duration       time.Duration
	WAFHit         bool
	WAFRules       string
	Event          string
	Error          string
}

func emitOperationalAccessLogs(entry operationalLogEntry) {
	line := operationalLogLine(entry)
	if shouldWriteInterestingLog(entry) {
		_ = emitLogOutputStream("intr", line)
	}
	if shouldWriteAccessErrorLog(entry) {
		_ = emitLogOutputStream("accerr", line)
	}
}

func operationalLogLine(entry operationalLogEntry) map[string]any {
	ts := entry.Timestamp.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	status := entry.Status
	if status <= 0 {
		status = http.StatusOK
	}
	line := map[string]any{
		"ts":              ts.Format(time.RFC3339Nano),
		"req_id":          strings.TrimSpace(entry.RequestID),
		"ip":              strings.TrimSpace(entry.IP),
		"country":         normalizeCountryCode(entry.Country),
		"method":          strings.TrimSpace(entry.Method),
		"path":            normalizeStatsPath(entry.Path),
		"qs":              strings.TrimSpace(entry.Query),
		"waf_hit":         boolToInt(entry.WAFHit),
		"waf_rules":       strings.TrimSpace(entry.WAFRules),
		"status":          status,
		"upstream_status": strings.TrimSpace(entry.UpstreamStatus),
		"rt":              durationSeconds(entry.Duration),
		"urt":             formatDurationSeconds(entry.Duration, entry.UpstreamStatus != ""),
		"ua":              strings.TrimSpace(entry.UserAgent),
		"event":           operationalEvent(entry),
	}
	if strings.TrimSpace(entry.Error) != "" {
		line["error"] = strings.TrimSpace(entry.Error)
	}
	return line
}

func operationalEvent(entry operationalLogEntry) string {
	event := strings.TrimSpace(entry.Event)
	if event != "" {
		return event
	}
	if entry.WAFHit {
		return "waf_hit_allow"
	}
	return "response"
}

func shouldWriteInterestingLog(entry operationalLogEntry) bool {
	if entry.Status >= 400 {
		return true
	}
	if entry.WAFHit {
		return true
	}
	if isSuspiciousRequestPath(entry.Path) {
		return true
	}
	return entry.Duration >= slowRequestThreshold
}

func shouldWriteAccessErrorLog(entry operationalLogEntry) bool {
	return entry.Status >= 400 || strings.TrimSpace(entry.Error) != ""
}

func isSuspiciousRequestPath(path string) bool {
	p := normalizeStatsPath(path)
	return strings.HasPrefix(p, "/wp-") ||
		strings.HasPrefix(p, "/xmlrpc.php") ||
		strings.HasPrefix(p, "/.git") ||
		strings.HasPrefix(p, "/.env")
}

func durationSeconds(d time.Duration) float64 {
	if d <= 0 {
		return 0
	}
	return float64(d) / float64(time.Second)
}

func formatDurationSeconds(d time.Duration, include bool) string {
	if !include {
		return ""
	}
	return strconv.FormatFloat(durationSeconds(d), 'f', 3, 64)
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func appendJSONLineToPath(path string, obj map[string]any) error {
	if strings.TrimSpace(path) == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()

	b, err := json.Marshal(obj)
	if err != nil {
		return err
	}
	_, err = f.Write(append(b, '\n'))
	return err
}
