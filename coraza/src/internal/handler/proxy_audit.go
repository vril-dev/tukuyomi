package handler

import (
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const (
	defaultProxyRulesAuditFile = "/app/logs/coraza/proxy-rules-audit.ndjson"
)

type proxyRulesAuditRestoredFrom struct {
	ETag      string `json:"etag,omitempty"`
	Timestamp string `json:"timestamp,omitempty"`
}

type proxyRulesAuditEntry struct {
	TS           string                       `json:"ts"`
	Service      string                       `json:"service"`
	Event        string                       `json:"event"`
	Actor        string                       `json:"actor"`
	IP           string                       `json:"ip,omitempty"`
	PrevETag     string                       `json:"prev_etag,omitempty"`
	NextETag     string                       `json:"next_etag,omitempty"`
	BeforeRaw    string                       `json:"before_raw"`
	AfterRaw     string                       `json:"after_raw"`
	RestoredFrom *proxyRulesAuditRestoredFrom `json:"restored_from,omitempty"`
}

func appendProxyRulesAudit(c *gin.Context, entry proxyRulesAuditEntry) {
	info := newAdminAuditInfo(c, entry.Event)
	entry.TS = info.TS
	entry.Service = info.Service
	entry.Event = info.Event
	entry.Actor = info.Actor
	entry.IP = info.IP

	emitJSONLog(map[string]any{
		"ts":        entry.TS,
		"service":   entry.Service,
		"event":     entry.Event,
		"actor":     entry.Actor,
		"ip":        entry.IP,
		"prev_etag": entry.PrevETag,
		"next_etag": entry.NextETag,
	})

	path := strings.TrimSpace(config.ProxyAuditFile)
	if path == "" {
		path = defaultProxyRulesAuditFile
	}
	appendAdminAudit(path, "proxy_rules_audit_write_error", entry)
}

func readProxyRulesAudit(limit int) ([]proxyRulesAuditEntry, error) {
	path := strings.TrimSpace(config.ProxyAuditFile)
	if path == "" {
		path = defaultProxyRulesAuditFile
	}
	return readAdminAuditLatest[proxyRulesAuditEntry](path, limit, "proxy")
}

func parseProxyRulesAuditLimit(raw string) int {
	return parseAdminAuditLimit(raw)
}
