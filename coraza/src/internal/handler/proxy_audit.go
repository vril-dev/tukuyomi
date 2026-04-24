package handler

import (
	"database/sql"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/config"
)

const (
	defaultProxyRulesAuditFile = "audit/proxy-rules-audit.ndjson"
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

	if getLogsStatsStore() != nil {
		return
	}

	path := strings.TrimSpace(config.ProxyAuditFile)
	if path == "" {
		path = defaultProxyRulesAuditFile
	}
	appendAdminAudit(path, "proxy_rules_audit_write_error", entry)
}

func readProxyRulesAudit(limit int) ([]proxyRulesAuditEntry, error) {
	if store := getLogsStatsStore(); store != nil {
		return store.readProxyRulesConfigAudit(limit)
	}

	path := strings.TrimSpace(config.ProxyAuditFile)
	if path == "" {
		path = defaultProxyRulesAuditFile
	}
	return readAdminAuditLatest[proxyRulesAuditEntry](path, limit, "proxy")
}

func parseProxyRulesAuditLimit(raw string) int {
	return parseAdminAuditLimit(raw)
}

func (s *wafEventStore) readProxyRulesConfigAudit(limit int) ([]proxyRulesAuditEntry, error) {
	if s == nil || s.db == nil {
		return []proxyRulesAuditEntry{}, nil
	}

	rows, err := s.query(
		`SELECT version_id, domain, generation, config_schema_version,
		        COALESCE(parent_version_id, 0), COALESCE(restored_from_version_id, 0),
		        source, actor, reason, content_hash, etag,
		        created_at, activated_at
		   FROM config_versions
		  WHERE domain = ? AND source IN (?, ?)
		  ORDER BY generation DESC
		  LIMIT ?`,
		proxyConfigDomain,
		configVersionSourceApply,
		configVersionSourceRollback,
		clampAdminAuditLimit(limit),
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	records := make([]configVersionRecord, 0)
	for rows.Next() {
		rec, err := scanConfigVersion(rows)
		if err != nil {
			return nil, err
		}
		records = append(records, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}

	entries := make([]proxyRulesAuditEntry, 0, len(records))
	for _, rec := range records {
		entry, err := s.proxyRulesAuditEntryFromConfigVersion(rec)
		if err != nil {
			return nil, err
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

func (s *wafEventStore) proxyRulesAuditEntryFromConfigVersion(rec configVersionRecord) (proxyRulesAuditEntry, error) {
	afterCfg, err := s.loadProxyConfigVersion(rec.VersionID)
	if err != nil {
		return proxyRulesAuditEntry{}, err
	}

	entry := proxyRulesAuditEntry{
		TS:        configVersionAuditTimestamp(rec),
		Service:   "coraza",
		Event:     proxyRulesAuditEventFromSource(rec.Source),
		Actor:     proxyRulesAuditActorFromVersion(rec.Actor),
		PrevETag:  "",
		NextETag:  rec.ETag,
		BeforeRaw: "{}\n",
		AfterRaw:  mustJSON(afterCfg),
	}

	if rec.ParentVersionID > 0 {
		parent, found, err := s.loadConfigVersionRecord(proxyConfigDomain, rec.ParentVersionID)
		if err != nil {
			return proxyRulesAuditEntry{}, err
		}
		if found {
			entry.PrevETag = parent.ETag
		}
		beforeCfg, err := s.loadProxyConfigVersion(rec.ParentVersionID)
		if err != nil {
			return proxyRulesAuditEntry{}, err
		}
		entry.BeforeRaw = mustJSON(beforeCfg)
	}

	if rec.Source == configVersionSourceRollback {
		restored := rec.RestoredFromVersionID
		if restored > 0 {
			restoredRec, found, err := s.loadConfigVersionRecord(proxyConfigDomain, restored)
			if err != nil {
				return proxyRulesAuditEntry{}, err
			}
			if found {
				entry.RestoredFrom = &proxyRulesAuditRestoredFrom{
					ETag:      restoredRec.ETag,
					Timestamp: configVersionAuditTimestamp(restoredRec),
				}
			}
		}
	}

	return entry, nil
}

func (s *wafEventStore) loadConfigVersionRecord(domain string, versionID int64) (configVersionRecord, bool, error) {
	if s == nil || s.db == nil || versionID <= 0 {
		return configVersionRecord{}, false, nil
	}
	row := s.queryRow(
		`SELECT version_id, domain, generation, config_schema_version,
		        COALESCE(parent_version_id, 0), COALESCE(restored_from_version_id, 0),
		        source, actor, reason, content_hash, etag,
		        created_at, activated_at
		   FROM config_versions
		  WHERE domain = ? AND version_id = ?`,
		strings.TrimSpace(domain),
		versionID,
	)
	rec, err := scanConfigVersion(row)
	if err != nil {
		if err == sql.ErrNoRows {
			return configVersionRecord{}, false, nil
		}
		return configVersionRecord{}, false, err
	}
	return rec, true, nil
}

func proxyRulesAuditEventFromSource(source string) string {
	if strings.TrimSpace(source) == configVersionSourceRollback {
		return "proxy_rules_rollback"
	}
	return "proxy_rules_apply"
}

func proxyRulesAuditActorFromVersion(actor string) string {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return "unknown"
	}
	return actor
}

func configVersionAuditTimestamp(rec configVersionRecord) string {
	ts := rec.ActivatedAt
	if ts.IsZero() {
		ts = rec.CreatedAt
	}
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	return ts.UTC().Format(time.RFC3339Nano)
}
