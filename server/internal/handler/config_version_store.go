package handler

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	configVersionSourceImport   = "import"
	configVersionSourceApply    = "apply"
	configVersionSourceRollback = "rollback"
)

var errConfigVersionConflict = errors.New("config version conflict")

type configVersionRecord struct {
	VersionID             int64
	Domain                string
	Generation            int64
	ConfigSchemaVersion   int
	ParentVersionID       int64
	RestoredFromVersionID int64
	Source                string
	Actor                 string
	Reason                string
	ContentHash           string
	ETag                  string
	CreatedAt             time.Time
	ActivatedAt           time.Time
}

type activeConfigDomain struct {
	Domain              string
	ActiveVersionID     int64
	HasActiveVersion    bool
	CurrentGeneration   int64
	CurrentETag         string
	ConfigSchemaVersion int
}

func configContentHash(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func configVersionETag(domain string, generation int64, contentHash string) string {
	return fmt.Sprintf("%s:%d:%s", strings.TrimSpace(domain), generation, strings.TrimSpace(contentHash))
}

func configVersionETagParts(etag string) (string, string) {
	parts := strings.SplitN(strings.TrimSpace(etag), ":", 3)
	if len(parts) != 3 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[2])
}

func configVersionETagSameContent(a string, b string) bool {
	aDomain, aHash := configVersionETagParts(a)
	bDomain, bHash := configVersionETagParts(b)
	return aDomain != "" && aHash != "" && aDomain == bDomain && aHash == bHash
}

func currentConfigVersionETag(domain string, fallback string) string {
	if store := getLogsStatsStore(); store != nil {
		if rec, found, err := store.loadActiveConfigVersion(domain); err == nil && found && strings.TrimSpace(rec.ETag) != "" {
			return rec.ETag
		}
	}
	return strings.TrimSpace(fallback)
}

func normalizeConfigVersionSource(source string) string {
	source = strings.ToLower(strings.TrimSpace(source))
	switch source {
	case configVersionSourceImport, configVersionSourceApply, configVersionSourceRollback:
		return source
	default:
		return configVersionSourceApply
	}
}

func (s *wafEventStore) ensureConfigDomainTx(tx *sql.Tx, domain string, schemaVersion int, now time.Time) error {
	if s == nil || tx == nil {
		return errors.New("db store is not initialized")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return errors.New("config domain is required")
	}
	if schemaVersion <= 0 {
		schemaVersion = 1
	}
	stmt := `INSERT INTO config_domains (domain, active_version_id, current_generation, current_etag, config_schema_version, updated_at_unix, updated_at)
		 VALUES (?, NULL, 0, '', ?, ?, ?)
		 ON CONFLICT (domain) DO NOTHING`
	if s.dbDriver == logStatsDBDriverMySQL {
		stmt = `INSERT IGNORE INTO config_domains (domain, active_version_id, current_generation, current_etag, config_schema_version, updated_at_unix, updated_at)
		 VALUES (?, NULL, 0, '', ?, ?, ?)`
	}
	_, err := s.txExec(tx, stmt, domain, schemaVersion, now.Unix(), now.Format(time.RFC3339Nano))
	return err
}

func (s *wafEventStore) loadActiveConfigDomainTx(tx *sql.Tx, domain string) (activeConfigDomain, error) {
	row := tx.QueryRow(s.bindSQL(`SELECT domain, active_version_id, current_generation, current_etag, config_schema_version FROM config_domains WHERE domain = ?`), domain)
	var out activeConfigDomain
	var active sql.NullInt64
	if err := row.Scan(&out.Domain, &active, &out.CurrentGeneration, &out.CurrentETag, &out.ConfigSchemaVersion); err != nil {
		return activeConfigDomain{}, err
	}
	if active.Valid {
		out.ActiveVersionID = active.Int64
		out.HasActiveVersion = true
	}
	return out, nil
}

func (s *wafEventStore) loadActiveConfigVersion(domain string) (configVersionRecord, bool, error) {
	if s == nil || s.db == nil {
		return configVersionRecord{}, false, errors.New("db store is not initialized")
	}
	row := s.queryRow(
		`SELECT v.version_id, v.domain, v.generation, v.config_schema_version,
		        COALESCE(v.parent_version_id, 0), COALESCE(v.restored_from_version_id, 0),
		        v.source, v.actor, v.reason, v.content_hash, v.etag,
		        v.created_at, v.activated_at
		   FROM config_domains d
		   JOIN config_versions v ON v.version_id = d.active_version_id
		  WHERE d.domain = ?`,
		strings.TrimSpace(domain),
	)
	rec, err := scanConfigVersion(row)
	if errors.Is(err, sql.ErrNoRows) {
		return configVersionRecord{}, false, nil
	}
	if err != nil {
		return configVersionRecord{}, false, err
	}
	return rec, true, nil
}

func (s *wafEventStore) findConfigVersionIDByETag(domain string, etag string) (int64, bool, error) {
	if s == nil || s.db == nil {
		return 0, false, errors.New("db store is not initialized")
	}
	domain = strings.TrimSpace(domain)
	etag = strings.TrimSpace(etag)
	if domain == "" || etag == "" {
		return 0, false, nil
	}
	row := s.queryRow(`SELECT version_id FROM config_versions WHERE domain = ? AND etag = ?`, domain, etag)
	var id int64
	if err := row.Scan(&id); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return id, true, nil
}

type configVersionScanner interface {
	Scan(dest ...any) error
}

func scanConfigVersion(scanner configVersionScanner) (configVersionRecord, error) {
	var rec configVersionRecord
	var createdAt, activatedAt string
	if err := scanner.Scan(
		&rec.VersionID,
		&rec.Domain,
		&rec.Generation,
		&rec.ConfigSchemaVersion,
		&rec.ParentVersionID,
		&rec.RestoredFromVersionID,
		&rec.Source,
		&rec.Actor,
		&rec.Reason,
		&rec.ContentHash,
		&rec.ETag,
		&createdAt,
		&activatedAt,
	); err != nil {
		return configVersionRecord{}, err
	}
	rec.CreatedAt, _ = time.Parse(time.RFC3339Nano, createdAt)
	rec.ActivatedAt, _ = time.Parse(time.RFC3339Nano, activatedAt)
	return rec, nil
}

func (s *wafEventStore) writeConfigVersion(
	domain string,
	schemaVersion int,
	expectedETag string,
	source string,
	actor string,
	reason string,
	contentHash string,
	restoredFromVersionID int64,
	writeRows func(tx *sql.Tx, versionID int64) error,
) (configVersionRecord, error) {
	if s == nil || s.db == nil {
		return configVersionRecord{}, errors.New("db store is not initialized")
	}
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return configVersionRecord{}, errors.New("config domain is required")
	}
	contentHash = strings.TrimSpace(contentHash)
	if contentHash == "" {
		return configVersionRecord{}, errors.New("content hash is required")
	}
	if schemaVersion <= 0 {
		schemaVersion = 1
	}
	source = normalizeConfigVersionSource(source)
	actor = strings.TrimSpace(actor)
	reason = strings.TrimSpace(reason)

	s.mu.Lock()
	defer s.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return configVersionRecord{}, err
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	now := time.Now().UTC()
	if err := s.ensureConfigDomainTx(tx, domain, schemaVersion, now); err != nil {
		return configVersionRecord{}, err
	}
	current, err := s.loadActiveConfigDomainTx(tx, domain)
	if err != nil {
		return configVersionRecord{}, err
	}
	if expectedETag = strings.TrimSpace(expectedETag); expectedETag != "" && expectedETag != current.CurrentETag {
		return configVersionRecord{}, errConfigVersionConflict
	}

	generation := current.CurrentGeneration + 1
	etag := configVersionETag(domain, generation, contentHash)
	rec := configVersionRecord{
		Domain:                domain,
		Generation:            generation,
		ConfigSchemaVersion:   schemaVersion,
		ParentVersionID:       current.ActiveVersionID,
		RestoredFromVersionID: restoredFromVersionID,
		Source:                source,
		Actor:                 actor,
		Reason:                reason,
		ContentHash:           contentHash,
		ETag:                  etag,
		CreatedAt:             now,
		ActivatedAt:           now,
	}
	versionID, err := s.insertConfigVersionTx(tx, rec)
	if err != nil {
		return configVersionRecord{}, err
	}
	rec.VersionID = versionID
	if writeRows != nil {
		if err := writeRows(tx, versionID); err != nil {
			return configVersionRecord{}, err
		}
	}
	if err := s.activateConfigVersionTx(tx, current, rec, now); err != nil {
		return configVersionRecord{}, err
	}
	if restoredFromVersionID > 0 || source == configVersionSourceRollback {
		if err := s.insertConfigRollbackTx(tx, current.ActiveVersionID, restoredFromVersionID, versionID, actor, reason, now, domain); err != nil {
			return configVersionRecord{}, err
		}
	}

	if err := tx.Commit(); err != nil {
		return configVersionRecord{}, err
	}
	tx = nil
	return rec, nil
}

func (s *wafEventStore) insertConfigVersionTx(tx *sql.Tx, rec configVersionRecord) (int64, error) {
	createdAt := rec.CreatedAt.Format(time.RFC3339Nano)
	activatedAt := rec.ActivatedAt.Format(time.RFC3339Nano)
	if s.dbDriver == logStatsDBDriverPostgres {
		row := tx.QueryRow(
			s.bindSQL(`INSERT INTO config_versions (
				domain, generation, config_schema_version, parent_version_id,
				restored_from_version_id, source, actor, reason, content_hash, etag,
				created_at_unix, created_at, activated_at_unix, activated_at
			) VALUES (?, ?, ?, NULLIF(?, 0), NULLIF(?, 0), ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING version_id`),
			rec.Domain,
			rec.Generation,
			rec.ConfigSchemaVersion,
			rec.ParentVersionID,
			rec.RestoredFromVersionID,
			rec.Source,
			rec.Actor,
			rec.Reason,
			rec.ContentHash,
			rec.ETag,
			rec.CreatedAt.Unix(),
			createdAt,
			rec.ActivatedAt.Unix(),
			activatedAt,
		)
		var id int64
		if err := row.Scan(&id); err != nil {
			return 0, err
		}
		return id, nil
	}
	res, err := s.txExec(
		tx,
		`INSERT INTO config_versions (
			domain, generation, config_schema_version, parent_version_id,
			restored_from_version_id, source, actor, reason, content_hash, etag,
			created_at_unix, created_at, activated_at_unix, activated_at
		) VALUES (?, ?, ?, NULLIF(?, 0), NULLIF(?, 0), ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		rec.Domain,
		rec.Generation,
		rec.ConfigSchemaVersion,
		rec.ParentVersionID,
		rec.RestoredFromVersionID,
		rec.Source,
		rec.Actor,
		rec.Reason,
		rec.ContentHash,
		rec.ETag,
		rec.CreatedAt.Unix(),
		createdAt,
		rec.ActivatedAt.Unix(),
		activatedAt,
	)
	if err != nil {
		return 0, err
	}
	return res.LastInsertId()
}

func (s *wafEventStore) activateConfigVersionTx(tx *sql.Tx, current activeConfigDomain, rec configVersionRecord, now time.Time) error {
	var (
		res sql.Result
		err error
	)
	if current.HasActiveVersion {
		res, err = s.txExec(
			tx,
			`UPDATE config_domains
			    SET active_version_id = ?, current_generation = ?, current_etag = ?,
			        config_schema_version = ?, updated_at_unix = ?, updated_at = ?
			  WHERE domain = ? AND active_version_id = ?`,
			rec.VersionID,
			rec.Generation,
			rec.ETag,
			rec.ConfigSchemaVersion,
			now.Unix(),
			now.Format(time.RFC3339Nano),
			rec.Domain,
			current.ActiveVersionID,
		)
	} else {
		res, err = s.txExec(
			tx,
			`UPDATE config_domains
			    SET active_version_id = ?, current_generation = ?, current_etag = ?,
			        config_schema_version = ?, updated_at_unix = ?, updated_at = ?
			  WHERE domain = ? AND active_version_id IS NULL`,
			rec.VersionID,
			rec.Generation,
			rec.ETag,
			rec.ConfigSchemaVersion,
			now.Unix(),
			now.Format(time.RFC3339Nano),
			rec.Domain,
		)
	}
	if err != nil {
		return err
	}
	affected, err := res.RowsAffected()
	if err == nil && affected != 1 {
		return errConfigVersionConflict
	}
	return nil
}

func (s *wafEventStore) insertConfigRollbackTx(tx *sql.Tx, fromVersionID int64, restoredVersionID int64, newVersionID int64, actor string, reason string, now time.Time, domain string) error {
	if restoredVersionID <= 0 {
		restoredVersionID = newVersionID
	}
	_, err := s.txExec(
		tx,
		`INSERT INTO config_rollbacks (
			domain, from_version_id, restored_version_id, new_version_id,
			actor, reason, created_at_unix, created_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		domain,
		fromVersionID,
		restoredVersionID,
		newVersionID,
		actor,
		reason,
		now.Unix(),
		now.Format(time.RFC3339Nano),
	)
	return err
}
