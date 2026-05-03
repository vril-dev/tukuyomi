package center

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"tukuyomi/internal/edgeconfigsnapshot"
	"tukuyomi/internal/handler"
)

const (
	MaxProxyRulePayloadBytes            = edgeconfigsnapshot.MaxBytes
	ProxyRuleAssignmentDispatchLeaseSec = int64(60)
)

var (
	ErrProxyRuleBundleNotFound       = errors.New("proxy rule bundle not found")
	ErrProxyRuleInvalid              = errors.New("invalid proxy rules")
	ErrProxyRuleAssignmentDispatched = errors.New("proxy rule assignment already dispatched")
)

type ProxyRuleSnapshotRecord struct {
	DeviceID              string `json:"device_id"`
	ConfigRevision        string `json:"config_revision"`
	ProxyETag             string `json:"proxy_etag"`
	Raw                   string `json:"raw"`
	Error                 string `json:"error"`
	SnapshotCreatedAtUnix int64  `json:"snapshot_created_at_unix"`
}

type ProxyRuleBundleBuild struct {
	DeviceID             string
	Raw                  string
	SourceConfigRevision string
	SourceProxyETag      string
	CreatedBy            string
	CreatedAtUnix        int64
}

type ProxyRuleBundleRecord struct {
	BundleRevision       string `json:"bundle_revision"`
	DeviceID             string `json:"device_id"`
	SourceConfigRevision string `json:"source_config_revision"`
	SourceProxyETag      string `json:"source_proxy_etag"`
	PayloadETag          string `json:"payload_etag"`
	PayloadHash          string `json:"payload_hash"`
	PayloadJSON          []byte `json:"-"`
	SizeBytes            int64  `json:"size_bytes"`
	CreatedBy            string `json:"created_by"`
	CreatedAtUnix        int64  `json:"created_at_unix"`
	CreatedAt            string `json:"created_at"`
	LocalProxyETag       string `json:"local_proxy_etag,omitempty"`
	ApplyState           string `json:"apply_state,omitempty"`
	ApplyError           string `json:"apply_error,omitempty"`
	LastAttemptAtUnix    int64  `json:"last_attempt_at_unix,omitempty"`
	AppliedAtUnix        int64  `json:"applied_at_unix,omitempty"`
	ApplyUpdatedAtUnix   int64  `json:"apply_updated_at_unix,omitempty"`
	Stored               bool   `json:"stored,omitempty"`
}

type ProxyRuleAssignmentUpdate struct {
	DeviceID       string
	BundleRevision string
	Reason         string
	AssignedBy     string
	AssignedAtUnix int64
}

type ProxyRuleAssignmentRecord struct {
	AssignmentID         int64  `json:"assignment_id"`
	DeviceID             string `json:"device_id"`
	BundleRevision       string `json:"bundle_revision"`
	BaseProxyETag        string `json:"base_proxy_etag"`
	Reason               string `json:"reason"`
	AssignedBy           string `json:"assigned_by"`
	AssignedAtUnix       int64  `json:"assigned_at_unix"`
	UpdatedAtUnix        int64  `json:"updated_at_unix"`
	DispatchedAtUnix     int64  `json:"dispatched_at_unix,omitempty"`
	SourceConfigRevision string `json:"source_config_revision"`
	SourceProxyETag      string `json:"source_proxy_etag"`
	PayloadETag          string `json:"payload_etag"`
	PayloadHash          string `json:"payload_hash"`
	SizeBytes            int64  `json:"size_bytes"`
}

type ProxyRuleDeviceAssignment struct {
	BundleRevision  string `json:"bundle_revision"`
	PayloadHash     string `json:"payload_hash"`
	PayloadETag     string `json:"payload_etag"`
	SourceProxyETag string `json:"source_proxy_etag"`
	SizeBytes       int64  `json:"size_bytes"`
	AssignedAtUnix  int64  `json:"assigned_at_unix"`
}

type ProxyRuleApplyStatusRecord struct {
	DeviceID              string `json:"device_id"`
	DesiredBundleRevision string `json:"desired_bundle_revision"`
	LocalProxyETag        string `json:"local_proxy_etag"`
	ApplyState            string `json:"apply_state"`
	ApplyError            string `json:"apply_error"`
	LastAttemptAtUnix     int64  `json:"last_attempt_at_unix"`
	UpdatedAtUnix         int64  `json:"updated_at_unix"`
}

type ProxyRulesDeploymentView struct {
	Device      DeviceRecord                `json:"device"`
	Current     *ProxyRuleSnapshotRecord    `json:"current"`
	Bundles     []ProxyRuleBundleRecord     `json:"bundles"`
	Assignment  *ProxyRuleAssignmentRecord  `json:"assignment"`
	ApplyStatus *ProxyRuleApplyStatusRecord `json:"apply_status"`
}

func ProxyRulesDeploymentForDevice(ctx context.Context, deviceID string) (ProxyRulesDeploymentView, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return ProxyRulesDeploymentView{}, ErrDeviceStatusNotFound
	}
	var out ProxyRulesDeploymentView
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		out.Device = device
		if current, found, err := latestProxyRuleSnapshotTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.Current = &current
		}
		bundles, err := listProxyRuleBundlesForDeviceTx(ctx, db, driver, deviceID, 20)
		if err != nil {
			return err
		}
		out.Bundles = bundles
		if assignment, found, err := loadProxyRuleAssignmentTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.Assignment = &assignment
		}
		if status, found, err := loadProxyRuleApplyStatusTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.ApplyStatus = &status
			if out.Assignment != nil && proxyRuleApplyStatusMatchesTerminal(status, *out.Assignment) {
				if _, err := db.ExecContext(ctx, `DELETE FROM center_device_proxy_rule_assignments WHERE device_id = `+placeholder(driver, 1), deviceID); err != nil {
					return err
				}
				out.Assignment = nil
			}
		}
		return nil
	})
	return out, err
}

func LoadProxyRuleBundleForDevice(ctx context.Context, deviceID, revision string) (ProxyRuleBundleRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return ProxyRuleBundleRecord{}, ErrProxyRuleBundleNotFound
	}
	var out ProxyRuleBundleRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		bundle, found, err := loadProxyRuleBundleTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		if !found || bundle.DeviceID != deviceID {
			return ErrProxyRuleBundleNotFound
		}
		out = bundle
		return nil
	})
	return out, err
}

func BuildProxyRuleBundleForDevice(ctx context.Context, in ProxyRuleBundleBuild) (ProxyRuleBundleRecord, error) {
	normalized, err := normalizeProxyRuleBundleBuild(in)
	if err != nil {
		return ProxyRuleBundleRecord{}, err
	}
	var out ProxyRuleBundleRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, normalized.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		if normalized.SourceConfigRevision == "" || normalized.SourceProxyETag == "" {
			if current, found, err := latestProxyRuleSnapshotTx(ctx, tx, driver, normalized.DeviceID); err != nil {
				return err
			} else if found {
				if normalized.SourceConfigRevision == "" {
					normalized.SourceConfigRevision = current.ConfigRevision
				}
				if normalized.SourceProxyETag == "" {
					normalized.SourceProxyETag = current.ProxyETag
				}
			}
		}
		normalized.BundleRevision = proxyRuleBundleRevision(normalized)
		existing, found, err := loadProxyRuleBundleTx(ctx, tx, driver, normalized.BundleRevision)
		if err != nil {
			return err
		}
		if found {
			out = existing
			out.Stored = false
			return tx.Commit()
		}
		if err := insertProxyRuleBundleTx(ctx, tx, driver, normalized); err != nil {
			return err
		}
		out = normalized
		out.Stored = true
		return tx.Commit()
	})
	return out, err
}

func AssignProxyRuleBundleToDevice(ctx context.Context, in ProxyRuleAssignmentUpdate) (ProxyRuleAssignmentRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.BundleRevision = strings.ToLower(strings.TrimSpace(in.BundleRevision))
	in.Reason = clampString(in.Reason, 512)
	in.AssignedBy = clampString(in.AssignedBy, 128)
	if !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.BundleRevision) {
		return ProxyRuleAssignmentRecord{}, ErrProxyRuleInvalid
	}
	if in.AssignedAtUnix <= 0 {
		in.AssignedAtUnix = time.Now().UTC().Unix()
	}
	var out ProxyRuleAssignmentRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, in.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		bundle, found, err := loadProxyRuleBundleTx(ctx, tx, driver, in.BundleRevision)
		if err != nil {
			return err
		}
		if !found || bundle.DeviceID != in.DeviceID {
			return ErrProxyRuleBundleNotFound
		}
		if existing, found, err := loadProxyRuleAssignmentTx(ctx, tx, driver, in.DeviceID); err != nil {
			return err
		} else if found && proxyRuleAssignmentDispatchActive(existing, in.AssignedAtUnix) {
			return ErrProxyRuleAssignmentDispatched
		}
		if err := upsertProxyRuleAssignmentTx(ctx, tx, driver, in, bundle); err != nil {
			return err
		}
		assignment, found, err := loadProxyRuleAssignmentTx(ctx, tx, driver, in.DeviceID)
		if err != nil {
			return err
		}
		if !found {
			return ErrProxyRuleBundleNotFound
		}
		out = assignment
		return tx.Commit()
	})
	return out, err
}

func ClearProxyRuleAssignment(ctx context.Context, deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return false, ErrDeviceStatusNotFound
	}
	var cleared bool
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var exists int
		if err := tx.QueryRowContext(ctx, `SELECT 1 FROM center_devices WHERE device_id = `+placeholder(driver, 1), deviceID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}
		assignment, found, err := loadProxyRuleAssignmentTx(ctx, tx, driver, deviceID)
		if err != nil {
			return err
		}
		if !found {
			return tx.Commit()
		}
		if proxyRuleAssignmentDispatchActive(assignment, time.Now().UTC().Unix()) {
			return ErrProxyRuleAssignmentDispatched
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM center_device_proxy_rule_assignments WHERE device_id = `+placeholder(driver, 1), deviceID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		cleared = err == nil && affected > 0
		return tx.Commit()
	})
	return cleared, err
}

func PendingProxyRuleAssignmentForDevice(ctx context.Context, deviceID string, dispatchedAtUnix int64) (*ProxyRuleDeviceAssignment, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	if dispatchedAtUnix <= 0 {
		dispatchedAtUnix = time.Now().UTC().Unix()
	}
	var out *ProxyRuleDeviceAssignment
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		assignment, found, err := loadProxyRuleAssignmentTx(ctx, tx, driver, deviceID)
		if err != nil || !found {
			return err
		}
		if proxyRuleAssignmentDispatchActive(assignment, dispatchedAtUnix) {
			return nil
		}
		if status, found, err := loadProxyRuleApplyStatusTx(ctx, tx, driver, deviceID); err != nil {
			return err
		} else if found && proxyRuleApplyStatusMatchesTerminal(status, assignment) {
			if err := deleteProxyRuleAssignmentTx(ctx, tx, driver, deviceID); err != nil {
				return err
			}
			return tx.Commit()
		}
		if err := markProxyRuleAssignmentDispatchedTx(ctx, tx, driver, deviceID, dispatchedAtUnix); err != nil {
			return err
		}
		out = &ProxyRuleDeviceAssignment{
			BundleRevision:  assignment.BundleRevision,
			PayloadHash:     assignment.PayloadHash,
			PayloadETag:     assignment.PayloadETag,
			SourceProxyETag: assignment.SourceProxyETag,
			SizeBytes:       assignment.SizeBytes,
			AssignedAtUnix:  assignment.AssignedAtUnix,
		}
		return tx.Commit()
	})
	return out, err
}

func ProxyRuleBundleDownloadForDevice(ctx context.Context, deviceID, bundleRevision, payloadHash string) (ProxyRuleBundleRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	bundleRevision = strings.ToLower(strings.TrimSpace(bundleRevision))
	payloadHash = strings.ToLower(strings.TrimSpace(payloadHash))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(bundleRevision) || !hex64Pattern.MatchString(payloadHash) {
		return ProxyRuleBundleRecord{}, nil, ErrProxyRuleInvalid
	}
	var out ProxyRuleBundleRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		assignment, found, err := loadProxyRuleAssignmentTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		if !found || assignment.BundleRevision != bundleRevision || assignment.PayloadHash != payloadHash {
			return ErrProxyRuleBundleNotFound
		}
		bundle, found, err := loadProxyRuleBundleTx(ctx, db, driver, bundleRevision)
		if err != nil {
			return err
		}
		if !found || bundle.DeviceID != deviceID || bundle.PayloadHash != payloadHash {
			return ErrProxyRuleBundleNotFound
		}
		out = bundle
		return nil
	})
	if err != nil {
		return ProxyRuleBundleRecord{}, nil, err
	}
	return out, append([]byte(nil), out.PayloadJSON...), nil
}

func UpsertProxyRuleApplyStatus(ctx context.Context, status ProxyRuleApplyStatusRecord) error {
	status.DeviceID = strings.TrimSpace(status.DeviceID)
	status.DesiredBundleRevision = strings.ToLower(strings.TrimSpace(status.DesiredBundleRevision))
	status.LocalProxyETag = strings.TrimSpace(status.LocalProxyETag)
	status.ApplyState = strings.TrimSpace(status.ApplyState)
	status.ApplyError = clampString(status.ApplyError, 512)
	if !deviceIDPattern.MatchString(status.DeviceID) {
		return ErrDeviceStatusNotFound
	}
	if status.DesiredBundleRevision != "" && !hex64Pattern.MatchString(status.DesiredBundleRevision) {
		return ErrProxyRuleInvalid
	}
	if !metadataPattern.MatchString(status.LocalProxyETag) || len(status.LocalProxyETag) > 128 {
		return ErrProxyRuleInvalid
	}
	if !metadataPattern.MatchString(status.ApplyState) || len(status.ApplyState) > 32 {
		return ErrProxyRuleInvalid
	}
	if !metadataPattern.MatchString(status.ApplyError) {
		return ErrProxyRuleInvalid
	}
	if status.UpdatedAtUnix <= 0 {
		status.UpdatedAtUnix = time.Now().UTC().Unix()
	}
	if status.LastAttemptAtUnix <= 0 && status.ApplyState != "" {
		status.LastAttemptAtUnix = status.UpdatedAtUnix
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, status.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		if err := upsertProxyRuleApplyStatusTx(ctx, tx, driver, status); err != nil {
			return err
		}
		if err := deleteTerminalProxyRuleAssignmentForStatusTx(ctx, tx, driver, status); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func normalizeProxyRuleBundleBuild(in ProxyRuleBundleBuild) (ProxyRuleBundleRecord, error) {
	deviceID := strings.TrimSpace(in.DeviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return ProxyRuleBundleRecord{}, ErrDeviceStatusNotFound
	}
	sourceRevision := strings.ToLower(strings.TrimSpace(in.SourceConfigRevision))
	if sourceRevision != "" && !hex64Pattern.MatchString(sourceRevision) {
		return ProxyRuleBundleRecord{}, ErrProxyRuleInvalid
	}
	sourceETag := strings.TrimSpace(in.SourceProxyETag)
	if !metadataPattern.MatchString(sourceETag) || len(sourceETag) > 128 {
		return ProxyRuleBundleRecord{}, ErrProxyRuleInvalid
	}
	raw := strings.TrimSpace(in.Raw)
	if raw == "" || len(raw) > MaxProxyRulePayloadBytes {
		return ProxyRuleBundleRecord{}, ErrProxyRuleInvalid
	}
	normalizedRaw, payloadETag, _, err := handler.NormalizeProxyRulesRawStandalone(raw)
	if err != nil {
		return ProxyRuleBundleRecord{}, fmt.Errorf("%w: %v", ErrProxyRuleInvalid, err)
	}
	payload := []byte(normalizedRaw)
	if len(payload) == 0 || len(payload) > MaxProxyRulePayloadBytes {
		return ProxyRuleBundleRecord{}, ErrProxyRuleInvalid
	}
	sum := sha256.Sum256(payload)
	now := in.CreatedAtUnix
	if now <= 0 {
		now = time.Now().UTC().Unix()
	}
	return ProxyRuleBundleRecord{
		DeviceID:             deviceID,
		SourceConfigRevision: sourceRevision,
		SourceProxyETag:      sourceETag,
		PayloadETag:          payloadETag,
		PayloadHash:          hex.EncodeToString(sum[:]),
		PayloadJSON:          append([]byte(nil), payload...),
		SizeBytes:            int64(len(payload)),
		CreatedBy:            clampString(in.CreatedBy, 128),
		CreatedAtUnix:        now,
		CreatedAt:            time.Unix(now, 0).UTC().Format(time.RFC3339),
	}, nil
}

func proxyRuleBundleRevision(rec ProxyRuleBundleRecord) string {
	sum := sha256.Sum256([]byte(
		rec.DeviceID + "\n" +
			rec.SourceConfigRevision + "\n" +
			rec.SourceProxyETag + "\n" +
			rec.PayloadETag + "\n" +
			rec.PayloadHash,
	))
	return hex.EncodeToString(sum[:])
}

func latestProxyRuleSnapshotTx(ctx context.Context, q queryer, driver, deviceID string) (ProxyRuleSnapshotRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT revision, payload_json, created_at_unix
  FROM center_device_config_snapshots
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY created_at_unix DESC, snapshot_id DESC
 LIMIT 1`, deviceID)
	var revision string
	var payloadRaw string
	var createdAtUnix int64
	if err := row.Scan(&revision, &payloadRaw, &createdAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyRuleSnapshotRecord{}, false, nil
		}
		return ProxyRuleSnapshotRecord{}, false, err
	}
	var payload edgeconfigsnapshot.Payload
	if err := json.Unmarshal([]byte(payloadRaw), &payload); err != nil {
		return ProxyRuleSnapshotRecord{}, false, err
	}
	domain, ok := payload.Domains["proxy"]
	if !ok {
		return ProxyRuleSnapshotRecord{}, false, nil
	}
	rec := ProxyRuleSnapshotRecord{
		DeviceID:              deviceID,
		ConfigRevision:        revision,
		ProxyETag:             strings.TrimSpace(domain.ETag),
		Error:                 strings.TrimSpace(domain.Error),
		SnapshotCreatedAtUnix: createdAtUnix,
	}
	if len(domain.Raw) > 0 {
		rec.Raw = string(domain.Raw)
	}
	return rec, true, nil
}

func insertProxyRuleBundleTx(ctx context.Context, tx *sql.Tx, driver string, rec ProxyRuleBundleRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_proxy_rule_bundles
    (bundle_revision, device_id, source_config_revision, source_proxy_etag, payload_etag,
     payload_hash, payload_json, size_bytes, created_by, created_at_unix, created_at)
VALUES
    (`+placeholders(driver, 11, 1)+`)`,
		rec.BundleRevision,
		rec.DeviceID,
		rec.SourceConfigRevision,
		rec.SourceProxyETag,
		rec.PayloadETag,
		rec.PayloadHash,
		string(rec.PayloadJSON),
		rec.SizeBytes,
		rec.CreatedBy,
		rec.CreatedAtUnix,
		rec.CreatedAt,
	)
	return err
}

func loadProxyRuleBundleTx(ctx context.Context, q queryer, driver string, revision string) (ProxyRuleBundleRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT bundle_revision, device_id, source_config_revision, source_proxy_etag, payload_etag,
       payload_hash, payload_json, size_bytes, created_by, created_at_unix, created_at
  FROM center_proxy_rule_bundles
 WHERE bundle_revision = `+placeholder(driver, 1), revision)
	var rec ProxyRuleBundleRecord
	var payload string
	if err := row.Scan(
		&rec.BundleRevision,
		&rec.DeviceID,
		&rec.SourceConfigRevision,
		&rec.SourceProxyETag,
		&rec.PayloadETag,
		&rec.PayloadHash,
		&payload,
		&rec.SizeBytes,
		&rec.CreatedBy,
		&rec.CreatedAtUnix,
		&rec.CreatedAt,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyRuleBundleRecord{}, false, nil
		}
		return ProxyRuleBundleRecord{}, false, err
	}
	rec.PayloadJSON = []byte(payload)
	return rec, true, nil
}

func listProxyRuleBundlesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]ProxyRuleBundleRecord, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	query := `
SELECT b.bundle_revision, b.device_id, b.source_config_revision, b.source_proxy_etag, b.payload_etag,
       b.payload_hash, b.size_bytes, b.created_by, b.created_at_unix, b.created_at,
       COALESCE(h.local_proxy_etag, ''), COALESCE(h.apply_state, ''), COALESCE(h.apply_error, ''),
       COALESCE(h.last_attempt_at_unix, 0), COALESCE(h.applied_at_unix, 0), COALESCE(h.updated_at_unix, 0)
  FROM center_proxy_rule_bundles b
  LEFT JOIN center_device_proxy_rule_apply_history h
    ON h.device_id = b.device_id AND h.bundle_revision = b.bundle_revision
 WHERE b.device_id = ` + placeholder(driver, 1) + `
 ORDER BY b.created_at_unix DESC, b.bundle_id DESC`
	args := []any{deviceID}
	if driver == "pgsql" {
		query += " LIMIT " + placeholders(driver, 1, 2)
		args = append(args, limit)
	} else {
		query += " LIMIT " + placeholder(driver, 2)
		args = append(args, limit)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ProxyRuleBundleRecord{}
	for rows.Next() {
		var rec ProxyRuleBundleRecord
		if err := rows.Scan(
			&rec.BundleRevision,
			&rec.DeviceID,
			&rec.SourceConfigRevision,
			&rec.SourceProxyETag,
			&rec.PayloadETag,
			&rec.PayloadHash,
			&rec.SizeBytes,
			&rec.CreatedBy,
			&rec.CreatedAtUnix,
			&rec.CreatedAt,
			&rec.LocalProxyETag,
			&rec.ApplyState,
			&rec.ApplyError,
			&rec.LastAttemptAtUnix,
			&rec.AppliedAtUnix,
			&rec.ApplyUpdatedAtUnix,
		); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func upsertProxyRuleAssignmentTx(ctx context.Context, tx *sql.Tx, driver string, in ProxyRuleAssignmentUpdate, bundle ProxyRuleBundleRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_proxy_rule_assignments
    (device_id, bundle_revision, base_proxy_etag, reason, assigned_by, assigned_at_unix, updated_at_unix, dispatched_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON CONFLICT (device_id) DO UPDATE SET
    bundle_revision = excluded.bundle_revision,
    base_proxy_etag = excluded.base_proxy_etag,
    reason = excluded.reason,
    assigned_by = excluded.assigned_by,
    assigned_at_unix = excluded.assigned_at_unix,
    updated_at_unix = excluded.updated_at_unix,
    dispatched_at_unix = 0`,
		in.DeviceID,
		bundle.BundleRevision,
		bundle.SourceProxyETag,
		in.Reason,
		in.AssignedBy,
		in.AssignedAtUnix,
		in.AssignedAtUnix,
		0,
	)
	return err
}

func loadProxyRuleAssignmentTx(ctx context.Context, q queryer, driver string, deviceID string) (ProxyRuleAssignmentRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT a.assignment_id, a.device_id, a.bundle_revision, a.base_proxy_etag, a.reason, a.assigned_by,
       a.assigned_at_unix, a.updated_at_unix, a.dispatched_at_unix,
       b.source_config_revision, b.source_proxy_etag, b.payload_etag, b.payload_hash, b.size_bytes
  FROM center_device_proxy_rule_assignments a
  JOIN center_proxy_rule_bundles b ON b.bundle_revision = a.bundle_revision
 WHERE a.device_id = `+placeholder(driver, 1), deviceID)
	var rec ProxyRuleAssignmentRecord
	if err := row.Scan(
		&rec.AssignmentID,
		&rec.DeviceID,
		&rec.BundleRevision,
		&rec.BaseProxyETag,
		&rec.Reason,
		&rec.AssignedBy,
		&rec.AssignedAtUnix,
		&rec.UpdatedAtUnix,
		&rec.DispatchedAtUnix,
		&rec.SourceConfigRevision,
		&rec.SourceProxyETag,
		&rec.PayloadETag,
		&rec.PayloadHash,
		&rec.SizeBytes,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyRuleAssignmentRecord{}, false, nil
		}
		return ProxyRuleAssignmentRecord{}, false, err
	}
	return rec, true, nil
}

func markProxyRuleAssignmentDispatchedTx(ctx context.Context, tx *sql.Tx, driver string, deviceID string, dispatchedAtUnix int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE center_device_proxy_rule_assignments
   SET dispatched_at_unix = `+placeholder(driver, 1)+`
 WHERE device_id = `+placeholder(driver, 2),
		dispatchedAtUnix,
		deviceID,
	)
	return err
}

func deleteProxyRuleAssignmentTx(ctx context.Context, tx *sql.Tx, driver string, deviceID string) error {
	_, err := tx.ExecContext(ctx, `DELETE FROM center_device_proxy_rule_assignments WHERE device_id = `+placeholder(driver, 1), deviceID)
	return err
}

func proxyRuleAssignmentDispatchActive(assignment ProxyRuleAssignmentRecord, nowUnix int64) bool {
	if assignment.DispatchedAtUnix <= 0 {
		return false
	}
	if nowUnix <= assignment.DispatchedAtUnix {
		return true
	}
	return nowUnix-assignment.DispatchedAtUnix < ProxyRuleAssignmentDispatchLeaseSec
}

func upsertProxyRuleApplyStatusTx(ctx context.Context, tx *sql.Tx, driver string, status ProxyRuleApplyStatusRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_proxy_rule_apply_status
    (device_id, desired_bundle_revision, local_proxy_etag, apply_state, apply_error, last_attempt_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 7, 1)+`)
ON CONFLICT (device_id) DO UPDATE SET
    desired_bundle_revision = excluded.desired_bundle_revision,
    local_proxy_etag = excluded.local_proxy_etag,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
		status.DeviceID,
		status.DesiredBundleRevision,
		status.LocalProxyETag,
		status.ApplyState,
		status.ApplyError,
		status.LastAttemptAtUnix,
		status.UpdatedAtUnix,
	)
	if err != nil {
		return err
	}
	return upsertProxyRuleApplyHistoryTx(ctx, tx, driver, status)
}

func upsertProxyRuleApplyHistoryTx(ctx context.Context, tx *sql.Tx, driver string, status ProxyRuleApplyStatusRecord) error {
	if status.DesiredBundleRevision == "" {
		return nil
	}
	attemptedAt := status.LastAttemptAtUnix
	if attemptedAt <= 0 {
		attemptedAt = status.UpdatedAtUnix
	}
	appliedAt := int64(0)
	if strings.TrimSpace(status.ApplyState) == "applied" {
		appliedAt = attemptedAt
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_proxy_rule_apply_history
    (device_id, bundle_revision, local_proxy_etag, apply_state, apply_error,
     last_attempt_at_unix, applied_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON CONFLICT (device_id, bundle_revision) DO UPDATE SET
    local_proxy_etag = excluded.local_proxy_etag,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    applied_at_unix = CASE
        WHEN excluded.apply_state = 'applied' THEN excluded.applied_at_unix
        ELSE center_device_proxy_rule_apply_history.applied_at_unix
    END,
    updated_at_unix = excluded.updated_at_unix`,
		status.DeviceID,
		status.DesiredBundleRevision,
		status.LocalProxyETag,
		status.ApplyState,
		status.ApplyError,
		attemptedAt,
		appliedAt,
		status.UpdatedAtUnix,
	)
	return err
}

func loadProxyRuleApplyStatusTx(ctx context.Context, q queryer, driver string, deviceID string) (ProxyRuleApplyStatusRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, desired_bundle_revision, local_proxy_etag, apply_state, apply_error, last_attempt_at_unix, updated_at_unix
  FROM center_device_proxy_rule_apply_status
 WHERE device_id = `+placeholder(driver, 1), deviceID)
	var rec ProxyRuleApplyStatusRecord
	if err := row.Scan(
		&rec.DeviceID,
		&rec.DesiredBundleRevision,
		&rec.LocalProxyETag,
		&rec.ApplyState,
		&rec.ApplyError,
		&rec.LastAttemptAtUnix,
		&rec.UpdatedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyRuleApplyStatusRecord{}, false, nil
		}
		return ProxyRuleApplyStatusRecord{}, false, err
	}
	return rec, true, nil
}

func deleteTerminalProxyRuleAssignmentForStatusTx(ctx context.Context, tx *sql.Tx, driver string, status ProxyRuleApplyStatusRecord) error {
	assignment, found, err := loadProxyRuleAssignmentTx(ctx, tx, driver, status.DeviceID)
	if err != nil || !found {
		return err
	}
	if !proxyRuleApplyStatusMatchesTerminal(status, assignment) {
		return nil
	}
	return deleteProxyRuleAssignmentTx(ctx, tx, driver, status.DeviceID)
}

func proxyRuleApplyStatusMatchesTerminal(status ProxyRuleApplyStatusRecord, assignment ProxyRuleAssignmentRecord) bool {
	if status.DesiredBundleRevision != assignment.BundleRevision {
		return false
	}
	switch strings.TrimSpace(status.ApplyState) {
	case "applied":
		return proxyRuleETagSameContent(status.LocalProxyETag, assignment.PayloadETag)
	case "failed", "blocked":
		return assignment.DispatchedAtUnix > 0
	default:
		return false
	}
}

func proxyRuleETagSameContent(a, b string) bool {
	aHash := proxyRuleETagContentHash(a)
	bHash := proxyRuleETagContentHash(b)
	return aHash != "" && bHash != "" && aHash == bHash
}

func proxyRuleETagContentHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	if strings.HasPrefix(value, `W/"sha256:`) && strings.HasSuffix(value, `"`) {
		hash := strings.TrimSuffix(strings.TrimPrefix(value, `W/"sha256:`), `"`)
		if hex64Pattern.MatchString(hash) {
			return hash
		}
		return ""
	}
	if strings.HasPrefix(value, `"sha256:`) && strings.HasSuffix(value, `"`) {
		hash := strings.TrimSuffix(strings.TrimPrefix(value, `"sha256:`), `"`)
		if hex64Pattern.MatchString(hash) {
			return hash
		}
		return ""
	}
	parts := strings.SplitN(value, ":", 3)
	if len(parts) == 3 && strings.TrimSpace(parts[0]) == "proxy" && hex64Pattern.MatchString(parts[2]) {
		return parts[2]
	}
	return ""
}
