package center

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"tukuyomi/internal/handler"
)

const (
	DeviceStatusApproved       = "approved"
	DeviceStatusProductChanged = "product_changed"
	DeviceStatusRevoked        = "revoked"
	DeviceStatusArchived       = "archived"

	EnrollmentStatusPending  = "pending"
	EnrollmentStatusApproved = "approved"
	EnrollmentStatusRejected = "rejected"
)

var (
	ErrEnrollmentReplay        = errors.New("device enrollment nonce was already used")
	ErrEnrollmentNotFound      = errors.New("device enrollment not found")
	ErrEnrollmentAlreadyClosed = errors.New("device enrollment is already closed")
	ErrDeviceStatusNotFound    = errors.New("device status not found")
	ErrDeviceStatusKeyMismatch = errors.New("device status key mismatch")
	ErrDeviceArchiveInvalid    = errors.New("device must be revoked before archive")
)

type DeviceRecord struct {
	DeviceID                   string                 `json:"device_id"`
	KeyID                      string                 `json:"key_id"`
	PublicKeyFingerprintSHA256 string                 `json:"public_key_fingerprint_sha256"`
	Status                     string                 `json:"status"`
	ProductID                  string                 `json:"product_id"`
	EnrollmentTokenID          int64                  `json:"enrollment_token_id"`
	EnrollmentTokenPrefix      string                 `json:"enrollment_token_prefix"`
	EnrollmentTokenLabel       string                 `json:"enrollment_token_label"`
	EnrollmentTokenStatus      string                 `json:"enrollment_token_status"`
	ApprovedEnrollmentID       int64                  `json:"approved_enrollment_id"`
	ApprovedAtUnix             int64                  `json:"approved_at_unix"`
	ApprovedBy                 string                 `json:"approved_by"`
	CreatedAtUnix              int64                  `json:"created_at_unix"`
	UpdatedAtUnix              int64                  `json:"updated_at_unix"`
	RevokedAtUnix              int64                  `json:"revoked_at_unix"`
	RevokedBy                  string                 `json:"revoked_by"`
	ArchivedAtUnix             int64                  `json:"archived_at_unix"`
	ArchivedBy                 string                 `json:"archived_by"`
	LastSeenAtUnix             int64                  `json:"last_seen_at_unix"`
	RuntimeRole                string                 `json:"runtime_role"`
	BuildVersion               string                 `json:"build_version"`
	GoVersion                  string                 `json:"go_version"`
	OS                         string                 `json:"os"`
	Arch                       string                 `json:"arch"`
	KernelVersion              string                 `json:"kernel_version"`
	DistroID                   string                 `json:"distro_id"`
	DistroIDLike               string                 `json:"distro_id_like"`
	DistroVersion              string                 `json:"distro_version"`
	RuntimeDeploymentSupported bool                   `json:"runtime_deployment_supported"`
	RuntimeInventory           []DeviceRuntimeSummary `json:"runtime_inventory,omitempty"`
	ConfigSnapshotRevision     string                 `json:"config_snapshot_revision"`
	ConfigSnapshotAtUnix       int64                  `json:"config_snapshot_at_unix"`
	ConfigSnapshotBytes        int64                  `json:"config_snapshot_bytes"`
}

type EnrollmentRecord struct {
	EnrollmentID               int64  `json:"enrollment_id"`
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Status                     string `json:"status"`
	EnrollmentTokenID          int64  `json:"enrollment_token_id"`
	EnrollmentTokenPrefix      string `json:"enrollment_token_prefix"`
	EnrollmentTokenLabel       string `json:"enrollment_token_label"`
	EnrollmentTokenStatus      string `json:"enrollment_token_status"`
	RequestedAtUnix            int64  `json:"requested_at_unix"`
	DecidedAtUnix              int64  `json:"decided_at_unix"`
	DecidedBy                  string `json:"decided_by"`
	DecisionReason             string `json:"decision_reason"`
	RemoteAddr                 string `json:"remote_addr"`
	UserAgent                  string `json:"user_agent"`
}

type enrollmentInsert struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyPEM               string
	PublicKeyFingerprintSHA256 string
	LicenseKeyHash             string
	NonceHash                  string
	BodyHash                   string
	SignatureB64               string
	RemoteAddr                 string
	UserAgent                  string
	RequestedAt                time.Time
}

type DeviceCounts struct {
	TotalDevices        int64 `json:"total_devices"`
	ApprovedDevices     int64 `json:"approved_devices"`
	PendingEnrollments  int64 `json:"pending_enrollments"`
	RejectedEnrollments int64 `json:"rejected_enrollments"`
}

type DeviceStatusRecord struct {
	DeviceID                   string
	KeyID                      string
	PublicKeyPEM               string
	PublicKeyFingerprintSHA256 string
	Status                     string
	ProductID                  string
	FromApprovedDevice         bool
}

type DeviceRuntimeInventory struct {
	RuntimeRole                string
	BuildVersion               string
	GoVersion                  string
	OS                         string
	Arch                       string
	KernelVersion              string
	DistroID                   string
	DistroIDLike               string
	DistroVersion              string
	RuntimeDeploymentSupported bool
	RuntimeInventory           []DeviceRuntimeSummary
}

type DeviceConfigSnapshotInsert struct {
	DeviceID       string
	Revision       string
	PayloadHash    string
	PayloadJSON    []byte
	ReceivedAtUnix int64
}

type DeviceConfigSnapshotRecord struct {
	DeviceID      string `json:"device_id"`
	Revision      string `json:"revision"`
	PayloadHash   string `json:"payload_hash"`
	PayloadJSON   []byte `json:"-"`
	SizeBytes     int64  `json:"size_bytes"`
	CreatedAtUnix int64  `json:"created_at_unix"`
	CreatedAt     string `json:"created_at"`
}

type DeviceConfigSnapshotListResult struct {
	Snapshots  []DeviceConfigSnapshotRecord `json:"snapshots"`
	Limit      int                          `json:"limit"`
	Offset     int                          `json:"offset"`
	NextOffset int                          `json:"next_offset"`
}

func CreatePendingEnrollment(ctx context.Context, in enrollmentInsert) (EnrollmentRecord, error) {
	if in.RequestedAt.IsZero() {
		in.RequestedAt = time.Now().UTC()
	}
	var out EnrollmentRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		requestedAtUnix := in.RequestedAt.Unix()
		if err := consumeEnrollmentTokenTx(ctx, tx, driver, in.LicenseKeyHash, in.DeviceID, requestedAtUnix); err != nil {
			return err
		}

		result, err := tx.ExecContext(ctx, `
INSERT INTO center_device_enrollments
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, license_key_hash,
     nonce_hash, body_hash, signature_b64, status, requested_at_unix, remote_addr, user_agent)
VALUES
    (`+placeholders(driver, 12, 1)+`)`,
			in.DeviceID,
			in.KeyID,
			in.PublicKeyPEM,
			in.PublicKeyFingerprintSHA256,
			in.LicenseKeyHash,
			in.NonceHash,
			in.BodyHash,
			in.SignatureB64,
			EnrollmentStatusPending,
			requestedAtUnix,
			clampString(in.RemoteAddr, 191),
			clampString(in.UserAgent, 512),
		)
		if err != nil {
			if isUniqueConstraintError(err) {
				return ErrEnrollmentReplay
			}
			return err
		}
		id, err := result.LastInsertId()
		if err != nil || id <= 0 {
			if err := loadEnrollmentByNonceTx(ctx, tx, driver, in.DeviceID, in.KeyID, in.NonceHash, &out); err != nil {
				return err
			}
			return tx.Commit()
		}
		rec, err := loadEnrollmentByIDTx(ctx, tx, driver, id)
		if err != nil {
			return err
		}
		out = rec
		return tx.Commit()
	})
	return out, err
}

func ListDevices(ctx context.Context, includeArchived bool) ([]DeviceRecord, error) {
	out := []DeviceRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		query := centerDeviceRecordSelect()
		args := []any{}
		if !includeArchived {
			query += " WHERE d.status <> " + placeholder(driver, 1)
			args = append(args, DeviceStatusArchived)
		}
		query += " ORDER BY d.updated_at_unix DESC, d.device_id ASC"
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rec DeviceRecord
			if err := scanDeviceRecord(rows, &rec); err != nil {
				_ = rows.Close()
				return err
			}
			out = append(out, rec)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return err
		}
		if err := rows.Close(); err != nil {
			return err
		}
		return attachRuntimeSummaries(ctx, db, driver, out)
	})
	return out, err
}

func ArchiveDeviceApproval(ctx context.Context, deviceID string, actor string) (DeviceRecord, error) {
	deviceID = clampString(deviceID, 191)
	if !deviceIDPattern.MatchString(deviceID) {
		return DeviceRecord{}, ErrDeviceStatusNotFound
	}
	actor = clampString(actor, 191)
	if actor == "" {
		actor = "unknown"
	}
	now := time.Now().UTC().Unix()
	var out DeviceRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		var current DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, deviceID, &current); err != nil {
			return err
		}
		if current.Status != DeviceStatusRevoked {
			return ErrDeviceArchiveInvalid
		}

		result, err := tx.ExecContext(ctx, `
UPDATE center_devices
   SET status = `+placeholder(driver, 1)+`,
       archived_at_unix = `+placeholder(driver, 2)+`,
       archived_by = `+placeholder(driver, 3)+`,
       updated_at_unix = `+placeholder(driver, 4)+`
 WHERE device_id = `+placeholder(driver, 5)+`
   AND status = `+placeholder(driver, 6),
			DeviceStatusArchived,
			now,
			actor,
			now,
			deviceID,
			DeviceStatusRevoked,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err == nil && affected == 0 {
			return ErrDeviceArchiveInvalid
		}
		if err := loadDeviceByIDTx(ctx, tx, driver, deviceID, &out); err != nil {
			return err
		}
		return tx.Commit()
	})
	return out, err
}

func RevokeDeviceApproval(ctx context.Context, deviceID string, actor string) (DeviceRecord, error) {
	deviceID = clampString(deviceID, 191)
	if !deviceIDPattern.MatchString(deviceID) {
		return DeviceRecord{}, ErrDeviceStatusNotFound
	}
	actor = clampString(actor, 191)
	if actor == "" {
		actor = "unknown"
	}
	now := time.Now().UTC().Unix()
	var out DeviceRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		result, err := tx.ExecContext(ctx, `
UPDATE center_devices
   SET status = `+placeholder(driver, 1)+`,
       revoked_at_unix = `+placeholder(driver, 2)+`,
       revoked_by = `+placeholder(driver, 3)+`,
       updated_at_unix = `+placeholder(driver, 4)+`
 WHERE device_id = `+placeholder(driver, 5),
			DeviceStatusRevoked,
			now,
			actor,
			now,
			deviceID,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err == nil && affected == 0 {
			return ErrDeviceStatusNotFound
		}
		if err := loadDeviceByIDTx(ctx, tx, driver, deviceID, &out); err != nil {
			return err
		}
		return tx.Commit()
	})
	return out, err
}

func ListEnrollments(ctx context.Context, status string, limit int) ([]EnrollmentRecord, error) {
	status = strings.ToLower(strings.TrimSpace(status))
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := []EnrollmentRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		query := `
SELECT e.enrollment_id, e.device_id, e.key_id, e.public_key_fingerprint_sha256, e.status,
       COALESCE(t.token_id, 0), COALESCE(t.token_prefix, ''), COALESCE(t.label, ''), COALESCE(t.status, ''),
       e.requested_at_unix, e.decided_at_unix, e.decided_by, e.decision_reason, e.remote_addr, e.user_agent
  FROM center_device_enrollments e
  LEFT JOIN center_enrollment_tokens t ON t.token_hash = e.license_key_hash`
		args := []any{}
		if status != "" && status != "all" {
			query += " WHERE e.status = " + placeholder(driver, 1)
			args = append(args, status)
		}
		query += " ORDER BY e.requested_at_unix DESC, e.enrollment_id DESC"
		if driver == "pgsql" {
			query += fmt.Sprintf(" LIMIT %d", limit)
		} else {
			query += " LIMIT ?"
			args = append(args, limit)
		}
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec EnrollmentRecord
			if err := rows.Scan(
				&rec.EnrollmentID,
				&rec.DeviceID,
				&rec.KeyID,
				&rec.PublicKeyFingerprintSHA256,
				&rec.Status,
				&rec.EnrollmentTokenID,
				&rec.EnrollmentTokenPrefix,
				&rec.EnrollmentTokenLabel,
				&rec.EnrollmentTokenStatus,
				&rec.RequestedAtUnix,
				&rec.DecidedAtUnix,
				&rec.DecidedBy,
				&rec.DecisionReason,
				&rec.RemoteAddr,
				&rec.UserAgent,
			); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func LookupDeviceStatus(ctx context.Context, deviceID string, keyID string, fingerprint string) (DeviceStatusRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	keyID = strings.TrimSpace(keyID)
	fingerprint = strings.ToLower(strings.TrimSpace(fingerprint))
	var out DeviceStatusRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		row := db.QueryRowContext(ctx, `
SELECT key_id, public_key_pem, public_key_fingerprint_sha256, status, product_id
  FROM center_devices
 WHERE device_id = `+placeholder(driver, 1),
			deviceID,
		)
		var approved DeviceStatusRecord
		approved.DeviceID = deviceID
		if err := row.Scan(
			&approved.KeyID,
			&approved.PublicKeyPEM,
			&approved.PublicKeyFingerprintSHA256,
			&approved.Status,
			&approved.ProductID,
		); err == nil {
			if approved.KeyID != keyID || !secureEqualHex(approved.PublicKeyFingerprintSHA256, fingerprint) {
				return ErrDeviceStatusKeyMismatch
			}
			approved.FromApprovedDevice = true
			out = approved
			return nil
		} else if !errors.Is(err, sql.ErrNoRows) {
			return err
		}

		query := `
SELECT device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status
  FROM center_device_enrollments
 WHERE device_id = ` + placeholder(driver, 1) + `
   AND key_id = ` + placeholder(driver, 2) + `
   AND public_key_fingerprint_sha256 = ` + placeholder(driver, 3) + `
 ORDER BY requested_at_unix DESC, enrollment_id DESC`
		args := []any{deviceID, keyID, fingerprint}
		if driver == "pgsql" {
			query += " LIMIT 1"
		} else {
			query += " LIMIT ?"
			args = append(args, 1)
		}
		row = db.QueryRowContext(ctx, query, args...)
		var enrollment DeviceStatusRecord
		if err := row.Scan(
			&enrollment.DeviceID,
			&enrollment.KeyID,
			&enrollment.PublicKeyPEM,
			&enrollment.PublicKeyFingerprintSHA256,
			&enrollment.Status,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}
		out = enrollment
		return nil
	})
	return out, err
}

func TouchApprovedDeviceHeartbeat(ctx context.Context, deviceID string, seenAtUnix int64, inventory DeviceRuntimeInventory) error {
	deviceID = strings.TrimSpace(deviceID)
	if deviceID == "" || seenAtUnix <= 0 {
		return nil
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		_, err = tx.ExecContext(ctx, `
UPDATE center_devices
   SET last_seen_at_unix = `+placeholder(driver, 1)+`,
       runtime_role = `+placeholder(driver, 2)+`,
       build_version = `+placeholder(driver, 3)+`,
       go_version = `+placeholder(driver, 4)+`,
       os = `+placeholder(driver, 5)+`,
       arch = `+placeholder(driver, 6)+`,
       kernel_version = `+placeholder(driver, 7)+`,
       distro_id = `+placeholder(driver, 8)+`,
       distro_id_like = `+placeholder(driver, 9)+`,
       distro_version = `+placeholder(driver, 10)+`,
       runtime_deployment_supported = `+placeholder(driver, 11)+`,
       updated_at_unix = `+placeholder(driver, 12)+`
 WHERE device_id = `+placeholder(driver, 13),
			seenAtUnix,
			inventory.RuntimeRole,
			inventory.BuildVersion,
			inventory.GoVersion,
			inventory.OS,
			inventory.Arch,
			inventory.KernelVersion,
			inventory.DistroID,
			inventory.DistroIDLike,
			inventory.DistroVersion,
			boolInt(inventory.RuntimeDeploymentSupported),
			seenAtUnix,
			deviceID,
		)
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM center_device_runtime_summaries WHERE device_id = `+placeholder(driver, 1), deviceID); err != nil {
			return err
		}
		for _, runtime := range inventory.RuntimeInventory {
			if isVirtualRuntimeRemovalSummary(runtime) {
				continue
			}
			if err := insertDeviceRuntimeSummaryTx(ctx, tx, driver, deviceID, runtime, seenAtUnix); err != nil {
				return err
			}
		}
		if err := updateRuntimeApplyStatusFromSummariesTx(ctx, tx, driver, deviceID, inventory.RuntimeInventory, seenAtUnix); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func isVirtualRuntimeRemovalSummary(runtime DeviceRuntimeSummary) bool {
	return strings.TrimSpace(runtime.ApplyState) == "removed" &&
		!runtime.Available &&
		strings.TrimSpace(runtime.Source) == "center"
}

func insertDeviceRuntimeSummaryTx(ctx context.Context, tx *sql.Tx, driver string, deviceID string, runtime DeviceRuntimeSummary, updatedAtUnix int64) error {
	targetsJSON, err := marshalRuntimeGeneratedTargets(runtime.GeneratedTargets)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_summaries
    (device_id, runtime_family, runtime_id, display_name, detected_version, source,
     available, availability_message, module_count, artifact_revision, artifact_hash,
     usage_reported, app_count, generated_targets_json, process_running, apply_state, apply_error, updated_at_unix)
VALUES
    (`+placeholders(driver, 18, 1)+`)`,
		deviceID,
		runtime.RuntimeFamily,
		runtime.RuntimeID,
		runtime.DisplayName,
		runtime.DetectedVersion,
		runtime.Source,
		boolInt(runtime.Available),
		runtime.AvailabilityMessage,
		runtime.ModuleCount,
		runtime.ArtifactRevision,
		runtime.ArtifactHash,
		boolInt(runtime.UsageReported),
		runtime.AppCount,
		targetsJSON,
		boolInt(runtime.ProcessRunning),
		runtime.ApplyState,
		runtime.ApplyError,
		updatedAtUnix,
	)
	return err
}

func attachRuntimeSummaries(ctx context.Context, db *sql.DB, driver string, devices []DeviceRecord) error {
	if len(devices) == 0 {
		return nil
	}
	indexByDeviceID := make(map[string]int, len(devices))
	args := make([]any, 0, len(devices))
	for i := range devices {
		indexByDeviceID[devices[i].DeviceID] = i
		args = append(args, devices[i].DeviceID)
	}
	rows, err := db.QueryContext(ctx, `
SELECT device_id, runtime_family, runtime_id, display_name, detected_version, source,
       available, availability_message, module_count, artifact_revision, artifact_hash,
       usage_reported, app_count, COALESCE(generated_targets_json, '[]'), process_running, apply_state, apply_error, updated_at_unix
  FROM center_device_runtime_summaries
 WHERE device_id IN (`+placeholders(driver, len(args), 1)+`)
 ORDER BY device_id ASC, runtime_family ASC, runtime_id ASC`, args...)
	if err != nil {
		return err
	}
	defer rows.Close()
	for rows.Next() {
		var deviceID string
		var available int
		var usageReported int
		var processRunning int
		var generatedTargetsJSON string
		var rec DeviceRuntimeSummary
		if err := rows.Scan(
			&deviceID,
			&rec.RuntimeFamily,
			&rec.RuntimeID,
			&rec.DisplayName,
			&rec.DetectedVersion,
			&rec.Source,
			&available,
			&rec.AvailabilityMessage,
			&rec.ModuleCount,
			&rec.ArtifactRevision,
			&rec.ArtifactHash,
			&usageReported,
			&rec.AppCount,
			&generatedTargetsJSON,
			&processRunning,
			&rec.ApplyState,
			&rec.ApplyError,
			&rec.UpdatedAtUnix,
		); err != nil {
			return err
		}
		rec.Available = available != 0
		rec.UsageReported = usageReported != 0
		rec.ProcessRunning = processRunning != 0
		rec.GeneratedTargets = unmarshalRuntimeGeneratedTargets(generatedTargetsJSON)
		if idx, ok := indexByDeviceID[deviceID]; ok {
			devices[idx].RuntimeInventory = append(devices[idx].RuntimeInventory, rec)
		}
	}
	return rows.Err()
}

func marshalRuntimeGeneratedTargets(targets []string) (string, error) {
	targets = normalizeDeviceRuntimeGeneratedTargets(targets)
	if len(targets) == 0 {
		return "[]", nil
	}
	raw, err := json.Marshal(targets)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func unmarshalRuntimeGeneratedTargets(raw string) []string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	var targets []string
	if err := json.Unmarshal([]byte(raw), &targets); err != nil {
		return nil
	}
	return normalizeDeviceRuntimeGeneratedTargets(targets)
}

func StoreDeviceConfigSnapshot(ctx context.Context, in DeviceConfigSnapshotInsert) (DeviceConfigSnapshotRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.Revision = strings.ToLower(strings.TrimSpace(in.Revision))
	in.PayloadHash = strings.ToLower(strings.TrimSpace(in.PayloadHash))
	if !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.Revision) || !hex64Pattern.MatchString(in.PayloadHash) {
		return DeviceConfigSnapshotRecord{}, ErrDeviceStatusNotFound
	}
	if len(in.PayloadJSON) == 0 || len(in.PayloadJSON) > MaxDeviceConfigSnapshotPayloadBytes {
		return DeviceConfigSnapshotRecord{}, ErrInvalidEnrollment
	}
	if in.ReceivedAtUnix <= 0 {
		in.ReceivedAtUnix = time.Now().UTC().Unix()
	}
	sizeBytes := int64(len(in.PayloadJSON))
	createdAt := time.Unix(in.ReceivedAtUnix, 0).UTC().Format(time.RFC3339)
	out := DeviceConfigSnapshotRecord{
		DeviceID:      in.DeviceID,
		Revision:      in.Revision,
		PayloadHash:   in.PayloadHash,
		PayloadJSON:   append([]byte(nil), in.PayloadJSON...),
		SizeBytes:     sizeBytes,
		CreatedAtUnix: in.ReceivedAtUnix,
		CreatedAt:     createdAt,
	}
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

		if err := upsertDeviceConfigSnapshotTx(ctx, tx, driver, out); err != nil {
			return err
		}
		result, err := tx.ExecContext(ctx, `
UPDATE center_devices
   SET config_snapshot_revision = `+placeholder(driver, 1)+`,
       config_snapshot_at_unix = `+placeholder(driver, 2)+`,
       config_snapshot_bytes = `+placeholder(driver, 3)+`,
       updated_at_unix = `+placeholder(driver, 4)+`
 WHERE device_id = `+placeholder(driver, 5)+`
   AND status = `+placeholder(driver, 6),
			out.Revision,
			out.CreatedAtUnix,
			out.SizeBytes,
			out.CreatedAtUnix,
			out.DeviceID,
			DeviceStatusApproved,
		)
		if err != nil {
			return err
		}
		if affected, err := result.RowsAffected(); err == nil && affected == 0 {
			return ErrDeviceStatusNotFound
		}
		return tx.Commit()
	})
	return out, err
}

func LoadLatestDeviceConfigSnapshot(ctx context.Context, deviceID string) (DeviceConfigSnapshotRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return DeviceConfigSnapshotRecord{}, ErrDeviceStatusNotFound
	}
	var out DeviceConfigSnapshotRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		row := db.QueryRowContext(ctx, `
SELECT s.device_id, s.revision, s.payload_hash, s.payload_json, s.size_bytes, s.created_at_unix, s.created_at
  FROM center_device_config_snapshots s
  JOIN center_devices d
    ON d.device_id = s.device_id
   AND d.config_snapshot_revision = s.revision
 WHERE s.device_id = `+placeholder(driver, 1),
			deviceID,
		)
		var payload string
		if err := row.Scan(
			&out.DeviceID,
			&out.Revision,
			&out.PayloadHash,
			&payload,
			&out.SizeBytes,
			&out.CreatedAtUnix,
			&out.CreatedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}
		out.PayloadJSON = []byte(payload)
		return nil
	})
	return out, err
}

func ListDeviceConfigSnapshots(ctx context.Context, deviceID string, limit int, offset int) (DeviceConfigSnapshotListResult, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return DeviceConfigSnapshotListResult{}, ErrDeviceStatusNotFound
	}
	if limit <= 0 {
		limit = 6
	}
	if limit > 6 {
		limit = 6
	}
	if offset < 0 {
		offset = 0
	}
	out := DeviceConfigSnapshotListResult{
		Snapshots: []DeviceConfigSnapshotRecord{},
		Limit:     limit,
		Offset:    offset,
	}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var exists int
		if err := db.QueryRowContext(ctx, `SELECT 1 FROM center_devices WHERE device_id = `+placeholder(driver, 1), deviceID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}

		query := `
SELECT device_id, revision, payload_hash, size_bytes, created_at_unix, created_at
  FROM center_device_config_snapshots
 WHERE device_id = ` + placeholder(driver, 1) + `
 ORDER BY created_at_unix DESC, snapshot_id DESC`
		args := []any{deviceID}
		fetchLimit := limit + 1
		switch driver {
		case "pgsql":
			query += fmt.Sprintf(" LIMIT %d OFFSET %d", fetchLimit, offset)
		default:
			query += " LIMIT " + placeholder(driver, 2) + " OFFSET " + placeholder(driver, 3)
			args = append(args, fetchLimit, offset)
		}
		rows, err := db.QueryContext(ctx, query, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec DeviceConfigSnapshotRecord
			if err := rows.Scan(
				&rec.DeviceID,
				&rec.Revision,
				&rec.PayloadHash,
				&rec.SizeBytes,
				&rec.CreatedAtUnix,
				&rec.CreatedAt,
			); err != nil {
				return err
			}
			if len(out.Snapshots) < limit {
				out.Snapshots = append(out.Snapshots, rec)
			} else {
				out.NextOffset = offset + limit
			}
		}
		return rows.Err()
	})
	return out, err
}

func LoadDeviceConfigSnapshot(ctx context.Context, deviceID string, revision string) (DeviceConfigSnapshotRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return DeviceConfigSnapshotRecord{}, ErrDeviceStatusNotFound
	}
	var out DeviceConfigSnapshotRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		row := db.QueryRowContext(ctx, `
SELECT device_id, revision, payload_hash, payload_json, size_bytes, created_at_unix, created_at
  FROM center_device_config_snapshots
 WHERE device_id = `+placeholder(driver, 1)+`
   AND revision = `+placeholder(driver, 2),
			deviceID,
			revision,
		)
		var payload string
		if err := row.Scan(
			&out.DeviceID,
			&out.Revision,
			&out.PayloadHash,
			&payload,
			&out.SizeBytes,
			&out.CreatedAtUnix,
			&out.CreatedAt,
		); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}
		out.PayloadJSON = []byte(payload)
		return nil
	})
	return out, err
}

func ApproveEnrollment(ctx context.Context, enrollmentID int64, actor string) (EnrollmentRecord, error) {
	return decideEnrollment(ctx, enrollmentID, actor, EnrollmentStatusApproved, "")
}

func RejectEnrollment(ctx context.Context, enrollmentID int64, actor string, reason string) (EnrollmentRecord, error) {
	return decideEnrollment(ctx, enrollmentID, actor, EnrollmentStatusRejected, reason)
}

func decideEnrollment(ctx context.Context, enrollmentID int64, actor string, status string, reason string) (EnrollmentRecord, error) {
	if enrollmentID <= 0 {
		return EnrollmentRecord{}, ErrEnrollmentNotFound
	}
	actor = strings.TrimSpace(actor)
	if actor == "" {
		actor = "unknown"
	}
	var out EnrollmentRecord
	now := time.Now().UTC().Unix()
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		enrollment, err := loadEnrollmentByIDTx(ctx, tx, driver, enrollmentID)
		if err != nil {
			return err
		}
		if enrollment.Status != EnrollmentStatusPending {
			return ErrEnrollmentAlreadyClosed
		}

		if _, err := tx.ExecContext(ctx, `
UPDATE center_device_enrollments
   SET status = `+placeholder(driver, 1)+`,
       decided_at_unix = `+placeholder(driver, 2)+`,
       decided_by = `+placeholder(driver, 3)+`,
       decision_reason = `+placeholder(driver, 4)+`
 WHERE enrollment_id = `+placeholder(driver, 5)+` AND status = `+placeholder(driver, 6),
			status,
			now,
			actor,
			clampString(strings.TrimSpace(reason), 1024),
			enrollmentID,
			EnrollmentStatusPending,
		); err != nil {
			return err
		}

		if status == EnrollmentStatusApproved {
			full, err := loadEnrollmentPrivateByIDTx(ctx, tx, driver, enrollmentID)
			if err != nil {
				return err
			}
			if err := upsertApprovedDeviceTx(ctx, tx, driver, full, actor, now); err != nil {
				return err
			}
		}

		if err := tx.Commit(); err != nil {
			return err
		}
		return withCenterDB(ctx, func(db *sql.DB, driver string) error {
			return loadEnrollmentByID(ctx, db, driver, enrollmentID, &out)
		})
	})
	return out, err
}

func CenterCounts(ctx context.Context) (DeviceCounts, error) {
	var out DeviceCounts
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM center_devices WHERE status <> `+placeholder(driver, 1), DeviceStatusArchived).Scan(&out.TotalDevices); err != nil {
			return err
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM center_devices WHERE status = `+placeholder(driver, 1), DeviceStatusApproved).Scan(&out.ApprovedDevices); err != nil {
			return err
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM center_device_enrollments WHERE status = `+placeholder(driver, 1), EnrollmentStatusPending).Scan(&out.PendingEnrollments); err != nil {
			return err
		}
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM center_device_enrollments WHERE status = `+placeholder(driver, 1), EnrollmentStatusRejected).Scan(&out.RejectedEnrollments); err != nil {
			return err
		}
		return nil
	})
	return out, err
}

type privateEnrollmentRecord struct {
	EnrollmentRecord
	PublicKeyPEM string
}

func loadEnrollmentByID(ctx context.Context, db *sql.DB, driver string, id int64, out *EnrollmentRecord) error {
	rec, err := loadEnrollmentByIDTx(ctx, db, driver, id)
	if err != nil {
		return err
	}
	*out = rec
	return nil
}

type queryer interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

type rowScanner interface {
	Scan(...any) error
}

func centerDeviceRecordSelect() string {
	return `
SELECT d.device_id, d.key_id, d.public_key_fingerprint_sha256, d.status, d.product_id,
       COALESCE(t.token_id, 0), COALESCE(t.token_prefix, ''), COALESCE(t.label, ''), COALESCE(t.status, ''),
       d.approved_enrollment_id, d.approved_at_unix, d.approved_by,
       d.created_at_unix, d.updated_at_unix, d.revoked_at_unix, d.revoked_by,
       d.archived_at_unix, d.archived_by, d.last_seen_at_unix,
       d.runtime_role, d.build_version, d.go_version,
       d.os, d.arch, d.kernel_version, d.distro_id, d.distro_id_like, d.distro_version,
       d.runtime_deployment_supported,
       d.config_snapshot_revision, d.config_snapshot_at_unix, d.config_snapshot_bytes
  FROM center_devices d
  LEFT JOIN center_device_enrollments e ON e.enrollment_id = d.approved_enrollment_id
  LEFT JOIN center_enrollment_tokens t ON t.token_hash = e.license_key_hash`
}

func scanDeviceRecord(scanner rowScanner, rec *DeviceRecord) error {
	var runtimeDeploymentSupported int
	if err := scanner.Scan(
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PublicKeyFingerprintSHA256,
		&rec.Status,
		&rec.ProductID,
		&rec.EnrollmentTokenID,
		&rec.EnrollmentTokenPrefix,
		&rec.EnrollmentTokenLabel,
		&rec.EnrollmentTokenStatus,
		&rec.ApprovedEnrollmentID,
		&rec.ApprovedAtUnix,
		&rec.ApprovedBy,
		&rec.CreatedAtUnix,
		&rec.UpdatedAtUnix,
		&rec.RevokedAtUnix,
		&rec.RevokedBy,
		&rec.ArchivedAtUnix,
		&rec.ArchivedBy,
		&rec.LastSeenAtUnix,
		&rec.RuntimeRole,
		&rec.BuildVersion,
		&rec.GoVersion,
		&rec.OS,
		&rec.Arch,
		&rec.KernelVersion,
		&rec.DistroID,
		&rec.DistroIDLike,
		&rec.DistroVersion,
		&runtimeDeploymentSupported,
		&rec.ConfigSnapshotRevision,
		&rec.ConfigSnapshotAtUnix,
		&rec.ConfigSnapshotBytes,
	); err != nil {
		return err
	}
	rec.RuntimeDeploymentSupported = runtimeDeploymentSupported != 0
	return nil
}

func loadDeviceByIDTx(ctx context.Context, q queryer, driver string, deviceID string, out *DeviceRecord) error {
	row := q.QueryRowContext(ctx, centerDeviceRecordSelect()+`
 WHERE d.device_id = `+placeholder(driver, 1), deviceID)
	var rec DeviceRecord
	if err := scanDeviceRecord(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrDeviceStatusNotFound
		}
		return err
	}
	*out = rec
	return nil
}

func loadEnrollmentByIDTx(ctx context.Context, q queryer, driver string, id int64) (EnrollmentRecord, error) {
	var rec EnrollmentRecord
	row := q.QueryRowContext(ctx, `
SELECT e.enrollment_id, e.device_id, e.key_id, e.public_key_fingerprint_sha256, e.status,
       COALESCE(t.token_id, 0), COALESCE(t.token_prefix, ''), COALESCE(t.label, ''), COALESCE(t.status, ''),
       e.requested_at_unix, e.decided_at_unix, e.decided_by, e.decision_reason, e.remote_addr, e.user_agent
  FROM center_device_enrollments e
  LEFT JOIN center_enrollment_tokens t ON t.token_hash = e.license_key_hash
 WHERE e.enrollment_id = `+placeholder(driver, 1), id)
	if err := row.Scan(
		&rec.EnrollmentID,
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PublicKeyFingerprintSHA256,
		&rec.Status,
		&rec.EnrollmentTokenID,
		&rec.EnrollmentTokenPrefix,
		&rec.EnrollmentTokenLabel,
		&rec.EnrollmentTokenStatus,
		&rec.RequestedAtUnix,
		&rec.DecidedAtUnix,
		&rec.DecidedBy,
		&rec.DecisionReason,
		&rec.RemoteAddr,
		&rec.UserAgent,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return EnrollmentRecord{}, ErrEnrollmentNotFound
		}
		return EnrollmentRecord{}, err
	}
	return rec, nil
}

func loadEnrollmentPrivateByIDTx(ctx context.Context, q queryer, driver string, id int64) (privateEnrollmentRecord, error) {
	var rec privateEnrollmentRecord
	row := q.QueryRowContext(ctx, `
SELECT enrollment_id, device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
       requested_at_unix, decided_at_unix, decided_by, decision_reason, remote_addr, user_agent
  FROM center_device_enrollments
 WHERE enrollment_id = `+placeholder(driver, 1), id)
	if err := row.Scan(
		&rec.EnrollmentID,
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PublicKeyPEM,
		&rec.PublicKeyFingerprintSHA256,
		&rec.Status,
		&rec.RequestedAtUnix,
		&rec.DecidedAtUnix,
		&rec.DecidedBy,
		&rec.DecisionReason,
		&rec.RemoteAddr,
		&rec.UserAgent,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return privateEnrollmentRecord{}, ErrEnrollmentNotFound
		}
		return privateEnrollmentRecord{}, err
	}
	return rec, nil
}

func loadEnrollmentByNonce(ctx context.Context, db *sql.DB, driver, deviceID, keyID, nonceHash string, out *EnrollmentRecord) error {
	return loadEnrollmentByNonceTx(ctx, db, driver, deviceID, keyID, nonceHash, out)
}

func loadEnrollmentByNonceTx(ctx context.Context, q queryer, driver, deviceID, keyID, nonceHash string, out *EnrollmentRecord) error {
	row := q.QueryRowContext(ctx, `
SELECT e.enrollment_id, e.device_id, e.key_id, e.public_key_fingerprint_sha256, e.status,
       COALESCE(t.token_id, 0), COALESCE(t.token_prefix, ''), COALESCE(t.label, ''), COALESCE(t.status, ''),
       e.requested_at_unix, e.decided_at_unix, e.decided_by, e.decision_reason, e.remote_addr, e.user_agent
  FROM center_device_enrollments e
  LEFT JOIN center_enrollment_tokens t ON t.token_hash = e.license_key_hash
 WHERE e.device_id = `+placeholder(driver, 1)+` AND e.key_id = `+placeholder(driver, 2)+` AND e.nonce_hash = `+placeholder(driver, 3),
		deviceID,
		keyID,
		nonceHash,
	)
	var rec EnrollmentRecord
	if err := row.Scan(
		&rec.EnrollmentID,
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PublicKeyFingerprintSHA256,
		&rec.Status,
		&rec.EnrollmentTokenID,
		&rec.EnrollmentTokenPrefix,
		&rec.EnrollmentTokenLabel,
		&rec.EnrollmentTokenStatus,
		&rec.RequestedAtUnix,
		&rec.DecidedAtUnix,
		&rec.DecidedBy,
		&rec.DecisionReason,
		&rec.RemoteAddr,
		&rec.UserAgent,
	); err != nil {
		return err
	}
	*out = rec
	return nil
}

func upsertApprovedDeviceTx(ctx context.Context, tx *sql.Tx, driver string, enrollment privateEnrollmentRecord, actor string, now int64) error {
	switch driver {
	case "pgsql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
     approved_enrollment_id, approved_at_unix, approved_by, created_at_unix, updated_at_unix)
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
ON CONFLICT (device_id) DO UPDATE SET
    key_id = EXCLUDED.key_id,
    public_key_pem = EXCLUDED.public_key_pem,
    public_key_fingerprint_sha256 = EXCLUDED.public_key_fingerprint_sha256,
    status = EXCLUDED.status,
    approved_enrollment_id = EXCLUDED.approved_enrollment_id,
    approved_at_unix = EXCLUDED.approved_at_unix,
    approved_by = EXCLUDED.approved_by,
    revoked_at_unix = 0,
    revoked_by = '',
    archived_at_unix = 0,
    archived_by = '',
    updated_at_unix = EXCLUDED.updated_at_unix`,
			enrollment.DeviceID,
			enrollment.KeyID,
			enrollment.PublicKeyPEM,
			enrollment.PublicKeyFingerprintSHA256,
			DeviceStatusApproved,
			enrollment.EnrollmentID,
			now,
			actor,
			now,
			now,
		)
		return err
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
     approved_enrollment_id, approved_at_unix, approved_by, created_at_unix, updated_at_unix)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    key_id = VALUES(key_id),
    public_key_pem = VALUES(public_key_pem),
    public_key_fingerprint_sha256 = VALUES(public_key_fingerprint_sha256),
    status = VALUES(status),
    approved_enrollment_id = VALUES(approved_enrollment_id),
    approved_at_unix = VALUES(approved_at_unix),
    approved_by = VALUES(approved_by),
    revoked_at_unix = 0,
    revoked_by = '',
    archived_at_unix = 0,
    archived_by = '',
    updated_at_unix = VALUES(updated_at_unix)`,
			enrollment.DeviceID,
			enrollment.KeyID,
			enrollment.PublicKeyPEM,
			enrollment.PublicKeyFingerprintSHA256,
			DeviceStatusApproved,
			enrollment.EnrollmentID,
			now,
			actor,
			now,
			now,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_devices
    (device_id, key_id, public_key_pem, public_key_fingerprint_sha256, status,
     approved_enrollment_id, approved_at_unix, approved_by, created_at_unix, updated_at_unix)
VALUES
    (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_id) DO UPDATE SET
    key_id = excluded.key_id,
    public_key_pem = excluded.public_key_pem,
    public_key_fingerprint_sha256 = excluded.public_key_fingerprint_sha256,
    status = excluded.status,
    approved_enrollment_id = excluded.approved_enrollment_id,
    approved_at_unix = excluded.approved_at_unix,
    approved_by = excluded.approved_by,
    revoked_at_unix = 0,
    revoked_by = '',
    archived_at_unix = 0,
    archived_by = '',
    updated_at_unix = excluded.updated_at_unix`,
			enrollment.DeviceID,
			enrollment.KeyID,
			enrollment.PublicKeyPEM,
			enrollment.PublicKeyFingerprintSHA256,
			DeviceStatusApproved,
			enrollment.EnrollmentID,
			now,
			actor,
			now,
			now,
		)
		return err
	}
}

func upsertDeviceConfigSnapshotTx(ctx context.Context, tx *sql.Tx, driver string, rec DeviceConfigSnapshotRecord) error {
	payload := string(rec.PayloadJSON)
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_config_snapshots
    (device_id, revision, payload_hash, payload_json, size_bytes, created_at_unix, created_at)
VALUES
    (?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    payload_hash = VALUES(payload_hash),
    payload_json = VALUES(payload_json),
    size_bytes = VALUES(size_bytes),
    created_at_unix = VALUES(created_at_unix),
    created_at = VALUES(created_at)`,
			rec.DeviceID,
			rec.Revision,
			rec.PayloadHash,
			payload,
			rec.SizeBytes,
			rec.CreatedAtUnix,
			rec.CreatedAt,
		)
		return err
	case "pgsql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_config_snapshots
    (device_id, revision, payload_hash, payload_json, size_bytes, created_at_unix, created_at)
VALUES
    ($1, $2, $3, $4, $5, $6, $7)
ON CONFLICT (device_id, revision) DO UPDATE SET
    payload_hash = EXCLUDED.payload_hash,
    payload_json = EXCLUDED.payload_json,
    size_bytes = EXCLUDED.size_bytes,
    created_at_unix = EXCLUDED.created_at_unix,
    created_at = EXCLUDED.created_at`,
			rec.DeviceID,
			rec.Revision,
			rec.PayloadHash,
			payload,
			rec.SizeBytes,
			rec.CreatedAtUnix,
			rec.CreatedAt,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_config_snapshots
    (device_id, revision, payload_hash, payload_json, size_bytes, created_at_unix, created_at)
VALUES
    (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(device_id, revision) DO UPDATE SET
    payload_hash = excluded.payload_hash,
    payload_json = excluded.payload_json,
    size_bytes = excluded.size_bytes,
    created_at_unix = excluded.created_at_unix,
    created_at = excluded.created_at`,
			rec.DeviceID,
			rec.Revision,
			rec.PayloadHash,
			payload,
			rec.SizeBytes,
			rec.CreatedAtUnix,
			rec.CreatedAt,
		)
		return err
	}
}

func withCenterDB(ctx context.Context, fn func(*sql.DB, string) error) error {
	if ctx == nil {
		ctx = context.Background()
	}
	return handler.WithConfigDBStore(func(db *sql.DB, driver string) error {
		driver = strings.ToLower(strings.TrimSpace(driver))
		if driver == "" {
			driver = "sqlite"
		}
		return fn(db, driver)
	})
}

func placeholder(driver string, n int) string {
	if driver == "pgsql" {
		return fmt.Sprintf("$%d", n)
	}
	return "?"
}

func placeholders(driver string, count int, start int) string {
	parts := make([]string, 0, count)
	for i := 0; i < count; i++ {
		parts = append(parts, placeholder(driver, start+i))
	}
	return strings.Join(parts, ", ")
}

func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func isUniqueConstraintError(err error) bool {
	if err == nil {
		return false
	}
	s := strings.ToLower(err.Error())
	return strings.Contains(s, "unique") || strings.Contains(s, "duplicate")
}

func clampString(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if maxBytes <= 0 || len(value) <= maxBytes {
		return value
	}
	return value[:maxBytes]
}
