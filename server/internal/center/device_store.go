package center

import (
	"context"
	"database/sql"
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
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Status                     string `json:"status"`
	ProductID                  string `json:"product_id"`
	EnrollmentTokenPrefix      string `json:"enrollment_token_prefix"`
	EnrollmentTokenLabel       string `json:"enrollment_token_label"`
	EnrollmentTokenStatus      string `json:"enrollment_token_status"`
	ApprovedEnrollmentID       int64  `json:"approved_enrollment_id"`
	ApprovedAtUnix             int64  `json:"approved_at_unix"`
	ApprovedBy                 string `json:"approved_by"`
	CreatedAtUnix              int64  `json:"created_at_unix"`
	UpdatedAtUnix              int64  `json:"updated_at_unix"`
	RevokedAtUnix              int64  `json:"revoked_at_unix"`
	RevokedBy                  string `json:"revoked_by"`
	ArchivedAtUnix             int64  `json:"archived_at_unix"`
	ArchivedBy                 string `json:"archived_by"`
	LastSeenAtUnix             int64  `json:"last_seen_at_unix"`
	RuntimeRole                string `json:"runtime_role"`
	BuildVersion               string `json:"build_version"`
	GoVersion                  string `json:"go_version"`
}

type EnrollmentRecord struct {
	EnrollmentID               int64  `json:"enrollment_id"`
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Status                     string `json:"status"`
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
	RuntimeRole  string
	BuildVersion string
	GoVersion    string
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
		defer rows.Close()
		for rows.Next() {
			var rec DeviceRecord
			if err := scanDeviceRecord(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
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
SELECT enrollment_id, device_id, key_id, public_key_fingerprint_sha256, status,
       requested_at_unix, decided_at_unix, decided_by, decision_reason, remote_addr, user_agent
  FROM center_device_enrollments`
		args := []any{}
		if status != "" && status != "all" {
			query += " WHERE status = " + placeholder(driver, 1)
			args = append(args, status)
		}
		query += " ORDER BY requested_at_unix DESC, enrollment_id DESC"
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
		_, err := db.ExecContext(ctx, `
UPDATE center_devices
   SET last_seen_at_unix = `+placeholder(driver, 1)+`,
       runtime_role = `+placeholder(driver, 2)+`,
       build_version = `+placeholder(driver, 3)+`,
       go_version = `+placeholder(driver, 4)+`,
       updated_at_unix = `+placeholder(driver, 5)+`
 WHERE device_id = `+placeholder(driver, 6),
			seenAtUnix,
			inventory.RuntimeRole,
			inventory.BuildVersion,
			inventory.GoVersion,
			seenAtUnix,
			deviceID,
		)
		return err
	})
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
       COALESCE(t.token_prefix, ''), COALESCE(t.label, ''), COALESCE(t.status, ''),
       d.approved_enrollment_id, d.approved_at_unix, d.approved_by,
       d.created_at_unix, d.updated_at_unix, d.revoked_at_unix, d.revoked_by,
       d.archived_at_unix, d.archived_by, d.last_seen_at_unix,
       d.runtime_role, d.build_version, d.go_version
  FROM center_devices d
  LEFT JOIN center_device_enrollments e ON e.enrollment_id = d.approved_enrollment_id
  LEFT JOIN center_enrollment_tokens t ON t.token_hash = e.license_key_hash`
}

func scanDeviceRecord(scanner rowScanner, rec *DeviceRecord) error {
	return scanner.Scan(
		&rec.DeviceID,
		&rec.KeyID,
		&rec.PublicKeyFingerprintSHA256,
		&rec.Status,
		&rec.ProductID,
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
	)
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
SELECT enrollment_id, device_id, key_id, public_key_fingerprint_sha256, status,
       requested_at_unix, decided_at_unix, decided_by, decision_reason, remote_addr, user_agent
  FROM center_device_enrollments
 WHERE enrollment_id = `+placeholder(driver, 1), id)
	if err := row.Scan(
		&rec.EnrollmentID,
		&rec.DeviceID,
		&rec.KeyID,
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
SELECT enrollment_id, device_id, key_id, public_key_fingerprint_sha256, status,
       requested_at_unix, decided_at_unix, decided_by, decision_reason, remote_addr, user_agent
  FROM center_device_enrollments
 WHERE device_id = `+placeholder(driver, 1)+` AND key_id = `+placeholder(driver, 2)+` AND nonce_hash = `+placeholder(driver, 3),
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
