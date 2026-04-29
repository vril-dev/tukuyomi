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
	DeviceStatusApproved = "approved"

	EnrollmentStatusPending  = "pending"
	EnrollmentStatusApproved = "approved"
	EnrollmentStatusRejected = "rejected"
)

var (
	ErrEnrollmentReplay        = errors.New("device enrollment nonce was already used")
	ErrEnrollmentNotFound      = errors.New("device enrollment not found")
	ErrEnrollmentAlreadyClosed = errors.New("device enrollment is already closed")
)

type DeviceRecord struct {
	DeviceID                   string `json:"device_id"`
	KeyID                      string `json:"key_id"`
	PublicKeyFingerprintSHA256 string `json:"public_key_fingerprint_sha256"`
	Status                     string `json:"status"`
	ApprovedEnrollmentID       int64  `json:"approved_enrollment_id"`
	ApprovedAtUnix             int64  `json:"approved_at_unix"`
	ApprovedBy                 string `json:"approved_by"`
	CreatedAtUnix              int64  `json:"created_at_unix"`
	UpdatedAtUnix              int64  `json:"updated_at_unix"`
	LastSeenAtUnix             int64  `json:"last_seen_at_unix"`
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

func CreatePendingEnrollment(ctx context.Context, in enrollmentInsert) (EnrollmentRecord, error) {
	if in.RequestedAt.IsZero() {
		in.RequestedAt = time.Now().UTC()
	}
	var out EnrollmentRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		result, err := db.ExecContext(ctx, `
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
			in.RequestedAt.Unix(),
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
			return loadEnrollmentByNonce(ctx, db, driver, in.DeviceID, in.KeyID, in.NonceHash, &out)
		}
		return loadEnrollmentByID(ctx, db, driver, id, &out)
	})
	return out, err
}

func ListDevices(ctx context.Context) ([]DeviceRecord, error) {
	out := []DeviceRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		rows, err := db.QueryContext(ctx, `
SELECT device_id, key_id, public_key_fingerprint_sha256, status, approved_enrollment_id,
       approved_at_unix, approved_by, created_at_unix, updated_at_unix, last_seen_at_unix
  FROM center_devices
 ORDER BY updated_at_unix DESC, device_id ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec DeviceRecord
			if err := rows.Scan(
				&rec.DeviceID,
				&rec.KeyID,
				&rec.PublicKeyFingerprintSHA256,
				&rec.Status,
				&rec.ApprovedEnrollmentID,
				&rec.ApprovedAtUnix,
				&rec.ApprovedBy,
				&rec.CreatedAtUnix,
				&rec.UpdatedAtUnix,
				&rec.LastSeenAtUnix,
			); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
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
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM center_devices`).Scan(&out.TotalDevices); err != nil {
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
	row := db.QueryRowContext(ctx, `
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
