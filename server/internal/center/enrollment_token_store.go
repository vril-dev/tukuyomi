package center

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	EnrollmentTokenStatusActive  = "active"
	EnrollmentTokenStatusRevoked = "revoked"

	EnrollmentTokenDefaultMaxUses = 10

	enrollmentTokenPlainPrefix = "tky_enroll_"
	enrollmentTokenRandomBytes = 32
	enrollmentTokenMaxBytes    = 256
)

var (
	ErrEnrollmentTokenRequired = errors.New("enrollment token required")
	ErrEnrollmentTokenInvalid  = errors.New("invalid enrollment token")
	ErrEnrollmentTokenNotFound = errors.New("enrollment token not found")
	ErrEnrollmentTokenRequest  = errors.New("invalid enrollment token request")
)

type EnrollmentTokenRecord struct {
	TokenID          int64  `json:"token_id"`
	TokenPrefix      string `json:"token_prefix"`
	Label            string `json:"label"`
	Status           string `json:"status"`
	MaxUses          int64  `json:"max_uses"`
	UseCount         int64  `json:"use_count"`
	ExpiresAtUnix    int64  `json:"expires_at_unix"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	CreatedBy        string `json:"created_by"`
	RevokedAtUnix    int64  `json:"revoked_at_unix"`
	RevokedBy        string `json:"revoked_by"`
	LastUsedAtUnix   int64  `json:"last_used_at_unix"`
	LastUsedByDevice string `json:"last_used_by_device"`
}

type EnrollmentTokenCreate struct {
	Label         string
	MaxUses       int64
	ExpiresAtUnix int64
	CreatedBy     string
}

func CreateEnrollmentToken(ctx context.Context, in EnrollmentTokenCreate) (EnrollmentTokenRecord, string, error) {
	in.Label = clampString(in.Label, 191)
	in.CreatedBy = clampString(in.CreatedBy, 191)
	if in.CreatedBy == "" {
		in.CreatedBy = "unknown"
	}
	var settings CenterSettingsConfig
	settingsLoaded := false
	loadSettings := func() (CenterSettingsConfig, error) {
		if settingsLoaded {
			return settings, nil
		}
		loaded, _, err := LoadCenterSettings(ctx)
		if err != nil {
			return CenterSettingsConfig{}, err
		}
		settings = loaded
		settingsLoaded = true
		return settings, nil
	}
	if in.MaxUses <= 0 {
		settings, err := loadSettings()
		if err != nil {
			return EnrollmentTokenRecord{}, "", err
		}
		in.MaxUses = settings.EnrollmentTokenDefaultMaxUses
	}
	if in.MaxUses > 1000000 {
		in.MaxUses = 1000000
	}
	now := time.Now().UTC().Unix()
	if in.ExpiresAtUnix < 0 {
		return EnrollmentTokenRecord{}, "", ErrEnrollmentTokenRequest
	}
	if in.ExpiresAtUnix == 0 {
		settings, err := loadSettings()
		if err != nil {
			return EnrollmentTokenRecord{}, "", err
		}
		if settings.EnrollmentTokenDefaultTTLSeconds > 0 {
			in.ExpiresAtUnix = now + settings.EnrollmentTokenDefaultTTLSeconds
		}
	}
	if in.ExpiresAtUnix > 0 && in.ExpiresAtUnix <= now {
		return EnrollmentTokenRecord{}, "", ErrEnrollmentTokenRequest
	}

	var out EnrollmentTokenRecord
	var plain string
	for attempt := 0; attempt < 5; attempt++ {
		token, err := newEnrollmentTokenPlaintext()
		if err != nil {
			return EnrollmentTokenRecord{}, "", err
		}
		hash := enrollmentTokenHash(token)
		prefix := enrollmentTokenPrefix(token)
		err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
			result, err := db.ExecContext(ctx, `
INSERT INTO center_enrollment_tokens
    (token_hash, token_prefix, label, status, max_uses, use_count, expires_at_unix,
     created_at_unix, created_by, revoked_at_unix, revoked_by, last_used_at_unix, last_used_by_device)
VALUES
    (`+placeholders(driver, 13, 1)+`)`,
				hash,
				prefix,
				in.Label,
				EnrollmentTokenStatusActive,
				in.MaxUses,
				0,
				in.ExpiresAtUnix,
				now,
				in.CreatedBy,
				0,
				"",
				0,
				"",
			)
			if err != nil {
				if isUniqueConstraintError(err) {
					return ErrEnrollmentTokenInvalid
				}
				return err
			}
			id, err := result.LastInsertId()
			if err != nil || id <= 0 {
				return loadEnrollmentTokenByHash(ctx, db, driver, hash, &out)
			}
			return loadEnrollmentTokenByID(ctx, db, driver, id, &out)
		})
		if errors.Is(err, ErrEnrollmentTokenInvalid) {
			continue
		}
		if err != nil {
			return EnrollmentTokenRecord{}, "", err
		}
		plain = token
		return out, plain, nil
	}
	return EnrollmentTokenRecord{}, "", fmt.Errorf("create enrollment token: repeated token collision")
}

func ListEnrollmentTokens(ctx context.Context, limit int) ([]EnrollmentTokenRecord, error) {
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	out := []EnrollmentTokenRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		query := `
SELECT token_id, token_prefix, label, status, max_uses, use_count, expires_at_unix,
       created_at_unix, created_by, revoked_at_unix, revoked_by, last_used_at_unix, last_used_by_device
  FROM center_enrollment_tokens
 ORDER BY created_at_unix DESC, token_id DESC`
		args := []any{}
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
			var rec EnrollmentTokenRecord
			if err := rows.Scan(
				&rec.TokenID,
				&rec.TokenPrefix,
				&rec.Label,
				&rec.Status,
				&rec.MaxUses,
				&rec.UseCount,
				&rec.ExpiresAtUnix,
				&rec.CreatedAtUnix,
				&rec.CreatedBy,
				&rec.RevokedAtUnix,
				&rec.RevokedBy,
				&rec.LastUsedAtUnix,
				&rec.LastUsedByDevice,
			); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func RevokeEnrollmentToken(ctx context.Context, tokenID int64, actor string) (EnrollmentTokenRecord, error) {
	if tokenID <= 0 {
		return EnrollmentTokenRecord{}, ErrEnrollmentTokenNotFound
	}
	actor = clampString(actor, 191)
	if actor == "" {
		actor = "unknown"
	}
	now := time.Now().UTC().Unix()
	var out EnrollmentTokenRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		var tokenHash string
		err = tx.QueryRowContext(ctx, `
SELECT token_hash
  FROM center_enrollment_tokens
 WHERE token_id = `+placeholder(driver, 1),
			tokenID,
		).Scan(&tokenHash)
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrEnrollmentTokenNotFound
			}
			return err
		}

		result, err := tx.ExecContext(ctx, `
UPDATE center_enrollment_tokens
   SET status = `+placeholder(driver, 1)+`,
       revoked_at_unix = `+placeholder(driver, 2)+`,
       revoked_by = `+placeholder(driver, 3)+`
 WHERE token_id = `+placeholder(driver, 4),
			EnrollmentTokenStatusRevoked,
			now,
			actor,
			tokenID,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		if err == nil && affected == 0 {
			return ErrEnrollmentTokenNotFound
		}
		_, err = tx.ExecContext(ctx, `
UPDATE center_device_enrollments
   SET status = `+placeholder(driver, 1)+`,
       decided_at_unix = `+placeholder(driver, 2)+`,
       decided_by = `+placeholder(driver, 3)+`,
       decision_reason = `+placeholder(driver, 4)+`
 WHERE license_key_hash = `+placeholder(driver, 5)+`
   AND status = `+placeholder(driver, 6),
			EnrollmentStatusRejected,
			now,
			actor,
			"enrollment token revoked",
			tokenHash,
			EnrollmentStatusPending,
		)
		if err != nil {
			return err
		}
		_, err = tx.ExecContext(ctx, `
UPDATE center_devices
   SET status = `+placeholder(driver, 1)+`,
       revoked_at_unix = `+placeholder(driver, 2)+`,
       revoked_by = `+placeholder(driver, 3)+`,
       updated_at_unix = `+placeholder(driver, 4)+`
 WHERE approved_enrollment_id IN (
       SELECT enrollment_id
         FROM center_device_enrollments
        WHERE license_key_hash = `+placeholder(driver, 5)+`
       )
   AND status <> `+placeholder(driver, 6),
			DeviceStatusRevoked,
			now,
			actor,
			now,
			tokenHash,
			DeviceStatusArchived,
		)
		if err != nil {
			return err
		}
		if err := loadEnrollmentTokenByID(ctx, tx, driver, tokenID, &out); err != nil {
			return err
		}
		return tx.Commit()
	})
	return out, err
}

func consumeEnrollmentTokenTx(ctx context.Context, tx *sql.Tx, driver string, tokenHash string, deviceID string, now int64) error {
	tokenHash = strings.ToLower(strings.TrimSpace(tokenHash))
	if tokenHash == "" {
		return ErrEnrollmentTokenRequired
	}
	if !hex64Pattern.MatchString(tokenHash) {
		return ErrEnrollmentTokenInvalid
	}
	deviceID = clampString(deviceID, 191)
	result, err := tx.ExecContext(ctx, `
UPDATE center_enrollment_tokens
   SET use_count = use_count + 1,
       last_used_at_unix = `+placeholder(driver, 1)+`,
       last_used_by_device = `+placeholder(driver, 2)+`
 WHERE token_hash = `+placeholder(driver, 3)+`
   AND status = `+placeholder(driver, 4)+`
   AND (expires_at_unix = 0 OR expires_at_unix >= `+placeholder(driver, 5)+`)
   AND (max_uses = 0 OR use_count < max_uses)`,
		now,
		deviceID,
		tokenHash,
		EnrollmentTokenStatusActive,
		now,
	)
	if err != nil {
		return err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if affected != 1 {
		return ErrEnrollmentTokenInvalid
	}
	return nil
}

func loadEnrollmentTokenByID(ctx context.Context, q queryer, driver string, id int64, out *EnrollmentTokenRecord) error {
	row := q.QueryRowContext(ctx, `
SELECT token_id, token_prefix, label, status, max_uses, use_count, expires_at_unix,
       created_at_unix, created_by, revoked_at_unix, revoked_by, last_used_at_unix, last_used_by_device
  FROM center_enrollment_tokens
 WHERE token_id = `+placeholder(driver, 1), id)
	return scanEnrollmentToken(row, out)
}

func loadEnrollmentTokenByHash(ctx context.Context, q queryer, driver string, hash string, out *EnrollmentTokenRecord) error {
	row := q.QueryRowContext(ctx, `
SELECT token_id, token_prefix, label, status, max_uses, use_count, expires_at_unix,
       created_at_unix, created_by, revoked_at_unix, revoked_by, last_used_at_unix, last_used_by_device
  FROM center_enrollment_tokens
 WHERE token_hash = `+placeholder(driver, 1), hash)
	return scanEnrollmentToken(row, out)
}

func scanEnrollmentToken(row *sql.Row, out *EnrollmentTokenRecord) error {
	var rec EnrollmentTokenRecord
	if err := row.Scan(
		&rec.TokenID,
		&rec.TokenPrefix,
		&rec.Label,
		&rec.Status,
		&rec.MaxUses,
		&rec.UseCount,
		&rec.ExpiresAtUnix,
		&rec.CreatedAtUnix,
		&rec.CreatedBy,
		&rec.RevokedAtUnix,
		&rec.RevokedBy,
		&rec.LastUsedAtUnix,
		&rec.LastUsedByDevice,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrEnrollmentTokenNotFound
		}
		return err
	}
	*out = rec
	return nil
}

func newEnrollmentTokenPlaintext() (string, error) {
	var raw [enrollmentTokenRandomBytes]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate enrollment token: %w", err)
	}
	return enrollmentTokenPlainPrefix + base64.RawURLEncoding.EncodeToString(raw[:]), nil
}

func enrollmentTokenHash(raw string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(raw)))
	return hex.EncodeToString(sum[:])
}

func enrollmentTokenPrefix(raw string) string {
	raw = strings.TrimSpace(raw)
	if len(raw) <= 18 {
		return raw
	}
	return raw[:18]
}
