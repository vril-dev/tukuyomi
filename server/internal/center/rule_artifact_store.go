package center

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"tukuyomi/internal/edgeartifactbundle"
)

const (
	RuleArtifactBundleSourceGateway = "gateway"
	RuleArtifactBundleSourceCenter  = "center"
)

type RuleArtifactBundleInsert struct {
	DeviceID         string
	BundleRevision   string
	BundleHash       string
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
	Files            []edgeartifactbundle.ParsedFile
	ReceivedAtUnix   int64
	Source           string
}

type RuleArtifactBundleRecord struct {
	DeviceID         string `json:"device_id"`
	BundleRevision   string `json:"bundle_revision"`
	BundleHash       string `json:"bundle_hash"`
	CompressedSize   int64  `json:"compressed_size"`
	UncompressedSize int64  `json:"uncompressed_size"`
	FileCount        int    `json:"file_count"`
	CreatedAtUnix    int64  `json:"created_at_unix"`
	CreatedAt        string `json:"created_at"`
	Source           string `json:"source"`
	Stored           bool   `json:"stored"`
}

func StoreRuleArtifactBundle(ctx context.Context, in RuleArtifactBundleInsert) (RuleArtifactBundleRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.BundleRevision = strings.ToLower(strings.TrimSpace(in.BundleRevision))
	in.BundleHash = strings.ToLower(strings.TrimSpace(in.BundleHash))
	in.Source = normalizeRuleArtifactBundleSource(in.Source)
	if !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.BundleRevision) || !hex64Pattern.MatchString(in.BundleHash) {
		return RuleArtifactBundleRecord{}, ErrDeviceStatusNotFound
	}
	if in.CompressedSize <= 0 || in.CompressedSize > edgeartifactbundle.MaxCompressedBytes ||
		in.UncompressedSize <= 0 || in.UncompressedSize > edgeartifactbundle.MaxUncompressedBytes ||
		in.FileCount <= 0 || in.FileCount > edgeartifactbundle.MaxFiles ||
		len(in.Files) != in.FileCount {
		return RuleArtifactBundleRecord{}, ErrInvalidEnrollment
	}
	if in.ReceivedAtUnix <= 0 {
		in.ReceivedAtUnix = time.Now().UTC().Unix()
	}
	createdAt := time.Unix(in.ReceivedAtUnix, 0).UTC().Format(time.RFC3339)
	out := RuleArtifactBundleRecord{
		DeviceID:         in.DeviceID,
		BundleRevision:   in.BundleRevision,
		BundleHash:       in.BundleHash,
		CompressedSize:   in.CompressedSize,
		UncompressedSize: in.UncompressedSize,
		FileCount:        in.FileCount,
		CreatedAtUnix:    in.ReceivedAtUnix,
		CreatedAt:        createdAt,
		Source:           in.Source,
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

		existing, found, err := loadRuleArtifactBundleTx(ctx, tx, driver, in.DeviceID, in.BundleRevision)
		if err != nil {
			return err
		}
		if found {
			if in.Source == RuleArtifactBundleSourceCenter && existing.Source != RuleArtifactBundleSourceCenter {
				if err := updateRuleArtifactBundleSourceTx(ctx, tx, driver, in.DeviceID, in.BundleRevision, RuleArtifactBundleSourceCenter); err != nil {
					return err
				}
				existing.Source = RuleArtifactBundleSourceCenter
			}
			existing.Stored = false
			out = existing
			return tx.Commit()
		}
		if err := insertRuleArtifactBundleTx(ctx, tx, driver, in, createdAt); err != nil {
			if isUniqueConstraintError(err) {
				existing, found, loadErr := loadRuleArtifactBundleTx(ctx, tx, driver, in.DeviceID, in.BundleRevision)
				if loadErr != nil {
					return loadErr
				}
				if found {
					if in.Source == RuleArtifactBundleSourceCenter && existing.Source != RuleArtifactBundleSourceCenter {
						if err := updateRuleArtifactBundleSourceTx(ctx, tx, driver, in.DeviceID, in.BundleRevision, RuleArtifactBundleSourceCenter); err != nil {
							return err
						}
						existing.Source = RuleArtifactBundleSourceCenter
					}
					existing.Stored = false
					out = existing
					return tx.Commit()
				}
			}
			return err
		}
		for _, file := range in.Files {
			if err := insertRuleArtifactFileTx(ctx, tx, driver, in.DeviceID, in.BundleRevision, file); err != nil {
				return err
			}
		}
		out.Stored = true
		return tx.Commit()
	})
	return out, err
}

func updateRuleArtifactBundleSourceTx(ctx context.Context, tx *sql.Tx, driver, deviceID, revision, source string) error {
	_, err := tx.ExecContext(ctx, `
UPDATE center_rule_artifact_bundles
   SET source = `+placeholder(driver, 1)+`
 WHERE device_id = `+placeholder(driver, 2)+`
   AND bundle_revision = `+placeholder(driver, 3),
		normalizeRuleArtifactBundleSource(source),
		deviceID,
		revision,
	)
	return err
}

func loadRuleArtifactBundleTx(ctx context.Context, q queryer, driver, deviceID, revision string) (RuleArtifactBundleRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, bundle_revision, bundle_hash, compressed_size_bytes, uncompressed_size_bytes, file_count, created_at_unix, created_at, source
  FROM center_rule_artifact_bundles
 WHERE device_id = `+placeholder(driver, 1)+`
   AND bundle_revision = `+placeholder(driver, 2),
		deviceID,
		revision,
	)
	var rec RuleArtifactBundleRecord
	if err := row.Scan(
		&rec.DeviceID,
		&rec.BundleRevision,
		&rec.BundleHash,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.CreatedAtUnix,
		&rec.CreatedAt,
		&rec.Source,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuleArtifactBundleRecord{}, false, nil
		}
		return RuleArtifactBundleRecord{}, false, err
	}
	return rec, true, nil
}

func insertRuleArtifactBundleTx(ctx context.Context, tx *sql.Tx, driver string, in RuleArtifactBundleInsert, createdAt string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_rule_artifact_bundles
    (device_id, bundle_revision, bundle_hash, compressed_size_bytes, uncompressed_size_bytes, file_count, created_at_unix, created_at, source)
VALUES
    (`+placeholders(driver, 9, 1)+`)`,
		in.DeviceID,
		in.BundleRevision,
		in.BundleHash,
		in.CompressedSize,
		in.UncompressedSize,
		in.FileCount,
		in.ReceivedAtUnix,
		createdAt,
		in.Source,
	)
	return err
}

func normalizeRuleArtifactBundleSource(source string) string {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case RuleArtifactBundleSourceCenter:
		return RuleArtifactBundleSourceCenter
	default:
		return RuleArtifactBundleSourceGateway
	}
}

func insertRuleArtifactFileTx(ctx context.Context, tx *sql.Tx, driver string, deviceID, revision string, file edgeartifactbundle.ParsedFile) error {
	disabled := 0
	if file.Disabled {
		disabled = 1
	}
	switch driver {
	case "pgsql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_rule_artifact_files
    (device_id, bundle_revision, asset_path, archive_path, asset_kind, etag, disabled, sha256, size_bytes, body)
VALUES
    (`+placeholders(driver, 10, 1)+`)`,
			deviceID,
			revision,
			file.Path,
			file.ArchivePath,
			file.Kind,
			file.ETag,
			file.Disabled,
			file.SHA256,
			file.SizeBytes,
			file.Body,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_rule_artifact_files
    (device_id, bundle_revision, asset_path, archive_path, asset_kind, etag, disabled, sha256, size_bytes, body)
VALUES
    (`+placeholders(driver, 10, 1)+`)`,
			deviceID,
			revision,
			file.Path,
			file.ArchivePath,
			file.Kind,
			file.ETag,
			disabled,
			file.SHA256,
			file.SizeBytes,
			file.Body,
		)
		return err
	}
}

func validateParsedRuleArtifactUpload(verified verifiedRuleArtifactBundleRequest, parsed edgeartifactbundle.Parsed) error {
	if parsed.Revision != verified.BundleRevision {
		return fmt.Errorf("%w: bundle_revision mismatch", ErrInvalidEnrollment)
	}
	if parsed.BundleHash != verified.BundleHash {
		return fmt.Errorf("%w: bundle_hash mismatch", ErrInvalidEnrollment)
	}
	if parsed.CompressedSize != verified.CompressedSize {
		return fmt.Errorf("%w: compressed_size mismatch", ErrInvalidEnrollment)
	}
	if parsed.UncompressedSize != verified.UncompressedSize {
		return fmt.Errorf("%w: uncompressed_size mismatch", ErrInvalidEnrollment)
	}
	if parsed.FileCount != verified.FileCount {
		return fmt.Errorf("%w: file_count mismatch", ErrInvalidEnrollment)
	}
	return nil
}
