package center

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path"
	"strconv"
	"strings"
	"time"
)

const (
	DaemonLogArchiveListLimit     = 20
	MaxDaemonLogArchiveBytes      = 16 * 1024 * 1024
	MaxDaemonLogUncompressedBytes = 32 * 1024 * 1024
)

type DaemonLogArchiveImport struct {
	DeviceID         string
	AppID            string
	ProcessID        string
	LogFile          string
	ArchiveName      string
	ArchiveHash      string
	CompressedSize   int64
	UncompressedSize int64
	RotatedAtUnix    int64
	Archive          []byte
}

type DaemonLogArchiveRecord struct {
	DeviceID         string `json:"device_id"`
	AppID            string `json:"app_id"`
	ArchiveRevision  string `json:"archive_revision"`
	ArchiveHash      string `json:"archive_hash"`
	ProcessID        string `json:"process_id,omitempty"`
	LogFile          string `json:"log_file,omitempty"`
	ArchiveName      string `json:"archive_name,omitempty"`
	CompressedSize   int64  `json:"compressed_size"`
	UncompressedSize int64  `json:"uncompressed_size"`
	RotatedAtUnix    int64  `json:"rotated_at_unix"`
	UploadedAtUnix   int64  `json:"uploaded_at_unix"`
	UploadedAt       string `json:"uploaded_at"`
}

func StoreDaemonLogArchive(ctx context.Context, in DaemonLogArchiveImport) (DaemonLogArchiveRecord, bool, error) {
	normalized, err := normalizeDaemonLogArchiveImport(in)
	if err != nil {
		return DaemonLogArchiveRecord{}, false, err
	}
	now := time.Now().UTC()
	out := DaemonLogArchiveRecord{
		DeviceID:         normalized.DeviceID,
		AppID:            normalized.AppID,
		ArchiveRevision:  daemonLogArchiveRevision(normalized.DeviceID, normalized.AppID, normalized.ArchiveHash, normalized.RotatedAtUnix),
		ArchiveHash:      normalized.ArchiveHash,
		ProcessID:        normalized.ProcessID,
		LogFile:          normalized.LogFile,
		ArchiveName:      normalized.ArchiveName,
		CompressedSize:   normalized.CompressedSize,
		UncompressedSize: normalized.UncompressedSize,
		RotatedAtUnix:    normalized.RotatedAtUnix,
		UploadedAtUnix:   now.Unix(),
		UploadedAt:       now.Format(time.RFC3339),
	}
	payloadExisted, err := writeCenterPayloadFile(
		centerPayloadDaemonLogArchives,
		out.ArchiveRevision,
		centerPayloadDaemonLogArchiveExt,
		normalized.Archive,
		normalized.CompressedSize,
		normalized.ArchiveHash,
	)
	if err != nil {
		return DaemonLogArchiveRecord{}, false, fmt.Errorf("%w: %v", ErrAppDeployInvalid, err)
	}
	created := true
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
			return ErrAppDeployIncompatible
		}
		if err := insertDaemonLogArchiveTx(ctx, tx, driver, out); err != nil {
			if isUniqueConstraintError(err) {
				existing, found, loadErr := loadDaemonLogArchiveForDeviceTx(ctx, tx, driver, normalized.DeviceID, out.ArchiveRevision)
				if loadErr != nil {
					return loadErr
				}
				if found && existing.AppID == out.AppID && existing.ArchiveHash == out.ArchiveHash {
					out = existing
					created = false
					return tx.Commit()
				}
			}
			return err
		}
		return tx.Commit()
	})
	if err != nil && !payloadExisted {
		removeCenterPayloadFile(centerPayloadDaemonLogArchives, out.ArchiveRevision, centerPayloadDaemonLogArchiveExt)
	}
	return out, created && err == nil, err
}

func ListDaemonLogArchivesForDevice(ctx context.Context, deviceID string, limit int) ([]DaemonLogArchiveRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrAppDeployInvalid
	}
	if limit <= 0 || limit > 100 {
		limit = DaemonLogArchiveListLimit
	}
	var out []DaemonLogArchiveRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		var err error
		out, err = listDaemonLogArchivesForDeviceTx(ctx, db, driver, deviceID, limit)
		return err
	})
	return out, err
}

func DownloadDaemonLogArchiveForDevice(ctx context.Context, deviceID, revision string) (DaemonLogArchiveRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return DaemonLogArchiveRecord{}, nil, ErrAppDeployInvalid
	}
	var out DaemonLogArchiveRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		rec, found, err := loadDaemonLogArchiveForDeviceTx(ctx, db, driver, deviceID, revision)
		if err != nil {
			return err
		}
		if !found {
			return ErrAppDeployNotFound
		}
		out = rec
		return nil
	})
	if err != nil {
		return DaemonLogArchiveRecord{}, nil, err
	}
	body, err := readCenterPayloadFile(centerPayloadDaemonLogArchives, out.ArchiveRevision, centerPayloadDaemonLogArchiveExt, out.CompressedSize, out.ArchiveHash)
	if err != nil {
		return DaemonLogArchiveRecord{}, nil, err
	}
	return out, body, nil
}

func DeleteDaemonLogArchiveForDevice(ctx context.Context, deviceID, revision string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return false, ErrAppDeployInvalid
	}
	var deleted bool
	var shouldRemovePayload bool
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
		rec, found, err := loadDaemonLogArchiveForDeviceTx(ctx, tx, driver, deviceID, revision)
		if err != nil {
			return err
		}
		if !found {
			return ErrAppDeployNotFound
		}
		res, err := tx.ExecContext(ctx, `
DELETE FROM center_daemon_log_archives
 WHERE device_id = `+placeholder(driver, 1)+`
   AND archive_revision = `+placeholder(driver, 2), deviceID, revision)
		if err != nil {
			return err
		}
		affected, _ := res.RowsAffected()
		deleted = affected > 0
		remaining, err := countDaemonLogArchivesByRevisionTx(ctx, tx, driver, rec.ArchiveRevision)
		if err != nil {
			return err
		}
		shouldRemovePayload = remaining == 0
		return tx.Commit()
	})
	if err != nil {
		return false, err
	}
	if deleted && shouldRemovePayload {
		removeCenterPayloadFile(centerPayloadDaemonLogArchives, revision, centerPayloadDaemonLogArchiveExt)
	}
	return deleted, nil
}

func normalizeDaemonLogArchiveImport(in DaemonLogArchiveImport) (DaemonLogArchiveImport, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.AppID = normalizeAppDeployID(in.AppID)
	in.ProcessID = normalizeAppDeployID(in.ProcessID)
	in.LogFile = cleanDaemonLogArchivePath(in.LogFile)
	in.ArchiveName = cleanDaemonLogArchiveName(in.ArchiveName)
	in.ArchiveHash = strings.ToLower(strings.TrimSpace(in.ArchiveHash))
	if !deviceIDPattern.MatchString(in.DeviceID) || in.AppID == "" {
		return DaemonLogArchiveImport{}, ErrAppDeployInvalid
	}
	if in.ArchiveName == "" {
		in.ArchiveName = "daemon-supervisor.log.gz"
	}
	if !hex64Pattern.MatchString(in.ArchiveHash) {
		return DaemonLogArchiveImport{}, ErrAppDeployInvalid
	}
	if in.CompressedSize <= 0 || int64(len(in.Archive)) != in.CompressedSize || in.CompressedSize > MaxDaemonLogArchiveBytes {
		return DaemonLogArchiveImport{}, ErrAppDeployInvalid
	}
	if in.UncompressedSize <= 0 || in.UncompressedSize > MaxDaemonLogUncompressedBytes {
		return DaemonLogArchiveImport{}, ErrAppDeployInvalid
	}
	if in.RotatedAtUnix <= 0 {
		in.RotatedAtUnix = time.Now().UTC().Unix()
	}
	sum := sha256.Sum256(in.Archive)
	if hex.EncodeToString(sum[:]) != in.ArchiveHash {
		return DaemonLogArchiveImport{}, ErrAppDeployInvalid
	}
	if err := verifyDaemonLogArchiveGzip(in.Archive, in.UncompressedSize); err != nil {
		return DaemonLogArchiveImport{}, err
	}
	return in, nil
}

func verifyDaemonLogArchiveGzip(body []byte, expectedUncompressedSize int64) error {
	zr, err := gzip.NewReader(bytes.NewReader(body))
	if err != nil {
		return ErrAppDeployInvalid
	}
	defer zr.Close()
	read, err := io.Copy(io.Discard, io.LimitReader(zr, MaxDaemonLogUncompressedBytes+1))
	if err != nil {
		return ErrAppDeployInvalid
	}
	if read > MaxDaemonLogUncompressedBytes || read != expectedUncompressedSize {
		return ErrAppDeployInvalid
	}
	return nil
}

func daemonLogArchiveRevision(deviceID, appID, archiveHash string, rotatedAtUnix int64) string {
	sum := sha256.Sum256([]byte("tukuyomi daemon log archive v1\x00" + deviceID + "\x00" + appID + "\x00" + archiveHash + "\x00" + strconv.FormatInt(rotatedAtUnix, 10)))
	return hex.EncodeToString(sum[:])
}

func cleanDaemonLogArchivePath(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.Contains(value, "\x00") || strings.HasPrefix(value, "/") {
		return ""
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return ""
	}
	return clampString(strings.Trim(cleaned, "/"), 512)
}

func cleanDaemonLogArchiveName(value string) string {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" || strings.Contains(value, "\x00") {
		return ""
	}
	base := path.Base(value)
	if base == "." || base == "/" {
		return ""
	}
	if !strings.HasSuffix(base, centerPayloadDaemonLogArchiveExt) {
		return ""
	}
	return clampString(base, 255)
}

func insertDaemonLogArchiveTx(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, driver string, rec DaemonLogArchiveRecord) error {
	_, err := q.ExecContext(ctx, `
INSERT INTO center_daemon_log_archives
  (device_id, app_id, archive_revision, archive_hash, process_id, log_file, archive_name,
   compressed_size, uncompressed_size, rotated_at_unix, uploaded_at_unix, uploaded_at)
VALUES (`+placeholders(driver, 12, 1)+`)`,
		rec.DeviceID,
		rec.AppID,
		rec.ArchiveRevision,
		rec.ArchiveHash,
		rec.ProcessID,
		rec.LogFile,
		rec.ArchiveName,
		rec.CompressedSize,
		rec.UncompressedSize,
		rec.RotatedAtUnix,
		rec.UploadedAtUnix,
		rec.UploadedAt,
	)
	return err
}

func loadDaemonLogArchiveForDeviceTx(ctx context.Context, q queryer, driver string, deviceID string, revision string) (DaemonLogArchiveRecord, bool, error) {
	row := q.QueryRowContext(ctx, daemonLogArchiveSelectSQL()+`
 WHERE device_id = `+placeholder(driver, 1)+`
   AND archive_revision = `+placeholder(driver, 2), deviceID, revision)
	var rec DaemonLogArchiveRecord
	if err := scanDaemonLogArchive(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DaemonLogArchiveRecord{}, false, nil
		}
		return DaemonLogArchiveRecord{}, false, err
	}
	return rec, true, nil
}

func listDaemonLogArchivesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]DaemonLogArchiveRecord, error) {
	rows, err := q.QueryContext(ctx, daemonLogArchiveSelectSQL()+`
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY uploaded_at_unix DESC, archive_revision DESC
 LIMIT `+placeholder(driver, 2), deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []DaemonLogArchiveRecord{}
	for rows.Next() {
		var rec DaemonLogArchiveRecord
		if err := scanDaemonLogArchive(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func countDaemonLogArchivesByRevisionTx(ctx context.Context, q queryer, driver string, revision string) (int64, error) {
	var count int64
	err := q.QueryRowContext(ctx, `
SELECT COUNT(*)
  FROM center_daemon_log_archives
 WHERE archive_revision = `+placeholder(driver, 1), revision).Scan(&count)
	return count, err
}

func daemonLogArchiveSelectSQL() string {
	return `
SELECT device_id, app_id, archive_revision, archive_hash, process_id, log_file, archive_name,
       compressed_size, uncompressed_size, rotated_at_unix, uploaded_at_unix, uploaded_at
  FROM center_daemon_log_archives`
}

func scanDaemonLogArchive(scanner rowScanner, rec *DaemonLogArchiveRecord) error {
	return scanner.Scan(
		&rec.DeviceID,
		&rec.AppID,
		&rec.ArchiveRevision,
		&rec.ArchiveHash,
		&rec.ProcessID,
		&rec.LogFile,
		&rec.ArchiveName,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.RotatedAtUnix,
		&rec.UploadedAtUnix,
		&rec.UploadedAt,
	)
}
