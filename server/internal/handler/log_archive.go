package handler

import (
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path"
	"strings"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/persistentstore"
)

const (
	logArchiveSourceWAFEvents = "waf_events"
	logArchiveStateWriting    = "writing"
	logArchiveStateSealed     = "sealed"
	logArchiveStatePruned     = "pruned"
	logArchiveStateFailed     = "failed"
)

type WAFLogArchiveResult struct {
	DaysProcessed int
	PartsWritten  int
	RowsArchived  int64
	RowsPruned    int64
}

type wafLogArchiveOptions struct {
	Now            time.Time
	RetentionDays  int
	Prefix         string
	MaxPartBytes   int64
	MaxPartRows    int
	MaxDaysPerRun  int
	StorageBackend string
	BlobStore      persistentstore.BlobStore
}

type logArchivePartRecord struct {
	ArchiveID         string
	Source            string
	ArchiveDay        string
	Part              int
	StorageBackend    string
	ObjectKey         string
	MetaObjectKey     string
	FromTSUnix        int64
	ToTSUnix          int64
	FirstEventID      int64
	LastEventID       int64
	RowCount          int64
	CompressedBytes   int64
	UncompressedBytes int64
	SHA256            string
	CreatedAt         time.Time
}

type logArchiveMetadataFile struct {
	SchemaVersion     int    `json:"schema_version"`
	Source            string `json:"source"`
	ArchiveDay        string `json:"archive_day"`
	Part              int    `json:"part"`
	FromTS            string `json:"from_ts"`
	ToTS              string `json:"to_ts"`
	FirstEventID      int64  `json:"first_event_id"`
	LastEventID       int64  `json:"last_event_id"`
	RowCount          int64  `json:"row_count"`
	CompressedBytes   int64  `json:"compressed_bytes"`
	UncompressedBytes int64  `json:"uncompressed_bytes"`
	SHA256            string `json:"sha256"`
	CreatedAt         string `json:"created_at"`
}

func RunWAFLogArchive(ctx context.Context) (WAFLogArchiveResult, error) {
	if err := ctx.Err(); err != nil {
		return WAFLogArchiveResult{}, err
	}
	if !config.LogArchiveEnabled || config.HotLogRetentionDays <= 0 {
		return WAFLogArchiveResult{}, nil
	}
	if err := FlushWAFEventAsync(ctx); err != nil {
		return WAFLogArchiveResult{}, fmt.Errorf("flush queued waf events before archive: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return WAFLogArchiveResult{}, errConfigDBStoreRequired
	}
	blobStore, err := persistentstore.NewBlobStoreFromConfig(persistentstore.BlobStoreConfig{
		Backend:      config.PersistentStorageBackend,
		LocalBaseDir: config.PersistentStorageLocalBaseDir,
		S3: persistentstore.S3CacheConfig{
			Bucket:         config.PersistentStorageS3Bucket,
			Region:         config.PersistentStorageS3Region,
			Endpoint:       config.PersistentStorageS3Endpoint,
			Prefix:         config.PersistentStorageS3Prefix,
			ForcePathStyle: config.PersistentStorageS3ForcePathStyle,
		},
	})
	if err != nil {
		return WAFLogArchiveResult{}, err
	}
	return store.archiveWAFLogs(ctx, wafLogArchiveOptions{
		Now:            time.Now().UTC(),
		RetentionDays:  config.HotLogRetentionDays,
		Prefix:         config.LogArchivePrefix,
		MaxPartBytes:   config.LogArchiveMaxPartBytes,
		MaxPartRows:    config.LogArchiveMaxPartRows,
		MaxDaysPerRun:  config.LogArchiveMaxDaysPerRun,
		StorageBackend: config.PersistentStorageBackend,
		BlobStore:      blobStore,
	})
}

func (s *wafEventStore) archiveWAFLogs(ctx context.Context, opts wafLogArchiveOptions) (WAFLogArchiveResult, error) {
	if s == nil || s.db == nil {
		return WAFLogArchiveResult{}, errConfigDBStoreRequired
	}
	if opts.BlobStore == nil {
		return WAFLogArchiveResult{}, fmt.Errorf("log archive blob store is nil")
	}
	if opts.RetentionDays <= 0 {
		return WAFLogArchiveResult{}, nil
	}
	opts.Now = opts.Now.UTC()
	if opts.Now.IsZero() {
		opts.Now = time.Now().UTC()
	}
	opts.Prefix = strings.Trim(strings.TrimSpace(strings.ReplaceAll(opts.Prefix, "\\", "/")), "/")
	if opts.Prefix == "" {
		opts.Prefix = config.DefaultLogArchivePrefix
	}
	if opts.MaxPartBytes <= 0 {
		opts.MaxPartBytes = config.DefaultLogArchiveMaxPartBytes
	}
	if opts.MaxPartRows <= 0 {
		opts.MaxPartRows = config.DefaultLogArchiveMaxPartRows
	}
	if opts.MaxDaysPerRun <= 0 {
		opts.MaxDaysPerRun = config.DefaultLogArchiveMaxDaysPerRun
	}
	opts.StorageBackend = strings.ToLower(strings.TrimSpace(opts.StorageBackend))
	if opts.StorageBackend == "" {
		opts.StorageBackend = config.DefaultPersistentStorageBackend
	}

	cutoffDay := utcDayStart(opts.Now).AddDate(0, 0, -opts.RetentionDays)

	s.mu.Lock()
	defer s.mu.Unlock()

	days, err := s.eligibleArchiveDays(cutoffDay, opts.MaxDaysPerRun)
	if err != nil {
		return WAFLogArchiveResult{}, err
	}
	var result WAFLogArchiveResult
	for _, day := range days {
		if err := ctx.Err(); err != nil {
			return result, err
		}
		dayResult, err := s.archiveWAFLogDay(ctx, opts, day)
		if err != nil {
			return result, err
		}
		if dayResult.RowsArchived > 0 || dayResult.RowsPruned > 0 {
			result.DaysProcessed++
		}
		result.PartsWritten += dayResult.PartsWritten
		result.RowsArchived += dayResult.RowsArchived
		result.RowsPruned += dayResult.RowsPruned
	}
	return result, nil
}

func (s *wafEventStore) eligibleArchiveDays(cutoffDay time.Time, maxDays int) ([]time.Time, error) {
	minTS, ok, err := s.minWAFEventTSBefore(cutoffDay.Unix())
	if err != nil || !ok {
		return nil, err
	}
	start := utcDayStart(time.Unix(minTS, 0).UTC())
	out := make([]time.Time, 0, maxDays)
	for day := start; day.Before(cutoffDay) && len(out) < maxDays; day = day.AddDate(0, 0, 1) {
		count, err := s.countWAFEventsForDay(day)
		if err != nil {
			return nil, err
		}
		if count > 0 {
			out = append(out, day)
		}
	}
	return out, nil
}

func (s *wafEventStore) archiveWAFLogDay(ctx context.Context, opts wafLogArchiveOptions, day time.Time) (WAFLogArchiveResult, error) {
	if pruned, err := s.pruneSealedWAFLogArchiveDay(ctx, day); err != nil || pruned > 0 {
		return WAFLogArchiveResult{RowsPruned: pruned}, err
	}
	if err := s.deleteRetryableWAFLogArchiveRecords(day); err != nil {
		return WAFLogArchiveResult{}, err
	}
	rowCount, err := s.countWAFEventsForDay(day)
	if err != nil || rowCount == 0 {
		return WAFLogArchiveResult{}, err
	}
	maxPart, err := s.maxLogArchivePart(logArchiveSourceWAFEvents, archiveDayString(day))
	if err != nil {
		return WAFLogArchiveResult{}, err
	}
	parts, err := s.writeWAFLogArchiveDayParts(ctx, opts, day, maxPart+1)
	if err != nil {
		_ = s.insertFailedLogArchiveRecord(day, maxPart+1, opts, err)
		return WAFLogArchiveResult{}, err
	}
	if len(parts) == 0 {
		return WAFLogArchiveResult{}, nil
	}
	if err := s.insertSealedLogArchiveParts(parts); err != nil {
		return WAFLogArchiveResult{}, err
	}
	pruned, err := s.pruneSealedWAFLogArchiveDay(ctx, day)
	if err != nil {
		return WAFLogArchiveResult{}, err
	}
	var archived int64
	for _, part := range parts {
		archived += part.RowCount
	}
	return WAFLogArchiveResult{PartsWritten: len(parts), RowsArchived: archived, RowsPruned: pruned}, nil
}

func (s *wafEventStore) writeWAFLogArchiveDayParts(ctx context.Context, opts wafLogArchiveOptions, day time.Time, firstPart int) ([]logArchivePartRecord, error) {
	dayStart := day.Unix()
	dayEnd := day.AddDate(0, 0, 1).Unix()
	rows, err := s.query(`SELECT id, raw_json FROM waf_events WHERE ts_unix >= ? AND ts_unix < ? ORDER BY ts_unix ASC, id ASC`, dayStart, dayEnd)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	writer := newWAFLogArchivePartWriter(opts, day, firstPart)
	defer writer.cleanup()
	for rows.Next() {
		var id int64
		var rawJSON string
		if err := rows.Scan(&id, &rawJSON); err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if err := writer.writeRow(ctx, id, rawJSON); err != nil {
			return nil, err
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return writer.close(ctx)
}

type wafLogArchivePartWriter struct {
	opts    wafLogArchiveOptions
	day     time.Time
	part    int
	current *wafLogArchiveOpenPart
	records []logArchivePartRecord
}

type wafLogArchiveOpenPart struct {
	part              int
	path              string
	file              *os.File
	gzip              *gzip.Writer
	hash              hash.Hash
	compressed        *countingWriter
	firstEventID      int64
	lastEventID       int64
	rowCount          int64
	uncompressedBytes int64
}

type countingWriter struct {
	w io.Writer
	n int64
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += int64(n)
	return n, err
}

func newWAFLogArchivePartWriter(opts wafLogArchiveOptions, day time.Time, firstPart int) *wafLogArchivePartWriter {
	return &wafLogArchivePartWriter{opts: opts, day: utcDayStart(day), part: firstPart}
}

func (w *wafLogArchivePartWriter) writeRow(ctx context.Context, id int64, rawJSON string) error {
	if w.current == nil {
		if err := w.openPart(); err != nil {
			return err
		}
	}
	rawJSON = strings.TrimSpace(rawJSON)
	if rawJSON == "" {
		rawJSON = "{}"
	}
	if w.current.rowCount == 0 {
		w.current.firstEventID = id
	}
	w.current.lastEventID = id
	lineBytes := int64(len(rawJSON) + 1)
	if _, err := io.WriteString(w.current.gzip, rawJSON); err != nil {
		return err
	}
	if _, err := w.current.gzip.Write([]byte{'\n'}); err != nil {
		return err
	}
	w.current.rowCount++
	w.current.uncompressedBytes += lineBytes
	if w.opts.MaxPartBytes > 0 {
		if err := w.current.gzip.Flush(); err != nil {
			return err
		}
	}
	if w.shouldRotate() {
		return w.closeCurrent(ctx)
	}
	return nil
}

func (w *wafLogArchivePartWriter) shouldRotate() bool {
	if w.current == nil || w.current.rowCount == 0 {
		return false
	}
	if w.opts.MaxPartRows > 0 && int(w.current.rowCount) >= w.opts.MaxPartRows {
		return true
	}
	return w.opts.MaxPartBytes > 0 && w.current.compressed.n >= w.opts.MaxPartBytes
}

func (w *wafLogArchivePartWriter) openPart() error {
	tmp, err := os.CreateTemp("", "tukuyomi-waf-log-archive-*.ndjson.gz")
	if err != nil {
		return err
	}
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		_ = os.Remove(tmp.Name())
		return err
	}
	hasher := sha256.New()
	counter := &countingWriter{w: io.MultiWriter(tmp, hasher)}
	w.current = &wafLogArchiveOpenPart{
		part:       w.part,
		path:       tmp.Name(),
		file:       tmp,
		hash:       hasher,
		compressed: counter,
	}
	w.current.gzip = gzip.NewWriter(counter)
	return nil
}

func (w *wafLogArchivePartWriter) close(ctx context.Context) ([]logArchivePartRecord, error) {
	if w.current != nil {
		if err := w.closeCurrent(ctx); err != nil {
			return nil, err
		}
	}
	return append([]logArchivePartRecord(nil), w.records...), nil
}

func (w *wafLogArchivePartWriter) closeCurrent(ctx context.Context) error {
	part := w.current
	if part == nil {
		return nil
	}
	w.current = nil
	if err := part.gzip.Close(); err != nil {
		_ = part.file.Close()
		return err
	}
	if err := part.file.Close(); err != nil {
		return err
	}
	if part.rowCount == 0 {
		_ = os.Remove(part.path)
		return nil
	}
	shaHex := hex.EncodeToString(part.hash.Sum(nil))
	objectKey := wafLogArchiveObjectKey(w.opts.Prefix, w.day, part.part)
	if err := w.opts.BlobStore.PutFile(ctx, objectKey, part.path, shaHex); err != nil {
		return err
	}
	info, found, err := w.opts.BlobStore.Stat(ctx, objectKey)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("archive object %q missing after write", objectKey)
	}
	if info.Size != part.compressed.n {
		return fmt.Errorf("archive object %q size=%d want=%d", objectKey, info.Size, part.compressed.n)
	}
	if info.SHA256 != "" && info.SHA256 != shaHex {
		return fmt.Errorf("archive object %q sha256 mismatch", objectKey)
	}
	record := logArchivePartRecord{
		ArchiveID:         wafLogArchiveID(w.day, part.part),
		Source:            logArchiveSourceWAFEvents,
		ArchiveDay:        archiveDayString(w.day),
		Part:              part.part,
		StorageBackend:    w.opts.StorageBackend,
		ObjectKey:         objectKey,
		MetaObjectKey:     wafLogArchiveMetaObjectKey(w.opts.Prefix, w.day, part.part),
		FromTSUnix:        w.day.Unix(),
		ToTSUnix:          w.day.AddDate(0, 0, 1).Unix(),
		FirstEventID:      part.firstEventID,
		LastEventID:       part.lastEventID,
		RowCount:          part.rowCount,
		CompressedBytes:   part.compressed.n,
		UncompressedBytes: part.uncompressedBytes,
		SHA256:            shaHex,
		CreatedAt:         time.Now().UTC(),
	}
	metaRaw, err := json.MarshalIndent(logArchiveMetadataFile{
		SchemaVersion:     1,
		Source:            record.Source,
		ArchiveDay:        record.ArchiveDay,
		Part:              record.Part,
		FromTS:            time.Unix(record.FromTSUnix, 0).UTC().Format(time.RFC3339),
		ToTS:              time.Unix(record.ToTSUnix, 0).UTC().Format(time.RFC3339),
		FirstEventID:      record.FirstEventID,
		LastEventID:       record.LastEventID,
		RowCount:          record.RowCount,
		CompressedBytes:   record.CompressedBytes,
		UncompressedBytes: record.UncompressedBytes,
		SHA256:            record.SHA256,
		CreatedAt:         record.CreatedAt.Format(time.RFC3339Nano),
	}, "", "  ")
	if err != nil {
		return err
	}
	metaRaw = append(metaRaw, '\n')
	if err := w.opts.BlobStore.PutBytes(ctx, record.MetaObjectKey, metaRaw, sha256HexBytes(metaRaw)); err != nil {
		return err
	}
	w.records = append(w.records, record)
	w.part++
	_ = os.Remove(part.path)
	return nil
}

func (w *wafLogArchivePartWriter) cleanup() {
	if w.current == nil {
		return
	}
	_ = w.current.gzip.Close()
	_ = w.current.file.Close()
	_ = os.Remove(w.current.path)
	w.current = nil
}

func (s *wafEventStore) minWAFEventTSBefore(cutoffUnix int64) (int64, bool, error) {
	var ts sql.NullInt64
	err := s.queryRow(`SELECT MIN(ts_unix) FROM waf_events WHERE ts_unix >= 0 AND ts_unix < ?`, cutoffUnix).Scan(&ts)
	if err != nil {
		return 0, false, err
	}
	if !ts.Valid {
		return 0, false, nil
	}
	return ts.Int64, true, nil
}

func (s *wafEventStore) countWAFEventsForDay(day time.Time) (int64, error) {
	var count int64
	err := s.queryRow(`SELECT COUNT(*) FROM waf_events WHERE ts_unix >= ? AND ts_unix < ?`, day.Unix(), day.AddDate(0, 0, 1).Unix()).Scan(&count)
	return count, err
}

func (s *wafEventStore) maxLogArchivePart(source string, archiveDay string) (int, error) {
	var part sql.NullInt64
	err := s.queryRow(`SELECT MAX(part) FROM log_archives WHERE source = ? AND archive_day = ?`, source, archiveDay).Scan(&part)
	if err != nil || !part.Valid {
		return 0, err
	}
	return int(part.Int64), nil
}

func (s *wafEventStore) deleteRetryableWAFLogArchiveRecords(day time.Time) error {
	_, err := s.exec(`DELETE FROM log_archives WHERE source = ? AND archive_day = ? AND state IN (?, ?)`,
		logArchiveSourceWAFEvents,
		archiveDayString(day),
		logArchiveStateWriting,
		logArchiveStateFailed,
	)
	return err
}

func (s *wafEventStore) insertFailedLogArchiveRecord(day time.Time, part int, opts wafLogArchiveOptions, cause error) error {
	now := time.Now().UTC()
	_, err := s.exec(`INSERT INTO log_archives (
		archive_id, source, archive_day, part, state, storage_backend, object_key, meta_object_key,
		from_ts_unix, to_ts_unix, first_event_id, last_event_id, row_count, compressed_bytes,
		uncompressed_bytes, sha256, error, created_at_unix, created_at, updated_at_unix, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, '', ?, ?, ?, ?, ?)`,
		wafLogArchiveID(day, part),
		logArchiveSourceWAFEvents,
		archiveDayString(day),
		part,
		logArchiveStateFailed,
		opts.StorageBackend,
		wafLogArchiveObjectKey(opts.Prefix, day, part),
		wafLogArchiveMetaObjectKey(opts.Prefix, day, part),
		day.Unix(),
		day.AddDate(0, 0, 1).Unix(),
		clampArchiveError(cause),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
	)
	return err
}

func (s *wafEventStore) insertSealedLogArchiveParts(parts []logArchivePartRecord) error {
	if len(parts) == 0 {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	now := time.Now().UTC()
	for _, part := range parts {
		if _, err := s.txExec(tx, `INSERT INTO log_archives (
			archive_id, source, archive_day, part, state, storage_backend, object_key, meta_object_key,
			from_ts_unix, to_ts_unix, first_event_id, last_event_id, row_count, compressed_bytes,
			uncompressed_bytes, sha256, error, created_at_unix, created_at, sealed_at_unix, sealed_at,
			updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, ?)`,
			part.ArchiveID,
			part.Source,
			part.ArchiveDay,
			part.Part,
			logArchiveStateSealed,
			part.StorageBackend,
			part.ObjectKey,
			part.MetaObjectKey,
			part.FromTSUnix,
			part.ToTSUnix,
			part.FirstEventID,
			part.LastEventID,
			part.RowCount,
			part.CompressedBytes,
			part.UncompressedBytes,
			part.SHA256,
			part.CreatedAt.Unix(),
			part.CreatedAt.Format(time.RFC3339Nano),
			now.Unix(),
			now.Format(time.RFC3339Nano),
			now.Unix(),
			now.Format(time.RFC3339Nano),
		); err != nil {
			_ = tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}

func (s *wafEventStore) pruneSealedWAFLogArchiveDay(ctx context.Context, day time.Time) (int64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	var sealedRows int64
	var sealedParts int64
	rows, err := s.query(`SELECT row_count FROM log_archives WHERE source = ? AND archive_day = ? AND state = ?`,
		logArchiveSourceWAFEvents,
		archiveDayString(day),
		logArchiveStateSealed,
	)
	if err != nil {
		return 0, err
	}
	for rows.Next() {
		var rowCount int64
		if err := rows.Scan(&rowCount); err != nil {
			_ = rows.Close()
			return 0, err
		}
		sealedParts++
		sealedRows += rowCount
	}
	if err := rows.Close(); err != nil {
		return 0, err
	}
	if sealedParts == 0 {
		return 0, nil
	}
	dbRows, err := s.countWAFEventsForDay(day)
	if err != nil {
		return 0, err
	}
	if dbRows != sealedRows {
		return 0, fmt.Errorf("sealed archive row count mismatch for %s: db=%d sealed=%d", archiveDayString(day), dbRows, sealedRows)
	}
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	res, err := s.txExec(tx, `DELETE FROM waf_events WHERE ts_unix >= ? AND ts_unix < ?`, day.Unix(), day.AddDate(0, 0, 1).Unix())
	if err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	deleted, err := res.RowsAffected()
	if err == nil && deleted != dbRows {
		_ = tx.Rollback()
		return 0, fmt.Errorf("archive prune deleted %d rows for %s; want %d", deleted, archiveDayString(day), dbRows)
	}
	now := time.Now().UTC()
	if _, err := s.txExec(tx, `UPDATE log_archives SET state = ?, pruned_at_unix = ?, pruned_at = ?, updated_at_unix = ?, updated_at = ? WHERE source = ? AND archive_day = ? AND state = ?`,
		logArchiveStatePruned,
		now.Unix(),
		now.Format(time.RFC3339Nano),
		now.Unix(),
		now.Format(time.RFC3339Nano),
		logArchiveSourceWAFEvents,
		archiveDayString(day),
		logArchiveStateSealed,
	); err != nil {
		_ = tx.Rollback()
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return dbRows, nil
}

func utcDayStart(t time.Time) time.Time {
	t = t.UTC()
	return time.Date(t.Year(), t.Month(), t.Day(), 0, 0, 0, 0, time.UTC)
}

func archiveDayString(day time.Time) string {
	return utcDayStart(day).Format("2006-01-02")
}

func wafLogArchiveID(day time.Time, part int) string {
	return fmt.Sprintf("%s:%s:%06d", logArchiveSourceWAFEvents, archiveDayString(day), part)
}

func wafLogArchiveObjectKey(prefix string, day time.Time, part int) string {
	day = utcDayStart(day)
	return path.Join(
		strings.Trim(strings.TrimSpace(prefix), "/"),
		"waf",
		fmt.Sprintf("yyyy=%04d", day.Year()),
		fmt.Sprintf("mm=%02d", int(day.Month())),
		fmt.Sprintf("dd=%02d", day.Day()),
		fmt.Sprintf("part-%06d.ndjson.gz", part),
	)
}

func wafLogArchiveMetaObjectKey(prefix string, day time.Time, part int) string {
	return strings.TrimSuffix(wafLogArchiveObjectKey(prefix, day, part), ".ndjson.gz") + ".meta.json"
}

func sha256HexBytes(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func clampArchiveError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 2048 {
		msg = msg[:2048]
	}
	return msg
}

func isNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows)
}
