package handler

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "modernc.org/sqlite"
)

const (
	logStatsStoreSourceWAF = "waf"

	logStatsStorageBackendFile = "file"
	logStatsStorageBackendDB   = "db"
	logStatsDBDriverSQLite     = "sqlite"
	logStatsDBDriverMySQL      = "mysql"

	maxDBMatchedValueBytes = 2048
)

var (
	logStatsStoreMu sync.RWMutex
	logStatsStore   *wafEventStore

	errNoWAFBlockEvent = errors.New("no waf_block event found")
)

type wafEventStore struct {
	db            *sql.DB
	dbDriver      string
	dbPath        string
	mu            sync.Mutex
	retentionDays int
}

type logIngestState struct {
	Offset    int64
	Size      int64
	ModTimeNS int64
}

type logSyncResult struct {
	ScannedLines int
}

type wafEventStoreStatus struct {
	TotalRows            int
	WAFBlockRows         int
	DBSizeBytes          int64
	LastIngestOffset     int64
	LastIngestModTime    string
	LastSyncScannedLines int
}

func InitLogsStatsStore(enabled bool, dbPath string, retentionDays int) error {
	backend := logStatsStorageBackendFile
	driver := ""
	if enabled {
		backend = logStatsStorageBackendDB
		driver = logStatsDBDriverSQLite
	}
	return InitLogsStatsStoreWithBackend(backend, driver, dbPath, "", retentionDays)
}

func InitLogsStatsStoreWithBackend(storageBackend, dbDriver, dbPath, dbDSN string, retentionDays int) error {
	logStatsStoreMu.Lock()
	defer logStatsStoreMu.Unlock()

	if logStatsStore != nil {
		_ = logStatsStore.Close()
		logStatsStore = nil
	}

	backend := strings.ToLower(strings.TrimSpace(storageBackend))
	if backend == "" {
		backend = logStatsStorageBackendFile
	}
	if backend == logStatsStorageBackendFile {
		return nil
	}
	if backend != logStatsStorageBackendDB {
		return fmt.Errorf("unsupported storage backend: %s", backend)
	}

	driver := strings.ToLower(strings.TrimSpace(dbDriver))
	if driver == "" {
		driver = logStatsDBDriverSQLite
	}

	var (
		store *wafEventStore
		err   error
	)
	switch driver {
	case logStatsDBDriverSQLite:
		store, err = openWAFEventStoreSQLite(dbPath, retentionDays)
		if err != nil {
			return err
		}
	case logStatsDBDriverMySQL:
		if strings.TrimSpace(dbDSN) == "" {
			return fmt.Errorf("mysql driver requires storage.db_dsn")
		}
		store, err = openWAFEventStoreMySQL(dbDSN, retentionDays)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported db driver: %s", driver)
	}
	logStatsStore = store
	return nil
}

func getLogsStatsStore() *wafEventStore {
	logStatsStoreMu.RLock()
	defer logStatsStoreMu.RUnlock()
	return logStatsStore
}

func openWAFEventStoreSQLite(dbPath string, retentionDays int) (*wafEventStore, error) {
	p := strings.TrimSpace(dbPath)
	if p == "" {
		return nil, fmt.Errorf("db path is empty")
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return nil, fmt.Errorf("mkdir db dir: %w", err)
	}

	db, err := sql.Open("sqlite", p)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	db.SetMaxOpenConns(1)

	stmts := []string{
		`PRAGMA journal_mode = WAL;`,
		`PRAGMA synchronous = NORMAL;`,
		`CREATE TABLE IF NOT EXISTS waf_events (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			event TEXT NOT NULL,
			ts_unix INTEGER NOT NULL,
			ts TEXT NOT NULL,
			rule_id TEXT NOT NULL,
			path TEXT NOT NULL,
			country TEXT NOT NULL,
			status INTEGER NOT NULL,
			req_id TEXT,
			method TEXT,
			matched_variable TEXT,
			matched_value TEXT,
			raw_json TEXT NOT NULL,
			line_hash TEXT NOT NULL UNIQUE
		);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_ts_unix ON waf_events(ts_unix);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_event_ts ON waf_events(event, ts_unix);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_rule_id ON waf_events(rule_id);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_path ON waf_events(path);`,
		`CREATE INDEX IF NOT EXISTS idx_waf_events_country ON waf_events(country);`,
		`CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_events_line_hash ON waf_events(line_hash);`,
		`CREATE TABLE IF NOT EXISTS ingest_state (
			source TEXT PRIMARY KEY,
			offset INTEGER NOT NULL,
			size INTEGER NOT NULL,
			mod_time_ns INTEGER NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS config_blobs (
			config_key TEXT PRIMARY KEY,
			raw_text TEXT NOT NULL,
			etag TEXT NOT NULL,
			updated_at_unix INTEGER NOT NULL,
			updated_at TEXT NOT NULL
		);`,
		`CREATE INDEX IF NOT EXISTS idx_config_blobs_updated_at_unix ON config_blobs(updated_at_unix);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init sqlite schema: %w", err)
		}
	}

	if err := ensureSQLiteColumn(db, "waf_events", "method", "TEXT"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureSQLiteColumn(db, "waf_events", "matched_variable", "TEXT"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureSQLiteColumn(db, "waf_events", "matched_value", "TEXT"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if err := ensureSQLiteColumn(db, "waf_events", "raw_json", `TEXT NOT NULL DEFAULT '{}'`); err != nil {
		_ = db.Close()
		return nil, err
	}

	if retentionDays < 0 {
		retentionDays = 0
	}
	return &wafEventStore{
		db:            db,
		dbDriver:      logStatsDBDriverSQLite,
		dbPath:        p,
		retentionDays: retentionDays,
	}, nil
}

func openWAFEventStoreMySQL(dbDSN string, retentionDays int) (*wafEventStore, error) {
	dsn := strings.TrimSpace(dbDSN)
	if dsn == "" {
		return nil, fmt.Errorf("mysql dsn is empty")
	}

	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("open mysql: %w", err)
	}
	db.SetConnMaxLifetime(5 * time.Minute)
	db.SetMaxOpenConns(16)
	db.SetMaxIdleConns(8)

	pingCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := db.PingContext(pingCtx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping mysql: %w", err)
	}

	stmts := []string{
		`CREATE TABLE IF NOT EXISTS waf_events (
			id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
			event VARCHAR(64) NOT NULL,
			ts_unix BIGINT NOT NULL,
			ts VARCHAR(64) NOT NULL,
			rule_id VARCHAR(128) NOT NULL,
			path TEXT NOT NULL,
			country VARCHAR(16) NOT NULL,
			status INT NOT NULL,
			req_id VARCHAR(128) NULL,
			method VARCHAR(16) NULL,
			matched_variable VARCHAR(255) NULL,
			matched_value TEXT NULL,
			raw_json LONGTEXT NOT NULL,
			line_hash CHAR(64) NOT NULL,
			UNIQUE KEY uq_waf_events_line_hash (line_hash),
			KEY idx_waf_events_ts_unix (ts_unix),
			KEY idx_waf_events_event_ts (event, ts_unix),
			KEY idx_waf_events_rule_id (rule_id),
			KEY idx_waf_events_path (path(191)),
			KEY idx_waf_events_country (country)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
		"CREATE TABLE IF NOT EXISTS ingest_state (" +
			"source VARCHAR(64) NOT NULL PRIMARY KEY," +
			"`offset` BIGINT NOT NULL," +
			"size BIGINT NOT NULL," +
			"mod_time_ns BIGINT NOT NULL" +
			") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;",
		`CREATE TABLE IF NOT EXISTS config_blobs (
			config_key VARCHAR(128) NOT NULL PRIMARY KEY,
			raw_text LONGTEXT NOT NULL,
			etag VARCHAR(128) NOT NULL,
			updated_at_unix BIGINT NOT NULL,
			updated_at VARCHAR(64) NOT NULL,
			KEY idx_config_blobs_updated_at_unix (updated_at_unix)
		) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			_ = db.Close()
			return nil, fmt.Errorf("init mysql schema: %w", err)
		}
	}

	if retentionDays < 0 {
		retentionDays = 0
	}
	return &wafEventStore{
		db:            db,
		dbDriver:      logStatsDBDriverMySQL,
		dbPath:        "",
		retentionDays: retentionDays,
	}, nil
}

func ensureSQLiteColumn(db *sql.DB, table, column, definition string) error {
	hasColumn, err := sqliteHasColumn(db, table, column)
	if err != nil {
		return err
	}
	if hasColumn {
		return nil
	}
	_, err = db.Exec(fmt.Sprintf(`ALTER TABLE %s ADD COLUMN %s %s`, table, column, definition))
	if err != nil {
		return fmt.Errorf("add sqlite column %s.%s: %w", table, column, err)
	}
	return nil
}

func sqliteHasColumn(db *sql.DB, table, column string) (bool, error) {
	rows, err := db.Query(fmt.Sprintf(`PRAGMA table_info(%s)`, table))
	if err != nil {
		return false, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			cid      int
			name     string
			typeName string
			notNull  int
			defaultV any
			pk       int
		)
		if err := rows.Scan(&cid, &name, &typeName, &notNull, &defaultV, &pk); err != nil {
			return false, err
		}
		if strings.EqualFold(name, column) {
			return true, nil
		}
	}
	if err := rows.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *wafEventStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}

func (s *wafEventStore) BuildLogsStats(logPath string, rangeHours int, now time.Time) (logsStatsResp, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now = now.UTC()
	seriesStart, seriesEnd := statsHourlyRange(now, rangeHours)
	emptySeries := buildHourlySeries(seriesStart, seriesEnd, map[int64]int{})
	base := logsStatsResp{
		GeneratedAt:  now.Format(time.RFC3339Nano),
		ScannedLines: 0,
		RangeHours:   rangeHours,
		WAFBlock: wafBlockStats{
			TopRuleIDs24h:   []statsBucket{},
			TopPaths24h:     []statsBucket{},
			TopCountries24h: []statsBucket{},
			SeriesHourly:    emptySeries,
		},
	}

	syncResult, err := s.syncWAFEvents(logPath)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.ScannedLines = syncResult.ScannedLines

	since1hUnix := now.Add(-1 * time.Hour).Unix()
	since24hUnix := now.Add(-24 * time.Hour).Unix()
	seriesStartUnix := seriesStart.Unix()
	seriesEndUnix := seriesEnd.Unix()

	base.WAFBlock.TotalInScan, err = s.queryCount(`SELECT COUNT(*) FROM waf_events WHERE event = 'waf_block'`)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.WAFBlock.Last1h, err = s.queryCount(`SELECT COUNT(*) FROM waf_events WHERE event = 'waf_block' AND ts_unix >= ?`, since1hUnix)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.WAFBlock.Last24h, err = s.queryCount(`SELECT COUNT(*) FROM waf_events WHERE event = 'waf_block' AND ts_unix >= ?`, since24hUnix)
	if err != nil {
		return logsStatsResp{}, err
	}

	base.WAFBlock.TopRuleIDs24h, err = s.queryTopBuckets("rule_id", since24hUnix, statsTopN)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.WAFBlock.TopPaths24h, err = s.queryTopBuckets("path", since24hUnix, statsTopN)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.WAFBlock.TopCountries24h, err = s.queryTopBuckets("country", since24hUnix, statsTopN)
	if err != nil {
		return logsStatsResp{}, err
	}
	seriesCounts, err := s.querySeriesCounts(seriesStartUnix, seriesEndUnix)
	if err != nil {
		return logsStatsResp{}, err
	}
	base.WAFBlock.SeriesHourly = buildHourlySeries(seriesStart, seriesEnd, seriesCounts)

	oldest, newest, err := s.queryMinMaxTS()
	if err != nil {
		return logsStatsResp{}, err
	}
	if oldest != 0 && newest != 0 {
		base.OldestScannedTS = time.Unix(oldest, 0).UTC().Format(time.RFC3339Nano)
		base.NewestScannedTS = time.Unix(newest, 0).UTC().Format(time.RFC3339Nano)
	}

	return base, nil
}

func (s *wafEventStore) StatusSnapshot(logPath string) (wafEventStoreStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	syncResult, err := s.syncWAFEvents(logPath)
	if err != nil {
		return wafEventStoreStatus{}, err
	}

	totalRows, err := s.queryCount(`SELECT COUNT(*) FROM waf_events`)
	if err != nil {
		return wafEventStoreStatus{}, err
	}
	wafBlockRows, err := s.queryCount(`SELECT COUNT(*) FROM waf_events WHERE event = 'waf_block'`)
	if err != nil {
		return wafEventStoreStatus{}, err
	}

	state, err := s.loadIngestState(logStatsStoreSourceWAF)
	if err != nil {
		return wafEventStoreStatus{}, err
	}

	dbSize, err := s.estimateDBSizeBytes()
	if err != nil {
		return wafEventStoreStatus{}, err
	}

	modTime := ""
	if state.ModTimeNS > 0 {
		modTime = time.Unix(0, state.ModTimeNS).UTC().Format(time.RFC3339Nano)
	}

	return wafEventStoreStatus{
		TotalRows:            totalRows,
		WAFBlockRows:         wafBlockRows,
		DBSizeBytes:          dbSize,
		LastIngestOffset:     state.Offset,
		LastIngestModTime:    modTime,
		LastSyncScannedLines: syncResult.ScannedLines,
	}, nil
}

func (s *wafEventStore) ReadWAFLogs(logPath string, tail int, cursor *int64, dir string, countryFilter string) ([]logLine, *int64, bool, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.syncWAFEvents(logPath); err != nil {
		return nil, nil, false, false, err
	}

	countQuery := `SELECT COUNT(*) FROM waf_events`
	countArgs := make([]any, 0, 1)
	if countryFilter != "" {
		countQuery += ` WHERE country = ?`
		countArgs = append(countArgs, countryFilter)
	}

	totalLines, err := s.queryCount(countQuery, countArgs...)
	if err != nil {
		return nil, nil, false, false, err
	}

	var cur int
	if cursor == nil {
		if tail > totalLines {
			cur = 0
		} else {
			cur = totalLines - tail
		}
	} else {
		cur = int(*cursor)
		if cur < 0 {
			cur = 0
		}
		if cur > totalLines {
			cur = totalLines
		}
	}

	var start, end int
	switch dir {
	case "prev":
		start, end = maxInt(cur-tail, 0), cur
	case "next", "":
		start, end = cur, minInt(cur+tail, totalLines)
	default:
		return nil, nil, false, false, fmt.Errorf("invalid dir")
	}

	if start >= end {
		nextCur := int64(end)
		return []logLine{}, &nextCur, start > 0, end < totalLines, nil
	}

	selectQuery := `SELECT raw_json FROM waf_events`
	selectArgs := make([]any, 0, 3)
	if countryFilter != "" {
		selectQuery += ` WHERE country = ?`
		selectArgs = append(selectArgs, countryFilter)
	}
	selectQuery += ` ORDER BY id ASC LIMIT ? OFFSET ?`
	selectArgs = append(selectArgs, end-start, start)

	rows, err := s.db.Query(selectQuery, selectArgs...)
	if err != nil {
		return nil, nil, false, false, err
	}
	defer rows.Close()

	out := make([]logLine, 0, end-start)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, nil, false, false, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, nil, false, false, err
	}

	var nextCur int64
	if dir == "prev" {
		nextCur = int64(start)
	} else {
		nextCur = int64(end)
	}
	hasPrev := start > 0
	hasNext := end < totalLines

	return out, &nextCur, hasPrev, hasNext, nil
}

func (s *wafEventStore) ReadWAFRequestLogs(logPath string, reqIDFilter string, countryFilter string) ([]logLine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.syncWAFEvents(logPath); err != nil {
		return nil, err
	}

	query := `SELECT raw_json FROM waf_events WHERE req_id = ?`
	args := make([]any, 0, 2)
	args = append(args, reqIDFilter)
	if countryFilter != "" {
		query += ` AND country = ?`
		args = append(args, countryFilter)
	}
	query += ` ORDER BY ts_unix ASC, id ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]logLine, 0, 8)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			continue
		}
		out = append(out, m)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *wafEventStore) DownloadWAFLogs(logPath string, w io.Writer, from, to time.Time, countryFilter string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.syncWAFEvents(logPath); err != nil {
		return err
	}

	query := `SELECT raw_json FROM waf_events WHERE ts_unix >= 0`
	args := make([]any, 0, 4)
	if !from.IsZero() {
		query += ` AND ts_unix >= ?`
		args = append(args, from.UTC().Unix())
	}
	if !to.IsZero() {
		query += ` AND ts_unix < ?`
		args = append(args, to.UTC().Unix())
	}
	if countryFilter != "" {
		query += ` AND country = ?`
		args = append(args, countryFilter)
	}
	query += ` ORDER BY id ASC`

	rows, err := s.db.Query(query, args...)
	if err != nil {
		return err
	}
	defer rows.Close()

	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return err
		}
		if _, err := io.WriteString(w, raw); err != nil {
			return err
		}
		if _, err := io.WriteString(w, "\n"); err != nil {
			return err
		}
	}
	return rows.Err()
}

func (s *wafEventStore) LatestWAFBlockEvent(logPath string) (fpTunerEventInput, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.syncWAFEvents(logPath); err != nil {
		return fpTunerEventInput{}, err
	}

	row := s.db.QueryRow(`
		SELECT raw_json
		  FROM waf_events
		 WHERE event = 'waf_block'
		 ORDER BY id DESC
		 LIMIT 1`)

	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fpTunerEventInput{}, errNoWAFBlockEvent
		}
		return fpTunerEventInput{}, err
	}

	var ln logLine
	if err := json.Unmarshal([]byte(raw), &ln); err != nil {
		return fpTunerEventInput{}, err
	}
	event, ok := fpTunerEventInputFromLogLine(ln)
	if !ok {
		return fpTunerEventInput{}, errNoWAFBlockEvent
	}
	event.EventType = ""
	return normalizeFPTunerEventInput(event), nil
}

func nullString(ns sql.NullString) string {
	if !ns.Valid {
		return ""
	}
	return strings.TrimSpace(ns.String)
}

func (s *wafEventStore) RecentWAFBlockLogLines(logPath string, limit int) ([]logLine, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, err := s.syncWAFEvents(logPath); err != nil {
		return nil, err
	}

	rows, err := s.db.Query(`
		SELECT raw_json
		  FROM waf_events
		 WHERE event = 'waf_block'
		 ORDER BY id DESC
		 LIMIT ?`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]logLine, 0, limit)
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			return nil, err
		}
		var ln logLine
		if err := json.Unmarshal([]byte(raw), &ln); err != nil {
			continue
		}
		out = append(out, normalizeFPTunerWAFLogLine(ln))
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return out, nil
}

func (s *wafEventStore) syncWAFEvents(logPath string) (logSyncResult, error) {
	fi, err := os.Stat(logPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return logSyncResult{ScannedLines: 0}, nil
		}
		return logSyncResult{}, err
	}

	state, err := s.loadIngestState(logStatsStoreSourceWAF)
	if err != nil {
		return logSyncResult{}, err
	}

	offset := state.Offset
	if offset < 0 || offset > fi.Size() {
		offset = 0
	}
	currentMod := fi.ModTime().UTC().UnixNano()
	if fi.Size() < offset || (state.ModTimeNS != 0 && state.ModTimeNS != currentMod && fi.Size() <= offset) {
		offset = 0
	}

	f, err := os.Open(logPath)
	if err != nil {
		return logSyncResult{}, err
	}
	defer f.Close()

	if _, err := f.Seek(offset, io.SeekStart); err != nil {
		return logSyncResult{}, err
	}

	tx, err := s.db.Begin()
	if err != nil {
		return logSyncResult{}, err
	}

	stmt, err := tx.Prepare(s.insertWAFEventStmt())
	if err != nil {
		_ = tx.Rollback()
		return logSyncResult{}, err
	}
	defer stmt.Close()

	reader := bufio.NewReaderSize(f, 64*1024)
	currentOffset := offset
	scannedLines := 0

	for {
		line, readErr := reader.ReadBytes('\n')
		if len(line) > 0 {
			scannedLines++
			currentOffset += int64(len(line))
			if err := ingestWAFEventLine(stmt, line); err != nil {
				_ = tx.Rollback()
				return logSyncResult{}, err
			}
		}

		if readErr != nil {
			if errors.Is(readErr, io.EOF) {
				break
			}
			_ = tx.Rollback()
			return logSyncResult{}, readErr
		}
	}

	finalSize := fi.Size()
	finalMod := currentMod
	if finalInfo, statErr := os.Stat(logPath); statErr == nil {
		finalSize = finalInfo.Size()
		finalMod = finalInfo.ModTime().UTC().UnixNano()
	}
	if currentOffset > finalSize {
		finalSize = currentOffset
	}

	nextState := logIngestState{
		Offset:    currentOffset,
		Size:      finalSize,
		ModTimeNS: finalMod,
	}
	if err := s.pruneExpiredWAFEvents(tx, time.Now().UTC()); err != nil {
		_ = tx.Rollback()
		return logSyncResult{}, err
	}
	if err := s.saveIngestState(tx, logStatsStoreSourceWAF, nextState); err != nil {
		_ = tx.Rollback()
		return logSyncResult{}, err
	}
	if err := tx.Commit(); err != nil {
		return logSyncResult{}, err
	}

	return logSyncResult{ScannedLines: scannedLines}, nil
}

func ingestWAFEventLine(stmt *sql.Stmt, rawLine []byte) error {
	line := bytes.TrimSpace(rawLine)
	if len(line) == 0 {
		return nil
	}

	var m map[string]any
	if err := json.Unmarshal(line, &m); err != nil {
		return nil
	}

	event := strings.TrimSpace(logFieldString(m["event"]))
	if event == "" {
		event = "unknown"
	}

	tsRaw := strings.TrimSpace(logFieldString(m["ts"]))
	tsUnix := int64(-1)
	tsNorm := tsRaw
	if ts, ok := parseLogTS(m["ts"]); ok {
		ts = ts.UTC()
		tsUnix = ts.Unix()
		tsNorm = ts.Format(time.RFC3339Nano)
	}

	ruleID := normalizeStatsRuleID(m["rule_id"])
	pathKey := normalizeStatsPath(m["path"])
	country := normalizeCountryFromAny(m["country"])
	status := anyToInt(m["status"])
	reqID := strings.TrimSpace(anyToString(m["req_id"]))
	method := strings.ToUpper(strings.TrimSpace(anyToString(m["method"])))
	matchedVariable := strings.TrimSpace(anyToString(m["matched_variable"]))
	matchedValue := clampText(strings.TrimSpace(anyToString(m["matched_value"])), maxDBMatchedValueBytes)

	rawJSON, err := json.Marshal(m)
	if err != nil {
		rawJSON = line
	}

	hash := sha256.Sum256(line)
	lineHash := hex.EncodeToString(hash[:])

	_, err = stmt.Exec(
		event,
		tsUnix,
		tsNorm,
		ruleID,
		pathKey,
		country,
		status,
		reqID,
		method,
		matchedVariable,
		matchedValue,
		string(rawJSON),
		lineHash,
	)
	return err
}

func (s *wafEventStore) loadIngestState(source string) (logIngestState, error) {
	var st logIngestState
	row := s.db.QueryRow("SELECT `offset`, size, mod_time_ns FROM ingest_state WHERE source = ?", source)
	switch err := row.Scan(&st.Offset, &st.Size, &st.ModTimeNS); {
	case errors.Is(err, sql.ErrNoRows):
		return logIngestState{}, nil
	case err != nil:
		return logIngestState{}, err
	default:
		return st, nil
	}
}

func (s *wafEventStore) pruneExpiredWAFEvents(tx *sql.Tx, now time.Time) error {
	if s == nil || s.retentionDays <= 0 {
		return nil
	}
	cutoffUnix := now.AddDate(0, 0, -s.retentionDays).Unix()
	_, err := tx.Exec(
		`DELETE FROM waf_events WHERE ts_unix >= 0 AND ts_unix < ?`,
		cutoffUnix,
	)
	return err
}

func (s *wafEventStore) saveIngestState(tx *sql.Tx, source string, st logIngestState) error {
	_, err := tx.Exec(s.upsertIngestStateStmt(), source, st.Offset, st.Size, st.ModTimeNS)
	return err
}

func (s *wafEventStore) insertWAFEventStmt() string {
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		return `INSERT IGNORE INTO waf_events (
			event, ts_unix, ts, rule_id, path, country, status, req_id, method,
			matched_variable, matched_value, raw_json, line_hash
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
	}
	return `INSERT OR IGNORE INTO waf_events (
		event, ts_unix, ts, rule_id, path, country, status, req_id, method,
		matched_variable, matched_value, raw_json, line_hash
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
}

func (s *wafEventStore) upsertIngestStateStmt() string {
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		return `INSERT INTO ingest_state (source, ` + "`offset`" + `, size, mod_time_ns)
		 VALUES (?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
			` + "`offset`" + ` = VALUES(` + "`offset`" + `),
			size = VALUES(size),
			mod_time_ns = VALUES(mod_time_ns)`
	}
	return `INSERT INTO ingest_state (source, ` + "`offset`" + `, size, mod_time_ns)
		 VALUES (?, ?, ?, ?)
		 ON CONFLICT(source) DO UPDATE SET
			` + "`offset`" + ` = excluded.` + "`offset`" + `,
			size = excluded.size,
			mod_time_ns = excluded.mod_time_ns`
}

func (s *wafEventStore) GetConfigBlob(configKey string) ([]byte, string, bool, error) {
	if s == nil || s.db == nil {
		return nil, "", false, nil
	}

	key := strings.TrimSpace(configKey)
	if key == "" {
		return nil, "", false, fmt.Errorf("config key is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var (
		raw  string
		etag string
	)
	row := s.db.QueryRow(`SELECT raw_text, etag FROM config_blobs WHERE config_key = ?`, key)
	switch err := row.Scan(&raw, &etag); {
	case errors.Is(err, sql.ErrNoRows):
		return nil, "", false, nil
	case err != nil:
		return nil, "", false, err
	default:
		return []byte(raw), etag, true, nil
	}
}

func (s *wafEventStore) GetConfigBlobUpdatedAt(configKey string) (string, bool, error) {
	if s == nil || s.db == nil {
		return "", false, nil
	}

	key := strings.TrimSpace(configKey)
	if key == "" {
		return "", false, fmt.Errorf("config key is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	var updatedAt string
	row := s.db.QueryRow(`SELECT updated_at FROM config_blobs WHERE config_key = ?`, key)
	switch err := row.Scan(&updatedAt); {
	case errors.Is(err, sql.ErrNoRows):
		return "", false, nil
	case err != nil:
		return "", false, err
	default:
		return strings.TrimSpace(updatedAt), true, nil
	}
}

func (s *wafEventStore) UpsertConfigBlob(configKey string, raw []byte, etag string, now time.Time) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("db store is not initialized")
	}

	key := strings.TrimSpace(configKey)
	if key == "" {
		return fmt.Errorf("config key is empty")
	}

	ts := now.UTC()
	if ts.IsZero() {
		ts = time.Now().UTC()
	}
	payload := string(raw)
	etag = strings.TrimSpace(etag)
	if etag == "" {
		sum := sha256.Sum256(raw)
		etag = hex.EncodeToString(sum[:])
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(
		s.upsertConfigBlobStmt(),
		key,
		payload,
		etag,
		ts.Unix(),
		ts.Format(time.RFC3339Nano),
	)
	return err
}

type configBlobRecord struct {
	ConfigKey string
	Raw       []byte
	ETag      string
	UpdatedAt string
}

func (s *wafEventStore) ListConfigBlobs(prefix string) ([]configBlobRecord, error) {
	if s == nil || s.db == nil {
		return nil, nil
	}

	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return nil, fmt.Errorf("config prefix is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.Query(`SELECT config_key, raw_text, etag, updated_at FROM config_blobs WHERE config_key LIKE ? ORDER BY config_key`, prefix+"%")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []configBlobRecord{}
	for rows.Next() {
		var rec configBlobRecord
		var raw string
		if err := rows.Scan(&rec.ConfigKey, &raw, &rec.ETag, &rec.UpdatedAt); err != nil {
			return nil, err
		}
		rec.Raw = []byte(raw)
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *wafEventStore) DeleteConfigBlob(configKey string) error {
	if s == nil || s.db == nil {
		return fmt.Errorf("db store is not initialized")
	}

	key := strings.TrimSpace(configKey)
	if key == "" {
		return fmt.Errorf("config key is empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.Exec(`DELETE FROM config_blobs WHERE config_key = ?`, key)
	return err
}

func (s *wafEventStore) upsertConfigBlobStmt() string {
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		return `INSERT INTO config_blobs (config_key, raw_text, etag, updated_at_unix, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON DUPLICATE KEY UPDATE
			raw_text = VALUES(raw_text),
			etag = VALUES(etag),
			updated_at_unix = VALUES(updated_at_unix),
			updated_at = VALUES(updated_at)`
	}
	return `INSERT INTO config_blobs (config_key, raw_text, etag, updated_at_unix, updated_at)
		 VALUES (?, ?, ?, ?, ?)
		 ON CONFLICT(config_key) DO UPDATE SET
			raw_text = excluded.raw_text,
			etag = excluded.etag,
			updated_at_unix = excluded.updated_at_unix,
			updated_at = excluded.updated_at`
}

func (s *wafEventStore) estimateDBSizeBytes() (int64, error) {
	if s == nil {
		return 0, nil
	}
	switch s.dbDriver {
	case logStatsDBDriverSQLite:
		if s.dbPath == "" {
			return 0, nil
		}
		if fi, statErr := os.Stat(s.dbPath); statErr == nil {
			return fi.Size(), nil
		}
		return 0, nil
	case logStatsDBDriverMySQL:
		var n sql.NullInt64
		row := s.db.QueryRow(`
			SELECT COALESCE(SUM(data_length + index_length), 0)
			  FROM information_schema.tables
			 WHERE table_schema = DATABASE()
			   AND table_name IN ('waf_events', 'ingest_state', 'config_blobs')`)
		if err := row.Scan(&n); err != nil {
			return 0, err
		}
		if !n.Valid {
			return 0, nil
		}
		return n.Int64, nil
	default:
		return 0, nil
	}
}

func (s *wafEventStore) queryCount(query string, args ...any) (int, error) {
	var n int
	if err := s.db.QueryRow(query, args...).Scan(&n); err != nil {
		return 0, err
	}
	return n, nil
}

func (s *wafEventStore) queryTopBuckets(column string, sinceUnix int64, n int) ([]statsBucket, error) {
	if n <= 0 {
		return []statsBucket{}, nil
	}

	switch column {
	case "rule_id", "path", "country":
	default:
		return nil, fmt.Errorf("invalid bucket column: %s", column)
	}

	q := fmt.Sprintf(
		`SELECT %s AS bucket_key, COUNT(*) AS cnt
		   FROM waf_events
		  WHERE event = 'waf_block' AND ts_unix >= ?
		  GROUP BY %s
		  ORDER BY cnt DESC, bucket_key ASC
		  LIMIT ?`,
		column,
		column,
	)
	rows, err := s.db.Query(q, sinceUnix, n)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]statsBucket, 0, n)
	for rows.Next() {
		var b statsBucket
		if err := rows.Scan(&b.Key, &b.Count); err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *wafEventStore) querySeriesCounts(startUnix, endUnix int64) (map[int64]int, error) {
	query := `SELECT (ts_unix / 3600) * 3600 AS bucket, COUNT(*) AS cnt
		   FROM waf_events
		  WHERE event = 'waf_block' AND ts_unix >= ? AND ts_unix < ?
		  GROUP BY bucket`
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		query = `SELECT FLOOR(ts_unix / 3600) * 3600 AS bucket, COUNT(*) AS cnt
		   FROM waf_events
		  WHERE event = 'waf_block' AND ts_unix >= ? AND ts_unix < ?
		  GROUP BY bucket`
	}
	rows, err := s.db.Query(query, startUnix, endUnix)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := map[int64]int{}
	for rows.Next() {
		var bucket int64
		var count int
		if err := rows.Scan(&bucket, &count); err != nil {
			return nil, err
		}
		out[bucket] = count
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *wafEventStore) queryMinMaxTS() (int64, int64, error) {
	var minTS sql.NullInt64
	var maxTS sql.NullInt64
	if err := s.db.QueryRow(
		`SELECT MIN(ts_unix), MAX(ts_unix)
		   FROM waf_events
		  WHERE event = 'waf_block' AND ts_unix >= 0`,
	).Scan(&minTS, &maxTS); err != nil {
		return 0, 0, err
	}
	if !minTS.Valid || !maxTS.Valid {
		return 0, 0, nil
	}
	return minTS.Int64, maxTS.Int64, nil
}
