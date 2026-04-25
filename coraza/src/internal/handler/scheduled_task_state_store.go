package handler

import (
	"database/sql"
	"sort"
	"strings"
	"time"
)

const (
	scheduledTaskRuntimeStateTable = "scheduled_task_runtime_state"
	scheduledTaskStateStorageLabel = "db:" + scheduledTaskRuntimeStateTable
)

func normalizeScheduledTaskStatusRecord(status ScheduledTaskStatus) ScheduledTaskStatus {
	status.Name = strings.TrimSpace(status.Name)
	if !status.Running || status.PID < 0 {
		status.PID = 0
	}
	return status
}

func (s *wafEventStore) loadScheduledTaskRuntimeStatuses() (map[string]ScheduledTaskStatus, error) {
	out := make(map[string]ScheduledTaskStatus)
	if s == nil || s.db == nil {
		return out, nil
	}

	rows, err := s.query(`SELECT task_name, running, pid, last_schedule_minute, last_started_at, last_finished_at, last_result, last_error, last_exit_code, last_duration_ms, log_file, resolved_command FROM scheduled_task_runtime_state ORDER BY task_name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var (
			status  ScheduledTaskStatus
			running int
		)
		if err := rows.Scan(
			&status.Name,
			&running,
			&status.PID,
			&status.LastScheduleMinute,
			&status.LastStartedAt,
			&status.LastFinishedAt,
			&status.LastResult,
			&status.LastError,
			&status.LastExitCode,
			&status.LastDurationMS,
			&status.LogFile,
			&status.ResolvedCommand,
		); err != nil {
			return nil, err
		}
		status.Running = boolFromDB(running)
		out[status.Name] = normalizeScheduledTaskStatusRecord(status)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func (s *wafEventStore) loadScheduledTaskRuntimeStatusTx(tx *sql.Tx, taskName string) (ScheduledTaskStatus, bool, error) {
	if s == nil || s.db == nil {
		return ScheduledTaskStatus{}, false, nil
	}

	var (
		status  ScheduledTaskStatus
		running int
	)
	row := tx.QueryRow(s.bindSQL(`SELECT task_name, running, pid, last_schedule_minute, last_started_at, last_finished_at, last_result, last_error, last_exit_code, last_duration_ms, log_file, resolved_command FROM scheduled_task_runtime_state WHERE task_name = ?`), taskName)
	switch err := row.Scan(
		&status.Name,
		&running,
		&status.PID,
		&status.LastScheduleMinute,
		&status.LastStartedAt,
		&status.LastFinishedAt,
		&status.LastResult,
		&status.LastError,
		&status.LastExitCode,
		&status.LastDurationMS,
		&status.LogFile,
		&status.ResolvedCommand,
	); {
	case err == nil:
		status.Running = boolFromDB(running)
		return normalizeScheduledTaskStatusRecord(status), true, nil
	case err == sql.ErrNoRows:
		return ScheduledTaskStatus{}, false, nil
	default:
		return ScheduledTaskStatus{}, false, err
	}
}

func (s *wafEventStore) upsertScheduledTaskRuntimeStatusStmt() string {
	if s != nil && s.dbDriver == logStatsDBDriverMySQL {
		return `INSERT INTO scheduled_task_runtime_state (
			task_name, running, pid, last_schedule_minute, last_started_at,
			last_finished_at, last_result, last_error, last_exit_code,
			last_duration_ms, log_file, resolved_command, updated_at_unix, updated_at
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON DUPLICATE KEY UPDATE
			running = VALUES(running),
			pid = VALUES(pid),
			last_schedule_minute = VALUES(last_schedule_minute),
			last_started_at = VALUES(last_started_at),
			last_finished_at = VALUES(last_finished_at),
			last_result = VALUES(last_result),
			last_error = VALUES(last_error),
			last_exit_code = VALUES(last_exit_code),
			last_duration_ms = VALUES(last_duration_ms),
			log_file = VALUES(log_file),
			resolved_command = VALUES(resolved_command),
			updated_at_unix = VALUES(updated_at_unix),
			updated_at = VALUES(updated_at)`
	}
	return `INSERT INTO scheduled_task_runtime_state (
		task_name, running, pid, last_schedule_minute, last_started_at,
		last_finished_at, last_result, last_error, last_exit_code,
		last_duration_ms, log_file, resolved_command, updated_at_unix, updated_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	ON CONFLICT(task_name) DO UPDATE SET
		running = excluded.running,
		pid = excluded.pid,
		last_schedule_minute = excluded.last_schedule_minute,
		last_started_at = excluded.last_started_at,
		last_finished_at = excluded.last_finished_at,
		last_result = excluded.last_result,
		last_error = excluded.last_error,
		last_exit_code = excluded.last_exit_code,
		last_duration_ms = excluded.last_duration_ms,
		log_file = excluded.log_file,
		resolved_command = excluded.resolved_command,
		updated_at_unix = excluded.updated_at_unix,
		updated_at = excluded.updated_at`
}

func (s *wafEventStore) upsertScheduledTaskRuntimeStatusTx(tx *sql.Tx, status ScheduledTaskStatus, now time.Time) error {
	status = normalizeScheduledTaskStatusRecord(status)
	ts := now.UTC()
	_, err := s.txExec(
		tx,
		s.upsertScheduledTaskRuntimeStatusStmt(),
		status.Name,
		boolToDB(status.Running),
		status.PID,
		status.LastScheduleMinute,
		status.LastStartedAt,
		status.LastFinishedAt,
		status.LastResult,
		status.LastError,
		status.LastExitCode,
		status.LastDurationMS,
		status.LogFile,
		status.ResolvedCommand,
		ts.Unix(),
		ts.Format(time.RFC3339Nano),
	)
	return err
}

func (s *wafEventStore) updateScheduledTaskRuntimeStatus(taskName string, fn func(*ScheduledTaskStatus)) error {
	if s == nil || s.db == nil {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	status, found, err := s.loadScheduledTaskRuntimeStatusTx(tx, taskName)
	if err != nil {
		return err
	}
	if !found {
		status = ScheduledTaskStatus{Name: taskName}
	}
	fn(&status)
	status.Name = taskName
	if err := s.upsertScheduledTaskRuntimeStatusTx(tx, status, time.Now().UTC()); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *wafEventStore) pruneScheduledTaskRuntimeStatuses(allowed map[string]struct{}) error {
	if s == nil || s.db == nil {
		return nil
	}
	if len(allowed) == 0 {
		_, err := s.exec(`DELETE FROM scheduled_task_runtime_state`)
		return err
	}

	names := make([]string, 0, len(allowed))
	for name := range allowed {
		names = append(names, name)
	}
	sort.Strings(names)

	args := make([]any, 0, len(names))
	placeholders := make([]string, 0, len(names))
	for _, name := range names {
		placeholders = append(placeholders, "?")
		args = append(args, name)
	}
	query := `DELETE FROM scheduled_task_runtime_state WHERE task_name NOT IN (` + strings.Join(placeholders, ", ") + `)`
	_, err := s.exec(query, args...)
	return err
}

func (s *wafEventStore) markScheduledTaskStatusAbandoned(taskName string, pid int, finishedAt time.Time) (bool, error) {
	if s == nil || s.db == nil || pid <= 0 {
		return false, nil
	}
	ts := finishedAt.UTC()
	formatted := ts.Format(time.RFC3339Nano)
	res, err := s.exec(
		`UPDATE scheduled_task_runtime_state
		    SET running = 0,
		        pid = 0,
		        last_finished_at = CASE WHEN last_finished_at = '' THEN ? ELSE last_finished_at END,
		        last_result = CASE WHEN last_result IN ('', 'running') THEN 'abandoned' ELSE last_result END,
		        updated_at_unix = ?,
		        updated_at = ?
		  WHERE task_name = ? AND running = 1 AND pid = ?`,
		formatted,
		ts.Unix(),
		formatted,
		taskName,
		pid,
	)
	if err != nil {
		return false, err
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return affected > 0, nil
}
