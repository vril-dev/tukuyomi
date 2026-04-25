CREATE TABLE IF NOT EXISTS scheduled_task_runtime_state (
    task_name TEXT PRIMARY KEY,
    running INTEGER NOT NULL DEFAULT 0,
    pid INTEGER NOT NULL DEFAULT 0,
    last_schedule_minute TEXT NOT NULL DEFAULT '',
    last_started_at TEXT NOT NULL DEFAULT '',
    last_finished_at TEXT NOT NULL DEFAULT '',
    last_result TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    last_exit_code INTEGER NOT NULL DEFAULT 0,
    last_duration_ms BIGINT NOT NULL DEFAULT 0,
    log_file TEXT NOT NULL DEFAULT '',
    resolved_command TEXT NOT NULL DEFAULT '',
    updated_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT ''
);
