CREATE TABLE IF NOT EXISTS scheduled_task_runtime_state (
    task_name VARCHAR(191) NOT NULL,
    running INT NOT NULL DEFAULT 0,
    pid INT NOT NULL DEFAULT 0,
    last_schedule_minute TEXT NOT NULL,
    last_started_at TEXT NOT NULL,
    last_finished_at TEXT NOT NULL,
    last_result TEXT NOT NULL,
    last_error TEXT NOT NULL,
    last_exit_code INT NOT NULL DEFAULT 0,
    last_duration_ms BIGINT NOT NULL DEFAULT 0,
    log_file TEXT NOT NULL,
    resolved_command TEXT NOT NULL,
    updated_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (task_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
