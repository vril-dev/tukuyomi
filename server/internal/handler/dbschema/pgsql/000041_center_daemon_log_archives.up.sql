CREATE TABLE IF NOT EXISTS center_daemon_log_archives (
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  archive_revision TEXT NOT NULL,
  archive_hash TEXT NOT NULL,
  process_id TEXT NOT NULL DEFAULT '',
  log_file TEXT NOT NULL DEFAULT '',
  archive_name TEXT NOT NULL DEFAULT '',
  compressed_size BIGINT NOT NULL,
  uncompressed_size BIGINT NOT NULL,
  rotated_at_unix BIGINT NOT NULL DEFAULT 0,
  uploaded_at_unix BIGINT NOT NULL,
  uploaded_at TEXT NOT NULL,
  PRIMARY KEY (device_id, app_id, archive_revision)
);

CREATE INDEX IF NOT EXISTS idx_center_daemon_log_archives_device_app
  ON center_daemon_log_archives(device_id, app_id, uploaded_at_unix DESC);
