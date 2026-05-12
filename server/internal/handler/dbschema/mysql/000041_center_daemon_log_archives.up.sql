CREATE TABLE IF NOT EXISTS center_daemon_log_archives (
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  archive_revision CHAR(64) NOT NULL,
  archive_hash CHAR(64) NOT NULL,
  process_id VARCHAR(64) NOT NULL DEFAULT '',
  log_file VARCHAR(512) NOT NULL DEFAULT '',
  archive_name VARCHAR(255) NOT NULL DEFAULT '',
  compressed_size BIGINT NOT NULL,
  uncompressed_size BIGINT NOT NULL,
  rotated_at_unix BIGINT NOT NULL DEFAULT 0,
  uploaded_at_unix BIGINT NOT NULL,
  uploaded_at VARCHAR(64) NOT NULL,
  PRIMARY KEY (device_id, app_id, archive_revision)
);

CREATE INDEX idx_center_daemon_log_archives_device_app
  ON center_daemon_log_archives(device_id, app_id, uploaded_at_unix);
