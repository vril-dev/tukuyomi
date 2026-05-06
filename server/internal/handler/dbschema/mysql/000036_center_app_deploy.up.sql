CREATE TABLE IF NOT EXISTS center_app_deploy_packages (
  package_revision CHAR(64) NOT NULL PRIMARY KEY,
  package_hash CHAR(64) NOT NULL,
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  runtime_family VARCHAR(32) NOT NULL,
  runtime_id VARCHAR(64) NOT NULL DEFAULT '',
  label VARCHAR(191) NOT NULL DEFAULT '',
  note MEDIUMTEXT NOT NULL,
  source_type VARCHAR(32) NOT NULL DEFAULT 'upload',
  compressed_size BIGINT NOT NULL,
  uncompressed_size BIGINT NOT NULL,
  file_count INT NOT NULL,
  manifest_json MEDIUMTEXT NOT NULL,
  package_blob LONGBLOB NOT NULL,
  uploaded_by VARCHAR(191) NOT NULL DEFAULT '',
  uploaded_at_unix BIGINT NOT NULL,
  uploaded_at VARCHAR(64) NOT NULL
);

CREATE TABLE IF NOT EXISTS center_app_deploy_package_files (
  package_revision CHAR(64) NOT NULL,
  path VARCHAR(1024) NOT NULL,
  root_id VARCHAR(64) NOT NULL DEFAULT '',
  sha256 CHAR(64) NOT NULL,
  size_bytes BIGINT NOT NULL,
  mode BIGINT NOT NULL,
  PRIMARY KEY (package_revision, path)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_requests (
  request_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  operation VARCHAR(32) NOT NULL,
  package_revision CHAR(64) NOT NULL DEFAULT '',
  package_hash CHAR(64) NOT NULL DEFAULT '',
  restart_behavior VARCHAR(32) NOT NULL DEFAULT 'restart-runtime',
  script_timeout_sec BIGINT NOT NULL DEFAULT 60,
  pre_switch_script TEXT NOT NULL,
  post_switch_script TEXT NOT NULL,
  reason VARCHAR(1024) NOT NULL DEFAULT '',
  requested_by VARCHAR(191) NOT NULL DEFAULT '',
  requested_at_unix BIGINT NOT NULL,
  updated_at_unix BIGINT NOT NULL,
  dispatched_at_unix BIGINT NOT NULL DEFAULT 0,
  UNIQUE KEY uq_center_device_app_deploy_request (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_apply_status (
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  desired_package_revision CHAR(64) NOT NULL DEFAULT '',
  local_package_revision CHAR(64) NOT NULL DEFAULT '',
  local_package_hash CHAR(64) NOT NULL DEFAULT '',
  apply_state VARCHAR(32) NOT NULL DEFAULT '',
  apply_error VARCHAR(2048) NOT NULL DEFAULT '',
  output_tail TEXT NOT NULL,
  last_attempt_at_unix BIGINT NOT NULL DEFAULT 0,
  updated_at_unix BIGINT NOT NULL,
  PRIMARY KEY (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_history (
  history_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(64) NOT NULL,
  operation VARCHAR(32) NOT NULL,
  package_revision CHAR(64) NOT NULL DEFAULT '',
  package_hash CHAR(64) NOT NULL DEFAULT '',
  apply_state VARCHAR(32) NOT NULL,
  apply_error VARCHAR(2048) NOT NULL DEFAULT '',
  output_tail TEXT NOT NULL,
  requested_by VARCHAR(191) NOT NULL DEFAULT '',
  requested_at_unix BIGINT NOT NULL DEFAULT 0,
  applied_at_unix BIGINT NOT NULL DEFAULT 0,
  updated_at_unix BIGINT NOT NULL
);

CREATE INDEX idx_center_app_deploy_packages_device_app
  ON center_app_deploy_packages(device_id, app_id, uploaded_at_unix);

CREATE INDEX idx_center_app_deploy_history_device_app
  ON center_device_app_deploy_history(device_id, app_id, updated_at_unix);
