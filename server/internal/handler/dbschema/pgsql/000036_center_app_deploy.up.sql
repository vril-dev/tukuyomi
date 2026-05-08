CREATE TABLE IF NOT EXISTS center_app_deploy_packages (
  package_revision TEXT PRIMARY KEY,
  package_hash TEXT NOT NULL,
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  runtime_family TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  label TEXT NOT NULL DEFAULT '',
  note TEXT NOT NULL DEFAULT '',
  source_type TEXT NOT NULL DEFAULT 'upload',
  compressed_size BIGINT NOT NULL,
  uncompressed_size BIGINT NOT NULL,
  file_count INTEGER NOT NULL,
  manifest_json TEXT NOT NULL DEFAULT '{}',
  uploaded_by TEXT NOT NULL DEFAULT '',
  uploaded_at_unix BIGINT NOT NULL,
  uploaded_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS center_app_deploy_package_files (
  package_revision TEXT NOT NULL,
  path TEXT NOT NULL,
  root_id TEXT NOT NULL DEFAULT '',
  sha256 TEXT NOT NULL,
  size_bytes BIGINT NOT NULL,
  mode BIGINT NOT NULL,
  PRIMARY KEY (package_revision, path)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_requests (
  request_id BIGSERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  package_revision TEXT NOT NULL DEFAULT '',
  package_hash TEXT NOT NULL DEFAULT '',
  restart_behavior TEXT NOT NULL DEFAULT 'restart-runtime',
  script_timeout_sec BIGINT NOT NULL DEFAULT 60,
  pre_switch_script TEXT NOT NULL DEFAULT '',
  post_switch_script TEXT NOT NULL DEFAULT '',
  reason TEXT NOT NULL DEFAULT '',
  requested_by TEXT NOT NULL DEFAULT '',
  requested_at_unix BIGINT NOT NULL,
  updated_at_unix BIGINT NOT NULL,
  dispatched_at_unix BIGINT NOT NULL DEFAULT 0,
  UNIQUE (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_apply_status (
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  desired_package_revision TEXT NOT NULL DEFAULT '',
  local_package_revision TEXT NOT NULL DEFAULT '',
  local_package_hash TEXT NOT NULL DEFAULT '',
  apply_state TEXT NOT NULL DEFAULT '',
  apply_error TEXT NOT NULL DEFAULT '',
  output_tail TEXT NOT NULL DEFAULT '',
  last_attempt_at_unix BIGINT NOT NULL DEFAULT 0,
  updated_at_unix BIGINT NOT NULL,
  PRIMARY KEY (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_history (
  history_id BIGSERIAL PRIMARY KEY,
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  operation TEXT NOT NULL,
  package_revision TEXT NOT NULL DEFAULT '',
  package_hash TEXT NOT NULL DEFAULT '',
  apply_state TEXT NOT NULL,
  apply_error TEXT NOT NULL DEFAULT '',
  output_tail TEXT NOT NULL DEFAULT '',
  requested_by TEXT NOT NULL DEFAULT '',
  requested_at_unix BIGINT NOT NULL DEFAULT 0,
  applied_at_unix BIGINT NOT NULL DEFAULT 0,
  updated_at_unix BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_center_app_deploy_packages_device_app
  ON center_app_deploy_packages(device_id, app_id, uploaded_at_unix DESC);

CREATE INDEX IF NOT EXISTS idx_center_app_deploy_history_device_app
  ON center_device_app_deploy_history(device_id, app_id, updated_at_unix DESC);
