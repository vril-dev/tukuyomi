CREATE TABLE IF NOT EXISTS center_app_deploy_profiles (
  profile_id INTEGER PRIMARY KEY AUTOINCREMENT,
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  runtime_family TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  profile_revision TEXT NOT NULL,
  roots_json TEXT NOT NULL DEFAULT '[]',
  created_by TEXT NOT NULL DEFAULT '',
  updated_by TEXT NOT NULL DEFAULT '',
  created_at_unix INTEGER NOT NULL,
  updated_at_unix INTEGER NOT NULL,
  UNIQUE (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_app_deploy_profile_roots (
  profile_id INTEGER NOT NULL,
  root_id TEXT NOT NULL,
  runtime_field TEXT NOT NULL,
  source_path TEXT NOT NULL DEFAULT '',
  package_prefix TEXT NOT NULL,
  target_subpath TEXT NOT NULL DEFAULT '',
  runtime_subpath TEXT NOT NULL DEFAULT '',
  required INTEGER NOT NULL DEFAULT 1,
  position INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (profile_id, root_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_candidates (
  device_id TEXT NOT NULL,
  app_id TEXT NOT NULL,
  runtime_family TEXT NOT NULL,
  runtime_id TEXT NOT NULL DEFAULT '',
  roots_json TEXT NOT NULL DEFAULT '[]',
  managed INTEGER NOT NULL DEFAULT 0,
  detected_at_unix INTEGER NOT NULL,
  PRIMARY KEY (device_id, app_id)
);

ALTER TABLE center_app_deploy_packages ADD COLUMN profile_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE center_app_deploy_packages ADD COLUMN roots_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE center_device_app_deploy_requests ADD COLUMN base_package_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_requests ADD COLUMN profile_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_requests ADD COLUMN roots_json TEXT NOT NULL DEFAULT '[]';

ALTER TABLE center_device_app_deploy_history ADD COLUMN base_package_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_history ADD COLUMN profile_revision TEXT NOT NULL DEFAULT '';
