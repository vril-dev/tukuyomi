CREATE TABLE IF NOT EXISTS center_app_deploy_profiles (
  profile_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(128) NOT NULL,
  runtime_family VARCHAR(32) NOT NULL,
  runtime_id VARCHAR(64) NOT NULL DEFAULT '',
  profile_revision CHAR(64) NOT NULL,
  roots_json LONGTEXT NOT NULL,
  created_by VARCHAR(128) NOT NULL DEFAULT '',
  updated_by VARCHAR(128) NOT NULL DEFAULT '',
  created_at_unix BIGINT NOT NULL,
  updated_at_unix BIGINT NOT NULL,
  UNIQUE KEY uniq_center_app_deploy_profiles_device_app (device_id, app_id)
);

CREATE TABLE IF NOT EXISTS center_app_deploy_profile_roots (
  profile_id BIGINT NOT NULL,
  root_id VARCHAR(64) NOT NULL,
  runtime_field VARCHAR(64) NOT NULL,
  source_path VARCHAR(512) NOT NULL DEFAULT '',
  package_prefix VARCHAR(256) NOT NULL,
  target_subpath VARCHAR(256) NOT NULL DEFAULT '',
  runtime_subpath VARCHAR(256) NOT NULL DEFAULT '',
  required TINYINT(1) NOT NULL DEFAULT 1,
  position INT NOT NULL DEFAULT 0,
  PRIMARY KEY (profile_id, root_id)
);

CREATE TABLE IF NOT EXISTS center_device_app_deploy_candidates (
  device_id VARCHAR(128) NOT NULL,
  app_id VARCHAR(128) NOT NULL,
  runtime_family VARCHAR(32) NOT NULL,
  runtime_id VARCHAR(64) NOT NULL DEFAULT '',
  roots_json LONGTEXT NOT NULL,
  managed TINYINT(1) NOT NULL DEFAULT 0,
  detected_at_unix BIGINT NOT NULL,
  PRIMARY KEY (device_id, app_id)
);

ALTER TABLE center_app_deploy_packages ADD COLUMN profile_revision CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE center_app_deploy_packages ADD COLUMN roots_json LONGTEXT NULL;
UPDATE center_app_deploy_packages SET roots_json = '[]' WHERE roots_json IS NULL OR roots_json = '';
ALTER TABLE center_app_deploy_packages MODIFY roots_json LONGTEXT NOT NULL;

ALTER TABLE center_device_app_deploy_requests ADD COLUMN base_package_revision CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_requests ADD COLUMN profile_revision CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_requests ADD COLUMN roots_json LONGTEXT NULL;
UPDATE center_device_app_deploy_requests SET roots_json = '[]' WHERE roots_json IS NULL OR roots_json = '';
ALTER TABLE center_device_app_deploy_requests MODIFY roots_json LONGTEXT NOT NULL;

ALTER TABLE center_device_app_deploy_history ADD COLUMN base_package_revision CHAR(64) NOT NULL DEFAULT '';
ALTER TABLE center_device_app_deploy_history ADD COLUMN profile_revision CHAR(64) NOT NULL DEFAULT '';
