ALTER TABLE center_device_runtime_summaries ADD COLUMN app_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE center_device_runtime_summaries ADD COLUMN generated_targets_json MEDIUMTEXT;
ALTER TABLE center_device_runtime_summaries ADD COLUMN process_running TINYINT(1) NOT NULL DEFAULT 0;
ALTER TABLE center_device_runtime_summaries ADD COLUMN usage_reported TINYINT(1) NOT NULL DEFAULT 0;
