ALTER TABLE center_device_runtime_summaries ADD COLUMN app_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE center_device_runtime_summaries ADD COLUMN generated_targets_json TEXT NOT NULL DEFAULT '[]';
ALTER TABLE center_device_runtime_summaries ADD COLUMN process_running INTEGER NOT NULL DEFAULT 0;
ALTER TABLE center_device_runtime_summaries ADD COLUMN usage_reported INTEGER NOT NULL DEFAULT 0;
