ALTER TABLE center_devices ADD COLUMN runtime_deployment_supported INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS center_device_runtime_summaries (
    summary_id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    runtime_family TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    detected_version TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    available INTEGER NOT NULL DEFAULT 0,
    availability_message TEXT NOT NULL DEFAULT '',
    module_count BIGINT NOT NULL DEFAULT 0,
    artifact_revision TEXT NOT NULL DEFAULT '',
    artifact_hash TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    updated_at_unix BIGINT NOT NULL,
    UNIQUE (device_id, runtime_family, runtime_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_device_runtime_summaries_device ON center_device_runtime_summaries(device_id);
