ALTER TABLE center_devices ADD COLUMN runtime_deployment_supported TINYINT(1) NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS center_device_runtime_summaries (
    summary_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    runtime_family VARCHAR(32) NOT NULL,
    runtime_id VARCHAR(64) NOT NULL,
    display_name VARCHAR(128) NOT NULL DEFAULT '',
    detected_version VARCHAR(128) NOT NULL DEFAULT '',
    source VARCHAR(32) NOT NULL DEFAULT '',
    available TINYINT(1) NOT NULL DEFAULT 0,
    availability_message VARCHAR(256) NOT NULL DEFAULT '',
    module_count BIGINT NOT NULL DEFAULT 0,
    artifact_revision VARCHAR(64) NOT NULL DEFAULT '',
    artifact_hash VARCHAR(64) NOT NULL DEFAULT '',
    apply_state VARCHAR(32) NOT NULL DEFAULT '',
    apply_error VARCHAR(256) NOT NULL DEFAULT '',
    updated_at_unix BIGINT NOT NULL,
    PRIMARY KEY (summary_id),
    UNIQUE KEY uq_center_device_runtime_summaries_device_runtime (device_id, runtime_family, runtime_id),
    KEY idx_center_device_runtime_summaries_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
