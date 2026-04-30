ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_revision VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_pushed_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_error VARCHAR(2048) NOT NULL DEFAULT '';

ALTER TABLE center_devices ADD COLUMN config_snapshot_revision VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN config_snapshot_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE center_devices ADD COLUMN config_snapshot_bytes BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS center_device_config_snapshots (
    snapshot_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    revision VARCHAR(64) NOT NULL,
    payload_hash VARCHAR(64) NOT NULL,
    payload_json LONGTEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (snapshot_id),
    UNIQUE KEY uq_center_device_config_snapshots_device_revision (device_id, revision),
    KEY idx_center_device_config_snapshots_device_created (device_id, created_at_unix)
);
