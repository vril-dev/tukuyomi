ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_pushed_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN config_snapshot_error TEXT NOT NULL DEFAULT '';

ALTER TABLE center_devices ADD COLUMN config_snapshot_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN config_snapshot_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE center_devices ADD COLUMN config_snapshot_bytes BIGINT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS center_device_config_snapshots (
    snapshot_id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    revision TEXT NOT NULL,
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (device_id, revision),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_device_config_snapshots_device_created ON center_device_config_snapshots(device_id, created_at_unix DESC);
