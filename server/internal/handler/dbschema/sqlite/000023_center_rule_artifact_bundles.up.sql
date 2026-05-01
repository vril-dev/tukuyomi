ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_revision TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_pushed_at_unix INTEGER NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_error TEXT NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS center_rule_artifact_bundles (
    bundle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    bundle_hash TEXT NOT NULL,
    compressed_size_bytes INTEGER NOT NULL,
    uncompressed_size_bytes INTEGER NOT NULL,
    file_count INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (device_id, bundle_revision),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS center_rule_artifact_files (
    file_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    asset_path TEXT NOT NULL,
    archive_path TEXT NOT NULL,
    asset_kind TEXT NOT NULL,
    etag TEXT NOT NULL DEFAULT '',
    disabled INTEGER NOT NULL DEFAULT 0,
    sha256 TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    body BLOB NOT NULL,
    UNIQUE (device_id, bundle_revision, asset_path),
    FOREIGN KEY (device_id, bundle_revision) REFERENCES center_rule_artifact_bundles(device_id, bundle_revision) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_rule_artifact_bundles_device_created ON center_rule_artifact_bundles(device_id, created_at_unix DESC);
CREATE INDEX IF NOT EXISTS idx_center_rule_artifact_files_device_bundle ON center_rule_artifact_files(device_id, bundle_revision);
