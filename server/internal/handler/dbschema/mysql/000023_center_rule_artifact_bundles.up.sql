ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_revision VARCHAR(64) NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_pushed_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN rule_artifact_error VARCHAR(2048) NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS center_rule_artifact_bundles (
    bundle_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    bundle_revision VARCHAR(64) NOT NULL,
    bundle_hash VARCHAR(64) NOT NULL,
    compressed_size_bytes BIGINT NOT NULL,
    uncompressed_size_bytes BIGINT NOT NULL,
    file_count BIGINT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (bundle_id),
    UNIQUE KEY uq_center_rule_artifact_bundles_device_revision (device_id, bundle_revision),
    KEY idx_center_rule_artifact_bundles_device_created (device_id, created_at_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_rule_artifact_files (
    file_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    bundle_revision VARCHAR(64) NOT NULL,
    asset_path VARCHAR(512) NOT NULL,
    archive_path VARCHAR(191) NOT NULL,
    asset_kind VARCHAR(64) NOT NULL,
    etag VARCHAR(256) NOT NULL DEFAULT '',
    disabled TINYINT(1) NOT NULL DEFAULT 0,
    sha256 VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    body LONGBLOB NOT NULL,
    PRIMARY KEY (file_id),
    UNIQUE KEY uq_center_rule_artifact_files_device_revision_path (device_id, bundle_revision, asset_path),
    KEY idx_center_rule_artifact_files_device_bundle (device_id, bundle_revision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
