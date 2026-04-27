CREATE TABLE IF NOT EXISTS waf_rule_assets (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    asset_path VARCHAR(512) NOT NULL,
    asset_kind VARCHAR(32) NOT NULL,
    content_hash VARCHAR(128) NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, asset_path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS waf_rule_asset_contents (
    version_id BIGINT NOT NULL,
    asset_path VARCHAR(512) NOT NULL,
    raw_text MEDIUMTEXT NOT NULL,
    etag VARCHAR(256) NOT NULL,
    PRIMARY KEY (version_id, asset_path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
