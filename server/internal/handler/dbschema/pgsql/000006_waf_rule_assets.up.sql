CREATE TABLE IF NOT EXISTS waf_rule_assets (
    version_id BIGINT NOT NULL,
    position INTEGER NOT NULL,
    asset_path TEXT NOT NULL,
    asset_kind TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, asset_path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS waf_rule_asset_contents (
    version_id BIGINT NOT NULL,
    asset_path TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    etag TEXT NOT NULL,
    PRIMARY KEY (version_id, asset_path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
