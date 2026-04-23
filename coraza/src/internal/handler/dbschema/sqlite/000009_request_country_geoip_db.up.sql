CREATE TABLE IF NOT EXISTS request_country_mmdb_assets (
    version_id INTEGER PRIMARY KEY,
    present INTEGER NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    content_hash TEXT NOT NULL DEFAULT '',
    raw_bytes BLOB
);

CREATE TABLE IF NOT EXISTS request_country_geoip_configs (
    version_id INTEGER PRIMARY KEY,
    present INTEGER NOT NULL DEFAULT 0,
    raw_text TEXT NOT NULL DEFAULT '',
    size_bytes BIGINT NOT NULL DEFAULT 0,
    has_account_id INTEGER NOT NULL DEFAULT 0,
    has_license_key INTEGER NOT NULL DEFAULT 0,
    supported_country_edition TEXT NOT NULL DEFAULT ''
);

CREATE TABLE IF NOT EXISTS request_country_geoip_config_editions (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    edition_id TEXT NOT NULL,
    PRIMARY KEY (version_id, position)
);

CREATE TABLE IF NOT EXISTS request_country_update_state (
    state_key TEXT PRIMARY KEY,
    last_attempt TEXT NOT NULL DEFAULT '',
    last_success TEXT NOT NULL DEFAULT '',
    last_result TEXT NOT NULL DEFAULT '',
    last_error TEXT NOT NULL DEFAULT '',
    updated_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at TEXT NOT NULL DEFAULT ''
);
