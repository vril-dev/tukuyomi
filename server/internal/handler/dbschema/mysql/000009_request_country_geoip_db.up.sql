CREATE TABLE IF NOT EXISTS request_country_mmdb_assets (
    version_id BIGINT NOT NULL PRIMARY KEY,
    present INT NOT NULL DEFAULT 0,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    content_hash CHAR(64) NOT NULL DEFAULT '',
    raw_bytes LONGBLOB NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS request_country_geoip_configs (
    version_id BIGINT NOT NULL PRIMARY KEY,
    present INT NOT NULL DEFAULT 0,
    raw_text LONGTEXT NOT NULL,
    size_bytes BIGINT NOT NULL DEFAULT 0,
    has_account_id INT NOT NULL DEFAULT 0,
    has_license_key INT NOT NULL DEFAULT 0,
    supported_country_edition VARCHAR(128) NOT NULL DEFAULT ''
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS request_country_geoip_config_editions (
    version_id BIGINT NOT NULL,
    position BIGINT NOT NULL,
    edition_id VARCHAR(128) NOT NULL,
    PRIMARY KEY (version_id, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS request_country_update_state (
    state_key VARCHAR(64) NOT NULL PRIMARY KEY,
    last_attempt VARCHAR(64) NOT NULL,
    last_success VARCHAR(64) NOT NULL,
    last_result VARCHAR(64) NOT NULL,
    last_error TEXT NOT NULL,
    updated_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
