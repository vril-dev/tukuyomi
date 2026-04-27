CREATE TABLE IF NOT EXISTS php_runtime_inventory_state (
    version_id BIGINT PRIMARY KEY,
    auto_discover INTEGER NOT NULL DEFAULT 0,
    raw_text TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
