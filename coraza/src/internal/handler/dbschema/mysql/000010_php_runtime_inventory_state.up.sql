CREATE TABLE IF NOT EXISTS php_runtime_inventory_state (
    version_id BIGINT NOT NULL PRIMARY KEY,
    auto_discover INT NOT NULL DEFAULT 0,
    raw_text LONGTEXT NOT NULL,
    CONSTRAINT fk_php_runtime_inventory_state_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
