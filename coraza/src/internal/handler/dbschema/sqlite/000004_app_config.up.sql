CREATE TABLE IF NOT EXISTS app_config_values (
    version_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    value_kind TEXT NOT NULL,
    value_text TEXT NOT NULL DEFAULT '',
    value_int INTEGER NOT NULL DEFAULT 0,
    value_real REAL NOT NULL DEFAULT 0,
    value_bool INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_config_lists (
    version_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    PRIMARY KEY (version_id, path),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS app_config_list_values (
    version_id INTEGER NOT NULL,
    path TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, path, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
