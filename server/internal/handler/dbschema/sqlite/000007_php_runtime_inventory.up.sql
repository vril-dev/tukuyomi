CREATE TABLE IF NOT EXISTS php_runtime_inventory (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    runtime_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    detected_version TEXT NOT NULL DEFAULT '',
    binary_path TEXT NOT NULL,
    cli_binary_path TEXT NOT NULL DEFAULT '',
    available INTEGER NOT NULL DEFAULT 0,
    availability_message TEXT NOT NULL DEFAULT '',
    run_user TEXT NOT NULL DEFAULT '',
    run_group TEXT NOT NULL DEFAULT '',
    source TEXT NOT NULL DEFAULT '',
    sha256 TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, runtime_id),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS php_runtime_modules (
    version_id INTEGER NOT NULL,
    runtime_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    module TEXT NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE (version_id, runtime_position, module),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS php_runtime_default_disabled_modules (
    version_id INTEGER NOT NULL,
    runtime_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    module TEXT NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE (version_id, runtime_position, module),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
