ALTER TABLE vhosts ADD COLUMN app_root TEXT NOT NULL DEFAULT '';
ALTER TABLE vhosts ADD COLUMN psgi_file TEXT NOT NULL DEFAULT '';
ALTER TABLE vhosts ADD COLUMN workers INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vhosts ADD COLUMN max_requests INTEGER NOT NULL DEFAULT 0;
ALTER TABLE vhosts ADD COLUMN include_extlib INTEGER NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS vhost_psgi_env (
    version_id INTEGER NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE (version_id, vhost_position, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS psgi_runtime_inventory (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    runtime_id TEXT NOT NULL,
    display_name TEXT NOT NULL DEFAULT '',
    detected_version TEXT NOT NULL DEFAULT '',
    perl_path TEXT NOT NULL,
    starman_path TEXT NOT NULL,
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

CREATE TABLE IF NOT EXISTS psgi_runtime_modules (
    version_id INTEGER NOT NULL,
    runtime_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    module TEXT NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE (version_id, runtime_position, module),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS psgi_runtime_inventory_state (
    version_id INTEGER PRIMARY KEY,
    auto_discover INTEGER NOT NULL DEFAULT 0,
    raw_text TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
