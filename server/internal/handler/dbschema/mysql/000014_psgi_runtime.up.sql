ALTER TABLE vhosts ADD COLUMN app_root VARCHAR(1024) NOT NULL DEFAULT '';
ALTER TABLE vhosts ADD COLUMN psgi_file VARCHAR(1024) NOT NULL DEFAULT '';
ALTER TABLE vhosts ADD COLUMN workers INT NOT NULL DEFAULT 0;
ALTER TABLE vhosts ADD COLUMN max_requests INT NOT NULL DEFAULT 0;
ALTER TABLE vhosts ADD COLUMN include_extlib INT NOT NULL DEFAULT 0;

CREATE TABLE IF NOT EXISTS vhost_psgi_env (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE KEY uq_vhost_psgi_env_name (version_id, vhost_position, name),
    CONSTRAINT fk_vhost_psgi_env_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS psgi_runtime_inventory (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    runtime_id VARCHAR(191) NOT NULL,
    display_name TEXT NOT NULL,
    detected_version TEXT NOT NULL,
    perl_path TEXT NOT NULL,
    starman_path TEXT NOT NULL,
    available INT NOT NULL DEFAULT 0,
    availability_message TEXT NOT NULL,
    run_user VARCHAR(191) NOT NULL DEFAULT '',
    run_group VARCHAR(191) NOT NULL DEFAULT '',
    source VARCHAR(64) NOT NULL DEFAULT '',
    sha256 VARCHAR(128) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    UNIQUE KEY uq_psgi_runtime_inventory_runtime_id (version_id, runtime_id),
    CONSTRAINT fk_psgi_runtime_inventory_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS psgi_runtime_modules (
    version_id BIGINT NOT NULL,
    runtime_position INT NOT NULL,
    position INT NOT NULL,
    module VARCHAR(191) NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE KEY uq_psgi_runtime_modules_module (version_id, runtime_position, module),
    CONSTRAINT fk_psgi_runtime_modules_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS psgi_runtime_inventory_state (
    version_id BIGINT PRIMARY KEY,
    auto_discover INT NOT NULL DEFAULT 0,
    raw_text TEXT NOT NULL,
    CONSTRAINT fk_psgi_runtime_inventory_state_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
