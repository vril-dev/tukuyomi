CREATE TABLE IF NOT EXISTS php_runtime_inventory (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    runtime_id VARCHAR(191) NOT NULL,
    display_name TEXT NOT NULL,
    detected_version TEXT NOT NULL,
    binary_path TEXT NOT NULL,
    cli_binary_path TEXT NOT NULL,
    available INT NOT NULL DEFAULT 0,
    availability_message TEXT NOT NULL,
    run_user VARCHAR(191) NOT NULL DEFAULT '',
    run_group VARCHAR(191) NOT NULL DEFAULT '',
    source VARCHAR(64) NOT NULL DEFAULT '',
    sha256 VARCHAR(128) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    UNIQUE KEY uq_php_runtime_inventory_runtime_id (version_id, runtime_id),
    CONSTRAINT fk_php_runtime_inventory_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS php_runtime_modules (
    version_id BIGINT NOT NULL,
    runtime_position INT NOT NULL,
    position INT NOT NULL,
    module VARCHAR(191) NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE KEY uq_php_runtime_modules_module (version_id, runtime_position, module),
    CONSTRAINT fk_php_runtime_modules_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS php_runtime_default_disabled_modules (
    version_id BIGINT NOT NULL,
    runtime_position INT NOT NULL,
    position INT NOT NULL,
    module VARCHAR(191) NOT NULL,
    PRIMARY KEY (version_id, runtime_position, position),
    UNIQUE KEY uq_php_runtime_default_disabled_modules_module (version_id, runtime_position, module),
    CONSTRAINT fk_php_runtime_default_disabled_modules_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
