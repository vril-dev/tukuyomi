CREATE TABLE IF NOT EXISTS app_config_values (
    version_id BIGINT NOT NULL,
    path VARCHAR(255) NOT NULL,
    value_kind VARCHAR(16) NOT NULL,
    value_text TEXT NOT NULL,
    value_int BIGINT NOT NULL DEFAULT 0,
    value_real DOUBLE NOT NULL DEFAULT 0,
    value_bool INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, path),
    CONSTRAINT fk_app_config_values_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS app_config_lists (
    version_id BIGINT NOT NULL,
    path VARCHAR(255) NOT NULL,
    PRIMARY KEY (version_id, path),
    CONSTRAINT fk_app_config_lists_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS app_config_list_values (
    version_id BIGINT NOT NULL,
    path VARCHAR(255) NOT NULL,
    position INT NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, path, position),
    CONSTRAINT fk_app_config_list_values_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
