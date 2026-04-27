CREATE TABLE IF NOT EXISTS sites (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    enabled_set INT NOT NULL DEFAULT 0,
    enabled INT NOT NULL DEFAULT 1,
    default_upstream TEXT NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE KEY uq_sites_name (version_id, name),
    CONSTRAINT fk_sites_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS site_hosts (
    version_id BIGINT NOT NULL,
    site_position INT NOT NULL,
    position INT NOT NULL,
    host VARCHAR(255) NOT NULL,
    PRIMARY KEY (version_id, site_position, position),
    UNIQUE KEY uq_site_hosts_host (version_id, host),
    CONSTRAINT fk_site_hosts_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS site_tls (
    version_id BIGINT NOT NULL,
    site_position INT NOT NULL,
    mode VARCHAR(32) NOT NULL,
    cert_file TEXT NOT NULL,
    key_file TEXT NOT NULL,
    PRIMARY KEY (version_id, site_position),
    CONSTRAINT fk_site_tls_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhosts (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    mode VARCHAR(32) NOT NULL,
    hostname VARCHAR(255) NOT NULL,
    listen_port INT NOT NULL DEFAULT 0,
    document_root TEXT NOT NULL,
    runtime_id VARCHAR(191) NOT NULL DEFAULT '',
    generated_target VARCHAR(191) NOT NULL DEFAULT '',
    linked_upstream_name VARCHAR(191) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    UNIQUE KEY uq_vhosts_name (version_id, name),
    UNIQUE KEY uq_vhosts_listener (version_id, hostname, listen_port),
    CONSTRAINT fk_vhosts_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_try_files (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    try_file TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    CONSTRAINT fk_vhost_try_files_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_rewrite_rules (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    pattern TEXT NOT NULL,
    replacement TEXT NOT NULL,
    flag VARCHAR(64) NOT NULL DEFAULT '',
    preserve_query INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, vhost_position, position),
    CONSTRAINT fk_vhost_rewrite_rules_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_access_rules (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    path_pattern TEXT NOT NULL,
    action VARCHAR(32) NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    CONSTRAINT fk_vhost_access_rules_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_access_rule_cidrs (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    access_rule_position INT NOT NULL,
    position INT NOT NULL,
    cidr VARCHAR(64) NOT NULL,
    PRIMARY KEY (version_id, vhost_position, access_rule_position, position),
    CONSTRAINT fk_vhost_access_rule_cidrs_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_basic_auth (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    scope VARCHAR(32) NOT NULL,
    access_rule_position INT NOT NULL DEFAULT -1,
    realm VARCHAR(255) NOT NULL,
    PRIMARY KEY (version_id, vhost_position, scope, access_rule_position),
    CONSTRAINT fk_vhost_basic_auth_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_basic_auth_users (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    scope VARCHAR(32) NOT NULL,
    access_rule_position INT NOT NULL DEFAULT -1,
    position INT NOT NULL,
    username VARCHAR(191) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    PRIMARY KEY (version_id, vhost_position, scope, access_rule_position, position),
    CONSTRAINT fk_vhost_basic_auth_users_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_php_values (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE KEY uq_vhost_php_values_name (version_id, vhost_position, name),
    CONSTRAINT fk_vhost_php_values_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS vhost_php_admin_values (
    version_id BIGINT NOT NULL,
    vhost_position INT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE KEY uq_vhost_php_admin_values_name (version_id, vhost_position, name),
    CONSTRAINT fk_vhost_php_admin_values_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    enabled INT NOT NULL DEFAULT 0,
    schedule VARCHAR(255) NOT NULL,
    timezone VARCHAR(128) NOT NULL DEFAULT '',
    command TEXT NOT NULL,
    timeout_sec INT NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE KEY uq_scheduled_tasks_name (version_id, name),
    CONSTRAINT fk_scheduled_tasks_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scheduled_task_env (
    version_id BIGINT NOT NULL,
    task_position INT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(191) NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, task_position, position),
    UNIQUE KEY uq_scheduled_task_env_name (version_id, task_position, name),
    CONSTRAINT fk_scheduled_task_env_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS scheduled_task_args (
    version_id BIGINT NOT NULL,
    task_position INT NOT NULL,
    position INT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, task_position, position),
    CONSTRAINT fk_scheduled_task_args_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS upstream_runtime_overrides (
    version_id BIGINT NOT NULL,
    backend_key_hash CHAR(64) NOT NULL,
    backend_key TEXT NOT NULL,
    admin_state_set INT NOT NULL DEFAULT 0,
    admin_state VARCHAR(32) NOT NULL DEFAULT '',
    weight_override_set INT NOT NULL DEFAULT 0,
    weight_override INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, backend_key_hash),
    CONSTRAINT fk_upstream_runtime_overrides_version FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
