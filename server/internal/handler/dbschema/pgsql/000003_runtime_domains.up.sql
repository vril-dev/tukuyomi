CREATE TABLE IF NOT EXISTS sites (
    version_id BIGINT NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    enabled_set INTEGER NOT NULL DEFAULT 0,
    enabled INTEGER NOT NULL DEFAULT 1,
    default_upstream TEXT NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS site_hosts (
    version_id BIGINT NOT NULL,
    site_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    host TEXT NOT NULL,
    PRIMARY KEY (version_id, site_position, position),
    UNIQUE (version_id, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS site_tls (
    version_id BIGINT NOT NULL,
    site_position INTEGER NOT NULL,
    mode TEXT NOT NULL,
    cert_file TEXT NOT NULL DEFAULT '',
    key_file TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, site_position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhosts (
    version_id BIGINT NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    mode TEXT NOT NULL,
    hostname TEXT NOT NULL,
    listen_port INTEGER NOT NULL DEFAULT 0,
    document_root TEXT NOT NULL,
    runtime_id TEXT NOT NULL DEFAULT '',
    generated_target TEXT NOT NULL DEFAULT '',
    linked_upstream_name TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, name),
    UNIQUE (version_id, hostname, listen_port),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_try_files (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    try_file TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_rewrite_rules (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    pattern TEXT NOT NULL,
    replacement TEXT NOT NULL,
    flag TEXT NOT NULL DEFAULT '',
    preserve_query INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, vhost_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_access_rules (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    path_pattern TEXT NOT NULL,
    action TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_access_rule_cidrs (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    access_rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    cidr TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, access_rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_basic_auth (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    scope TEXT NOT NULL,
    access_rule_position INTEGER NOT NULL DEFAULT -1,
    realm TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, scope, access_rule_position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_basic_auth_users (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    scope TEXT NOT NULL,
    access_rule_position INTEGER NOT NULL DEFAULT -1,
    position INTEGER NOT NULL,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, scope, access_rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_php_values (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE (version_id, vhost_position, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS vhost_php_admin_values (
    version_id BIGINT NOT NULL,
    vhost_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, vhost_position, position),
    UNIQUE (version_id, vhost_position, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scheduled_tasks (
    version_id BIGINT NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    schedule TEXT NOT NULL,
    timezone TEXT NOT NULL DEFAULT '',
    command TEXT NOT NULL,
    timeout_sec INTEGER NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scheduled_task_env (
    version_id BIGINT NOT NULL,
    task_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, task_position, position),
    UNIQUE (version_id, task_position, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS scheduled_task_args (
    version_id BIGINT NOT NULL,
    task_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    value TEXT NOT NULL,
    PRIMARY KEY (version_id, task_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS upstream_runtime_overrides (
    version_id BIGINT NOT NULL,
    backend_key_hash TEXT NOT NULL,
    backend_key TEXT NOT NULL,
    admin_state_set INTEGER NOT NULL DEFAULT 0,
    admin_state TEXT NOT NULL DEFAULT '',
    weight_override_set INTEGER NOT NULL DEFAULT 0,
    weight_override INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, backend_key_hash),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
