CREATE TABLE IF NOT EXISTS center_remote_ssh_sessions (
    session_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(191) NOT NULL,
    status VARCHAR(32) NOT NULL,
    reason VARCHAR(1024) NOT NULL DEFAULT '',
    requested_by_user_id BIGINT,
    requested_by_username VARCHAR(191) NOT NULL DEFAULT '',
    operator_public_key TEXT NOT NULL,
    operator_public_key_fingerprint_sha256 CHAR(64) NOT NULL,
    attach_token_hash CHAR(64) NOT NULL,
    gateway_host_key_fingerprint_sha256 CHAR(64) NOT NULL DEFAULT '',
    gateway_host_public_key TEXT NOT NULL,
    ttl_sec BIGINT NOT NULL,
    expires_at_unix BIGINT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    gateway_connected_at_unix BIGINT NOT NULL DEFAULT 0,
    operator_connected_at_unix BIGINT NOT NULL DEFAULT 0,
    started_at_unix BIGINT NOT NULL DEFAULT 0,
    ended_at_unix BIGINT NOT NULL DEFAULT 0,
    close_reason VARCHAR(256) NOT NULL DEFAULT '',
    operator_ip VARCHAR(191) NOT NULL DEFAULT '',
    operator_user_agent VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (session_id),
    UNIQUE KEY uq_center_remote_ssh_sessions_attach_token_hash (attach_token_hash),
    KEY idx_center_remote_ssh_sessions_device_status_expires (device_id, status, expires_at_unix),
    KEY idx_center_remote_ssh_sessions_status_created (status, created_at_unix),
    KEY idx_center_remote_ssh_sessions_requested_by (requested_by_user_id),
    CONSTRAINT fk_center_remote_ssh_sessions_device
        FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    CONSTRAINT fk_center_remote_ssh_sessions_user
        FOREIGN KEY (requested_by_user_id) REFERENCES admin_users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_remote_ssh_events (
    event_id BIGINT NOT NULL AUTO_INCREMENT,
    session_id VARCHAR(64) NOT NULL,
    device_id VARCHAR(191) NOT NULL,
    event_type VARCHAR(64) NOT NULL,
    message VARCHAR(1024) NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    PRIMARY KEY (event_id),
    KEY idx_center_remote_ssh_events_session_created (session_id, created_at_unix),
    KEY idx_center_remote_ssh_events_device_created (device_id, created_at_unix),
    CONSTRAINT fk_center_remote_ssh_events_session
        FOREIGN KEY (session_id) REFERENCES center_remote_ssh_sessions(session_id) ON DELETE CASCADE,
    CONSTRAINT fk_center_remote_ssh_events_device
        FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_device_remote_ssh_policy (
    device_id VARCHAR(191) NOT NULL,
    enabled TINYINT(1) NOT NULL DEFAULT 0,
    max_ttl_sec BIGINT NOT NULL DEFAULT 900,
    allowed_run_as_user VARCHAR(191) NOT NULL DEFAULT '',
    require_reason TINYINT(1) NOT NULL DEFAULT 1,
    updated_by_user_id BIGINT,
    updated_by_username VARCHAR(191) NOT NULL DEFAULT '',
    updated_at_unix BIGINT NOT NULL,
    PRIMARY KEY (device_id),
    KEY idx_center_device_remote_ssh_policy_enabled (enabled),
    KEY idx_center_device_remote_ssh_policy_updated_by (updated_by_user_id),
    CONSTRAINT fk_center_device_remote_ssh_policy_device
        FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    CONSTRAINT fk_center_device_remote_ssh_policy_user
        FOREIGN KEY (updated_by_user_id) REFERENCES admin_users(user_id) ON DELETE SET NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remote_ssh_host_keys (
    key_id VARCHAR(64) NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 CHAR(64) NOT NULL,
    created_at_unix BIGINT NOT NULL,
    rotated_at_unix BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (key_id),
    UNIQUE KEY uq_remote_ssh_host_keys_fingerprint (public_key_fingerprint_sha256)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS remote_ssh_accepted_nonces (
    nonce_hash CHAR(64) NOT NULL,
    session_id VARCHAR(64) NOT NULL,
    expires_at_unix BIGINT NOT NULL,
    accepted_at_unix BIGINT NOT NULL,
    PRIMARY KEY (nonce_hash),
    KEY idx_remote_ssh_accepted_nonces_expires (expires_at_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
