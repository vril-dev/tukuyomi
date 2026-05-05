CREATE TABLE IF NOT EXISTS center_remote_ssh_sessions (
    session_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    status TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    requested_by_user_id INTEGER,
    requested_by_username TEXT NOT NULL DEFAULT '',
    operator_public_key TEXT NOT NULL,
    operator_public_key_fingerprint_sha256 TEXT NOT NULL,
    attach_token_hash TEXT NOT NULL,
    gateway_host_key_fingerprint_sha256 TEXT NOT NULL DEFAULT '',
    gateway_host_public_key TEXT NOT NULL DEFAULT '',
    ttl_sec INTEGER NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    created_at_unix INTEGER NOT NULL,
    gateway_connected_at_unix INTEGER NOT NULL DEFAULT 0,
    operator_connected_at_unix INTEGER NOT NULL DEFAULT 0,
    started_at_unix INTEGER NOT NULL DEFAULT 0,
    ended_at_unix INTEGER NOT NULL DEFAULT 0,
    close_reason TEXT NOT NULL DEFAULT '',
    operator_ip TEXT NOT NULL DEFAULT '',
    operator_user_agent TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (requested_by_user_id) REFERENCES admin_users(user_id) ON DELETE SET NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_center_remote_ssh_sessions_attach_token_hash
    ON center_remote_ssh_sessions(attach_token_hash);
CREATE INDEX IF NOT EXISTS idx_center_remote_ssh_sessions_device_status_expires
    ON center_remote_ssh_sessions(device_id, status, expires_at_unix);
CREATE INDEX IF NOT EXISTS idx_center_remote_ssh_sessions_status_created
    ON center_remote_ssh_sessions(status, created_at_unix);

CREATE TABLE IF NOT EXISTS center_remote_ssh_events (
    event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id TEXT NOT NULL,
    device_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    message TEXT NOT NULL DEFAULT '',
    metadata_json TEXT NOT NULL DEFAULT '{}',
    created_at_unix INTEGER NOT NULL,
    FOREIGN KEY (session_id) REFERENCES center_remote_ssh_sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_remote_ssh_events_session_created
    ON center_remote_ssh_events(session_id, created_at_unix);
CREATE INDEX IF NOT EXISTS idx_center_remote_ssh_events_device_created
    ON center_remote_ssh_events(device_id, created_at_unix);

CREATE TABLE IF NOT EXISTS center_device_remote_ssh_policy (
    device_id TEXT PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    max_ttl_sec INTEGER NOT NULL DEFAULT 900,
    allowed_run_as_user TEXT NOT NULL DEFAULT '',
    require_reason INTEGER NOT NULL DEFAULT 1,
    updated_by_user_id INTEGER,
    updated_by_username TEXT NOT NULL DEFAULT '',
    updated_at_unix INTEGER NOT NULL,
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (updated_by_user_id) REFERENCES admin_users(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_center_device_remote_ssh_policy_enabled
    ON center_device_remote_ssh_policy(enabled);

CREATE TABLE IF NOT EXISTS remote_ssh_host_keys (
    key_id TEXT PRIMARY KEY,
    private_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 TEXT NOT NULL,
    created_at_unix INTEGER NOT NULL,
    rotated_at_unix INTEGER NOT NULL DEFAULT 0
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_remote_ssh_host_keys_fingerprint
    ON remote_ssh_host_keys(public_key_fingerprint_sha256);

CREATE TABLE IF NOT EXISTS remote_ssh_accepted_nonces (
    nonce_hash TEXT PRIMARY KEY,
    session_id TEXT NOT NULL,
    expires_at_unix INTEGER NOT NULL,
    accepted_at_unix INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_remote_ssh_accepted_nonces_expires
    ON remote_ssh_accepted_nonces(expires_at_unix);
