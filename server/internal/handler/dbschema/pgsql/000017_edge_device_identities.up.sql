CREATE TABLE IF NOT EXISTS edge_device_identities (
    identity_id BIGINT PRIMARY KEY CHECK (identity_id = 1),
    device_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 TEXT NOT NULL,
    enrollment_status TEXT NOT NULL DEFAULT 'local',
    center_url TEXT NOT NULL DEFAULT '',
    last_enrollment_at_unix BIGINT NOT NULL DEFAULT 0,
    last_enrollment_error TEXT NOT NULL DEFAULT '',
    created_at_unix BIGINT NOT NULL,
    updated_at_unix BIGINT NOT NULL
);
