CREATE TABLE IF NOT EXISTS edge_device_identities (
    identity_id BIGINT NOT NULL,
    device_id VARCHAR(191) NOT NULL,
    key_id VARCHAR(191) NOT NULL,
    private_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 CHAR(64) NOT NULL,
    enrollment_status VARCHAR(32) NOT NULL DEFAULT 'local',
    center_url VARCHAR(2048) NOT NULL DEFAULT '',
    last_enrollment_at_unix BIGINT NOT NULL DEFAULT 0,
    last_enrollment_error TEXT NOT NULL,
    created_at_unix BIGINT NOT NULL,
    updated_at_unix BIGINT NOT NULL,
    PRIMARY KEY (identity_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
