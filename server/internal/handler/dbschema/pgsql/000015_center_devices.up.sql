CREATE TABLE IF NOT EXISTS center_devices (
    device_pk BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL UNIQUE,
    key_id TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 TEXT NOT NULL,
    status TEXT NOT NULL,
    approved_enrollment_id BIGINT NOT NULL DEFAULT 0,
    approved_at_unix BIGINT NOT NULL DEFAULT 0,
    approved_by TEXT NOT NULL DEFAULT '',
    created_at_unix BIGINT NOT NULL,
    updated_at_unix BIGINT NOT NULL,
    last_seen_at_unix BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_center_devices_status ON center_devices(status);

CREATE TABLE IF NOT EXISTS center_device_enrollments (
    enrollment_id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    public_key_pem TEXT NOT NULL,
    public_key_fingerprint_sha256 TEXT NOT NULL,
    license_key_hash TEXT NOT NULL DEFAULT '',
    nonce_hash TEXT NOT NULL,
    body_hash TEXT NOT NULL,
    signature_b64 TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at_unix BIGINT NOT NULL,
    decided_at_unix BIGINT NOT NULL DEFAULT 0,
    decided_by TEXT NOT NULL DEFAULT '',
    decision_reason TEXT NOT NULL DEFAULT '',
    remote_addr TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    UNIQUE (device_id, key_id, nonce_hash)
);

CREATE INDEX IF NOT EXISTS idx_center_device_enrollments_status ON center_device_enrollments(status);
CREATE INDEX IF NOT EXISTS idx_center_device_enrollments_device ON center_device_enrollments(device_id);
