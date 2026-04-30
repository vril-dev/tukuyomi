CREATE TABLE IF NOT EXISTS center_enrollment_tokens (
    token_id BIGSERIAL PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    token_prefix TEXT NOT NULL,
    label TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    max_uses BIGINT NOT NULL DEFAULT 1,
    use_count BIGINT NOT NULL DEFAULT 0,
    expires_at_unix BIGINT NOT NULL DEFAULT 0,
    created_at_unix BIGINT NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    revoked_at_unix BIGINT NOT NULL DEFAULT 0,
    revoked_by TEXT NOT NULL DEFAULT '',
    last_used_at_unix BIGINT NOT NULL DEFAULT 0,
    last_used_by_device TEXT NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_center_enrollment_tokens_status ON center_enrollment_tokens(status);
CREATE INDEX IF NOT EXISTS idx_center_enrollment_tokens_expires ON center_enrollment_tokens(expires_at_unix);
