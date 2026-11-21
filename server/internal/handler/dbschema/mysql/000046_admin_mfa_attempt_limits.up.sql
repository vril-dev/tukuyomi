ALTER TABLE admin_mfa_challenges ADD COLUMN attempt_count BIGINT NOT NULL DEFAULT 0;
ALTER TABLE admin_mfa_totp ADD COLUMN failed_attempts BIGINT NOT NULL DEFAULT 0;
ALTER TABLE admin_mfa_totp ADD COLUMN locked_until_unix BIGINT NOT NULL DEFAULT 0;
