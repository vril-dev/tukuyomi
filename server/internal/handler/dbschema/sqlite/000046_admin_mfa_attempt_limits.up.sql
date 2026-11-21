ALTER TABLE admin_mfa_challenges ADD COLUMN attempt_count INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_mfa_totp ADD COLUMN failed_attempts INTEGER NOT NULL DEFAULT 0;
ALTER TABLE admin_mfa_totp ADD COLUMN locked_until_unix INTEGER NOT NULL DEFAULT 0;
