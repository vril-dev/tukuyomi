CREATE TABLE IF NOT EXISTS admin_mfa_totp (
	user_id BIGINT PRIMARY KEY REFERENCES admin_users(user_id) ON DELETE CASCADE,
	secret_base32 TEXT NOT NULL,
	issuer TEXT NOT NULL,
	account_name TEXT NOT NULL,
	last_used_counter BIGINT,
	enabled_at_unix BIGINT NOT NULL,
	enabled_at TEXT NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL,
	updated_at_unix BIGINT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS admin_mfa_recovery_codes (
	code_id BIGSERIAL PRIMARY KEY,
	user_id BIGINT NOT NULL REFERENCES admin_users(user_id) ON DELETE CASCADE,
	code_hash TEXT NOT NULL,
	used_at_unix BIGINT,
	used_at TEXT,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_mfa_recovery_codes_user_id ON admin_mfa_recovery_codes(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_mfa_recovery_codes_hash ON admin_mfa_recovery_codes(code_hash);

CREATE TABLE IF NOT EXISTS admin_mfa_setups (
	setup_id TEXT PRIMARY KEY,
	user_id BIGINT NOT NULL REFERENCES admin_users(user_id) ON DELETE CASCADE,
	secret_base32 TEXT NOT NULL,
	issuer TEXT NOT NULL,
	account_name TEXT NOT NULL,
	expires_at_unix BIGINT NOT NULL,
	expires_at TEXT NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_mfa_setups_user_id ON admin_mfa_setups(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_mfa_setups_expires ON admin_mfa_setups(expires_at_unix);

CREATE TABLE IF NOT EXISTS admin_mfa_challenges (
	challenge_id BIGSERIAL PRIMARY KEY,
	user_id BIGINT NOT NULL REFERENCES admin_users(user_id) ON DELETE CASCADE,
	challenge_token_hash TEXT NOT NULL,
	expires_at_unix BIGINT NOT NULL,
	expires_at TEXT NOT NULL,
	consumed_at_unix BIGINT,
	consumed_at TEXT,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL,
	ip TEXT,
	user_agent TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_mfa_challenges_token_hash ON admin_mfa_challenges(challenge_token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_mfa_challenges_user_id ON admin_mfa_challenges(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_mfa_challenges_expires ON admin_mfa_challenges(expires_at_unix);
