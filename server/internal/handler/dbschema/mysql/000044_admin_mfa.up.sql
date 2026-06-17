CREATE TABLE IF NOT EXISTS admin_mfa_totp (
	user_id BIGINT NOT NULL PRIMARY KEY,
	secret_base32 VARCHAR(128) NOT NULL,
	issuer VARCHAR(128) NOT NULL,
	account_name VARCHAR(254) NOT NULL,
	last_used_counter BIGINT NULL,
	enabled_at_unix BIGINT NOT NULL,
	enabled_at VARCHAR(64) NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	updated_at_unix BIGINT NOT NULL,
	updated_at VARCHAR(64) NOT NULL,
	CONSTRAINT fk_admin_mfa_totp_user_id FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_mfa_recovery_codes (
	code_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	user_id BIGINT NOT NULL,
	code_hash VARCHAR(96) NOT NULL,
	used_at_unix BIGINT NULL,
	used_at VARCHAR(64) NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	UNIQUE KEY uq_admin_mfa_recovery_codes_hash (code_hash),
	KEY idx_admin_mfa_recovery_codes_user_id (user_id),
	CONSTRAINT fk_admin_mfa_recovery_codes_user_id FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_mfa_setups (
	setup_id VARCHAR(128) NOT NULL PRIMARY KEY,
	user_id BIGINT NOT NULL,
	secret_base32 VARCHAR(128) NOT NULL,
	issuer VARCHAR(128) NOT NULL,
	account_name VARCHAR(254) NOT NULL,
	expires_at_unix BIGINT NOT NULL,
	expires_at VARCHAR(64) NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	KEY idx_admin_mfa_setups_user_id (user_id),
	KEY idx_admin_mfa_setups_expires (expires_at_unix),
	CONSTRAINT fk_admin_mfa_setups_user_id FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS admin_mfa_challenges (
	challenge_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	user_id BIGINT NOT NULL,
	challenge_token_hash VARCHAR(96) NOT NULL,
	expires_at_unix BIGINT NOT NULL,
	expires_at VARCHAR(64) NOT NULL,
	consumed_at_unix BIGINT NULL,
	consumed_at VARCHAR(64) NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	ip VARCHAR(64) NULL,
	user_agent TEXT NULL,
	UNIQUE KEY uq_admin_mfa_challenges_token_hash (challenge_token_hash),
	KEY idx_admin_mfa_challenges_user_id (user_id),
	KEY idx_admin_mfa_challenges_expires (expires_at_unix),
	CONSTRAINT fk_admin_mfa_challenges_user_id FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
