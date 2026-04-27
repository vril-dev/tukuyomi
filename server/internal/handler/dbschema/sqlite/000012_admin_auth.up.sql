CREATE TABLE IF NOT EXISTS admin_users (
	user_id INTEGER PRIMARY KEY AUTOINCREMENT,
	username TEXT NOT NULL,
	username_normalized TEXT NOT NULL,
	email TEXT,
	email_normalized TEXT,
	role TEXT NOT NULL,
	password_hash TEXT NOT NULL,
	password_algo TEXT NOT NULL DEFAULT 'argon2id',
	must_change_password INTEGER NOT NULL DEFAULT 0,
	session_version INTEGER NOT NULL DEFAULT 1,
	disabled_at_unix INTEGER,
	disabled_at TEXT,
	last_login_at_unix INTEGER,
	last_login_at TEXT,
	created_at_unix INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	updated_at_unix INTEGER NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_users_username_normalized ON admin_users(username_normalized);
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_users_email_normalized ON admin_users(email_normalized) WHERE email_normalized IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_admin_users_role ON admin_users(role);
CREATE INDEX IF NOT EXISTS idx_admin_users_disabled_at_unix ON admin_users(disabled_at_unix);

CREATE TABLE IF NOT EXISTS admin_api_tokens (
	token_id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	label TEXT NOT NULL,
	token_prefix TEXT NOT NULL,
	token_hash TEXT NOT NULL,
	scopes_json TEXT NOT NULL,
	expires_at_unix INTEGER,
	expires_at TEXT,
	revoked_at_unix INTEGER,
	revoked_at TEXT,
	last_used_at_unix INTEGER,
	last_used_at TEXT,
	created_at_unix INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_api_tokens_token_prefix ON admin_api_tokens(token_prefix);
CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_api_tokens_token_hash ON admin_api_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_api_tokens_user_id ON admin_api_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_api_tokens_expires_at_unix ON admin_api_tokens(expires_at_unix);
CREATE INDEX IF NOT EXISTS idx_admin_api_tokens_revoked_at_unix ON admin_api_tokens(revoked_at_unix);

CREATE TABLE IF NOT EXISTS admin_sessions (
	session_id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER NOT NULL,
	session_token_hash TEXT NOT NULL,
	csrf_token_hash TEXT NOT NULL,
	session_version INTEGER NOT NULL,
	expires_at_unix INTEGER NOT NULL,
	expires_at TEXT NOT NULL,
	revoked_at_unix INTEGER,
	revoked_at TEXT,
	last_seen_at_unix INTEGER NOT NULL,
	last_seen_at TEXT NOT NULL,
	created_at_unix INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE CASCADE
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_admin_sessions_session_token_hash ON admin_sessions(session_token_hash);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_user_id ON admin_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expires_at_unix ON admin_sessions(expires_at_unix);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_revoked_at_unix ON admin_sessions(revoked_at_unix);

CREATE TABLE IF NOT EXISTS admin_auth_audit (
	event_id INTEGER PRIMARY KEY AUTOINCREMENT,
	event_type TEXT NOT NULL,
	user_id INTEGER,
	username TEXT,
	auth_kind TEXT NOT NULL,
	auth_credential_id TEXT,
	success INTEGER NOT NULL,
	ip TEXT,
	user_agent TEXT,
	metadata_json TEXT NOT NULL DEFAULT '{}',
	created_at_unix INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	FOREIGN KEY (user_id) REFERENCES admin_users(user_id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_admin_auth_audit_event_created ON admin_auth_audit(event_type, created_at_unix);
CREATE INDEX IF NOT EXISTS idx_admin_auth_audit_user_created ON admin_auth_audit(user_id, created_at_unix);
CREATE INDEX IF NOT EXISTS idx_admin_auth_audit_success_created ON admin_auth_audit(success, created_at_unix);
