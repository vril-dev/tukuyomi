CREATE TABLE IF NOT EXISTS schema_migrations (
	migration_name TEXT PRIMARY KEY,
	applied_at_unix BIGINT NOT NULL,
	applied_at TEXT NOT NULL
);
