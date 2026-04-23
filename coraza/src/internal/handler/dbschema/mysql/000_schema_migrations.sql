CREATE TABLE IF NOT EXISTS schema_migrations (
	migration_name VARCHAR(255) NOT NULL PRIMARY KEY,
	applied_at_unix BIGINT NOT NULL,
	applied_at VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
