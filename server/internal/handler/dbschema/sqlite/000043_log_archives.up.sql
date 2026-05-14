CREATE TABLE IF NOT EXISTS log_archives (
	archive_id TEXT PRIMARY KEY,
	source TEXT NOT NULL,
	archive_day TEXT NOT NULL,
	part INTEGER NOT NULL,
	state TEXT NOT NULL,
	storage_backend TEXT NOT NULL,
	object_key TEXT NOT NULL,
	meta_object_key TEXT NOT NULL,
	from_ts_unix INTEGER NOT NULL,
	to_ts_unix INTEGER NOT NULL,
	first_event_id INTEGER NOT NULL,
	last_event_id INTEGER NOT NULL,
	row_count INTEGER NOT NULL,
	compressed_bytes INTEGER NOT NULL,
	uncompressed_bytes INTEGER NOT NULL,
	sha256 TEXT NOT NULL,
	error TEXT NOT NULL DEFAULT '',
	created_at_unix INTEGER NOT NULL,
	created_at TEXT NOT NULL,
	sealed_at_unix INTEGER NOT NULL DEFAULT 0,
	sealed_at TEXT NOT NULL DEFAULT '',
	pruned_at_unix INTEGER NOT NULL DEFAULT 0,
	pruned_at TEXT NOT NULL DEFAULT '',
	updated_at_unix INTEGER NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_log_archives_source_day_part ON log_archives(source, archive_day, part);
CREATE INDEX IF NOT EXISTS idx_log_archives_state ON log_archives(state);
CREATE INDEX IF NOT EXISTS idx_log_archives_archive_day ON log_archives(archive_day);
