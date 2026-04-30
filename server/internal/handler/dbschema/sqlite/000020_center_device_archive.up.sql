ALTER TABLE center_devices ADD COLUMN archived_at_unix INTEGER NOT NULL DEFAULT 0;
ALTER TABLE center_devices ADD COLUMN archived_by TEXT NOT NULL DEFAULT '';
