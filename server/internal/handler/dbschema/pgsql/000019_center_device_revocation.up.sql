ALTER TABLE center_devices ADD COLUMN revoked_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE center_devices ADD COLUMN revoked_by TEXT NOT NULL DEFAULT '';
