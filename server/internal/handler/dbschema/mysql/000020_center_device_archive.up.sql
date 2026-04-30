ALTER TABLE center_devices ADD COLUMN archived_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE center_devices ADD COLUMN archived_by VARCHAR(191) NOT NULL DEFAULT '';
