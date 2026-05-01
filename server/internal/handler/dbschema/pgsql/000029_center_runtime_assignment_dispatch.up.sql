ALTER TABLE center_device_runtime_assignments
    ADD COLUMN IF NOT EXISTS dispatched_at_unix BIGINT NOT NULL DEFAULT 0;
