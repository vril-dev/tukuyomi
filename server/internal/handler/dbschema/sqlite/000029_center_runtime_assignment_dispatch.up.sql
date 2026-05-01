ALTER TABLE center_device_runtime_assignments
    ADD COLUMN dispatched_at_unix INTEGER NOT NULL DEFAULT 0;
