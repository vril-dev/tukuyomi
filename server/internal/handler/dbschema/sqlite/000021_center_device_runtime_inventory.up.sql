ALTER TABLE center_devices ADD COLUMN runtime_role TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN build_version TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN go_version TEXT NOT NULL DEFAULT '';
