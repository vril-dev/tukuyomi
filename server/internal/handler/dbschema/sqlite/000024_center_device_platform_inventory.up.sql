ALTER TABLE center_devices ADD COLUMN os TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN arch TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN kernel_version TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN distro_id TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN distro_id_like TEXT NOT NULL DEFAULT '';
ALTER TABLE center_devices ADD COLUMN distro_version TEXT NOT NULL DEFAULT '';
