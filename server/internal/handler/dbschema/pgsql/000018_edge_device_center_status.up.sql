ALTER TABLE center_devices ADD COLUMN product_id TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN center_product_id TEXT NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN center_status_checked_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN center_status_error TEXT NOT NULL DEFAULT '';
