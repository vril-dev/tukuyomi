ALTER TABLE center_devices ADD COLUMN product_id VARCHAR(191) NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN center_product_id VARCHAR(191) NOT NULL DEFAULT '';
ALTER TABLE edge_device_identities ADD COLUMN center_status_checked_at_unix BIGINT NOT NULL DEFAULT 0;
ALTER TABLE edge_device_identities ADD COLUMN center_status_error VARCHAR(2048) NOT NULL DEFAULT '';
