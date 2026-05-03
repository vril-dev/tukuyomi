ALTER TABLE center_rule_artifact_bundles ADD COLUMN source VARCHAR(16) NOT NULL DEFAULT 'gateway';

CREATE INDEX idx_center_rule_artifact_bundles_device_source_created
    ON center_rule_artifact_bundles(device_id, source, created_at_unix);
