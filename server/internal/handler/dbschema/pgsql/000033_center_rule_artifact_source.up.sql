ALTER TABLE center_rule_artifact_bundles ADD COLUMN source TEXT NOT NULL DEFAULT 'gateway';

UPDATE center_rule_artifact_bundles
   SET source = 'center'
 WHERE EXISTS (
       SELECT 1
         FROM center_device_waf_rule_assignments a
        WHERE a.device_id = center_rule_artifact_bundles.device_id
          AND a.bundle_revision = center_rule_artifact_bundles.bundle_revision
   )
    OR EXISTS (
       SELECT 1
         FROM center_device_waf_rule_apply_history h
        WHERE h.device_id = center_rule_artifact_bundles.device_id
          AND h.bundle_revision = center_rule_artifact_bundles.bundle_revision
   );

CREATE INDEX IF NOT EXISTS idx_center_rule_artifact_bundles_device_source_created
    ON center_rule_artifact_bundles(device_id, source, created_at_unix DESC);
