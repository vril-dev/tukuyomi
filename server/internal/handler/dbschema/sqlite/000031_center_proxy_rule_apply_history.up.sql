CREATE TABLE IF NOT EXISTS center_device_proxy_rule_apply_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    local_proxy_etag TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    last_attempt_at_unix INTEGER NOT NULL DEFAULT 0,
    applied_at_unix INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (device_id, bundle_revision),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (bundle_revision) REFERENCES center_proxy_rule_bundles(bundle_revision)
);

INSERT INTO center_device_proxy_rule_apply_history
    (device_id, bundle_revision, local_proxy_etag, apply_state, apply_error,
     last_attempt_at_unix, applied_at_unix, updated_at_unix)
SELECT s.device_id,
       s.desired_bundle_revision,
       s.local_proxy_etag,
       s.apply_state,
       s.apply_error,
       s.last_attempt_at_unix,
       CASE WHEN s.apply_state = 'applied' THEN COALESCE(NULLIF(s.last_attempt_at_unix, 0), s.updated_at_unix) ELSE 0 END,
       s.updated_at_unix
  FROM center_device_proxy_rule_apply_status s
  JOIN center_proxy_rule_bundles b ON b.bundle_revision = s.desired_bundle_revision
 WHERE s.desired_bundle_revision != ''
ON CONFLICT (device_id, bundle_revision) DO UPDATE SET
    local_proxy_etag = excluded.local_proxy_etag,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    applied_at_unix = excluded.applied_at_unix,
    updated_at_unix = excluded.updated_at_unix;

CREATE INDEX IF NOT EXISTS idx_center_device_proxy_rule_apply_history_device
    ON center_device_proxy_rule_apply_history(device_id, updated_at_unix DESC);
