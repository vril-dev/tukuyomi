CREATE TABLE IF NOT EXISTS center_device_waf_rule_assignments (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    base_bundle_revision TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    assigned_by TEXT NOT NULL DEFAULT '',
    assigned_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    dispatched_at_unix INTEGER NOT NULL DEFAULT 0,
    UNIQUE (device_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id, bundle_revision) REFERENCES center_rule_artifact_bundles(device_id, bundle_revision)
);

CREATE TABLE IF NOT EXISTS center_device_waf_rule_apply_status (
    status_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    desired_bundle_revision TEXT NOT NULL DEFAULT '',
    local_bundle_revision TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    last_attempt_at_unix INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (device_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS center_device_waf_rule_apply_history (
    history_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    local_bundle_revision TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    last_attempt_at_unix INTEGER NOT NULL DEFAULT 0,
    applied_at_unix INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (device_id, bundle_revision),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (device_id, bundle_revision) REFERENCES center_rule_artifact_bundles(device_id, bundle_revision)
);

CREATE INDEX IF NOT EXISTS idx_center_device_waf_rule_assignments_device
    ON center_device_waf_rule_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_center_device_waf_rule_apply_status_device
    ON center_device_waf_rule_apply_status(device_id);
CREATE INDEX IF NOT EXISTS idx_center_device_waf_rule_apply_history_device
    ON center_device_waf_rule_apply_history(device_id, updated_at_unix DESC);
