CREATE TABLE IF NOT EXISTS center_proxy_rule_bundles (
    bundle_id INTEGER PRIMARY KEY AUTOINCREMENT,
    bundle_revision TEXT NOT NULL,
    device_id TEXT NOT NULL,
    source_config_revision TEXT NOT NULL DEFAULT '',
    source_proxy_etag TEXT NOT NULL DEFAULT '',
    payload_etag TEXT NOT NULL DEFAULT '',
    payload_hash TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    size_bytes INTEGER NOT NULL,
    created_by TEXT NOT NULL DEFAULT '',
    created_at_unix INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    UNIQUE (bundle_revision),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS center_device_proxy_rule_assignments (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    bundle_revision TEXT NOT NULL,
    base_proxy_etag TEXT NOT NULL DEFAULT '',
    reason TEXT NOT NULL DEFAULT '',
    assigned_by TEXT NOT NULL DEFAULT '',
    assigned_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    dispatched_at_unix INTEGER NOT NULL DEFAULT 0,
    UNIQUE (device_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (bundle_revision) REFERENCES center_proxy_rule_bundles(bundle_revision)
);

CREATE TABLE IF NOT EXISTS center_device_proxy_rule_apply_status (
    status_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    desired_bundle_revision TEXT NOT NULL DEFAULT '',
    local_proxy_etag TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    last_attempt_at_unix INTEGER NOT NULL DEFAULT 0,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (device_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_proxy_rule_bundles_device_created ON center_proxy_rule_bundles(device_id, created_at_unix DESC);
CREATE INDEX IF NOT EXISTS idx_center_device_proxy_rule_assignments_device ON center_device_proxy_rule_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_center_device_proxy_rule_apply_status_device ON center_device_proxy_rule_apply_status(device_id);
