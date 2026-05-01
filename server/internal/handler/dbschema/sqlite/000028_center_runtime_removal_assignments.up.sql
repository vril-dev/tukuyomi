PRAGMA foreign_keys=off;

CREATE TABLE IF NOT EXISTS center_device_runtime_assignments_next (
    assignment_id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    runtime_family TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    desired_artifact_revision TEXT NOT NULL DEFAULT '',
    desired_state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    assigned_by TEXT NOT NULL DEFAULT '',
    assigned_at_unix INTEGER NOT NULL,
    updated_at_unix INTEGER NOT NULL,
    UNIQUE (device_id, runtime_family, runtime_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

INSERT OR IGNORE INTO center_device_runtime_assignments_next
    (assignment_id, device_id, runtime_family, runtime_id, desired_artifact_revision,
     desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix)
SELECT assignment_id, device_id, runtime_family, runtime_id, desired_artifact_revision,
       desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix
  FROM center_device_runtime_assignments;

DROP TABLE center_device_runtime_assignments;
ALTER TABLE center_device_runtime_assignments_next RENAME TO center_device_runtime_assignments;

CREATE INDEX IF NOT EXISTS idx_center_device_runtime_assignments_device ON center_device_runtime_assignments(device_id);

PRAGMA foreign_keys=on;

