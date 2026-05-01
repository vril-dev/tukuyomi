CREATE TABLE IF NOT EXISTS center_runtime_artifacts (
    artifact_id BIGSERIAL PRIMARY KEY,
    artifact_revision TEXT NOT NULL UNIQUE,
    artifact_hash TEXT NOT NULL,
    runtime_family TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    detected_version TEXT NOT NULL DEFAULT '',
    target_os TEXT NOT NULL,
    target_arch TEXT NOT NULL,
    target_kernel_version TEXT NOT NULL DEFAULT '',
    target_distro_id TEXT NOT NULL,
    target_distro_id_like TEXT NOT NULL DEFAULT '',
    target_distro_version TEXT NOT NULL,
    compressed_size_bytes BIGINT NOT NULL,
    uncompressed_size_bytes BIGINT NOT NULL,
    file_count BIGINT NOT NULL,
    manifest_json TEXT NOT NULL,
    artifact_blob BYTEA,
    storage_state TEXT NOT NULL,
    builder_version TEXT NOT NULL DEFAULT '',
    builder_profile TEXT NOT NULL DEFAULT '',
    created_by TEXT NOT NULL DEFAULT '',
    created_at_unix BIGINT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS center_runtime_artifact_files (
    file_id BIGSERIAL PRIMARY KEY,
    artifact_revision TEXT NOT NULL,
    archive_path TEXT NOT NULL,
    file_kind TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    size_bytes BIGINT NOT NULL,
    mode BIGINT NOT NULL DEFAULT 0,
    UNIQUE (artifact_revision, archive_path),
    FOREIGN KEY (artifact_revision) REFERENCES center_runtime_artifacts(artifact_revision) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS center_device_runtime_assignments (
    assignment_id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    runtime_family TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    desired_artifact_revision TEXT NOT NULL,
    desired_state TEXT NOT NULL,
    reason TEXT NOT NULL DEFAULT '',
    assigned_by TEXT NOT NULL DEFAULT '',
    assigned_at_unix BIGINT NOT NULL,
    updated_at_unix BIGINT NOT NULL,
    UNIQUE (device_id, runtime_family, runtime_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE,
    FOREIGN KEY (desired_artifact_revision) REFERENCES center_runtime_artifacts(artifact_revision)
);

CREATE TABLE IF NOT EXISTS center_device_runtime_apply_status (
    status_id BIGSERIAL PRIMARY KEY,
    device_id TEXT NOT NULL,
    runtime_family TEXT NOT NULL,
    runtime_id TEXT NOT NULL,
    desired_artifact_revision TEXT NOT NULL DEFAULT '',
    local_artifact_revision TEXT NOT NULL DEFAULT '',
    local_artifact_hash TEXT NOT NULL DEFAULT '',
    apply_state TEXT NOT NULL DEFAULT '',
    apply_error TEXT NOT NULL DEFAULT '',
    last_attempt_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL,
    UNIQUE (device_id, runtime_family, runtime_id),
    FOREIGN KEY (device_id) REFERENCES center_devices(device_id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_center_runtime_artifacts_target ON center_runtime_artifacts(runtime_family, runtime_id, target_os, target_arch, target_distro_id, target_distro_version);
CREATE INDEX IF NOT EXISTS idx_center_runtime_artifact_files_revision ON center_runtime_artifact_files(artifact_revision);
CREATE INDEX IF NOT EXISTS idx_center_device_runtime_assignments_device ON center_device_runtime_assignments(device_id);
CREATE INDEX IF NOT EXISTS idx_center_device_runtime_apply_status_device ON center_device_runtime_apply_status(device_id);
