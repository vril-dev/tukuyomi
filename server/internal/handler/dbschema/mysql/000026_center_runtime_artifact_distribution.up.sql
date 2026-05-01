CREATE TABLE IF NOT EXISTS center_runtime_artifacts (
    artifact_id BIGINT NOT NULL AUTO_INCREMENT,
    artifact_revision VARCHAR(64) NOT NULL,
    artifact_hash VARCHAR(64) NOT NULL,
    runtime_family VARCHAR(32) NOT NULL,
    runtime_id VARCHAR(64) NOT NULL,
    detected_version VARCHAR(128) NOT NULL DEFAULT '',
    target_os VARCHAR(32) NOT NULL,
    target_arch VARCHAR(32) NOT NULL,
    target_kernel_version VARCHAR(128) NOT NULL DEFAULT '',
    target_distro_id VARCHAR(64) NOT NULL,
    target_distro_id_like VARCHAR(128) NOT NULL DEFAULT '',
    target_distro_version VARCHAR(64) NOT NULL,
    compressed_size_bytes BIGINT NOT NULL,
    uncompressed_size_bytes BIGINT NOT NULL,
    file_count BIGINT NOT NULL,
    manifest_json MEDIUMTEXT NOT NULL,
    artifact_blob LONGBLOB,
    storage_state VARCHAR(32) NOT NULL,
    builder_version VARCHAR(128) NOT NULL DEFAULT '',
    builder_profile VARCHAR(128) NOT NULL DEFAULT '',
    created_by VARCHAR(191) NOT NULL DEFAULT '',
    created_at_unix BIGINT NOT NULL,
    created_at VARCHAR(64) NOT NULL,
    PRIMARY KEY (artifact_id),
    UNIQUE KEY uq_center_runtime_artifacts_revision (artifact_revision),
    KEY idx_center_runtime_artifacts_target (runtime_family, runtime_id, target_os, target_arch, target_distro_id, target_distro_version)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_runtime_artifact_files (
    file_id BIGINT NOT NULL AUTO_INCREMENT,
    artifact_revision VARCHAR(64) NOT NULL,
    archive_path VARCHAR(512) NOT NULL,
    file_kind VARCHAR(64) NOT NULL,
    sha256 VARCHAR(64) NOT NULL,
    size_bytes BIGINT NOT NULL,
    mode BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (file_id),
    UNIQUE KEY uq_center_runtime_artifact_files_revision_path (artifact_revision, archive_path),
    KEY idx_center_runtime_artifact_files_revision (artifact_revision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_device_runtime_assignments (
    assignment_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    runtime_family VARCHAR(32) NOT NULL,
    runtime_id VARCHAR(64) NOT NULL,
    desired_artifact_revision VARCHAR(64) NOT NULL,
    desired_state VARCHAR(32) NOT NULL,
    reason VARCHAR(1024) NOT NULL DEFAULT '',
    assigned_by VARCHAR(191) NOT NULL DEFAULT '',
    assigned_at_unix BIGINT NOT NULL,
    updated_at_unix BIGINT NOT NULL,
    PRIMARY KEY (assignment_id),
    UNIQUE KEY uq_center_device_runtime_assignments_device_runtime (device_id, runtime_family, runtime_id),
    KEY idx_center_device_runtime_assignments_device (device_id),
    KEY idx_center_device_runtime_assignments_revision (desired_artifact_revision)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE IF NOT EXISTS center_device_runtime_apply_status (
    status_id BIGINT NOT NULL AUTO_INCREMENT,
    device_id VARCHAR(191) NOT NULL,
    runtime_family VARCHAR(32) NOT NULL,
    runtime_id VARCHAR(64) NOT NULL,
    desired_artifact_revision VARCHAR(64) NOT NULL DEFAULT '',
    local_artifact_revision VARCHAR(64) NOT NULL DEFAULT '',
    local_artifact_hash VARCHAR(64) NOT NULL DEFAULT '',
    apply_state VARCHAR(32) NOT NULL DEFAULT '',
    apply_error VARCHAR(256) NOT NULL DEFAULT '',
    last_attempt_at_unix BIGINT NOT NULL DEFAULT 0,
    updated_at_unix BIGINT NOT NULL,
    PRIMARY KEY (status_id),
    UNIQUE KEY uq_center_device_runtime_apply_status_device_runtime (device_id, runtime_family, runtime_id),
    KEY idx_center_device_runtime_apply_status_device (device_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
