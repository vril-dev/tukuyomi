ALTER TABLE center_device_runtime_assignments
    DROP CONSTRAINT IF EXISTS center_device_runtime_assignments_desired_artifact_revision_fkey;

ALTER TABLE center_device_runtime_assignments
    ALTER COLUMN desired_artifact_revision SET DEFAULT '';

