package center

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"regexp"
	"sort"
	"strings"
	"time"

	"tukuyomi/internal/runtimeartifactbundle"
)

const (
	RuntimeFamilyPHPFPM = "php-fpm"
	RuntimeFamilyPSGI   = "psgi"

	RuntimeArtifactStorageStored       = "stored"
	RuntimeArtifactStorageMetadataOnly = "metadata_only"

	RuntimeAssignmentDesiredInstalled = "installed"
	RuntimeAssignmentDesiredRemoved   = "removed"

	MaxRuntimeArtifactCompressedBytes   = runtimeartifactbundle.MaxCompressedBytes
	MaxRuntimeArtifactUncompressedBytes = runtimeartifactbundle.MaxUncompressedBytes
	MaxRuntimeArtifactFiles             = runtimeartifactbundle.MaxFiles
	MaxRuntimeArtifactManifestBytes     = runtimeartifactbundle.MaxManifestBytes
	MaxRuntimeArtifactImportBodyBytes   = MaxRuntimeArtifactCompressedBytes + MaxRuntimeArtifactCompressedBytes/2 + 64*1024
)

var (
	ErrRuntimeArtifactNotFound     = errors.New("runtime artifact not found")
	ErrRuntimeArtifactInvalid      = errors.New("invalid runtime artifact")
	ErrRuntimeArtifactIncompatible = errors.New("runtime artifact is incompatible with device")

	runtimeArtifactFileKindPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,64}$`)
)

type RuntimeTargetKey struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelVersion string `json:"kernel_version,omitempty"`
	DistroID      string `json:"distro_id"`
	DistroIDLike  string `json:"distro_id_like,omitempty"`
	DistroVersion string `json:"distro_version"`
}

type RuntimeArtifactFileMetadata struct {
	ArchivePath string `json:"archive_path"`
	FileKind    string `json:"file_kind"`
	SHA256      string `json:"sha256"`
	SizeBytes   int64  `json:"size_bytes"`
	Mode        int64  `json:"mode"`
}

type RuntimeArtifactInsert struct {
	ArtifactRevision string
	ArtifactHash     string
	RuntimeFamily    string
	RuntimeID        string
	DetectedVersion  string
	Target           RuntimeTargetKey
	CompressedSize   int64
	UncompressedSize int64
	FileCount        int
	ManifestJSON     string
	ArtifactBytes    []byte
	Files            []RuntimeArtifactFileMetadata
	BuilderVersion   string
	BuilderProfile   string
	CreatedBy        string
	CreatedAtUnix    int64
}

type RuntimeArtifactRecord struct {
	ArtifactRevision string           `json:"artifact_revision"`
	ArtifactHash     string           `json:"artifact_hash"`
	RuntimeFamily    string           `json:"runtime_family"`
	RuntimeID        string           `json:"runtime_id"`
	DetectedVersion  string           `json:"detected_version"`
	Target           RuntimeTargetKey `json:"target"`
	CompressedSize   int64            `json:"compressed_size"`
	UncompressedSize int64            `json:"uncompressed_size"`
	FileCount        int              `json:"file_count"`
	StorageState     string           `json:"storage_state"`
	BuilderVersion   string           `json:"builder_version"`
	BuilderProfile   string           `json:"builder_profile"`
	CreatedBy        string           `json:"created_by"`
	CreatedAtUnix    int64            `json:"created_at_unix"`
	CreatedAt        string           `json:"created_at"`
	Stored           bool             `json:"stored,omitempty"`
}

type RuntimeAssignmentUpdate struct {
	DeviceID         string
	RuntimeFamily    string
	RuntimeID        string
	ArtifactRevision string
	Reason           string
	AssignedBy       string
	AssignedAtUnix   int64
}

type RuntimeAssignmentRecord struct {
	AssignmentID            int64            `json:"assignment_id"`
	DeviceID                string           `json:"device_id"`
	RuntimeFamily           string           `json:"runtime_family"`
	RuntimeID               string           `json:"runtime_id"`
	DesiredArtifactRevision string           `json:"desired_artifact_revision"`
	DesiredState            string           `json:"desired_state"`
	Reason                  string           `json:"reason"`
	AssignedBy              string           `json:"assigned_by"`
	AssignedAtUnix          int64            `json:"assigned_at_unix"`
	UpdatedAtUnix           int64            `json:"updated_at_unix"`
	ArtifactHash            string           `json:"artifact_hash"`
	CompressedSize          int64            `json:"compressed_size"`
	UncompressedSize        int64            `json:"uncompressed_size"`
	FileCount               int              `json:"file_count"`
	DetectedVersion         string           `json:"detected_version"`
	StorageState            string           `json:"storage_state"`
	Target                  RuntimeTargetKey `json:"target"`
}

type RuntimeApplyStatusRecord struct {
	DeviceID                string `json:"device_id"`
	RuntimeFamily           string `json:"runtime_family"`
	RuntimeID               string `json:"runtime_id"`
	DesiredArtifactRevision string `json:"desired_artifact_revision"`
	LocalArtifactRevision   string `json:"local_artifact_revision"`
	LocalArtifactHash       string `json:"local_artifact_hash"`
	ApplyState              string `json:"apply_state"`
	ApplyError              string `json:"apply_error"`
	LastAttemptAtUnix       int64  `json:"last_attempt_at_unix"`
	UpdatedAtUnix           int64  `json:"updated_at_unix"`
}

type RuntimeDeviceAssignment struct {
	RuntimeFamily    string `json:"runtime_family"`
	RuntimeID        string `json:"runtime_id"`
	ArtifactRevision string `json:"artifact_revision"`
	ArtifactHash     string `json:"artifact_hash"`
	CompressedSize   int64  `json:"compressed_size"`
	UncompressedSize int64  `json:"uncompressed_size"`
	FileCount        int    `json:"file_count"`
	DetectedVersion  string `json:"detected_version"`
	DesiredState     string `json:"desired_state"`
	AssignedAtUnix   int64  `json:"assigned_at_unix"`
}

type RuntimeDeploymentView struct {
	Device      DeviceRecord               `json:"device"`
	Artifacts   []RuntimeArtifactRecord    `json:"artifacts"`
	Assignments []RuntimeAssignmentRecord  `json:"assignments"`
	ApplyStatus []RuntimeApplyStatusRecord `json:"apply_status"`
}

func StoreRuntimeArtifact(ctx context.Context, in RuntimeArtifactInsert) (RuntimeArtifactRecord, error) {
	normalized, manifestJSON, files, storageState, err := normalizeRuntimeArtifactInsert(in)
	if err != nil {
		return RuntimeArtifactRecord{}, err
	}
	if normalized.CreatedAtUnix <= 0 {
		normalized.CreatedAtUnix = time.Now().UTC().Unix()
	}
	createdAt := time.Unix(normalized.CreatedAtUnix, 0).UTC().Format(time.RFC3339)
	out := runtimeArtifactRecordFromInsert(normalized, storageState, createdAt)

	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		existing, found, err := loadRuntimeArtifactByRevisionTx(ctx, tx, driver, normalized.ArtifactRevision)
		if err != nil {
			return err
		}
		if found {
			if !runtimeArtifactDuplicateMatches(existing, out) {
				return fmt.Errorf("%w: artifact revision already exists with different metadata", ErrRuntimeArtifactInvalid)
			}
			existing.Stored = false
			out = existing
			return tx.Commit()
		}
		if err := insertRuntimeArtifactTx(ctx, tx, driver, normalized, manifestJSON, storageState, createdAt); err != nil {
			if isUniqueConstraintError(err) {
				existing, found, loadErr := loadRuntimeArtifactByRevisionTx(ctx, tx, driver, normalized.ArtifactRevision)
				if loadErr != nil {
					return loadErr
				}
				if found {
					if !runtimeArtifactDuplicateMatches(existing, out) {
						return fmt.Errorf("%w: artifact revision already exists with different metadata", ErrRuntimeArtifactInvalid)
					}
					existing.Stored = false
					out = existing
					return tx.Commit()
				}
			}
			return err
		}
		for _, file := range files {
			if err := insertRuntimeArtifactFileTx(ctx, tx, driver, normalized.ArtifactRevision, file); err != nil {
				return err
			}
		}
		out.Stored = true
		return tx.Commit()
	})
	return out, err
}

func StoreRuntimeArtifactBundle(ctx context.Context, compressed []byte, actor string) (RuntimeArtifactRecord, error) {
	parsed, err := runtimeartifactbundle.Parse(compressed)
	if err != nil {
		return RuntimeArtifactRecord{}, fmt.Errorf("%w: %v", ErrRuntimeArtifactInvalid, err)
	}
	manifestJSON, err := json.Marshal(parsed.Manifest)
	if err != nil {
		return RuntimeArtifactRecord{}, fmt.Errorf("%w: marshal manifest", ErrRuntimeArtifactInvalid)
	}
	files := make([]RuntimeArtifactFileMetadata, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		files = append(files, RuntimeArtifactFileMetadata{
			ArchivePath: file.ArchivePath,
			FileKind:    file.FileKind,
			SHA256:      file.SHA256,
			SizeBytes:   file.SizeBytes,
			Mode:        file.Mode,
		})
	}
	generatedAtUnix := int64(0)
	if generatedAt, err := time.Parse(time.RFC3339Nano, parsed.Manifest.GeneratedAt); err == nil {
		generatedAtUnix = generatedAt.UTC().Unix()
	}
	return StoreRuntimeArtifact(ctx, RuntimeArtifactInsert{
		ArtifactRevision: parsed.Revision,
		ArtifactHash:     parsed.ArtifactHash,
		RuntimeFamily:    parsed.Manifest.RuntimeFamily,
		RuntimeID:        parsed.Manifest.RuntimeID,
		DetectedVersion:  parsed.Manifest.DetectedVersion,
		Target: RuntimeTargetKey{
			OS:            parsed.Manifest.Target.OS,
			Arch:          parsed.Manifest.Target.Arch,
			KernelVersion: parsed.Manifest.Target.KernelVersion,
			DistroID:      parsed.Manifest.Target.DistroID,
			DistroIDLike:  parsed.Manifest.Target.DistroIDLike,
			DistroVersion: parsed.Manifest.Target.DistroVersion,
		},
		CompressedSize:   parsed.CompressedSize,
		UncompressedSize: parsed.UncompressedSize,
		FileCount:        parsed.FileCount,
		ManifestJSON:     string(manifestJSON),
		ArtifactBytes:    compressed,
		Files:            files,
		BuilderVersion:   parsed.Manifest.BuilderVersion,
		BuilderProfile:   parsed.Manifest.BuilderProfile,
		CreatedBy:        actor,
		CreatedAtUnix:    generatedAtUnix,
	})
}

func RuntimeDeploymentForDevice(ctx context.Context, deviceID string) (RuntimeDeploymentView, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return RuntimeDeploymentView{}, ErrDeviceStatusNotFound
	}
	var out RuntimeDeploymentView
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		devices := []DeviceRecord{device}
		if err := attachRuntimeSummaries(ctx, db, driver, devices); err != nil {
			return err
		}
		out.Device = devices[0]
		artifacts, err := listCompatibleRuntimeArtifactsTx(ctx, db, driver, device)
		if err != nil {
			return err
		}
		assignments, err := listRuntimeAssignmentsForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		status, err := listRuntimeApplyStatusForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		out.Artifacts = artifacts
		out.Assignments = assignments
		out.ApplyStatus = status
		return nil
	})
	return out, err
}

func AssignRuntimeArtifactToDevice(ctx context.Context, in RuntimeAssignmentUpdate) (RuntimeAssignmentRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.ArtifactRevision = strings.ToLower(strings.TrimSpace(in.ArtifactRevision))
	in.Reason = clampString(in.Reason, 1024)
	in.AssignedBy = clampString(in.AssignedBy, 191)
	if in.AssignedBy == "" {
		in.AssignedBy = "unknown"
	}
	if in.AssignedAtUnix <= 0 {
		in.AssignedAtUnix = time.Now().UTC().Unix()
	}
	family, runtimeID, err := normalizeAssignableRuntimeIdentity(in.RuntimeFamily, in.RuntimeID)
	if err != nil {
		return RuntimeAssignmentRecord{}, err
	}
	in.RuntimeFamily = family
	in.RuntimeID = runtimeID
	if !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.ArtifactRevision) {
		return RuntimeAssignmentRecord{}, ErrRuntimeArtifactInvalid
	}

	var out RuntimeAssignmentRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, in.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved || !device.RuntimeDeploymentSupported {
			return ErrRuntimeArtifactIncompatible
		}
		artifact, found, err := loadRuntimeArtifactByRevisionTx(ctx, tx, driver, in.ArtifactRevision)
		if err != nil {
			return err
		}
		if !found || artifact.StorageState != RuntimeArtifactStorageStored {
			return ErrRuntimeArtifactNotFound
		}
		if artifact.RuntimeFamily != in.RuntimeFamily || artifact.RuntimeID != in.RuntimeID || !runtimeArtifactCompatibleWithDevice(artifact, device) {
			return ErrRuntimeArtifactIncompatible
		}
		if err := upsertRuntimeAssignmentTx(ctx, tx, driver, in); err != nil {
			return err
		}
		rec, err := loadRuntimeAssignmentTx(ctx, tx, driver, in.DeviceID, in.RuntimeFamily, in.RuntimeID)
		if err != nil {
			return err
		}
		out = rec
		return tx.Commit()
	})
	return out, err
}

func RequestRuntimeRemovalForDevice(ctx context.Context, in RuntimeAssignmentUpdate) (RuntimeAssignmentRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.Reason = clampString(in.Reason, 1024)
	in.AssignedBy = clampString(in.AssignedBy, 191)
	if in.AssignedBy == "" {
		in.AssignedBy = "unknown"
	}
	if in.AssignedAtUnix <= 0 {
		in.AssignedAtUnix = time.Now().UTC().Unix()
	}
	family, runtimeID, err := normalizeAssignableRuntimeIdentity(in.RuntimeFamily, in.RuntimeID)
	if err != nil {
		return RuntimeAssignmentRecord{}, err
	}
	in.RuntimeFamily = family
	in.RuntimeID = runtimeID
	if !deviceIDPattern.MatchString(in.DeviceID) {
		return RuntimeAssignmentRecord{}, ErrRuntimeArtifactInvalid
	}

	var out RuntimeAssignmentRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, in.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved || !device.RuntimeDeploymentSupported {
			return ErrRuntimeArtifactIncompatible
		}
		summary, found, err := loadDeviceRuntimeSummaryTx(ctx, tx, driver, in.DeviceID, in.RuntimeFamily, in.RuntimeID)
		if err != nil {
			return err
		}
		if !found || !summary.Available || !summary.UsageReported {
			return ErrRuntimeArtifactNotFound
		}
		if summary.AppCount > 0 || summary.ProcessRunning {
			return ErrRuntimeArtifactIncompatible
		}
		if err := upsertRuntimeRemovalAssignmentTx(ctx, tx, driver, in); err != nil {
			return err
		}
		rec, err := loadRuntimeAssignmentTx(ctx, tx, driver, in.DeviceID, in.RuntimeFamily, in.RuntimeID)
		if err != nil {
			return err
		}
		out = rec
		return tx.Commit()
	})
	return out, err
}

func ClearRuntimeAssignment(ctx context.Context, deviceID, runtimeFamily, runtimeID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	family, id, err := normalizeAssignableRuntimeIdentity(runtimeFamily, runtimeID)
	if err != nil {
		return false, err
	}
	if !deviceIDPattern.MatchString(deviceID) {
		return false, ErrDeviceStatusNotFound
	}
	var cleared bool
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var exists int
		if err := db.QueryRowContext(ctx, `SELECT 1 FROM center_devices WHERE device_id = `+placeholder(driver, 1), deviceID).Scan(&exists); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrDeviceStatusNotFound
			}
			return err
		}
		result, err := db.ExecContext(ctx, `
DELETE FROM center_device_runtime_assignments
 WHERE device_id = `+placeholder(driver, 1)+`
   AND runtime_family = `+placeholder(driver, 2)+`
   AND runtime_id = `+placeholder(driver, 3),
			deviceID,
			family,
			id,
		)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		cleared = err == nil && affected > 0
		return nil
	})
	return cleared, err
}

func PendingRuntimeAssignmentsForDevice(ctx context.Context, deviceID string) ([]RuntimeDeviceAssignment, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	out := []RuntimeDeviceAssignment{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		assignments, err := listRuntimeAssignmentsForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		statusByRuntime, err := loadRuntimeApplyStatusMapTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		for _, assignment := range assignments {
			if assignment.DesiredState == RuntimeAssignmentDesiredRemoved {
				status := statusByRuntime[assignment.RuntimeFamily+"\x00"+assignment.RuntimeID]
				if status.ApplyState == "removed" {
					continue
				}
				out = append(out, RuntimeDeviceAssignment{
					RuntimeFamily:  assignment.RuntimeFamily,
					RuntimeID:      assignment.RuntimeID,
					DesiredState:   assignment.DesiredState,
					AssignedAtUnix: assignment.AssignedAtUnix,
				})
				continue
			}
			artifact := RuntimeArtifactRecord{
				RuntimeFamily:    assignment.RuntimeFamily,
				RuntimeID:        assignment.RuntimeID,
				ArtifactRevision: assignment.DesiredArtifactRevision,
				ArtifactHash:     assignment.ArtifactHash,
				DetectedVersion:  assignment.DetectedVersion,
				CompressedSize:   assignment.CompressedSize,
				UncompressedSize: assignment.UncompressedSize,
				FileCount:        assignment.FileCount,
				StorageState:     assignment.StorageState,
				Target:           assignment.Target,
			}
			if assignment.StorageState != RuntimeArtifactStorageStored || !runtimeArtifactCompatibleWithDevice(artifact, device) {
				continue
			}
			status := statusByRuntime[assignment.RuntimeFamily+"\x00"+assignment.RuntimeID]
			if status.LocalArtifactRevision == assignment.DesiredArtifactRevision && status.ApplyState == "installed" {
				continue
			}
			out = append(out, RuntimeDeviceAssignment{
				RuntimeFamily:    assignment.RuntimeFamily,
				RuntimeID:        assignment.RuntimeID,
				ArtifactRevision: assignment.DesiredArtifactRevision,
				ArtifactHash:     assignment.ArtifactHash,
				CompressedSize:   assignment.CompressedSize,
				UncompressedSize: assignment.UncompressedSize,
				FileCount:        assignment.FileCount,
				DetectedVersion:  assignment.DetectedVersion,
				DesiredState:     assignment.DesiredState,
				AssignedAtUnix:   assignment.AssignedAtUnix,
			})
		}
		return nil
	})
	return out, err
}

func loadDeviceRuntimeSummaryTx(ctx context.Context, q queryer, driver, deviceID, runtimeFamily, runtimeID string) (DeviceRuntimeSummary, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT runtime_family, runtime_id, display_name, detected_version, source,
       available, availability_message, module_count, artifact_revision, artifact_hash,
       usage_reported, app_count, COALESCE(generated_targets_json, '[]'), process_running, apply_state, apply_error, updated_at_unix
  FROM center_device_runtime_summaries
 WHERE device_id = `+placeholder(driver, 1)+`
   AND runtime_family = `+placeholder(driver, 2)+`
   AND runtime_id = `+placeholder(driver, 3),
		deviceID,
		runtimeFamily,
		runtimeID,
	)
	var rec DeviceRuntimeSummary
	var available int
	var usageReported int
	var processRunning int
	var generatedTargetsJSON string
	if err := row.Scan(
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.DisplayName,
		&rec.DetectedVersion,
		&rec.Source,
		&available,
		&rec.AvailabilityMessage,
		&rec.ModuleCount,
		&rec.ArtifactRevision,
		&rec.ArtifactHash,
		&usageReported,
		&rec.AppCount,
		&generatedTargetsJSON,
		&processRunning,
		&rec.ApplyState,
		&rec.ApplyError,
		&rec.UpdatedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return DeviceRuntimeSummary{}, false, nil
		}
		return DeviceRuntimeSummary{}, false, err
	}
	rec.Available = available != 0
	rec.UsageReported = usageReported != 0
	rec.ProcessRunning = processRunning != 0
	rec.GeneratedTargets = unmarshalRuntimeGeneratedTargets(generatedTargetsJSON)
	return rec, true, nil
}

func RuntimeArtifactDownloadForDevice(ctx context.Context, deviceID, runtimeFamily, runtimeID, revision, hash string) (RuntimeArtifactRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	hash = strings.ToLower(strings.TrimSpace(hash))
	family, id, err := normalizeAssignableRuntimeIdentity(runtimeFamily, runtimeID)
	if err != nil {
		return RuntimeArtifactRecord{}, nil, err
	}
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) || !hex64Pattern.MatchString(hash) {
		return RuntimeArtifactRecord{}, nil, ErrRuntimeArtifactInvalid
	}

	var out RuntimeArtifactRecord
	var blob []byte
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved || !device.RuntimeDeploymentSupported {
			return ErrRuntimeArtifactIncompatible
		}
		rec, artifactBlob, found, err := loadAssignedRuntimeArtifactBlobTx(ctx, db, driver, deviceID, family, id, revision, hash)
		if err != nil {
			return err
		}
		if !found {
			return ErrRuntimeArtifactNotFound
		}
		if rec.StorageState != RuntimeArtifactStorageStored || len(artifactBlob) == 0 {
			return ErrRuntimeArtifactNotFound
		}
		if !runtimeArtifactCompatibleWithDevice(rec, device) {
			return ErrRuntimeArtifactIncompatible
		}
		if int64(len(artifactBlob)) != rec.CompressedSize {
			return ErrRuntimeArtifactInvalid
		}
		sum := sha256.Sum256(artifactBlob)
		if !secureEqualHex(hex.EncodeToString(sum[:]), rec.ArtifactHash) {
			return ErrRuntimeArtifactInvalid
		}
		out = rec
		blob = artifactBlob
		return nil
	})
	if err != nil {
		return RuntimeArtifactRecord{}, nil, err
	}
	return out, append([]byte(nil), blob...), nil
}

func updateRuntimeApplyStatusFromSummariesTx(ctx context.Context, tx *sql.Tx, driver, deviceID string, summaries []DeviceRuntimeSummary, updatedAtUnix int64) error {
	desired, err := loadRuntimeAssignmentDesiredRevisionsTx(ctx, tx, driver, deviceID)
	if err != nil {
		return err
	}
	for _, summary := range summaries {
		status := RuntimeApplyStatusRecord{
			DeviceID:                deviceID,
			RuntimeFamily:           summary.RuntimeFamily,
			RuntimeID:               summary.RuntimeID,
			DesiredArtifactRevision: desired[summary.RuntimeFamily+"\x00"+summary.RuntimeID],
			LocalArtifactRevision:   summary.ArtifactRevision,
			LocalArtifactHash:       summary.ArtifactHash,
			ApplyState:              summary.ApplyState,
			ApplyError:              summary.ApplyError,
			UpdatedAtUnix:           updatedAtUnix,
		}
		if status.ApplyState != "" {
			status.LastAttemptAtUnix = updatedAtUnix
		}
		if err := upsertRuntimeApplyStatusTx(ctx, tx, driver, status); err != nil {
			return err
		}
	}
	return nil
}

func normalizeRuntimeArtifactInsert(in RuntimeArtifactInsert) (RuntimeArtifactInsert, string, []RuntimeArtifactFileMetadata, string, error) {
	var err error
	in.RuntimeFamily, in.RuntimeID, err = normalizeAssignableRuntimeIdentity(in.RuntimeFamily, in.RuntimeID)
	if err != nil {
		return RuntimeArtifactInsert{}, "", nil, "", err
	}
	in.ArtifactRevision = strings.ToLower(strings.TrimSpace(in.ArtifactRevision))
	in.ArtifactHash = strings.ToLower(strings.TrimSpace(in.ArtifactHash))
	in.DetectedVersion = strings.TrimSpace(in.DetectedVersion)
	in.Target.OS = strings.TrimSpace(in.Target.OS)
	in.Target.Arch = strings.TrimSpace(in.Target.Arch)
	in.Target.KernelVersion = strings.TrimSpace(in.Target.KernelVersion)
	in.Target.DistroID = strings.TrimSpace(in.Target.DistroID)
	in.Target.DistroIDLike = strings.TrimSpace(in.Target.DistroIDLike)
	in.Target.DistroVersion = strings.TrimSpace(in.Target.DistroVersion)
	in.BuilderVersion = clampString(in.BuilderVersion, 128)
	in.BuilderProfile = clampString(in.BuilderProfile, 128)
	in.CreatedBy = clampString(in.CreatedBy, 191)

	if !hex64Pattern.MatchString(in.ArtifactRevision) || !hex64Pattern.MatchString(in.ArtifactHash) {
		return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: invalid revision or hash", ErrRuntimeArtifactInvalid)
	}
	if !metadataPattern.MatchString(in.DetectedVersion) || len(in.DetectedVersion) > 128 {
		return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: invalid detected_version", ErrRuntimeArtifactInvalid)
	}
	if !metadataPattern.MatchString(in.Target.OS) || len(in.Target.OS) > 32 ||
		!metadataPattern.MatchString(in.Target.Arch) || len(in.Target.Arch) > 32 ||
		!metadataPattern.MatchString(in.Target.KernelVersion) || len(in.Target.KernelVersion) > 128 ||
		!metadataPattern.MatchString(in.Target.DistroID) || len(in.Target.DistroID) > 64 ||
		!metadataPattern.MatchString(in.Target.DistroIDLike) || len(in.Target.DistroIDLike) > 128 ||
		!metadataPattern.MatchString(in.Target.DistroVersion) || len(in.Target.DistroVersion) > 64 {
		return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: invalid target key", ErrRuntimeArtifactInvalid)
	}
	if in.Target.OS == "" || in.Target.Arch == "" || in.Target.DistroID == "" || in.Target.DistroVersion == "" {
		return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: target key is incomplete", ErrRuntimeArtifactInvalid)
	}
	if in.CompressedSize <= 0 || in.CompressedSize > MaxRuntimeArtifactCompressedBytes ||
		in.UncompressedSize <= 0 || in.UncompressedSize > MaxRuntimeArtifactUncompressedBytes ||
		in.FileCount <= 0 || in.FileCount > MaxRuntimeArtifactFiles ||
		len(in.Files) != in.FileCount {
		return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: invalid artifact sizes", ErrRuntimeArtifactInvalid)
	}

	storageState := RuntimeArtifactStorageMetadataOnly
	if len(in.ArtifactBytes) > 0 {
		if int64(len(in.ArtifactBytes)) != in.CompressedSize {
			return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: compressed size mismatch", ErrRuntimeArtifactInvalid)
		}
		sum := sha256.Sum256(in.ArtifactBytes)
		if !secureEqualHex(hex.EncodeToString(sum[:]), in.ArtifactHash) {
			return RuntimeArtifactInsert{}, "", nil, "", fmt.Errorf("%w: artifact hash mismatch", ErrRuntimeArtifactInvalid)
		}
		storageState = RuntimeArtifactStorageStored
	}

	manifestJSON, err := normalizeRuntimeArtifactManifestJSON(in.ManifestJSON)
	if err != nil {
		return RuntimeArtifactInsert{}, "", nil, "", err
	}
	files, err := normalizeRuntimeArtifactFiles(in.Files)
	if err != nil {
		return RuntimeArtifactInsert{}, "", nil, "", err
	}
	return in, manifestJSON, files, storageState, nil
}

func normalizeAssignableRuntimeIdentity(runtimeFamily, runtimeID string) (string, string, error) {
	family := strings.TrimSpace(runtimeFamily)
	id := strings.TrimSpace(runtimeID)
	switch family {
	case RuntimeFamilyPHPFPM:
		switch id {
		case "php83", "php84", "php85":
		default:
			return "", "", fmt.Errorf("%w: unsupported runtime_id", ErrRuntimeArtifactInvalid)
		}
	case RuntimeFamilyPSGI:
		switch id {
		case "perl538":
		default:
			return "", "", fmt.Errorf("%w: unsupported runtime_id", ErrRuntimeArtifactInvalid)
		}
	default:
		return "", "", fmt.Errorf("%w: unsupported runtime_family", ErrRuntimeArtifactInvalid)
	}
	return family, id, nil
}

func normalizeRuntimeArtifactManifestJSON(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > MaxRuntimeArtifactManifestBytes {
		return "", fmt.Errorf("%w: invalid manifest_json size", ErrRuntimeArtifactInvalid)
	}
	var decoded any
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decoded); err != nil {
		return "", fmt.Errorf("%w: invalid manifest_json", ErrRuntimeArtifactInvalid)
	}
	if _, ok := decoded.(map[string]any); !ok {
		return "", fmt.Errorf("%w: manifest_json must be an object", ErrRuntimeArtifactInvalid)
	}
	var compacted bytes.Buffer
	if err := json.Compact(&compacted, []byte(raw)); err != nil {
		return "", fmt.Errorf("%w: invalid manifest_json", ErrRuntimeArtifactInvalid)
	}
	return compacted.String(), nil
}

func normalizeRuntimeArtifactFiles(files []RuntimeArtifactFileMetadata) ([]RuntimeArtifactFileMetadata, error) {
	out := make([]RuntimeArtifactFileMetadata, 0, len(files))
	seen := map[string]struct{}{}
	for _, file := range files {
		archivePath, err := cleanRuntimeArtifactArchivePath(file.ArchivePath)
		if err != nil {
			return nil, err
		}
		file.ArchivePath = archivePath
		file.FileKind = strings.TrimSpace(file.FileKind)
		file.SHA256 = strings.ToLower(strings.TrimSpace(file.SHA256))
		if !runtimeArtifactFileKindPattern.MatchString(file.FileKind) || !hex64Pattern.MatchString(file.SHA256) {
			return nil, fmt.Errorf("%w: invalid artifact file metadata", ErrRuntimeArtifactInvalid)
		}
		if file.SizeBytes <= 0 || file.SizeBytes > MaxRuntimeArtifactUncompressedBytes {
			return nil, fmt.Errorf("%w: invalid artifact file size", ErrRuntimeArtifactInvalid)
		}
		if file.Mode < 0 || file.Mode > 0o777 {
			return nil, fmt.Errorf("%w: invalid artifact file mode", ErrRuntimeArtifactInvalid)
		}
		if _, ok := seen[file.ArchivePath]; ok {
			return nil, fmt.Errorf("%w: duplicate artifact file path", ErrRuntimeArtifactInvalid)
		}
		seen[file.ArchivePath] = struct{}{}
		out = append(out, file)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ArchivePath < out[j].ArchivePath })
	return out, nil
}

func cleanRuntimeArtifactArchivePath(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || strings.Contains(raw, "\x00") || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\\") {
		return "", fmt.Errorf("%w: unsafe artifact archive path", ErrRuntimeArtifactInvalid)
	}
	parts := strings.Split(raw, "/")
	for _, part := range parts {
		if part == "" || part == "." || part == ".." {
			return "", fmt.Errorf("%w: unsafe artifact archive path", ErrRuntimeArtifactInvalid)
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || cleaned == ".." || len(cleaned) > 512 {
		return "", fmt.Errorf("%w: unsafe artifact archive path", ErrRuntimeArtifactInvalid)
	}
	return cleaned, nil
}

func runtimeArtifactRecordFromInsert(in RuntimeArtifactInsert, storageState string, createdAt string) RuntimeArtifactRecord {
	return RuntimeArtifactRecord{
		ArtifactRevision: in.ArtifactRevision,
		ArtifactHash:     in.ArtifactHash,
		RuntimeFamily:    in.RuntimeFamily,
		RuntimeID:        in.RuntimeID,
		DetectedVersion:  in.DetectedVersion,
		Target:           in.Target,
		CompressedSize:   in.CompressedSize,
		UncompressedSize: in.UncompressedSize,
		FileCount:        in.FileCount,
		StorageState:     storageState,
		BuilderVersion:   in.BuilderVersion,
		BuilderProfile:   in.BuilderProfile,
		CreatedBy:        in.CreatedBy,
		CreatedAtUnix:    in.CreatedAtUnix,
		CreatedAt:        createdAt,
	}
}

func runtimeArtifactDuplicateMatches(existing RuntimeArtifactRecord, next RuntimeArtifactRecord) bool {
	return existing.ArtifactRevision == next.ArtifactRevision &&
		existing.ArtifactHash == next.ArtifactHash &&
		existing.RuntimeFamily == next.RuntimeFamily &&
		existing.RuntimeID == next.RuntimeID &&
		existing.DetectedVersion == next.DetectedVersion &&
		existing.Target == next.Target &&
		existing.CompressedSize == next.CompressedSize &&
		existing.UncompressedSize == next.UncompressedSize &&
		existing.FileCount == next.FileCount &&
		existing.StorageState == next.StorageState &&
		existing.BuilderVersion == next.BuilderVersion &&
		existing.BuilderProfile == next.BuilderProfile
}

func insertRuntimeArtifactTx(ctx context.Context, tx *sql.Tx, driver string, in RuntimeArtifactInsert, manifestJSON string, storageState string, createdAt string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_runtime_artifacts
    (artifact_revision, artifact_hash, runtime_family, runtime_id, detected_version,
     target_os, target_arch, target_kernel_version, target_distro_id, target_distro_id_like, target_distro_version,
     compressed_size_bytes, uncompressed_size_bytes, file_count, manifest_json, artifact_blob, storage_state,
     builder_version, builder_profile, created_by, created_at_unix, created_at)
VALUES
    (`+placeholders(driver, 22, 1)+`)`,
		in.ArtifactRevision,
		in.ArtifactHash,
		in.RuntimeFamily,
		in.RuntimeID,
		in.DetectedVersion,
		in.Target.OS,
		in.Target.Arch,
		in.Target.KernelVersion,
		in.Target.DistroID,
		in.Target.DistroIDLike,
		in.Target.DistroVersion,
		in.CompressedSize,
		in.UncompressedSize,
		in.FileCount,
		manifestJSON,
		in.ArtifactBytes,
		storageState,
		in.BuilderVersion,
		in.BuilderProfile,
		in.CreatedBy,
		in.CreatedAtUnix,
		createdAt,
	)
	return err
}

func insertRuntimeArtifactFileTx(ctx context.Context, tx *sql.Tx, driver string, revision string, file RuntimeArtifactFileMetadata) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_runtime_artifact_files
    (artifact_revision, archive_path, file_kind, sha256, size_bytes, mode)
VALUES
    (`+placeholders(driver, 6, 1)+`)`,
		revision,
		file.ArchivePath,
		file.FileKind,
		file.SHA256,
		file.SizeBytes,
		file.Mode,
	)
	return err
}

func loadRuntimeArtifactByRevisionTx(ctx context.Context, q queryer, driver string, revision string) (RuntimeArtifactRecord, bool, error) {
	row := q.QueryRowContext(ctx, runtimeArtifactSelectSQL()+`
 WHERE artifact_revision = `+placeholder(driver, 1), revision)
	var rec RuntimeArtifactRecord
	if err := scanRuntimeArtifactRecord(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuntimeArtifactRecord{}, false, nil
		}
		return RuntimeArtifactRecord{}, false, err
	}
	return rec, true, nil
}

func loadAssignedRuntimeArtifactBlobTx(ctx context.Context, q queryer, driver, deviceID, runtimeFamily, runtimeID, revision, hash string) (RuntimeArtifactRecord, []byte, bool, error) {
	row := q.QueryRowContext(ctx, runtimeArtifactWithBlobSelectSQL()+`
  FROM center_device_runtime_assignments a
  JOIN center_runtime_artifacts r ON r.artifact_revision = a.desired_artifact_revision
 WHERE a.device_id = `+placeholder(driver, 1)+`
   AND a.runtime_family = `+placeholder(driver, 2)+`
   AND a.runtime_id = `+placeholder(driver, 3)+`
   AND a.desired_artifact_revision = `+placeholder(driver, 4)+`
   AND r.artifact_hash = `+placeholder(driver, 5),
		deviceID,
		runtimeFamily,
		runtimeID,
		revision,
		hash,
	)
	var rec RuntimeArtifactRecord
	var artifactBlob []byte
	if err := scanRuntimeArtifactRecordWithBlob(row, &rec, &artifactBlob); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuntimeArtifactRecord{}, nil, false, nil
		}
		return RuntimeArtifactRecord{}, nil, false, err
	}
	return rec, artifactBlob, true, nil
}

func runtimeArtifactSelectSQL() string {
	return `
SELECT artifact_revision, artifact_hash, runtime_family, runtime_id, detected_version,
       target_os, target_arch, target_kernel_version, target_distro_id, target_distro_id_like, target_distro_version,
       compressed_size_bytes, uncompressed_size_bytes, file_count, storage_state,
       builder_version, builder_profile, created_by, created_at_unix, created_at
  FROM center_runtime_artifacts`
}

func runtimeArtifactWithBlobSelectSQL() string {
	return `
SELECT r.artifact_revision, r.artifact_hash, r.runtime_family, r.runtime_id, r.detected_version,
       r.target_os, r.target_arch, r.target_kernel_version, r.target_distro_id, r.target_distro_id_like, r.target_distro_version,
       r.compressed_size_bytes, r.uncompressed_size_bytes, r.file_count, r.storage_state,
       r.builder_version, r.builder_profile, r.created_by, r.created_at_unix, r.created_at, r.artifact_blob`
}

func scanRuntimeArtifactRecord(scanner rowScanner, rec *RuntimeArtifactRecord) error {
	return scanner.Scan(
		&rec.ArtifactRevision,
		&rec.ArtifactHash,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.DetectedVersion,
		&rec.Target.OS,
		&rec.Target.Arch,
		&rec.Target.KernelVersion,
		&rec.Target.DistroID,
		&rec.Target.DistroIDLike,
		&rec.Target.DistroVersion,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.StorageState,
		&rec.BuilderVersion,
		&rec.BuilderProfile,
		&rec.CreatedBy,
		&rec.CreatedAtUnix,
		&rec.CreatedAt,
	)
}

func scanRuntimeArtifactRecordWithBlob(scanner rowScanner, rec *RuntimeArtifactRecord, artifactBlob *[]byte) error {
	return scanner.Scan(
		&rec.ArtifactRevision,
		&rec.ArtifactHash,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.DetectedVersion,
		&rec.Target.OS,
		&rec.Target.Arch,
		&rec.Target.KernelVersion,
		&rec.Target.DistroID,
		&rec.Target.DistroIDLike,
		&rec.Target.DistroVersion,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.StorageState,
		&rec.BuilderVersion,
		&rec.BuilderProfile,
		&rec.CreatedBy,
		&rec.CreatedAtUnix,
		&rec.CreatedAt,
		artifactBlob,
	)
}

func listCompatibleRuntimeArtifactsTx(ctx context.Context, db *sql.DB, driver string, device DeviceRecord) ([]RuntimeArtifactRecord, error) {
	if strings.TrimSpace(device.OS) == "" || strings.TrimSpace(device.Arch) == "" ||
		strings.TrimSpace(device.DistroID) == "" || strings.TrimSpace(device.DistroVersion) == "" {
		return []RuntimeArtifactRecord{}, nil
	}
	query := runtimeArtifactSelectSQL() + `
 WHERE target_os = ` + placeholder(driver, 1) + `
   AND target_arch = ` + placeholder(driver, 2) + `
   AND target_distro_id = ` + placeholder(driver, 3) + `
   AND target_distro_version = ` + placeholder(driver, 4) + `
   AND (target_distro_id_like = '' OR target_distro_id_like = ` + placeholder(driver, 5) + `)
 ORDER BY created_at_unix DESC, artifact_revision ASC`
	if driver == "pgsql" {
		query += " LIMIT 200"
	} else {
		query += " LIMIT 200"
	}
	rows, err := db.QueryContext(ctx, query, device.OS, device.Arch, device.DistroID, device.DistroVersion, device.DistroIDLike)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimeArtifactRecord{}
	for rows.Next() {
		var rec RuntimeArtifactRecord
		if err := scanRuntimeArtifactRecord(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func runtimeArtifactCompatibleWithDevice(artifact RuntimeArtifactRecord, device DeviceRecord) bool {
	if artifact.Target.OS == "" || artifact.Target.Arch == "" || artifact.Target.DistroID == "" || artifact.Target.DistroVersion == "" {
		return false
	}
	if device.OS == "" || device.Arch == "" || device.DistroID == "" || device.DistroVersion == "" {
		return false
	}
	if artifact.Target.OS != device.OS || artifact.Target.Arch != device.Arch ||
		artifact.Target.DistroID != device.DistroID || artifact.Target.DistroVersion != device.DistroVersion {
		return false
	}
	return artifact.Target.DistroIDLike == "" || artifact.Target.DistroIDLike == device.DistroIDLike
}

func upsertRuntimeAssignmentTx(ctx context.Context, tx *sql.Tx, driver string, in RuntimeAssignmentUpdate) error {
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_assignments
    (device_id, runtime_family, runtime_id, desired_artifact_revision, desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 9, 1)+`)
ON DUPLICATE KEY UPDATE
    desired_artifact_revision = VALUES(desired_artifact_revision),
    desired_state = VALUES(desired_state),
    reason = VALUES(reason),
    assigned_by = VALUES(assigned_by),
    assigned_at_unix = VALUES(assigned_at_unix),
    updated_at_unix = VALUES(updated_at_unix)`,
			in.DeviceID,
			in.RuntimeFamily,
			in.RuntimeID,
			in.ArtifactRevision,
			RuntimeAssignmentDesiredInstalled,
			in.Reason,
			in.AssignedBy,
			in.AssignedAtUnix,
			in.AssignedAtUnix,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_assignments
    (device_id, runtime_family, runtime_id, desired_artifact_revision, desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 9, 1)+`)
ON CONFLICT(device_id, runtime_family, runtime_id) DO UPDATE SET
    desired_artifact_revision = excluded.desired_artifact_revision,
    desired_state = excluded.desired_state,
    reason = excluded.reason,
    assigned_by = excluded.assigned_by,
    assigned_at_unix = excluded.assigned_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
			in.DeviceID,
			in.RuntimeFamily,
			in.RuntimeID,
			in.ArtifactRevision,
			RuntimeAssignmentDesiredInstalled,
			in.Reason,
			in.AssignedBy,
			in.AssignedAtUnix,
			in.AssignedAtUnix,
		)
		return err
	}
}

func upsertRuntimeRemovalAssignmentTx(ctx context.Context, tx *sql.Tx, driver string, in RuntimeAssignmentUpdate) error {
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_assignments
    (device_id, runtime_family, runtime_id, desired_artifact_revision, desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 9, 1)+`)
ON DUPLICATE KEY UPDATE
    desired_artifact_revision = VALUES(desired_artifact_revision),
    desired_state = VALUES(desired_state),
    reason = VALUES(reason),
    assigned_by = VALUES(assigned_by),
    assigned_at_unix = VALUES(assigned_at_unix),
    updated_at_unix = VALUES(updated_at_unix)`,
			in.DeviceID,
			in.RuntimeFamily,
			in.RuntimeID,
			"",
			RuntimeAssignmentDesiredRemoved,
			in.Reason,
			in.AssignedBy,
			in.AssignedAtUnix,
			in.AssignedAtUnix,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_assignments
    (device_id, runtime_family, runtime_id, desired_artifact_revision, desired_state, reason, assigned_by, assigned_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 9, 1)+`)
ON CONFLICT(device_id, runtime_family, runtime_id) DO UPDATE SET
    desired_artifact_revision = excluded.desired_artifact_revision,
    desired_state = excluded.desired_state,
    reason = excluded.reason,
    assigned_by = excluded.assigned_by,
    assigned_at_unix = excluded.assigned_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
			in.DeviceID,
			in.RuntimeFamily,
			in.RuntimeID,
			"",
			RuntimeAssignmentDesiredRemoved,
			in.Reason,
			in.AssignedBy,
			in.AssignedAtUnix,
			in.AssignedAtUnix,
		)
		return err
	}
}

func loadRuntimeAssignmentTx(ctx context.Context, q queryer, driver, deviceID, runtimeFamily, runtimeID string) (RuntimeAssignmentRecord, error) {
	row := q.QueryRowContext(ctx, runtimeAssignmentSelectSQL()+`
 WHERE a.device_id = `+placeholder(driver, 1)+`
   AND a.runtime_family = `+placeholder(driver, 2)+`
   AND a.runtime_id = `+placeholder(driver, 3),
		deviceID,
		runtimeFamily,
		runtimeID,
	)
	var rec RuntimeAssignmentRecord
	if err := scanRuntimeAssignmentRecord(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return RuntimeAssignmentRecord{}, ErrRuntimeArtifactNotFound
		}
		return RuntimeAssignmentRecord{}, err
	}
	return rec, nil
}

func listRuntimeAssignmentsForDeviceTx(ctx context.Context, db *sql.DB, driver string, deviceID string) ([]RuntimeAssignmentRecord, error) {
	rows, err := db.QueryContext(ctx, runtimeAssignmentSelectSQL()+`
 WHERE a.device_id = `+placeholder(driver, 1)+`
 ORDER BY a.runtime_family ASC, a.runtime_id ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimeAssignmentRecord{}
	for rows.Next() {
		var rec RuntimeAssignmentRecord
		if err := scanRuntimeAssignmentRecord(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func runtimeAssignmentSelectSQL() string {
	return `
SELECT a.assignment_id, a.device_id, a.runtime_family, a.runtime_id, a.desired_artifact_revision,
       a.desired_state, a.reason, a.assigned_by, a.assigned_at_unix, a.updated_at_unix,
       COALESCE(r.artifact_hash, ''), COALESCE(r.compressed_size_bytes, 0), COALESCE(r.uncompressed_size_bytes, 0), COALESCE(r.file_count, 0),
       COALESCE(r.detected_version, ''), COALESCE(r.storage_state, ''),
       COALESCE(r.target_os, ''), COALESCE(r.target_arch, ''), COALESCE(r.target_kernel_version, ''), COALESCE(r.target_distro_id, ''), COALESCE(r.target_distro_id_like, ''), COALESCE(r.target_distro_version, '')
  FROM center_device_runtime_assignments a
  LEFT JOIN center_runtime_artifacts r ON r.artifact_revision = a.desired_artifact_revision`
}

func scanRuntimeAssignmentRecord(scanner rowScanner, rec *RuntimeAssignmentRecord) error {
	return scanner.Scan(
		&rec.AssignmentID,
		&rec.DeviceID,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.DesiredArtifactRevision,
		&rec.DesiredState,
		&rec.Reason,
		&rec.AssignedBy,
		&rec.AssignedAtUnix,
		&rec.UpdatedAtUnix,
		&rec.ArtifactHash,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.DetectedVersion,
		&rec.StorageState,
		&rec.Target.OS,
		&rec.Target.Arch,
		&rec.Target.KernelVersion,
		&rec.Target.DistroID,
		&rec.Target.DistroIDLike,
		&rec.Target.DistroVersion,
	)
}

func loadRuntimeAssignmentDesiredRevisionsTx(ctx context.Context, tx *sql.Tx, driver, deviceID string) (map[string]string, error) {
	rows, err := tx.QueryContext(ctx, `
SELECT runtime_family, runtime_id, desired_artifact_revision
  FROM center_device_runtime_assignments
 WHERE device_id = `+placeholder(driver, 1), deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var family, id, revision string
		if err := rows.Scan(&family, &id, &revision); err != nil {
			return nil, err
		}
		out[family+"\x00"+id] = revision
	}
	return out, rows.Err()
}

func upsertRuntimeApplyStatusTx(ctx context.Context, tx *sql.Tx, driver string, status RuntimeApplyStatusRecord) error {
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_apply_status
    (device_id, runtime_family, runtime_id, desired_artifact_revision, local_artifact_revision, local_artifact_hash,
     apply_state, apply_error, last_attempt_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 10, 1)+`)
ON DUPLICATE KEY UPDATE
    desired_artifact_revision = VALUES(desired_artifact_revision),
    local_artifact_revision = VALUES(local_artifact_revision),
    local_artifact_hash = VALUES(local_artifact_hash),
    apply_state = VALUES(apply_state),
    apply_error = VALUES(apply_error),
    last_attempt_at_unix = VALUES(last_attempt_at_unix),
    updated_at_unix = VALUES(updated_at_unix)`,
			status.DeviceID,
			status.RuntimeFamily,
			status.RuntimeID,
			status.DesiredArtifactRevision,
			status.LocalArtifactRevision,
			status.LocalArtifactHash,
			status.ApplyState,
			status.ApplyError,
			status.LastAttemptAtUnix,
			status.UpdatedAtUnix,
		)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_runtime_apply_status
    (device_id, runtime_family, runtime_id, desired_artifact_revision, local_artifact_revision, local_artifact_hash,
     apply_state, apply_error, last_attempt_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 10, 1)+`)
ON CONFLICT(device_id, runtime_family, runtime_id) DO UPDATE SET
    desired_artifact_revision = excluded.desired_artifact_revision,
    local_artifact_revision = excluded.local_artifact_revision,
    local_artifact_hash = excluded.local_artifact_hash,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
			status.DeviceID,
			status.RuntimeFamily,
			status.RuntimeID,
			status.DesiredArtifactRevision,
			status.LocalArtifactRevision,
			status.LocalArtifactHash,
			status.ApplyState,
			status.ApplyError,
			status.LastAttemptAtUnix,
			status.UpdatedAtUnix,
		)
		return err
	}
}

func listRuntimeApplyStatusForDeviceTx(ctx context.Context, db *sql.DB, driver string, deviceID string) ([]RuntimeApplyStatusRecord, error) {
	rows, err := db.QueryContext(ctx, runtimeApplyStatusSelectSQL()+`
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY runtime_family ASC, runtime_id ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RuntimeApplyStatusRecord{}
	for rows.Next() {
		var rec RuntimeApplyStatusRecord
		if err := scanRuntimeApplyStatusRecord(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func loadRuntimeApplyStatusMapTx(ctx context.Context, db *sql.DB, driver string, deviceID string) (map[string]RuntimeApplyStatusRecord, error) {
	items, err := listRuntimeApplyStatusForDeviceTx(ctx, db, driver, deviceID)
	if err != nil {
		return nil, err
	}
	out := make(map[string]RuntimeApplyStatusRecord, len(items))
	for _, item := range items {
		out[item.RuntimeFamily+"\x00"+item.RuntimeID] = item
	}
	return out, nil
}

func runtimeApplyStatusSelectSQL() string {
	return `
SELECT device_id, runtime_family, runtime_id, desired_artifact_revision, local_artifact_revision,
       local_artifact_hash, apply_state, apply_error, last_attempt_at_unix, updated_at_unix
  FROM center_device_runtime_apply_status`
}

func scanRuntimeApplyStatusRecord(scanner rowScanner, rec *RuntimeApplyStatusRecord) error {
	return scanner.Scan(
		&rec.DeviceID,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.DesiredArtifactRevision,
		&rec.LocalArtifactRevision,
		&rec.LocalArtifactHash,
		&rec.ApplyState,
		&rec.ApplyError,
		&rec.LastAttemptAtUnix,
		&rec.UpdatedAtUnix,
	)
}
