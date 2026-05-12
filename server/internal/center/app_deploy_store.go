package center

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"sort"
	"strings"
	"time"

	"tukuyomi/internal/appdeploybundle"
)

const (
	AppDeployOperationDeploy   = "deploy"
	AppDeployOperationRollback = "rollback"
	AppDeployOperationAdopt    = "adopt"

	AppDeploySourceUpload          = "upload"
	AppDeploySourceGatewayBaseline = "gateway_baseline"

	AppDeployRestartNone           = "none"
	AppDeployRestartReloadRuntime  = "reload-runtime"
	AppDeployRestartRestartRuntime = "restart-runtime"

	AppDeployDispatchLeaseSec = int64(15 * 60)
	AppDeployDiffListLimit    = 500
)

var (
	ErrAppDeployNotFound     = errors.New("app deploy package not found")
	ErrAppDeployInvalid      = errors.New("invalid app deploy payload")
	ErrAppDeployIncompatible = errors.New("app deploy package is incompatible with device")
)

type AppDeployRootRecord struct {
	RootID         string `json:"root_id"`
	RuntimeField   string `json:"runtime_field"`
	SourcePath     string `json:"source_path,omitempty"`
	PackagePrefix  string `json:"package_prefix"`
	TargetSubpath  string `json:"target_subpath"`
	RuntimeSubpath string `json:"runtime_subpath,omitempty"`
	Required       bool   `json:"required"`
}

type AppDeployProfileRecord struct {
	ProfileID       int64                 `json:"profile_id"`
	DeviceID        string                `json:"device_id"`
	AppID           string                `json:"app_id"`
	RuntimeFamily   string                `json:"runtime_family"`
	RuntimeID       string                `json:"runtime_id"`
	ProfileRevision string                `json:"profile_revision"`
	Roots           []AppDeployRootRecord `json:"roots"`
	CreatedBy       string                `json:"created_by"`
	UpdatedBy       string                `json:"updated_by"`
	CreatedAtUnix   int64                 `json:"created_at_unix"`
	UpdatedAtUnix   int64                 `json:"updated_at_unix"`
}

type AppDeployCandidateRecord struct {
	DeviceID       string                `json:"device_id"`
	AppID          string                `json:"app_id"`
	RuntimeFamily  string                `json:"runtime_family"`
	RuntimeID      string                `json:"runtime_id"`
	Roots          []AppDeployRootRecord `json:"roots"`
	Managed        bool                  `json:"managed"`
	DetectedAtUnix int64                 `json:"detected_at_unix"`
}

type AppDeployPackageImport struct {
	DeviceID        string
	AppID           string
	RuntimeFamily   string
	RuntimeID       string
	Roots           []AppDeployRootRecord
	Label           string
	Note            string
	SourceType      string
	Archive         []byte
	UploadedBy      string
	UploadedAtUnix  int64
	UpsertProfile   bool
	ProfileRevision string
}

type AppDeployPackageFileRecord struct {
	Path      string `json:"path"`
	RootID    string `json:"root_id,omitempty"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
	Mode      int64  `json:"mode"`
}

type AppDeployPackageRecord struct {
	PackageRevision  string                `json:"package_revision"`
	PackageHash      string                `json:"package_hash"`
	DeviceID         string                `json:"device_id"`
	AppID            string                `json:"app_id"`
	RuntimeFamily    string                `json:"runtime_family"`
	RuntimeID        string                `json:"runtime_id"`
	ProfileRevision  string                `json:"profile_revision"`
	Roots            []AppDeployRootRecord `json:"roots"`
	Label            string                `json:"label"`
	Note             string                `json:"note,omitempty"`
	SourceType       string                `json:"source_type"`
	CompressedSize   int64                 `json:"compressed_size"`
	UncompressedSize int64                 `json:"uncompressed_size"`
	FileCount        int                   `json:"file_count"`
	UploadedBy       string                `json:"uploaded_by"`
	UploadedAtUnix   int64                 `json:"uploaded_at_unix"`
	UploadedAt       string                `json:"uploaded_at"`
}

type AppDeployRequestUpdate struct {
	DeviceID            string
	AppID               string
	Operation           string
	PackageRevision     string
	BasePackageRevision string
	RuntimeFamily       string
	RuntimeID           string
	Roots               []AppDeployRootRecord
	RestartBehavior     string
	ScriptTimeoutSec    int64
	PreSwitchScript     string
	PostSwitchScript    string
	Reason              string
	RequestedBy         string
	RequestedAtUnix     int64
}

type AppDeployRequestRecord struct {
	RequestID           int64                 `json:"request_id"`
	DeviceID            string                `json:"device_id"`
	AppID               string                `json:"app_id"`
	Operation           string                `json:"operation"`
	PackageRevision     string                `json:"package_revision"`
	PackageHash         string                `json:"package_hash"`
	BasePackageRevision string                `json:"base_package_revision"`
	ProfileRevision     string                `json:"profile_revision"`
	Roots               []AppDeployRootRecord `json:"roots"`
	RestartBehavior     string                `json:"restart_behavior"`
	ScriptTimeoutSec    int64                 `json:"script_timeout_sec"`
	PreSwitchScript     string                `json:"pre_switch_script,omitempty"`
	PostSwitchScript    string                `json:"post_switch_script,omitempty"`
	Reason              string                `json:"reason"`
	RequestedBy         string                `json:"requested_by"`
	RequestedAtUnix     int64                 `json:"requested_at_unix"`
	UpdatedAtUnix       int64                 `json:"updated_at_unix"`
	DispatchedAtUnix    int64                 `json:"dispatched_at_unix,omitempty"`
	CompressedSize      int64                 `json:"compressed_size,omitempty"`
	UncompressedSize    int64                 `json:"uncompressed_size,omitempty"`
	FileCount           int                   `json:"file_count,omitempty"`
	RuntimeFamily       string                `json:"runtime_family,omitempty"`
	RuntimeID           string                `json:"runtime_id,omitempty"`
}

type AppDeployApplyStatusRecord struct {
	DeviceID               string `json:"device_id"`
	AppID                  string `json:"app_id"`
	DesiredPackageRevision string `json:"desired_package_revision"`
	LocalPackageRevision   string `json:"local_package_revision"`
	LocalPackageHash       string `json:"local_package_hash"`
	ApplyState             string `json:"apply_state"`
	ApplyError             string `json:"apply_error"`
	OutputTail             string `json:"output_tail,omitempty"`
	LastAttemptAtUnix      int64  `json:"last_attempt_at_unix"`
	UpdatedAtUnix          int64  `json:"updated_at_unix"`
}

type AppDeployHistoryRecord struct {
	HistoryID           int64  `json:"history_id"`
	DeviceID            string `json:"device_id"`
	AppID               string `json:"app_id"`
	Operation           string `json:"operation"`
	PackageRevision     string `json:"package_revision"`
	PackageHash         string `json:"package_hash"`
	BasePackageRevision string `json:"base_package_revision"`
	ProfileRevision     string `json:"profile_revision"`
	ApplyState          string `json:"apply_state"`
	ApplyError          string `json:"apply_error"`
	OutputTail          string `json:"output_tail,omitempty"`
	RequestedBy         string `json:"requested_by"`
	RequestedAtUnix     int64  `json:"requested_at_unix"`
	AppliedAtUnix       int64  `json:"applied_at_unix"`
	UpdatedAtUnix       int64  `json:"updated_at_unix"`
}

type AppDeployDeviceAssignment struct {
	RequestID           int64                 `json:"request_id"`
	AppID               string                `json:"app_id"`
	Operation           string                `json:"operation"`
	PackageRevision     string                `json:"package_revision,omitempty"`
	PackageHash         string                `json:"package_hash,omitempty"`
	BasePackageRevision string                `json:"base_package_revision,omitempty"`
	ProfileRevision     string                `json:"profile_revision"`
	Roots               []AppDeployRootRecord `json:"roots"`
	RuntimeFamily       string                `json:"runtime_family,omitempty"`
	RuntimeID           string                `json:"runtime_id,omitempty"`
	CompressedSize      int64                 `json:"compressed_size,omitempty"`
	UncompressedSize    int64                 `json:"uncompressed_size,omitempty"`
	FileCount           int                   `json:"file_count,omitempty"`
	RestartBehavior     string                `json:"restart_behavior"`
	ScriptTimeoutSec    int64                 `json:"script_timeout_sec"`
	PreSwitchScript     string                `json:"pre_switch_script,omitempty"`
	PostSwitchScript    string                `json:"post_switch_script,omitempty"`
	AssignedAtUnix      int64                 `json:"assigned_at_unix"`
}

type AppDeployView struct {
	Device     DeviceRecord                 `json:"device"`
	Candidates []AppDeployCandidateRecord   `json:"candidates"`
	Profiles   []AppDeployProfileRecord     `json:"profiles"`
	Packages   []AppDeployPackageRecord     `json:"packages"`
	Request    *AppDeployRequestRecord      `json:"request"`
	Status     []AppDeployApplyStatusRecord `json:"status"`
	History    []AppDeployHistoryRecord     `json:"history"`
}

type AppDeployPackageDetail struct {
	Package AppDeployPackageRecord       `json:"package"`
	Files   []AppDeployPackageFileRecord `json:"files"`
}

type AppDeployPackageFileDetail struct {
	File AppDeployPackageFileRecord `json:"file"`
	Raw  string                     `json:"raw,omitempty"`
	Body []byte                     `json:"-"`
}

type AppDeployPackageDiff struct {
	BasePackageRevision   string                       `json:"base_package_revision"`
	TargetPackageRevision string                       `json:"target_package_revision"`
	BaseKnown             bool                         `json:"base_known"`
	AddedFiles            []AppDeployPackageFileRecord `json:"added_files"`
	UpdatedFiles          []AppDeployPackageFileRecord `json:"updated_files"`
	RemovedFiles          []AppDeployPackageFileRecord `json:"removed_files"`
	AddedDirectories      []string                     `json:"added_directories"`
	RemovedDirectories    []string                     `json:"removed_directories"`
	Truncated             bool                         `json:"truncated"`
}

type appDeployPackageManifest struct {
	SchemaVersion int                          `json:"schema_version"`
	Roots         []AppDeployRootRecord        `json:"roots"`
	Files         []AppDeployPackageFileRecord `json:"files"`
}

func AppDeploymentsForDevice(ctx context.Context, deviceID string) (AppDeployView, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return AppDeployView{}, ErrDeviceStatusNotFound
	}
	var out AppDeployView
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &out.Device); err != nil {
			return err
		}
		var err error
		out.Candidates, err = listAppDeployCandidatesForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		out.Profiles, err = listAppDeployProfilesForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		out.Packages, err = listAppDeployPackagesForDeviceTx(ctx, db, driver, deviceID, 50)
		if err != nil {
			return err
		}
		if request, found, err := loadAppDeployRequestForDeviceTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.Request = &request
		}
		out.Status, err = listAppDeployApplyStatusForDeviceTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		out.History, err = listAppDeployHistoryForDeviceTx(ctx, db, driver, deviceID, 50)
		return err
	})
	return out, err
}

func LoadAppDeployPackageForDevice(ctx context.Context, deviceID, revision string) (AppDeployPackageDetail, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = appdeploybundle.ValidateRevision(revision)
	if !deviceIDPattern.MatchString(deviceID) || revision == "" {
		return AppDeployPackageDetail{}, ErrAppDeployInvalid
	}
	var out AppDeployPackageDetail
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		pkg, found, err := loadAppDeployPackageTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		if !found || pkg.DeviceID != deviceID {
			return ErrAppDeployNotFound
		}
		files, err := listAppDeployPackageFilesTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		out.Package = pkg
		out.Files = files
		return nil
	})
	return out, err
}

func DownloadAppDeployPackageForDevice(ctx context.Context, deviceID, revision string) (AppDeployPackageRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = appdeploybundle.ValidateRevision(revision)
	if !deviceIDPattern.MatchString(deviceID) || revision == "" {
		return AppDeployPackageRecord{}, nil, ErrAppDeployInvalid
	}
	var out AppDeployPackageRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		pkg, found, err := loadAppDeployPackageTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		if !found || pkg.DeviceID != deviceID {
			return ErrAppDeployNotFound
		}
		out = pkg
		return nil
	})
	if err != nil {
		return AppDeployPackageRecord{}, nil, err
	}
	blob, err := readAppDeployPackageBody(ctx, out)
	if err != nil {
		return AppDeployPackageRecord{}, nil, err
	}
	return out, blob, nil
}

func LoadAppDeployPackageFileForDevice(ctx context.Context, deviceID, revision, assetPath string) (AppDeployPackageFileDetail, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = appdeploybundle.ValidateRevision(revision)
	assetPath, ok := appdeploybundle.CleanArchivePath(assetPath)
	if !deviceIDPattern.MatchString(deviceID) || revision == "" || !ok {
		return AppDeployPackageFileDetail{}, ErrAppDeployInvalid
	}
	var detail AppDeployPackageFileDetail
	var pkg AppDeployPackageRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		foundPkg, found, err := loadAppDeployPackageTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		if !found || foundPkg.DeviceID != deviceID {
			return ErrAppDeployNotFound
		}
		pkg = foundPkg
		return nil
	})
	if err != nil {
		return detail, err
	}
	blob, err := readAppDeployPackageBody(ctx, pkg)
	if err != nil {
		return detail, err
	}
	parsed, err := parseAppDeployPackageArchive(blob, pkg.Roots)
	if err != nil {
		return detail, fmt.Errorf("%w: %v", ErrAppDeployInvalid, err)
	}
	for _, file := range parsed.Files {
		if file.Path != assetPath {
			continue
		}
		detail.File = AppDeployPackageFileRecord{
			Path:      file.Path,
			RootID:    rootIDForAppDeployPath(pkg.Roots, file.Path),
			SHA256:    file.SHA256,
			SizeBytes: file.SizeBytes,
			Mode:      file.Mode,
		}
		detail.Body = append([]byte(nil), file.Body...)
		detail.Raw = string(file.Body)
		return detail, nil
	}
	return detail, ErrAppDeployNotFound
}

func StoreAppDeployPackage(ctx context.Context, in AppDeployPackageImport) (AppDeployPackageRecord, error) {
	normalized, parsed, files, manifestJSON, rootsJSON, err := normalizeAppDeployPackageImport(in)
	if err != nil {
		return AppDeployPackageRecord{}, err
	}
	if normalized.UploadedAtUnix <= 0 {
		normalized.UploadedAtUnix = time.Now().UTC().Unix()
	}
	uploadedAt := time.Unix(normalized.UploadedAtUnix, 0).UTC().Format(time.RFC3339)
	packageRevision := appDeployPackageRevision(normalized.DeviceID, normalized.AppID, parsed.PackageHash)
	profileRevision := normalized.ProfileRevision
	if profileRevision == "" {
		profileRevision = appDeployProfileRevision(normalized.DeviceID, normalized.AppID, normalized.RuntimeFamily, normalized.RuntimeID, rootsJSON)
	}
	out := AppDeployPackageRecord{
		PackageRevision:  packageRevision,
		PackageHash:      parsed.PackageHash,
		DeviceID:         normalized.DeviceID,
		AppID:            normalized.AppID,
		RuntimeFamily:    normalized.RuntimeFamily,
		RuntimeID:        normalized.RuntimeID,
		ProfileRevision:  profileRevision,
		Roots:            append([]AppDeployRootRecord(nil), normalized.Roots...),
		Label:            normalized.Label,
		Note:             normalized.Note,
		SourceType:       normalized.SourceType,
		CompressedSize:   parsed.CompressedSize,
		UncompressedSize: parsed.UncompressedSize,
		FileCount:        parsed.FileCount,
		UploadedBy:       normalized.UploadedBy,
		UploadedAtUnix:   normalized.UploadedAtUnix,
		UploadedAt:       uploadedAt,
	}
	payloadExisted, err := writeCenterPayloadFile(
		centerPayloadAppDeploy,
		packageRevision,
		centerPayloadAppDeployExt,
		normalized.Archive,
		parsed.CompressedSize,
		parsed.PackageHash,
	)
	if err != nil {
		return AppDeployPackageRecord{}, fmt.Errorf("%w: %v", ErrAppDeployInvalid, err)
	}
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, normalized.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrAppDeployIncompatible
		}
		profile := AppDeployProfileRecord{
			DeviceID:        normalized.DeviceID,
			AppID:           normalized.AppID,
			RuntimeFamily:   normalized.RuntimeFamily,
			RuntimeID:       normalized.RuntimeID,
			ProfileRevision: profileRevision,
			Roots:           normalized.Roots,
			CreatedBy:       normalized.UploadedBy,
			UpdatedBy:       normalized.UploadedBy,
			CreatedAtUnix:   normalized.UploadedAtUnix,
			UpdatedAtUnix:   normalized.UploadedAtUnix,
		}
		if err := ensureAppDeployCandidateMatchesProfileTx(ctx, tx, driver, profile); err != nil {
			return err
		}
		if normalized.UpsertProfile {
			if _, err := replaceAppDeployProfileTx(ctx, tx, driver, profile); err != nil {
				return err
			}
		}
		if err := insertAppDeployPackageTx(ctx, tx, driver, out, manifestJSON, rootsJSON); err != nil {
			if isUniqueConstraintError(err) {
				existing, found, loadErr := loadAppDeployPackageTx(ctx, tx, driver, packageRevision)
				if loadErr != nil {
					return loadErr
				}
				if found && existing.PackageHash == out.PackageHash && existing.DeviceID == out.DeviceID && existing.AppID == out.AppID {
					out = existing
					return tx.Commit()
				}
			}
			return err
		}
		for _, file := range files {
			if err := insertAppDeployPackageFileTx(ctx, tx, driver, packageRevision, file); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
	if err != nil && !payloadExisted {
		removeCenterPayloadFile(centerPayloadAppDeploy, packageRevision, centerPayloadAppDeployExt)
	}
	return out, err
}

func CreateAppDeployRequest(ctx context.Context, in AppDeployRequestUpdate) (AppDeployRequestRecord, error) {
	normalized, err := normalizeAppDeployRequestUpdate(in)
	if err != nil {
		return AppDeployRequestRecord{}, err
	}
	var out AppDeployRequestRecord
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, normalized.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrAppDeployIncompatible
		}
		var hash string
		var profile AppDeployProfileRecord
		switch normalized.Operation {
		case AppDeployOperationDeploy, AppDeployOperationRollback:
			pkg, found, err := loadAppDeployPackageTx(ctx, tx, driver, normalized.PackageRevision)
			if err != nil {
				return err
			}
			if !found || pkg.DeviceID != normalized.DeviceID || pkg.AppID != normalized.AppID {
				return ErrAppDeployNotFound
			}
			hash = pkg.PackageHash
			profile = AppDeployProfileRecord{
				DeviceID:        pkg.DeviceID,
				AppID:           pkg.AppID,
				RuntimeFamily:   pkg.RuntimeFamily,
				RuntimeID:       pkg.RuntimeID,
				ProfileRevision: pkg.ProfileRevision,
				Roots:           pkg.Roots,
			}
		case AppDeployOperationAdopt:
			candidate, found, err := loadAppDeployCandidateForAppTx(ctx, tx, driver, normalized.DeviceID, normalized.AppID)
			if err != nil {
				return err
			}
			if !found || candidate.Managed {
				return ErrAppDeployIncompatible
			}
			profile = AppDeployProfileRecord{
				DeviceID:        normalized.DeviceID,
				AppID:           normalized.AppID,
				RuntimeFamily:   normalized.RuntimeFamily,
				RuntimeID:       normalized.RuntimeID,
				ProfileRevision: appDeployProfileRevision(normalized.DeviceID, normalized.AppID, normalized.RuntimeFamily, normalized.RuntimeID, mustMarshalAppDeployRoots(normalized.Roots)),
				Roots:           normalized.Roots,
				CreatedBy:       normalized.RequestedBy,
				UpdatedBy:       normalized.RequestedBy,
				CreatedAtUnix:   normalized.RequestedAtUnix,
				UpdatedAtUnix:   normalized.RequestedAtUnix,
			}
			if _, err := replaceAppDeployProfileTx(ctx, tx, driver, profile); err != nil {
				return err
			}
		}
		if err := ensureAppDeployCandidateMatchesProfileTx(ctx, tx, driver, profile); err != nil {
			return err
		}
		if err := replaceAppDeployRequestTx(ctx, tx, driver, normalized, profile, hash); err != nil {
			return err
		}
		rec, found, err := loadAppDeployRequestForAppTx(ctx, tx, driver, normalized.DeviceID, normalized.AppID)
		if err != nil {
			return err
		}
		if !found {
			return ErrAppDeployNotFound
		}
		out = rec
		return tx.Commit()
	})
	return out, err
}

func ClearAppDeployRequest(ctx context.Context, deviceID, appID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	appID = normalizeAppDeployID(appID)
	if !deviceIDPattern.MatchString(deviceID) || appID == "" {
		return false, ErrAppDeployInvalid
	}
	var cleared bool
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		res, err := db.ExecContext(ctx, `
DELETE FROM center_device_app_deploy_requests
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2)+`
   AND dispatched_at_unix = 0`,
			deviceID,
			appID,
		)
		if err != nil {
			return err
		}
		n, _ := res.RowsAffected()
		cleared = n > 0
		return nil
	})
	return cleared, err
}

func PendingAppDeployAssignmentForDevice(ctx context.Context, deviceID string, dispatchedAtUnix int64) (*AppDeployDeviceAssignment, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	var out *AppDeployDeviceAssignment
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		request, found, err := loadAppDeployRequestForDeviceTx(ctx, tx, driver, deviceID)
		if err != nil || !found {
			return err
		}
		if status, found, err := loadAppDeployApplyStatusTx(ctx, tx, driver, request.DeviceID, request.AppID); err != nil {
			return err
		} else if found && appDeployApplyStatusMatchesTerminal(status, request) {
			if err := deleteAppDeployRequestTx(ctx, tx, driver, request.DeviceID, request.AppID); err != nil {
				return err
			}
			return tx.Commit()
		}
		if request.DispatchedAtUnix > 0 && dispatchedAtUnix-request.DispatchedAtUnix < AppDeployDispatchLeaseSec {
			out = appDeployAssignmentFromRequest(request)
			return tx.Commit()
		}
		if err := markAppDeployRequestDispatchedTx(ctx, tx, driver, request.DeviceID, request.AppID, dispatchedAtUnix); err != nil {
			return err
		}
		request.DispatchedAtUnix = dispatchedAtUnix
		out = appDeployAssignmentFromRequest(request)
		return tx.Commit()
	})
	return out, err
}

func AppDeployPackageDownloadForDevice(ctx context.Context, deviceID, appID, revision, hash string) (AppDeployPackageRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	appID = normalizeAppDeployID(appID)
	revision = appdeploybundle.ValidateRevision(revision)
	hash = appdeploybundle.ValidateRevision(hash)
	if !deviceIDPattern.MatchString(deviceID) || appID == "" || revision == "" || hash == "" {
		return AppDeployPackageRecord{}, nil, ErrAppDeployInvalid
	}
	var out AppDeployPackageRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrAppDeployIncompatible
		}
		request, found, err := loadAppDeployRequestForAppTx(ctx, db, driver, deviceID, appID)
		if err != nil {
			return err
		}
		if !found || request.PackageRevision != revision || request.PackageHash != hash {
			return ErrAppDeployNotFound
		}
		rec, found, err := loadAppDeployPackageTx(ctx, db, driver, revision)
		if err != nil {
			return err
		}
		if !found || rec.PackageHash != hash || rec.DeviceID != deviceID || rec.AppID != appID {
			return ErrAppDeployNotFound
		}
		out = rec
		return nil
	})
	if err != nil {
		return AppDeployPackageRecord{}, nil, err
	}
	blob, err := readAppDeployPackageBody(ctx, out)
	if err != nil {
		return AppDeployPackageRecord{}, nil, err
	}
	return out, append([]byte(nil), blob...), nil
}

func readAppDeployPackageBody(ctx context.Context, pkg AppDeployPackageRecord) ([]byte, error) {
	blob, err := readCenterPayloadFile(centerPayloadAppDeploy, pkg.PackageRevision, centerPayloadAppDeployExt, pkg.CompressedSize, pkg.PackageHash)
	if errors.Is(err, errCenterPayloadFileNotFound) {
		blob, err = loadLegacyAppDeployPackageBlobAndMigrate(ctx, pkg)
	}
	if err != nil {
		if errors.Is(err, ErrAppDeployInvalid) || errors.Is(err, ErrAppDeployNotFound) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: %v", ErrAppDeployInvalid, err)
	}
	return blob, nil
}

func loadLegacyAppDeployPackageBlobAndMigrate(ctx context.Context, pkg AppDeployPackageRecord) ([]byte, error) {
	var blob []byte
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		exists, err := centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		if err != nil {
			return err
		}
		if !exists {
			return ErrAppDeployNotFound
		}
		row := db.QueryRowContext(ctx, `
SELECT package_blob
  FROM center_app_deploy_packages
 WHERE package_revision = `+placeholder(driver, 1), pkg.PackageRevision)
		if err := row.Scan(&blob); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return ErrAppDeployNotFound
			}
			return err
		}
		if int64(len(blob)) != pkg.CompressedSize || !centerPayloadBytesHashMatches(blob, pkg.PackageHash) {
			return ErrAppDeployInvalid
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if _, err := writeCenterPayloadFile(
		centerPayloadAppDeploy,
		pkg.PackageRevision,
		centerPayloadAppDeployExt,
		blob,
		pkg.CompressedSize,
		pkg.PackageHash,
	); err != nil {
		return nil, err
	}
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		exists, err := centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		if err != nil || !exists {
			return err
		}
		_, err = db.ExecContext(ctx, `
UPDATE center_app_deploy_packages
   SET package_blob = `+placeholder(driver, 1)+`
 WHERE package_revision = `+placeholder(driver, 2), []byte{}, pkg.PackageRevision)
		return err
	})
	if err != nil {
		return nil, err
	}
	return blob, nil
}

func UpsertAppDeployCandidates(ctx context.Context, deviceID string, candidates []AppDeployCandidateRecord, updatedAtUnix int64) error {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return ErrDeviceStatusNotFound
	}
	if updatedAtUnix <= 0 {
		updatedAtUnix = time.Now().UTC().Unix()
	}
	normalized := make([]AppDeployCandidateRecord, 0, len(candidates))
	for _, candidate := range candidates {
		candidate.DeviceID = deviceID
		next, err := normalizeAppDeployCandidate(candidate, updatedAtUnix)
		if err != nil {
			return err
		}
		normalized = append(normalized, next)
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if _, err := tx.ExecContext(ctx, `DELETE FROM center_device_app_deploy_candidates WHERE device_id = `+placeholder(driver, 1), deviceID); err != nil {
			return err
		}
		for _, candidate := range normalized {
			rootsJSON, err := marshalAppDeployRoots(candidate.Roots)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_candidates
    (device_id, app_id, runtime_family, runtime_id, roots_json, managed, detected_at_unix)
VALUES (`+placeholders(driver, 7, 1)+`)`,
				candidate.DeviceID,
				candidate.AppID,
				candidate.RuntimeFamily,
				candidate.RuntimeID,
				rootsJSON,
				dbBool(driver, candidate.Managed),
				candidate.DetectedAtUnix,
			); err != nil {
				return err
			}
		}
		return tx.Commit()
	})
}

func UpsertAppDeployApplyStatuses(ctx context.Context, deviceID string, statuses []AppDeployApplyStatusRecord, updatedAtUnix int64) error {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return ErrDeviceStatusNotFound
	}
	if updatedAtUnix <= 0 {
		updatedAtUnix = time.Now().UTC().Unix()
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		for _, status := range statuses {
			status.DeviceID = deviceID
			normalized, err := normalizeAppDeployApplyStatus(status, updatedAtUnix)
			if err != nil {
				return err
			}
			if err := upsertAppDeployApplyStatusTx(ctx, tx, driver, normalized); err != nil {
				return err
			}
			if request, found, err := loadAppDeployRequestForAppTx(ctx, tx, driver, normalized.DeviceID, normalized.AppID); err != nil {
				return err
			} else if found && appDeployApplyStatusMatchesTerminal(normalized, request) {
				if err := insertAppDeployHistoryTx(ctx, tx, driver, AppDeployHistoryRecord{
					DeviceID:            normalized.DeviceID,
					AppID:               normalized.AppID,
					Operation:           request.Operation,
					PackageRevision:     nonEmpty(normalized.LocalPackageRevision, request.PackageRevision),
					PackageHash:         nonEmpty(normalized.LocalPackageHash, request.PackageHash),
					BasePackageRevision: request.BasePackageRevision,
					ProfileRevision:     request.ProfileRevision,
					ApplyState:          normalized.ApplyState,
					ApplyError:          normalized.ApplyError,
					OutputTail:          normalized.OutputTail,
					RequestedBy:         request.RequestedBy,
					RequestedAtUnix:     request.RequestedAtUnix,
					AppliedAtUnix:       normalized.LastAttemptAtUnix,
					UpdatedAtUnix:       normalized.UpdatedAtUnix,
				}); err != nil {
					return err
				}
				if err := deleteAppDeployRequestTx(ctx, tx, driver, normalized.DeviceID, normalized.AppID); err != nil {
					return err
				}
			}
		}
		return tx.Commit()
	})
}

func DiffAppDeployPackagesForDevice(ctx context.Context, deviceID, baseRevision, targetRevision string) (AppDeployPackageDiff, error) {
	deviceID = strings.TrimSpace(deviceID)
	baseRevision = appdeploybundle.ValidateRevision(baseRevision)
	targetRevision = appdeploybundle.ValidateRevision(targetRevision)
	if !deviceIDPattern.MatchString(deviceID) || targetRevision == "" {
		return AppDeployPackageDiff{}, ErrAppDeployInvalid
	}
	var out AppDeployPackageDiff
	out.BasePackageRevision = baseRevision
	out.TargetPackageRevision = targetRevision
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		target, found, err := loadAppDeployPackageTx(ctx, db, driver, targetRevision)
		if err != nil {
			return err
		}
		if !found || target.DeviceID != deviceID {
			return ErrAppDeployNotFound
		}
		targetFiles, err := listAppDeployPackageFilesTx(ctx, db, driver, targetRevision)
		if err != nil {
			return err
		}
		var baseFiles []AppDeployPackageFileRecord
		if baseRevision != "" {
			base, found, err := loadAppDeployPackageTx(ctx, db, driver, baseRevision)
			if err != nil {
				return err
			}
			if found && base.DeviceID == deviceID && base.AppID == target.AppID {
				baseFiles, err = listAppDeployPackageFilesTx(ctx, db, driver, baseRevision)
				if err != nil {
					return err
				}
				out.BaseKnown = true
			}
		}
		fillAppDeployDiff(&out, baseFiles, targetFiles)
		return nil
	})
	return out, err
}

func normalizeAppDeployPackageImport(in AppDeployPackageImport) (AppDeployPackageImport, appdeploybundle.Parsed, []AppDeployPackageFileRecord, string, string, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.AppID = normalizeAppDeployID(in.AppID)
	in.RuntimeFamily = normalizeAppDeployRuntimeFamily(in.RuntimeFamily)
	in.RuntimeID = normalizeAppDeployID(in.RuntimeID)
	in.Label = clampString(in.Label, 191)
	in.Note = clampString(in.Note, 4096)
	in.SourceType = normalizeAppDeploySourceType(in.SourceType)
	in.UploadedBy = clampString(in.UploadedBy, 191)
	in.ProfileRevision = appdeploybundle.ValidateRevision(in.ProfileRevision)
	if in.UploadedBy == "" {
		in.UploadedBy = "unknown"
	}
	if !deviceIDPattern.MatchString(in.DeviceID) || in.AppID == "" || in.RuntimeFamily == "" {
		return AppDeployPackageImport{}, appdeploybundle.Parsed{}, nil, "", "", ErrAppDeployInvalid
	}
	roots, rootsJSON, err := normalizeAppDeployRoots(in.Roots)
	if err != nil {
		return AppDeployPackageImport{}, appdeploybundle.Parsed{}, nil, "", "", err
	}
	if err := validateAppDeployRootsForApp(in.AppID, roots); err != nil {
		return AppDeployPackageImport{}, appdeploybundle.Parsed{}, nil, "", "", err
	}
	in.Roots = roots
	parsed, files, err := parseAppDeployPackageArchiveWithFiles(in.Archive, roots)
	if err != nil {
		return AppDeployPackageImport{}, appdeploybundle.Parsed{}, nil, "", "", fmt.Errorf("%w: %v", ErrAppDeployInvalid, err)
	}
	manifest, err := json.Marshal(appDeployPackageManifest{SchemaVersion: 1, Roots: roots, Files: files})
	if err != nil {
		return AppDeployPackageImport{}, appdeploybundle.Parsed{}, nil, "", "", ErrAppDeployInvalid
	}
	return in, parsed, files, string(manifest), rootsJSON, nil
}

func normalizeAppDeployRequestUpdate(in AppDeployRequestUpdate) (AppDeployRequestUpdate, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.AppID = normalizeAppDeployID(in.AppID)
	in.Operation = normalizeAppDeployOperation(in.Operation)
	in.PackageRevision = appdeploybundle.ValidateRevision(in.PackageRevision)
	in.BasePackageRevision = appdeploybundle.ValidateRevision(in.BasePackageRevision)
	in.RuntimeFamily = normalizeAppDeployRuntimeFamily(in.RuntimeFamily)
	in.RuntimeID = normalizeAppDeployID(in.RuntimeID)
	in.RestartBehavior = normalizeAppDeployRestartBehavior(in.RestartBehavior)
	in.PreSwitchScript = clampString(strings.TrimRight(in.PreSwitchScript, "\r\n\t "), appdeploybundle.MaxScriptBytes)
	in.PostSwitchScript = clampString(strings.TrimRight(in.PostSwitchScript, "\r\n\t "), appdeploybundle.MaxScriptBytes)
	in.Reason = clampString(in.Reason, 1024)
	in.RequestedBy = clampString(in.RequestedBy, 191)
	if in.RequestedBy == "" {
		in.RequestedBy = "unknown"
	}
	if in.ScriptTimeoutSec <= 0 {
		in.ScriptTimeoutSec = 60
	}
	if in.ScriptTimeoutSec > 900 {
		in.ScriptTimeoutSec = 900
	}
	if in.RequestedAtUnix <= 0 {
		in.RequestedAtUnix = time.Now().UTC().Unix()
	}
	if !deviceIDPattern.MatchString(in.DeviceID) || in.AppID == "" || in.Operation == "" {
		return AppDeployRequestUpdate{}, ErrAppDeployInvalid
	}
	switch in.Operation {
	case AppDeployOperationDeploy, AppDeployOperationRollback:
		if in.PackageRevision == "" {
			return AppDeployRequestUpdate{}, ErrAppDeployInvalid
		}
	case AppDeployOperationAdopt:
		if in.RuntimeFamily == "" {
			return AppDeployRequestUpdate{}, ErrAppDeployInvalid
		}
		roots, _, err := normalizeAppDeployRoots(in.Roots)
		if err != nil {
			return AppDeployRequestUpdate{}, err
		}
		if err := validateAppDeployAdoptionRootsForApp(in.AppID, roots); err != nil {
			return AppDeployRequestUpdate{}, err
		}
		in.Roots = roots
	default:
		return AppDeployRequestUpdate{}, ErrAppDeployInvalid
	}
	return in, nil
}

func normalizeAppDeployApplyStatus(in AppDeployApplyStatusRecord, updatedAtUnix int64) (AppDeployApplyStatusRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.AppID = normalizeAppDeployID(in.AppID)
	in.DesiredPackageRevision = appdeploybundle.ValidateRevision(in.DesiredPackageRevision)
	in.LocalPackageRevision = appdeploybundle.ValidateRevision(in.LocalPackageRevision)
	in.LocalPackageHash = appdeploybundle.ValidateRevision(in.LocalPackageHash)
	in.ApplyState = clampString(strings.ToLower(strings.TrimSpace(in.ApplyState)), 32)
	in.ApplyError = clampString(in.ApplyError, 2048)
	in.OutputTail = clampString(in.OutputTail, appdeploybundle.MaxScriptOutputBytes)
	if in.LastAttemptAtUnix <= 0 {
		in.LastAttemptAtUnix = updatedAtUnix
	}
	in.UpdatedAtUnix = updatedAtUnix
	if !deviceIDPattern.MatchString(in.DeviceID) || in.AppID == "" || in.ApplyState == "" {
		return AppDeployApplyStatusRecord{}, ErrAppDeployInvalid
	}
	return in, nil
}

func normalizeAppDeployCandidate(in AppDeployCandidateRecord, detectedAtUnix int64) (AppDeployCandidateRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.AppID = normalizeAppDeployID(in.AppID)
	in.RuntimeFamily = normalizeAppDeployRuntimeFamily(in.RuntimeFamily)
	in.RuntimeID = normalizeAppDeployID(in.RuntimeID)
	if in.DetectedAtUnix <= 0 {
		in.DetectedAtUnix = detectedAtUnix
	}
	roots, _, err := normalizeAppDeployRoots(in.Roots)
	if err != nil {
		return AppDeployCandidateRecord{}, err
	}
	if err := validateAppDeployRootsForApp(in.AppID, roots); err != nil {
		return AppDeployCandidateRecord{}, err
	}
	in.Roots = roots
	if !deviceIDPattern.MatchString(in.DeviceID) || in.AppID == "" || in.RuntimeFamily == "" {
		return AppDeployCandidateRecord{}, ErrAppDeployInvalid
	}
	return in, nil
}

func normalizeAppDeployID(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || !runtimeIDPattern.MatchString(value) {
		return ""
	}
	return value
}

func appDeployPackageRevision(deviceID, appID, packageHash string) string {
	sum := sha256.Sum256([]byte("tukuyomi app deploy package v1\x00" + deviceID + "\x00" + appID + "\x00" + packageHash))
	return hex.EncodeToString(sum[:])
}

func appDeployProfileRevision(deviceID, appID, runtimeFamily, runtimeID, rootsJSON string) string {
	sum := sha256.Sum256([]byte("tukuyomi app deploy profile v1\x00" + deviceID + "\x00" + appID + "\x00" + runtimeFamily + "\x00" + runtimeID + "\x00" + rootsJSON))
	return hex.EncodeToString(sum[:])
}

func normalizeAppDeployRuntimeFamily(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "php-fpm", "psgi", "daemon":
		return value
	default:
		return ""
	}
}

func normalizeAppDeployOperation(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", AppDeployOperationDeploy:
		return AppDeployOperationDeploy
	case AppDeployOperationRollback, AppDeployOperationAdopt:
		return value
	default:
		return ""
	}
}

func normalizeAppDeploySourceType(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case AppDeploySourceGatewayBaseline:
		return AppDeploySourceGatewayBaseline
	default:
		return AppDeploySourceUpload
	}
}

func normalizeAppDeployRestartBehavior(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case AppDeployRestartNone, AppDeployRestartReloadRuntime, AppDeployRestartRestartRuntime:
		return value
	default:
		return AppDeployRestartRestartRuntime
	}
}

func normalizeAppDeployRoots(items []AppDeployRootRecord) ([]AppDeployRootRecord, string, error) {
	if len(items) == 0 || len(items) > 8 {
		return nil, "", ErrAppDeployInvalid
	}
	out := make([]AppDeployRootRecord, 0, len(items))
	seenRoot := map[string]struct{}{}
	seenPrefix := map[string]struct{}{}
	for _, item := range items {
		rootID := normalizeAppDeployID(item.RootID)
		field := strings.ToLower(strings.TrimSpace(item.RuntimeField))
		sourcePath, ok := cleanAppDeployLocalPath(item.SourcePath)
		if !ok {
			return nil, "", ErrAppDeployInvalid
		}
		prefix, ok := cleanAppDeployRelativePath(item.PackagePrefix)
		if !ok {
			return nil, "", ErrAppDeployInvalid
		}
		target, ok := cleanAppDeployRelativePath(item.TargetSubpath)
		if !ok {
			return nil, "", ErrAppDeployInvalid
		}
		runtimeSubpath, ok := cleanAppDeployRelativePath(item.RuntimeSubpath)
		if !ok {
			return nil, "", ErrAppDeployInvalid
		}
		if runtimeSubpath == "" {
			runtimeSubpath = target
		}
		if rootID == "" {
			return nil, "", ErrAppDeployInvalid
		}
		switch field {
		case "document_root", "app_root":
		default:
			return nil, "", ErrAppDeployInvalid
		}
		if _, exists := seenRoot[rootID]; exists {
			return nil, "", ErrAppDeployInvalid
		}
		seenRoot[rootID] = struct{}{}
		if _, exists := seenPrefix[prefix]; exists {
			return nil, "", ErrAppDeployInvalid
		}
		for existing := range seenPrefix {
			if appDeployPathHasPrefix(existing, prefix) || appDeployPathHasPrefix(prefix, existing) {
				return nil, "", ErrAppDeployInvalid
			}
		}
		seenPrefix[prefix] = struct{}{}
		out = append(out, AppDeployRootRecord{
			RootID:         rootID,
			RuntimeField:   field,
			SourcePath:     sourcePath,
			PackagePrefix:  prefix,
			TargetSubpath:  target,
			RuntimeSubpath: runtimeSubpath,
			Required:       item.Required,
		})
	}
	raw, err := marshalAppDeployRoots(out)
	if err != nil {
		return nil, "", ErrAppDeployInvalid
	}
	return out, raw, nil
}

func marshalAppDeployRoots(items []AppDeployRootRecord) (string, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func mustMarshalAppDeployRoots(items []AppDeployRootRecord) string {
	raw, _ := marshalAppDeployRoots(items)
	return raw
}

func unmarshalAppDeployRoots(raw string) []AppDeployRootRecord {
	var roots []AppDeployRootRecord
	if err := json.Unmarshal([]byte(strings.TrimSpace(raw)), &roots); err != nil {
		return nil
	}
	roots, _, err := normalizeAppDeployRoots(roots)
	if err != nil {
		return nil
	}
	return roots
}

func cleanAppDeployRelativePath(value string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return "", true
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "\x00") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == "." {
		return "", true
	}
	if cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	return strings.Trim(cleaned, "/"), true
}

func cleanAppDeployLocalPath(value string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, "\\", "/"))
	if value == "" {
		return "", true
	}
	if strings.HasPrefix(value, "/") || strings.Contains(value, "\x00") {
		return "", false
	}
	cleaned := path.Clean(value)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") {
		return "", false
	}
	cleaned = strings.Trim(cleaned, "/")
	if !appDeploySourcePathAllowed(cleaned) {
		return "", false
	}
	return cleaned, true
}

func appDeploySourcePathAllowed(value string) bool {
	value = strings.Trim(value, "/")
	return strings.HasPrefix(value, "data/runtime-sites/") && len(value) > len("data/runtime-sites/")
}

func validateAppDeployRootsForApp(appID string, roots []AppDeployRootRecord) error {
	appID = normalizeAppDeployID(appID)
	if appID == "" {
		return ErrAppDeployInvalid
	}
	for _, root := range roots {
		sourcePath := strings.Trim(strings.TrimSpace(root.SourcePath), "/")
		if sourcePath == "" {
			continue
		}
		if !appDeploySourcePathAllowedForApp(sourcePath, appID) {
			return ErrAppDeployInvalid
		}
	}
	return nil
}

func validateAppDeployAdoptionRootsForApp(appID string, roots []AppDeployRootRecord) error {
	if err := validateAppDeployRootsForApp(appID, roots); err != nil {
		return err
	}
	for _, root := range roots {
		if strings.TrimSpace(root.SourcePath) == "" {
			return ErrAppDeployInvalid
		}
	}
	return nil
}

func appDeploySourcePathAllowedForApp(value string, appID string) bool {
	value = strings.Trim(value, "/")
	appID = normalizeAppDeployID(appID)
	if appID == "" {
		return false
	}
	root := "data/runtime-sites/" + appID
	return value == root || strings.HasPrefix(value, root+"/")
}

func appDeployFilesForParsedPackage(parsed appdeploybundle.Parsed, roots []AppDeployRootRecord) ([]AppDeployPackageFileRecord, error) {
	countByRoot := map[string]int{}
	files := make([]AppDeployPackageFileRecord, 0, len(parsed.Files))
	for _, file := range parsed.Files {
		rootID := rootIDForAppDeployPath(roots, file.Path)
		if rootID == "" {
			return nil, fmt.Errorf("%w: package file is outside deployment roots", ErrAppDeployInvalid)
		}
		countByRoot[rootID]++
		files = append(files, AppDeployPackageFileRecord{
			Path:      file.Path,
			RootID:    rootID,
			SHA256:    file.SHA256,
			SizeBytes: file.SizeBytes,
			Mode:      file.Mode,
		})
	}
	for _, root := range roots {
		if root.Required && countByRoot[root.RootID] == 0 {
			return nil, fmt.Errorf("%w: required deployment root has no files", ErrAppDeployInvalid)
		}
	}
	return files, nil
}

func parseAppDeployPackageArchive(raw []byte, roots []AppDeployRootRecord) (appdeploybundle.Parsed, error) {
	parsed, _, err := parseAppDeployPackageArchiveWithFiles(raw, roots)
	return parsed, err
}

func parseAppDeployPackageArchiveWithFiles(raw []byte, roots []AppDeployRootRecord) (appdeploybundle.Parsed, []AppDeployPackageFileRecord, error) {
	preserved, preserveErr := appdeploybundle.ParseZIPPreservePaths(raw)
	if preserveErr == nil {
		files, err := appDeployFilesForParsedPackage(preserved, roots)
		if err == nil {
			return preserved, files, nil
		}
	}
	stripped, stripErr := appdeploybundle.ParseZIP(raw)
	if stripErr != nil {
		if preserveErr != nil {
			return appdeploybundle.Parsed{}, nil, preserveErr
		}
		return appdeploybundle.Parsed{}, nil, stripErr
	}
	files, err := appDeployFilesForParsedPackage(stripped, roots)
	if err != nil {
		return appdeploybundle.Parsed{}, nil, err
	}
	return stripped, files, nil
}

func rootIDForAppDeployPath(roots []AppDeployRootRecord, filePath string) string {
	for _, root := range roots {
		if appDeployPathHasPrefix(filePath, root.PackagePrefix) {
			return root.RootID
		}
	}
	return ""
}

func appDeployPathHasPrefix(value, prefix string) bool {
	value = strings.Trim(value, "/")
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return value != ""
	}
	return strings.HasPrefix(value, prefix+"/")
}

func appDeployApplyStatusMatchesTerminal(status AppDeployApplyStatusRecord, request AppDeployRequestRecord) bool {
	if status.DeviceID != request.DeviceID || status.AppID != request.AppID {
		return false
	}
	if request.DispatchedAtUnix <= 0 || status.LastAttemptAtUnix < request.DispatchedAtUnix {
		return false
	}
	switch request.Operation {
	case AppDeployOperationAdopt:
		if status.DesiredPackageRevision == "" || status.DesiredPackageRevision != request.ProfileRevision {
			return false
		}
	default:
		if status.DesiredPackageRevision != "" && status.DesiredPackageRevision != request.PackageRevision {
			return false
		}
	}
	switch status.ApplyState {
	case "applied", "failed", "failed_after_switch", "blocked":
		return true
	default:
		return false
	}
}

func appDeployAssignmentFromRequest(request AppDeployRequestRecord) *AppDeployDeviceAssignment {
	return &AppDeployDeviceAssignment{
		RequestID:           request.RequestID,
		AppID:               request.AppID,
		Operation:           request.Operation,
		PackageRevision:     request.PackageRevision,
		PackageHash:         request.PackageHash,
		BasePackageRevision: request.BasePackageRevision,
		ProfileRevision:     request.ProfileRevision,
		Roots:               append([]AppDeployRootRecord(nil), request.Roots...),
		RuntimeFamily:       request.RuntimeFamily,
		RuntimeID:           request.RuntimeID,
		CompressedSize:      request.CompressedSize,
		UncompressedSize:    request.UncompressedSize,
		FileCount:           request.FileCount,
		RestartBehavior:     request.RestartBehavior,
		ScriptTimeoutSec:    request.ScriptTimeoutSec,
		PreSwitchScript:     request.PreSwitchScript,
		PostSwitchScript:    request.PostSwitchScript,
		AssignedAtUnix:      request.RequestedAtUnix,
	}
}

func fillAppDeployDiff(out *AppDeployPackageDiff, baseFiles, targetFiles []AppDeployPackageFileRecord) {
	baseByPath := make(map[string]AppDeployPackageFileRecord, len(baseFiles))
	targetByPath := make(map[string]AppDeployPackageFileRecord, len(targetFiles))
	for _, file := range baseFiles {
		baseByPath[file.Path] = file
	}
	for _, file := range targetFiles {
		targetByPath[file.Path] = file
		if old, ok := baseByPath[file.Path]; !ok {
			appendLimitedFile(&out.AddedFiles, file, out)
		} else if old.SHA256 != file.SHA256 || old.SizeBytes != file.SizeBytes || old.Mode != file.Mode {
			appendLimitedFile(&out.UpdatedFiles, file, out)
		}
	}
	if !out.BaseKnown {
		out.AddedDirectories = sortedDirsForFiles(targetFiles)
		return
	}
	for _, file := range baseFiles {
		if _, ok := targetByPath[file.Path]; !ok {
			appendLimitedFile(&out.RemovedFiles, file, out)
		}
	}
	out.AddedDirectories = sortedDirsForFiles(out.AddedFiles)
	out.RemovedDirectories = sortedDirsForFiles(out.RemovedFiles)
}

func appendLimitedFile(dst *[]AppDeployPackageFileRecord, file AppDeployPackageFileRecord, out *AppDeployPackageDiff) {
	if len(*dst) >= AppDeployDiffListLimit {
		out.Truncated = true
		return
	}
	*dst = append(*dst, file)
}

func sortedDirsForFiles(files []AppDeployPackageFileRecord) []string {
	seen := map[string]struct{}{}
	for _, file := range files {
		dir := path.Dir(file.Path)
		for dir != "." && dir != "/" && dir != "" {
			seen[dir] = struct{}{}
			next := path.Dir(dir)
			if next == dir {
				break
			}
			dir = next
		}
	}
	out := make([]string, 0, len(seen))
	for dir := range seen {
		out = append(out, dir)
	}
	sort.Strings(out)
	if len(out) > AppDeployDiffListLimit {
		return out[:AppDeployDiffListLimit]
	}
	return out
}

func insertAppDeployPackageTx(ctx context.Context, tx *sql.Tx, driver string, rec AppDeployPackageRecord, manifestJSON string, rootsJSON string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_app_deploy_packages
    (package_revision, package_hash, device_id, app_id, runtime_family, runtime_id, profile_revision, roots_json,
     label, note, source_type, compressed_size, uncompressed_size, file_count, manifest_json,
     uploaded_by, uploaded_at_unix, uploaded_at)
VALUES (`+placeholders(driver, 18, 1)+`)`,
		rec.PackageRevision,
		rec.PackageHash,
		rec.DeviceID,
		rec.AppID,
		rec.RuntimeFamily,
		rec.RuntimeID,
		rec.ProfileRevision,
		rootsJSON,
		rec.Label,
		rec.Note,
		rec.SourceType,
		rec.CompressedSize,
		rec.UncompressedSize,
		rec.FileCount,
		manifestJSON,
		rec.UploadedBy,
		rec.UploadedAtUnix,
		rec.UploadedAt,
	)
	return err
}

func insertAppDeployPackageFileTx(ctx context.Context, tx *sql.Tx, driver string, revision string, file AppDeployPackageFileRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_app_deploy_package_files
    (package_revision, path, root_id, sha256, size_bytes, mode)
VALUES (`+placeholders(driver, 6, 1)+`)`,
		revision,
		file.Path,
		file.RootID,
		file.SHA256,
		file.SizeBytes,
		file.Mode,
	)
	return err
}

func replaceAppDeployProfileTx(ctx context.Context, tx *sql.Tx, driver string, rec AppDeployProfileRecord) (AppDeployProfileRecord, error) {
	if rec.CreatedAtUnix <= 0 {
		rec.CreatedAtUnix = time.Now().UTC().Unix()
	}
	if rec.UpdatedAtUnix <= 0 {
		rec.UpdatedAtUnix = rec.CreatedAtUnix
	}
	rootsJSON, err := marshalAppDeployRoots(rec.Roots)
	if err != nil {
		return AppDeployProfileRecord{}, err
	}
	if rec.ProfileRevision == "" {
		rec.ProfileRevision = appDeployProfileRevision(rec.DeviceID, rec.AppID, rec.RuntimeFamily, rec.RuntimeID, rootsJSON)
	}
	if err := deleteAppDeployProfileTx(ctx, tx, driver, rec.DeviceID, rec.AppID); err != nil {
		return AppDeployProfileRecord{}, err
	}
	switch driver {
	case "pgsql":
		row := tx.QueryRowContext(ctx, `
INSERT INTO center_app_deploy_profiles
    (device_id, app_id, runtime_family, runtime_id, profile_revision, roots_json,
     created_by, updated_by, created_at_unix, updated_at_unix)
VALUES (`+placeholders(driver, 10, 1)+`)
RETURNING profile_id`,
			rec.DeviceID, rec.AppID, rec.RuntimeFamily, rec.RuntimeID, rec.ProfileRevision, rootsJSON,
			rec.CreatedBy, rec.UpdatedBy, rec.CreatedAtUnix, rec.UpdatedAtUnix)
		if err := row.Scan(&rec.ProfileID); err != nil {
			return AppDeployProfileRecord{}, err
		}
	default:
		res, err := tx.ExecContext(ctx, `
INSERT INTO center_app_deploy_profiles
    (device_id, app_id, runtime_family, runtime_id, profile_revision, roots_json,
     created_by, updated_by, created_at_unix, updated_at_unix)
VALUES (`+placeholders(driver, 10, 1)+`)`,
			rec.DeviceID, rec.AppID, rec.RuntimeFamily, rec.RuntimeID, rec.ProfileRevision, rootsJSON,
			rec.CreatedBy, rec.UpdatedBy, rec.CreatedAtUnix, rec.UpdatedAtUnix)
		if err != nil {
			return AppDeployProfileRecord{}, err
		}
		id, _ := res.LastInsertId()
		rec.ProfileID = id
	}
	for idx, root := range rec.Roots {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO center_app_deploy_profile_roots
    (profile_id, root_id, runtime_field, source_path, package_prefix, target_subpath, runtime_subpath, required, position)
VALUES (`+placeholders(driver, 9, 1)+`)`,
			rec.ProfileID, root.RootID, root.RuntimeField, root.SourcePath, root.PackagePrefix, root.TargetSubpath, root.RuntimeSubpath, dbBool(driver, root.Required), idx); err != nil {
			return AppDeployProfileRecord{}, err
		}
	}
	return rec, nil
}

func deleteAppDeployProfileTx(ctx context.Context, tx *sql.Tx, driver, deviceID, appID string) error {
	rows, err := tx.QueryContext(ctx, `
SELECT profile_id
  FROM center_app_deploy_profiles
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2), deviceID, appID)
	if err != nil {
		return err
	}
	ids := []any{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return err
		}
		ids = append(ids, id)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	if len(ids) > 0 {
		if _, err := tx.ExecContext(ctx, `DELETE FROM center_app_deploy_profile_roots WHERE profile_id IN (`+placeholders(driver, len(ids), 1)+`)`, ids...); err != nil {
			return err
		}
	}
	_, err = tx.ExecContext(ctx, `
DELETE FROM center_app_deploy_profiles
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2), deviceID, appID)
	return err
}

func replaceAppDeployRequestTx(ctx context.Context, tx *sql.Tx, driver string, in AppDeployRequestUpdate, profile AppDeployProfileRecord, hash string) error {
	if err := deleteAppDeployRequestTx(ctx, tx, driver, in.DeviceID, in.AppID); err != nil {
		return err
	}
	rootsJSON, err := marshalAppDeployRoots(profile.Roots)
	if err != nil {
		return err
	}
	now := in.RequestedAtUnix
	_, err = tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_requests
    (device_id, app_id, operation, package_revision, package_hash, base_package_revision, profile_revision, roots_json,
     restart_behavior, script_timeout_sec, pre_switch_script, post_switch_script, reason,
     requested_by, requested_at_unix, updated_at_unix, dispatched_at_unix)
VALUES (`+placeholders(driver, 17, 1)+`)`,
		in.DeviceID,
		in.AppID,
		in.Operation,
		in.PackageRevision,
		hash,
		in.BasePackageRevision,
		profile.ProfileRevision,
		rootsJSON,
		in.RestartBehavior,
		in.ScriptTimeoutSec,
		in.PreSwitchScript,
		in.PostSwitchScript,
		in.Reason,
		in.RequestedBy,
		in.RequestedAtUnix,
		now,
		0,
	)
	return err
}

func loadAppDeployPackageTx(ctx context.Context, q queryer, driver string, revision string) (AppDeployPackageRecord, bool, error) {
	row := q.QueryRowContext(ctx, appDeployPackageSelectSQL()+`
 WHERE package_revision = `+placeholder(driver, 1), revision)
	var rec AppDeployPackageRecord
	if err := scanAppDeployPackage(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AppDeployPackageRecord{}, false, nil
		}
		return AppDeployPackageRecord{}, false, err
	}
	return rec, true, nil
}

func appDeployPackageSelectSQL() string {
	return `
SELECT package_revision, package_hash, device_id, app_id, runtime_family, runtime_id, profile_revision,
       COALESCE(roots_json, '[]'), label, note, source_type, compressed_size, uncompressed_size, file_count,
       uploaded_by, uploaded_at_unix, uploaded_at
  FROM center_app_deploy_packages`
}

func scanAppDeployPackage(scanner rowScanner, rec *AppDeployPackageRecord) error {
	var rootsJSON string
	if err := scanner.Scan(
		&rec.PackageRevision,
		&rec.PackageHash,
		&rec.DeviceID,
		&rec.AppID,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
		&rec.ProfileRevision,
		&rootsJSON,
		&rec.Label,
		&rec.Note,
		&rec.SourceType,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.UploadedBy,
		&rec.UploadedAtUnix,
		&rec.UploadedAt,
	); err != nil {
		return err
	}
	rec.Roots = unmarshalAppDeployRoots(rootsJSON)
	return nil
}

func listAppDeployPackagesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]AppDeployPackageRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := q.QueryContext(ctx, appDeployPackageSelectSQL()+`
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY uploaded_at_unix DESC, package_revision DESC
 LIMIT `+placeholder(driver, 2), deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployPackageRecord{}
	for rows.Next() {
		var rec AppDeployPackageRecord
		if err := scanAppDeployPackage(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func listAppDeployPackageFilesTx(ctx context.Context, q queryerWithRows, driver string, revision string) ([]AppDeployPackageFileRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT path, root_id, sha256, size_bytes, mode
  FROM center_app_deploy_package_files
 WHERE package_revision = `+placeholder(driver, 1)+`
 ORDER BY path ASC`, revision)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployPackageFileRecord{}
	for rows.Next() {
		var rec AppDeployPackageFileRecord
		if err := rows.Scan(&rec.Path, &rec.RootID, &rec.SHA256, &rec.SizeBytes, &rec.Mode); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func listAppDeployProfilesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string) ([]AppDeployProfileRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT profile_id, device_id, app_id, runtime_family, runtime_id, profile_revision, COALESCE(roots_json, '[]'),
       created_by, updated_by, created_at_unix, updated_at_unix
  FROM center_app_deploy_profiles
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY app_id ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployProfileRecord{}
	for rows.Next() {
		var rec AppDeployProfileRecord
		var rootsJSON string
		if err := rows.Scan(&rec.ProfileID, &rec.DeviceID, &rec.AppID, &rec.RuntimeFamily, &rec.RuntimeID, &rec.ProfileRevision, &rootsJSON, &rec.CreatedBy, &rec.UpdatedBy, &rec.CreatedAtUnix, &rec.UpdatedAtUnix); err != nil {
			return nil, err
		}
		rec.Roots = unmarshalAppDeployRoots(rootsJSON)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func listAppDeployCandidatesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string) ([]AppDeployCandidateRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT device_id, app_id, runtime_family, runtime_id, COALESCE(roots_json, '[]'), managed, detected_at_unix
  FROM center_device_app_deploy_candidates
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY app_id ASC`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployCandidateRecord{}
	for rows.Next() {
		var rec AppDeployCandidateRecord
		var rootsJSON string
		var managed any
		if err := rows.Scan(&rec.DeviceID, &rec.AppID, &rec.RuntimeFamily, &rec.RuntimeID, &rootsJSON, &managed, &rec.DetectedAtUnix); err != nil {
			return nil, err
		}
		rec.Roots = unmarshalAppDeployRoots(rootsJSON)
		rec.Managed = dbValueBool(managed)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func loadAppDeployCandidateForAppTx(ctx context.Context, q queryer, driver string, deviceID string, appID string) (AppDeployCandidateRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, app_id, runtime_family, runtime_id, COALESCE(roots_json, '[]'), managed, detected_at_unix
  FROM center_device_app_deploy_candidates
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2), deviceID, appID)
	var rec AppDeployCandidateRecord
	var rootsJSON string
	var managed any
	if err := row.Scan(&rec.DeviceID, &rec.AppID, &rec.RuntimeFamily, &rec.RuntimeID, &rootsJSON, &managed, &rec.DetectedAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AppDeployCandidateRecord{}, false, nil
		}
		return AppDeployCandidateRecord{}, false, err
	}
	rec.Roots = unmarshalAppDeployRoots(rootsJSON)
	rec.Managed = dbValueBool(managed)
	return rec, true, nil
}

func ensureAppDeployCandidateMatchesProfileTx(ctx context.Context, q queryer, driver string, profile AppDeployProfileRecord) error {
	candidate, found, err := loadAppDeployCandidateForAppTx(ctx, q, driver, profile.DeviceID, profile.AppID)
	if err != nil {
		return err
	}
	if !found {
		return ErrAppDeployIncompatible
	}
	if candidate.RuntimeFamily != profile.RuntimeFamily || candidate.RuntimeID != profile.RuntimeID {
		return ErrAppDeployIncompatible
	}
	return nil
}

func appDeployRequestSelectSQL() string {
	return `
SELECT r.request_id, r.device_id, r.app_id, r.operation, r.package_revision, r.package_hash,
       r.base_package_revision, r.profile_revision, COALESCE(r.roots_json, '[]'),
       r.restart_behavior, r.script_timeout_sec, r.pre_switch_script, r.post_switch_script,
       r.reason, r.requested_by, r.requested_at_unix, r.updated_at_unix, r.dispatched_at_unix,
       COALESCE(p.compressed_size, 0), COALESCE(p.uncompressed_size, 0), COALESCE(p.file_count, 0),
       COALESCE(p.runtime_family, pr.runtime_family, ''), COALESCE(p.runtime_id, pr.runtime_id, '')
  FROM center_device_app_deploy_requests r
  LEFT JOIN center_app_deploy_packages p ON p.package_revision = r.package_revision
  LEFT JOIN center_app_deploy_profiles pr ON pr.device_id = r.device_id AND pr.app_id = r.app_id`
}

func loadAppDeployRequestForDeviceTx(ctx context.Context, q queryer, driver string, deviceID string) (AppDeployRequestRecord, bool, error) {
	row := q.QueryRowContext(ctx, appDeployRequestSelectSQL()+`
 WHERE r.device_id = `+placeholder(driver, 1)+`
 ORDER BY r.requested_at_unix ASC, r.request_id ASC
 LIMIT 1`, deviceID)
	var rec AppDeployRequestRecord
	if err := scanAppDeployRequest(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AppDeployRequestRecord{}, false, nil
		}
		return AppDeployRequestRecord{}, false, err
	}
	return rec, true, nil
}

func loadAppDeployRequestForAppTx(ctx context.Context, q queryer, driver string, deviceID string, appID string) (AppDeployRequestRecord, bool, error) {
	row := q.QueryRowContext(ctx, appDeployRequestSelectSQL()+`
 WHERE r.device_id = `+placeholder(driver, 1)+`
   AND r.app_id = `+placeholder(driver, 2), deviceID, appID)
	var rec AppDeployRequestRecord
	if err := scanAppDeployRequest(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AppDeployRequestRecord{}, false, nil
		}
		return AppDeployRequestRecord{}, false, err
	}
	return rec, true, nil
}

func scanAppDeployRequest(scanner rowScanner, rec *AppDeployRequestRecord) error {
	var rootsJSON string
	if err := scanner.Scan(
		&rec.RequestID,
		&rec.DeviceID,
		&rec.AppID,
		&rec.Operation,
		&rec.PackageRevision,
		&rec.PackageHash,
		&rec.BasePackageRevision,
		&rec.ProfileRevision,
		&rootsJSON,
		&rec.RestartBehavior,
		&rec.ScriptTimeoutSec,
		&rec.PreSwitchScript,
		&rec.PostSwitchScript,
		&rec.Reason,
		&rec.RequestedBy,
		&rec.RequestedAtUnix,
		&rec.UpdatedAtUnix,
		&rec.DispatchedAtUnix,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.RuntimeFamily,
		&rec.RuntimeID,
	); err != nil {
		return err
	}
	rec.Roots = unmarshalAppDeployRoots(rootsJSON)
	return nil
}

func markAppDeployRequestDispatchedTx(ctx context.Context, tx *sql.Tx, driver, deviceID, appID string, dispatchedAtUnix int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE center_device_app_deploy_requests
   SET dispatched_at_unix = `+placeholder(driver, 1)+`,
       updated_at_unix = `+placeholder(driver, 2)+`
 WHERE device_id = `+placeholder(driver, 3)+`
   AND app_id = `+placeholder(driver, 4),
		dispatchedAtUnix,
		dispatchedAtUnix,
		deviceID,
		appID,
	)
	return err
}

func deleteAppDeployRequestTx(ctx context.Context, tx *sql.Tx, driver, deviceID, appID string) error {
	_, err := tx.ExecContext(ctx, `
DELETE FROM center_device_app_deploy_requests
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2),
		deviceID,
		appID,
	)
	return err
}

func upsertAppDeployApplyStatusTx(ctx context.Context, tx *sql.Tx, driver string, status AppDeployApplyStatusRecord) error {
	switch driver {
	case "mysql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_apply_status
    (device_id, app_id, desired_package_revision, local_package_revision, local_package_hash,
     apply_state, apply_error, output_tail, last_attempt_at_unix, updated_at_unix)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON DUPLICATE KEY UPDATE
    desired_package_revision = VALUES(desired_package_revision),
    local_package_revision = VALUES(local_package_revision),
    local_package_hash = VALUES(local_package_hash),
    apply_state = VALUES(apply_state),
    apply_error = VALUES(apply_error),
    output_tail = VALUES(output_tail),
    last_attempt_at_unix = VALUES(last_attempt_at_unix),
    updated_at_unix = VALUES(updated_at_unix)`,
			status.DeviceID, status.AppID, status.DesiredPackageRevision, status.LocalPackageRevision, status.LocalPackageHash,
			status.ApplyState, status.ApplyError, status.OutputTail, status.LastAttemptAtUnix, status.UpdatedAtUnix)
		return err
	case "pgsql":
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_apply_status
    (device_id, app_id, desired_package_revision, local_package_revision, local_package_hash,
     apply_state, apply_error, output_tail, last_attempt_at_unix, updated_at_unix)
VALUES (`+placeholders(driver, 10, 1)+`)
ON CONFLICT (device_id, app_id) DO UPDATE SET
    desired_package_revision = EXCLUDED.desired_package_revision,
    local_package_revision = EXCLUDED.local_package_revision,
    local_package_hash = EXCLUDED.local_package_hash,
    apply_state = EXCLUDED.apply_state,
    apply_error = EXCLUDED.apply_error,
    output_tail = EXCLUDED.output_tail,
    last_attempt_at_unix = EXCLUDED.last_attempt_at_unix,
    updated_at_unix = EXCLUDED.updated_at_unix`,
			status.DeviceID, status.AppID, status.DesiredPackageRevision, status.LocalPackageRevision, status.LocalPackageHash,
			status.ApplyState, status.ApplyError, status.OutputTail, status.LastAttemptAtUnix, status.UpdatedAtUnix)
		return err
	default:
		_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_apply_status
    (device_id, app_id, desired_package_revision, local_package_revision, local_package_hash,
     apply_state, apply_error, output_tail, last_attempt_at_unix, updated_at_unix)
VALUES (`+placeholders(driver, 10, 1)+`)
ON CONFLICT(device_id, app_id) DO UPDATE SET
    desired_package_revision = excluded.desired_package_revision,
    local_package_revision = excluded.local_package_revision,
    local_package_hash = excluded.local_package_hash,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    output_tail = excluded.output_tail,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
			status.DeviceID, status.AppID, status.DesiredPackageRevision, status.LocalPackageRevision, status.LocalPackageHash,
			status.ApplyState, status.ApplyError, status.OutputTail, status.LastAttemptAtUnix, status.UpdatedAtUnix)
		return err
	}
}

func listAppDeployApplyStatusForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string) ([]AppDeployApplyStatusRecord, error) {
	rows, err := q.QueryContext(ctx, `
SELECT device_id, app_id, desired_package_revision, local_package_revision, local_package_hash,
       apply_state, apply_error, output_tail, last_attempt_at_unix, updated_at_unix
  FROM center_device_app_deploy_apply_status
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY app_id`, deviceID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployApplyStatusRecord{}
	for rows.Next() {
		var rec AppDeployApplyStatusRecord
		if err := scanAppDeployApplyStatus(rows, &rec); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func loadAppDeployApplyStatusTx(ctx context.Context, q queryer, driver string, deviceID string, appID string) (AppDeployApplyStatusRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, app_id, desired_package_revision, local_package_revision, local_package_hash,
       apply_state, apply_error, output_tail, last_attempt_at_unix, updated_at_unix
  FROM center_device_app_deploy_apply_status
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2), deviceID, appID)
	var rec AppDeployApplyStatusRecord
	if err := scanAppDeployApplyStatus(row, &rec); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return AppDeployApplyStatusRecord{}, false, nil
		}
		return AppDeployApplyStatusRecord{}, false, err
	}
	return rec, true, nil
}

func scanAppDeployApplyStatus(scanner rowScanner, rec *AppDeployApplyStatusRecord) error {
	return scanner.Scan(
		&rec.DeviceID,
		&rec.AppID,
		&rec.DesiredPackageRevision,
		&rec.LocalPackageRevision,
		&rec.LocalPackageHash,
		&rec.ApplyState,
		&rec.ApplyError,
		&rec.OutputTail,
		&rec.LastAttemptAtUnix,
		&rec.UpdatedAtUnix,
	)
}

func insertAppDeployHistoryTx(ctx context.Context, tx *sql.Tx, driver string, rec AppDeployHistoryRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_app_deploy_history
    (device_id, app_id, operation, package_revision, package_hash, base_package_revision, profile_revision,
     apply_state, apply_error, output_tail, requested_by, requested_at_unix, applied_at_unix, updated_at_unix)
VALUES (`+placeholders(driver, 14, 1)+`)`,
		rec.DeviceID,
		rec.AppID,
		rec.Operation,
		rec.PackageRevision,
		rec.PackageHash,
		rec.BasePackageRevision,
		rec.ProfileRevision,
		rec.ApplyState,
		rec.ApplyError,
		rec.OutputTail,
		rec.RequestedBy,
		rec.RequestedAtUnix,
		rec.AppliedAtUnix,
		rec.UpdatedAtUnix,
	)
	return err
}

func listAppDeployHistoryForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]AppDeployHistoryRecord, error) {
	if limit <= 0 || limit > 100 {
		limit = 50
	}
	rows, err := q.QueryContext(ctx, `
SELECT history_id, device_id, app_id, operation, package_revision, package_hash, base_package_revision, profile_revision,
       apply_state, apply_error, output_tail, requested_by, requested_at_unix, applied_at_unix, updated_at_unix
  FROM center_device_app_deploy_history
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY updated_at_unix DESC, history_id DESC
 LIMIT `+placeholder(driver, 2), deviceID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []AppDeployHistoryRecord{}
	for rows.Next() {
		var rec AppDeployHistoryRecord
		if err := rows.Scan(
			&rec.HistoryID,
			&rec.DeviceID,
			&rec.AppID,
			&rec.Operation,
			&rec.PackageRevision,
			&rec.PackageHash,
			&rec.BasePackageRevision,
			&rec.ProfileRevision,
			&rec.ApplyState,
			&rec.ApplyError,
			&rec.OutputTail,
			&rec.RequestedBy,
			&rec.RequestedAtUnix,
			&rec.AppliedAtUnix,
			&rec.UpdatedAtUnix,
		); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func dbBool(driver string, value bool) any {
	if driver == "pgsql" {
		return value
	}
	if value {
		return 1
	}
	return 0
}

func dbValueBool(value any) bool {
	switch v := value.(type) {
	case bool:
		return v
	case int64:
		return v != 0
	case int:
		return v != 0
	case []byte:
		return string(v) != "" && string(v) != "0" && string(v) != "false"
	case string:
		return v != "" && v != "0" && v != "false"
	default:
		return false
	}
}

func nonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
