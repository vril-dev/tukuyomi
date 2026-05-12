package center

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"
	"testing"

	"tukuyomi/internal/appdeploybundle"
)

func TestNormalizeAppDeployRootsAllowsSourceRoot(t *testing.T) {
	roots, raw, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
		RootID:         "source_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app",
		PackagePrefix:  ".",
		TargetSubpath:  ".",
		RuntimeSubpath: "public",
		Required:       true,
	}})
	if err != nil {
		t.Fatalf("normalizeAppDeployRoots: %v", err)
	}
	if len(roots) != 1 {
		t.Fatalf("len(roots)=%d want 1", len(roots))
	}
	root := roots[0]
	if root.SourcePath != "data/runtime-sites/app" {
		t.Fatalf("SourcePath=%q want data/runtime-sites/app", root.SourcePath)
	}
	if root.PackagePrefix != "" || root.TargetSubpath != "" {
		t.Fatalf("package/target=%q/%q want empty", root.PackagePrefix, root.TargetSubpath)
	}
	if root.RuntimeSubpath != "public" {
		t.Fatalf("RuntimeSubpath=%q want public", root.RuntimeSubpath)
	}
	if !strings.Contains(raw, `"source_path":"data/runtime-sites/app"`) || !strings.Contains(raw, `"runtime_subpath":"public"`) {
		t.Fatalf("normalized roots JSON omitted source/runtime subpath: %s", raw)
	}
}

func TestNormalizeAppDeployRuntimeFamilyAllowsDaemon(t *testing.T) {
	if got := normalizeAppDeployRuntimeFamily(" daemon "); got != "daemon" {
		t.Fatalf("normalize daemon=%q", got)
	}
	if got := normalizeAppDeployRuntimeFamily("fcgi"); got != "" {
		t.Fatalf("normalize unsupported=%q want empty", got)
	}
}

func TestNormalizeAppDeployRootsRejectsUnsafeSourcePath(t *testing.T) {
	for _, sourcePath := range []string{"/srv/app", "etc", "data", "data/vhosts/app"} {
		_, _, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
			RootID:        "source_root",
			RuntimeField:  "document_root",
			SourcePath:    sourcePath,
			PackagePrefix: ".",
			TargetSubpath: ".",
			Required:      true,
		}})
		if !errors.Is(err, ErrAppDeployInvalid) {
			t.Fatalf("source_path=%q err=%v want ErrAppDeployInvalid", sourcePath, err)
		}
	}
}

func TestValidateAppDeployRootsForAppRequiresAppDirectory(t *testing.T) {
	validRoots := []AppDeployRootRecord{
		{SourcePath: "data/runtime-sites/app-1"},
		{SourcePath: "data/runtime-sites/app-1/public"},
		{SourcePath: ""},
	}
	if err := validateAppDeployRootsForApp("app-1", validRoots); err != nil {
		t.Fatalf("validateAppDeployRootsForApp(valid): %v", err)
	}
	for _, sourcePath := range []string{"data/runtime-sites/app-10", "data/runtime-sites/samples/app-1", "data/runtime-sites/app"} {
		if err := validateAppDeployRootsForApp("app-1", []AppDeployRootRecord{{SourcePath: sourcePath}}); !errors.Is(err, ErrAppDeployInvalid) {
			t.Fatalf("source_path=%q err=%v want ErrAppDeployInvalid", sourcePath, err)
		}
	}
}

func TestValidateAppDeployAdoptionRootsForAppRequiresSourcePath(t *testing.T) {
	err := validateAppDeployAdoptionRootsForApp("app-1", []AppDeployRootRecord{{
		SourcePath: "",
	}})
	if !errors.Is(err, ErrAppDeployInvalid) {
		t.Fatalf("err=%v want ErrAppDeployInvalid", err)
	}
	if err := validateAppDeployAdoptionRootsForApp("app-1", []AppDeployRootRecord{{
		SourcePath: "data/runtime-sites/app-1/public",
	}}); err != nil {
		t.Fatalf("validateAppDeployAdoptionRootsForApp(valid): %v", err)
	}
}

func TestAppDeployFilesForParsedPackageAllowsRootPackagePrefix(t *testing.T) {
	roots, _, err := normalizeAppDeployRoots([]AppDeployRootRecord{{
		RootID:         "source_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app",
		PackagePrefix:  "",
		TargetSubpath:  "",
		RuntimeSubpath: "public",
		Required:       true,
	}})
	if err != nil {
		t.Fatalf("normalizeAppDeployRoots: %v", err)
	}
	files, err := appDeployFilesForParsedPackage(appdeploybundle.Parsed{Files: []appdeploybundle.File{
		{Path: "artisan", SHA256: strings.Repeat("a", 64), SizeBytes: 1, Mode: 0o644},
		{Path: "public/index.php", SHA256: strings.Repeat("b", 64), SizeBytes: 2, Mode: 0o644},
	}}, roots)
	if err != nil {
		t.Fatalf("appDeployFilesForParsedPackage: %v", err)
	}
	if len(files) != 2 {
		t.Fatalf("len(files)=%d want 2", len(files))
	}
	for _, file := range files {
		if file.RootID != "source_root" {
			t.Fatalf("file %q RootID=%q want source_root", file.Path, file.RootID)
		}
	}
}

func TestStoreAppDeployGatewayBaselineWithSavedProfile(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-baseline"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	roots := []AppDeployRootRecord{{
		RootID:         "document_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app-1/_before-laravel-public/20260422-220957",
		PackagePrefix:  "public",
		TargetSubpath:  "public",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         roots,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	req, err := CreateAppDeployRequest(ctx, AppDeployRequestUpdate{
		DeviceID:         deviceID,
		AppID:            "app-1",
		Operation:        AppDeployOperationAdopt,
		RuntimeFamily:    "php-fpm",
		RuntimeID:        "php85",
		Roots:            roots,
		RestartBehavior:  "restart-runtime",
		ScriptTimeoutSec: 60,
		Reason:           "adopt baseline",
		RequestedBy:      "test",
		RequestedAtUnix:  1001,
	})
	if err != nil {
		t.Fatalf("CreateAppDeployRequest: %v", err)
	}
	pkg, err := StoreAppDeployPackage(ctx, AppDeployPackageImport{
		DeviceID:      deviceID,
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         req.Roots,
		Label:         "Gateway baseline",
		Note:          "Adopted from Gateway current Runtime App source.",
		SourceType:    AppDeploySourceGatewayBaseline,
		Archive: testAppDeployZip(t, map[string]string{
			"public/index.php": "<?php echo 'ok';",
			"public/up.php":    "<?php echo 'up';",
			"public/test.html": "ok",
		}),
		UploadedBy:      "gateway:" + deviceID,
		UploadedAtUnix:  1002,
		UpsertProfile:   true,
		ProfileRevision: req.ProfileRevision,
	})
	if err != nil {
		t.Fatalf("StoreAppDeployPackage: %v", err)
	}
	if pkg.SourceType != AppDeploySourceGatewayBaseline || pkg.FileCount != 3 {
		t.Fatalf("baseline package not stored as expected: %+v", pkg)
	}
}

func TestStoreAppDeployPackageUsesFileBackedPayload(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-file-backed"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	roots := []AppDeployRootRecord{{
		RootID:         "document_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app-1/public",
		PackagePrefix:  "public",
		TargetSubpath:  "public",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         roots,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	archive := testAppDeployZip(t, map[string]string{"public/index.php": "<?php echo 'ok';"})
	pkg, err := StoreAppDeployPackage(ctx, AppDeployPackageImport{
		DeviceID:       deviceID,
		AppID:          "app-1",
		RuntimeFamily:  "php-fpm",
		RuntimeID:      "php85",
		Roots:          roots,
		SourceType:     AppDeploySourceUpload,
		Archive:        archive,
		UploadedBy:     "operator",
		UploadedAtUnix: 1001,
		UpsertProfile:  true,
	})
	if err != nil {
		t.Fatalf("StoreAppDeployPackage: %v", err)
	}
	var blobColumnExists bool
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var err error
		blobColumnExists, err = centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		return err
	}); err != nil {
		t.Fatalf("inspect package blob column: %v", err)
	}
	if blobColumnExists {
		t.Fatal("fresh app deploy schema unexpectedly has package_blob column")
	}
	stored, err := readCenterPayloadFile(centerPayloadAppDeploy, pkg.PackageRevision, centerPayloadAppDeployExt, pkg.CompressedSize, pkg.PackageHash)
	if err != nil {
		t.Fatalf("read file-backed package: %v", err)
	}
	if !bytes.Equal(stored, archive) {
		t.Fatal("file-backed package body mismatch")
	}
	_, downloaded, err := DownloadAppDeployPackageForDevice(ctx, deviceID, pkg.PackageRevision)
	if err != nil {
		t.Fatalf("DownloadAppDeployPackageForDevice: %v", err)
	}
	if !bytes.Equal(downloaded, archive) {
		t.Fatal("downloaded package body mismatch")
	}
}

func TestDownloadAppDeployPackageMigratesLegacyBlob(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-legacy-blob"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	roots := []AppDeployRootRecord{{
		RootID:         "document_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app-1/public",
		PackagePrefix:  "public",
		TargetSubpath:  "public",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         roots,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	archive := testAppDeployZip(t, map[string]string{"public/index.php": "<?php echo 'legacy';"})
	pkg, err := StoreAppDeployPackage(ctx, AppDeployPackageImport{
		DeviceID:       deviceID,
		AppID:          "app-1",
		RuntimeFamily:  "php-fpm",
		RuntimeID:      "php85",
		Roots:          roots,
		SourceType:     AppDeploySourceUpload,
		Archive:        archive,
		UploadedBy:     "operator",
		UploadedAtUnix: 1001,
		UpsertProfile:  true,
	})
	if err != nil {
		t.Fatalf("StoreAppDeployPackage: %v", err)
	}
	removeCenterPayloadFile(centerPayloadAppDeploy, pkg.PackageRevision, centerPayloadAppDeployExt)
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		if _, err := db.ExecContext(ctx, `ALTER TABLE center_app_deploy_packages ADD COLUMN package_blob BLOB`); err != nil {
			return err
		}
		_, err := db.ExecContext(ctx, `
UPDATE center_app_deploy_packages
   SET package_blob = `+placeholder(driver, 1)+`
 WHERE package_revision = `+placeholder(driver, 2), archive, pkg.PackageRevision)
		return err
	}); err != nil {
		t.Fatalf("restore legacy package blob: %v", err)
	}
	_, downloaded, err := DownloadAppDeployPackageForDevice(ctx, deviceID, pkg.PackageRevision)
	if err != nil {
		t.Fatalf("DownloadAppDeployPackageForDevice: %v", err)
	}
	if !bytes.Equal(downloaded, archive) {
		t.Fatal("legacy downloaded package body mismatch")
	}
	if _, err := MigrateCenterPayloadBlobs(ctx); err != nil {
		t.Fatalf("MigrateCenterPayloadBlobs: %v", err)
	}
	var blobColumnExists bool
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var err error
		blobColumnExists, err = centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		return err
	}); err != nil {
		t.Fatalf("inspect migrated package blob column: %v", err)
	}
	if blobColumnExists {
		t.Fatal("migrated app deploy schema still has package_blob column")
	}
}

func TestMigrateCenterPayloadBlobsRemovesOrphanPayloadFiles(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	ctx := context.Background()
	runtimeBody := []byte("orphan-runtime-payload")
	runtimeHash := sha256.Sum256(runtimeBody)
	runtimeRevision := strings.Repeat("a", 64)
	if _, err := writeCenterPayloadFile(centerPayloadRuntimeArtifacts, runtimeRevision, centerPayloadRuntimeArtifactExt, runtimeBody, int64(len(runtimeBody)), hex.EncodeToString(runtimeHash[:])); err != nil {
		t.Fatalf("write orphan runtime payload: %v", err)
	}
	appBody := testAppDeployZip(t, map[string]string{"public/index.php": "<?php echo 'orphan';"})
	appHash := sha256.Sum256(appBody)
	appRevision := strings.Repeat("b", 64)
	if _, err := writeCenterPayloadFile(centerPayloadAppDeploy, appRevision, centerPayloadAppDeployExt, appBody, int64(len(appBody)), hex.EncodeToString(appHash[:])); err != nil {
		t.Fatalf("write orphan app payload: %v", err)
	}
	stats, err := MigrateCenterPayloadBlobs(ctx)
	if err != nil {
		t.Fatalf("MigrateCenterPayloadBlobs: %v", err)
	}
	if stats.RuntimePayloadOrphansRemoved != 1 || stats.AppPayloadOrphansRemoved != 1 {
		t.Fatalf("orphan stats runtime=%d app=%d want 1/1", stats.RuntimePayloadOrphansRemoved, stats.AppPayloadOrphansRemoved)
	}
	if _, err := readCenterPayloadFile(centerPayloadRuntimeArtifacts, runtimeRevision, centerPayloadRuntimeArtifactExt, int64(len(runtimeBody)), hex.EncodeToString(runtimeHash[:])); !errors.Is(err, errCenterPayloadFileNotFound) {
		t.Fatalf("runtime orphan read err=%v want not found", err)
	}
	if _, err := readCenterPayloadFile(centerPayloadAppDeploy, appRevision, centerPayloadAppDeployExt, int64(len(appBody)), hex.EncodeToString(appHash[:])); !errors.Is(err, errCenterPayloadFileNotFound) {
		t.Fatalf("app orphan read err=%v want not found", err)
	}
}

func TestEnsureAppDeployCandidateMatchesProfileIgnoresSourceRootShape(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-managed-candidate"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	profileRoots := []AppDeployRootRecord{{
		RootID:         "source_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app-1",
		PackagePrefix:  "",
		TargetSubpath:  "",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	candidateRoots := []AppDeployRootRecord{{
		RootID:         "document_root",
		RuntimeField:   "document_root",
		SourcePath:     "",
		PackagePrefix:  "public",
		TargetSubpath:  "public",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         candidateRoots,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	profile := AppDeployProfileRecord{
		DeviceID:      deviceID,
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         profileRoots,
	}
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		return ensureAppDeployCandidateMatchesProfileTx(ctx, db, driver, profile)
	}); err != nil {
		t.Fatalf("ensureAppDeployCandidateMatchesProfileTx: %v", err)
	}
}

func TestCreateAppDeployRequestRejectsManagedCandidateAdoption(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-managed-adopt"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	roots := []AppDeployRootRecord{{
		RootID:         "app_root",
		RuntimeField:   "app_root",
		SourcePath:     "data/runtime-sites/mqtt-broker/app",
		PackagePrefix:  "app",
		TargetSubpath:  "app",
		RuntimeSubpath: "app",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "mqtt-broker",
		RuntimeFamily: "daemon",
		Roots:         roots,
		Managed:       true,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	_, err := CreateAppDeployRequest(ctx, AppDeployRequestUpdate{
		DeviceID:         deviceID,
		AppID:            "mqtt-broker",
		Operation:        AppDeployOperationAdopt,
		RuntimeFamily:    "daemon",
		Roots:            roots,
		RestartBehavior:  "restart-runtime",
		ScriptTimeoutSec: 60,
		Reason:           "repeat baseline",
		RequestedBy:      "test",
		RequestedAtUnix:  1001,
	})
	if !errors.Is(err, ErrAppDeployIncompatible) {
		t.Fatalf("err=%v want ErrAppDeployIncompatible", err)
	}
}

func TestAppDeployAdoptIgnoresStaleTerminalStatus(t *testing.T) {
	setupRemoteSSHStoreTest(t)
	deviceID := "tky-app-deploy-stale"
	insertRemoteSSHApprovedDeviceForTest(t, deviceID)
	ctx := context.Background()
	roots := []AppDeployRootRecord{{
		RootID:         "document_root",
		RuntimeField:   "document_root",
		SourcePath:     "data/runtime-sites/app-1/public",
		PackagePrefix:  "public",
		TargetSubpath:  "public",
		RuntimeSubpath: "public",
		Required:       true,
	}}
	if err := UpsertAppDeployCandidates(ctx, deviceID, []AppDeployCandidateRecord{{
		AppID:         "app-1",
		RuntimeFamily: "php-fpm",
		RuntimeID:     "php85",
		Roots:         roots,
	}}, 1000); err != nil {
		t.Fatalf("UpsertAppDeployCandidates: %v", err)
	}
	req, err := CreateAppDeployRequest(ctx, AppDeployRequestUpdate{
		DeviceID:         deviceID,
		AppID:            "app-1",
		Operation:        AppDeployOperationAdopt,
		RuntimeFamily:    "php-fpm",
		RuntimeID:        "php85",
		Roots:            roots,
		RestartBehavior:  "restart-runtime",
		ScriptTimeoutSec: 60,
		Reason:           "retry baseline",
		RequestedBy:      "test",
		RequestedAtUnix:  1001,
	})
	if err != nil {
		t.Fatalf("CreateAppDeployRequest: %v", err)
	}
	if err := UpsertAppDeployApplyStatuses(ctx, deviceID, []AppDeployApplyStatusRecord{{
		AppID:      "app-1",
		ApplyState: "failed",
		ApplyError: "old baseline upload failed",
	}}, 1002); err != nil {
		t.Fatalf("Upsert stale AppDeployApplyStatus: %v", err)
	}
	assignment, err := PendingAppDeployAssignmentForDevice(ctx, deviceID, 1003)
	if err != nil {
		t.Fatalf("PendingAppDeployAssignmentForDevice: %v", err)
	}
	if assignment == nil || assignment.RequestID != req.RequestID || assignment.ProfileRevision != req.ProfileRevision {
		t.Fatalf("stale terminal status consumed adopt request: assignment=%+v req=%+v", assignment, req)
	}

	localRevision := strings.Repeat("b", 64)
	localHash := strings.Repeat("c", 64)
	if err := UpsertAppDeployApplyStatuses(ctx, deviceID, []AppDeployApplyStatusRecord{{
		AppID:                  "app-1",
		DesiredPackageRevision: req.ProfileRevision,
		LocalPackageRevision:   localRevision,
		LocalPackageHash:       localHash,
		ApplyState:             "applied",
	}}, 1004); err != nil {
		t.Fatalf("Upsert matching AppDeployApplyStatus: %v", err)
	}
	assignment, err = PendingAppDeployAssignmentForDevice(ctx, deviceID, 1005)
	if err != nil {
		t.Fatalf("Pending after matching status: %v", err)
	}
	if assignment != nil {
		t.Fatalf("matching terminal status should clear request, assignment=%+v", assignment)
	}
	var historyRevision string
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		return db.QueryRowContext(ctx, `
SELECT package_revision
  FROM center_device_app_deploy_history
 WHERE device_id = `+placeholder(driver, 1)+`
   AND app_id = `+placeholder(driver, 2),
			deviceID, "app-1").Scan(&historyRevision)
	}); err != nil {
		t.Fatalf("load app deploy history: %v", err)
	}
	if historyRevision != localRevision {
		t.Fatalf("history package_revision=%q want %q", historyRevision, localRevision)
	}
}

func testAppDeployZip(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("create zip entry %s: %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("write zip entry %s: %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("close zip: %v", err)
	}
	return buf.Bytes()
}
