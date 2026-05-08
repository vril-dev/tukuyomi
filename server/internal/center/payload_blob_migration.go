package center

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type CenterPayloadBlobMigrationStats struct {
	RuntimeArtifacts                 int
	AppPackages                      int
	RuntimeArtifactBlobColumnDropped bool
	AppPackageBlobColumnDropped      bool
	Vacuumed                         bool
	RuntimePayloadOrphansRemoved     int
	AppPayloadOrphansRemoved         int
}

func (s CenterPayloadBlobMigrationStats) Total() int {
	return s.RuntimeArtifacts + s.AppPackages
}

func MigrateCenterPayloadBlobs(ctx context.Context) (CenterPayloadBlobMigrationStats, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var stats CenterPayloadBlobMigrationStats
	runtimeArtifacts, err := listLegacyRuntimeArtifactBlobs(ctx)
	if err != nil {
		return stats, err
	}
	for _, rec := range runtimeArtifacts {
		if _, err := loadLegacyRuntimeArtifactBlobAndMigrate(ctx, rec); err != nil {
			return stats, fmt.Errorf("migrate runtime artifact %s: %w", rec.ArtifactRevision, err)
		}
		stats.RuntimeArtifacts++
	}
	appPackages, err := listLegacyAppDeployPackageBlobs(ctx)
	if err != nil {
		return stats, err
	}
	for _, pkg := range appPackages {
		if _, err := loadLegacyAppDeployPackageBlobAndMigrate(ctx, pkg); err != nil {
			return stats, fmt.Errorf("migrate app deploy package %s: %w", pkg.PackageRevision, err)
		}
		stats.AppPackages++
	}
	runtimeDropped, appDropped, vacuumed, err := cleanupCenterPayloadBlobColumns(ctx)
	if err != nil {
		return stats, err
	}
	stats.RuntimeArtifactBlobColumnDropped = runtimeDropped
	stats.AppPackageBlobColumnDropped = appDropped
	stats.Vacuumed = vacuumed
	runtimeOrphans, appOrphans, err := cleanupCenterPayloadOrphans(ctx)
	if err != nil {
		return stats, err
	}
	stats.RuntimePayloadOrphansRemoved = runtimeOrphans
	stats.AppPayloadOrphansRemoved = appOrphans
	return stats, nil
}

func listLegacyRuntimeArtifactBlobs(ctx context.Context) ([]RuntimeArtifactRecord, error) {
	out := []RuntimeArtifactRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		exists, err := centerDBColumnExists(db, driver, "center_runtime_artifacts", "artifact_blob")
		if err != nil || !exists {
			return err
		}
		rows, err := db.QueryContext(ctx, runtimeArtifactSelectSQL()+`
 WHERE COALESCE(length(artifact_blob), 0) > 0
 ORDER BY created_at_unix ASC, artifact_revision ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec RuntimeArtifactRecord
			if err := scanRuntimeArtifactRecord(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func listLegacyAppDeployPackageBlobs(ctx context.Context) ([]AppDeployPackageRecord, error) {
	out := []AppDeployPackageRecord{}
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		exists, err := centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		if err != nil || !exists {
			return err
		}
		rows, err := db.QueryContext(ctx, appDeployPackageSelectSQL()+`
 WHERE COALESCE(length(package_blob), 0) > 0
 ORDER BY uploaded_at_unix ASC, package_revision ASC`)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var rec AppDeployPackageRecord
			if err := scanAppDeployPackage(rows, &rec); err != nil {
				return err
			}
			out = append(out, rec)
		}
		return rows.Err()
	})
	return out, err
}

func cleanupCenterPayloadBlobColumns(ctx context.Context) (bool, bool, bool, error) {
	if err := verifyCenterPayloadFilesBeforeBlobColumnDrop(ctx); err != nil {
		return false, false, false, fmt.Errorf("verify file-backed payloads before blob cleanup: %w", err)
	}
	var (
		driver         string
		runtimeDropped bool
		appDropped     bool
	)
	err := withCenterDB(ctx, func(db *sql.DB, d string) error {
		driver = strings.ToLower(strings.TrimSpace(d))
		runtimeExists, err := centerDBColumnExists(db, driver, "center_runtime_artifacts", "artifact_blob")
		if err != nil {
			return fmt.Errorf("inspect center_runtime_artifacts.artifact_blob: %w", err)
		}
		appExists, err := centerDBColumnExists(db, driver, "center_app_deploy_packages", "package_blob")
		if err != nil {
			return fmt.Errorf("inspect center_app_deploy_packages.package_blob: %w", err)
		}
		if runtimeExists {
			if err := ensureNoRemainingLegacyBlobRows(ctx, db, driver, "center_runtime_artifacts", "artifact_blob"); err != nil {
				return err
			}
			if _, err := db.ExecContext(ctx, `ALTER TABLE center_runtime_artifacts DROP COLUMN artifact_blob`); err != nil {
				return fmt.Errorf("drop center_runtime_artifacts.artifact_blob: %w", err)
			}
			runtimeDropped = true
		}
		if appExists {
			if err := ensureNoRemainingLegacyBlobRows(ctx, db, driver, "center_app_deploy_packages", "package_blob"); err != nil {
				return err
			}
			if _, err := db.ExecContext(ctx, `ALTER TABLE center_app_deploy_packages DROP COLUMN package_blob`); err != nil {
				return fmt.Errorf("drop center_app_deploy_packages.package_blob: %w", err)
			}
			appDropped = true
		}
		return nil
	})
	if err != nil {
		return false, false, false, err
	}
	vacuumed := false
	if runtimeDropped || appDropped {
		if err := vacuumCenterPayloadTables(ctx, driver, runtimeDropped, appDropped); err != nil {
			return runtimeDropped, appDropped, false, err
		}
		vacuumed = driver == "sqlite" || driver == "pgsql"
	}
	return runtimeDropped, appDropped, vacuumed, nil
}

func cleanupCenterPayloadOrphans(ctx context.Context) (int, int, error) {
	runtimeRevisions := map[string]struct{}{}
	appRevisions := map[string]struct{}{}
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		rows, err := db.QueryContext(ctx, `
SELECT artifact_revision
  FROM center_runtime_artifacts
 WHERE storage_state = `+placeholder(driver, 1), RuntimeArtifactStorageStored)
		if err != nil {
			return err
		}
		for rows.Next() {
			var revision string
			if err := rows.Scan(&revision); err != nil {
				_ = rows.Close()
				return err
			}
			runtimeRevisions[revision] = struct{}{}
		}
		if err := rows.Close(); err != nil {
			return err
		}
		rows, err = db.QueryContext(ctx, `
SELECT package_revision
  FROM center_app_deploy_packages`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var revision string
			if err := rows.Scan(&revision); err != nil {
				_ = rows.Close()
				return err
			}
			appRevisions[revision] = struct{}{}
		}
		return rows.Close()
	}); err != nil {
		return 0, 0, err
	}
	runtimeRemoved, err := removeOrphanCenterPayloadFiles(centerPayloadRuntimeArtifacts, centerPayloadRuntimeArtifactExt, runtimeRevisions)
	if err != nil {
		return runtimeRemoved, 0, err
	}
	appRemoved, err := removeOrphanCenterPayloadFiles(centerPayloadAppDeploy, centerPayloadAppDeployExt, appRevisions)
	if err != nil {
		return runtimeRemoved, appRemoved, err
	}
	return runtimeRemoved, appRemoved, nil
}

func removeOrphanCenterPayloadFiles(kind string, ext string, live map[string]struct{}) (int, error) {
	root, err := centerPayloadKindDir(kind)
	if err != nil {
		return 0, err
	}
	if _, err := os.Stat(root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, nil
		}
		return 0, err
	}
	removed := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		name := entry.Name()
		if !strings.HasSuffix(name, ext) {
			return nil
		}
		revision := strings.TrimSuffix(name, ext)
		if !hex64Pattern.MatchString(revision) {
			return nil
		}
		if _, ok := live[revision]; ok {
			return nil
		}
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		removed++
		return nil
	})
	if err != nil {
		return removed, err
	}
	removeEmptyCenterPayloadDirs(root)
	return removed, nil
}

func removeEmptyCenterPayloadDirs(root string) {
	entries, err := os.ReadDir(root)
	if err != nil {
		return
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		_ = os.Remove(filepath.Join(root, entry.Name()))
	}
}

func verifyCenterPayloadFilesBeforeBlobColumnDrop(ctx context.Context) error {
	runtimeArtifacts := []RuntimeArtifactRecord{}
	appPackages := []AppDeployPackageRecord{}
	if err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		rows, err := db.QueryContext(ctx, runtimeArtifactSelectSQL()+`
 WHERE storage_state = `+placeholder(driver, 1)+`
 ORDER BY created_at_unix ASC, artifact_revision ASC`, RuntimeArtifactStorageStored)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rec RuntimeArtifactRecord
			if err := scanRuntimeArtifactRecord(rows, &rec); err != nil {
				_ = rows.Close()
				return err
			}
			runtimeArtifacts = append(runtimeArtifacts, rec)
		}
		if err := rows.Close(); err != nil {
			return err
		}
		rows, err = db.QueryContext(ctx, appDeployPackageSelectSQL()+`
 ORDER BY uploaded_at_unix ASC, package_revision ASC`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var rec AppDeployPackageRecord
			if err := scanAppDeployPackage(rows, &rec); err != nil {
				_ = rows.Close()
				return err
			}
			appPackages = append(appPackages, rec)
		}
		return rows.Close()
	}); err != nil {
		return err
	}
	for _, rec := range runtimeArtifacts {
		if err := verifyCenterPayloadFileMustExist(centerPayloadRuntimeArtifacts, rec.ArtifactRevision, centerPayloadRuntimeArtifactExt, rec.CompressedSize, rec.ArtifactHash); err != nil {
			return fmt.Errorf("runtime artifact %s: %w", rec.ArtifactRevision, err)
		}
	}
	for _, rec := range appPackages {
		if err := verifyCenterPayloadFileMustExist(centerPayloadAppDeploy, rec.PackageRevision, centerPayloadAppDeployExt, rec.CompressedSize, rec.PackageHash); err != nil {
			return fmt.Errorf("app deploy package %s: %w", rec.PackageRevision, err)
		}
	}
	return nil
}

func verifyCenterPayloadFileMustExist(kind, revision, ext string, expectedSize int64, expectedHash string) error {
	target, err := centerPayloadFilePath(kind, revision, ext)
	if err != nil {
		return err
	}
	if err := verifyCenterPayloadFile(target, expectedSize, expectedHash); err != nil {
		return err
	}
	return nil
}

func ensureNoRemainingLegacyBlobRows(ctx context.Context, db *sql.DB, driver string, table string, column string) error {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM `+table+` WHERE COALESCE(length(`+column+`), 0) > 0`).Scan(&count)
	if err != nil {
		return err
	}
	if count > 0 {
		return fmt.Errorf("%s.%s still has %d legacy payload blob rows", table, column, count)
	}
	return nil
}

func vacuumCenterPayloadTables(ctx context.Context, driver string, runtimeDropped bool, appDropped bool) error {
	driver = strings.ToLower(strings.TrimSpace(driver))
	if driver != "sqlite" && driver != "pgsql" {
		return nil
	}
	vacuumCtx, cancel := context.WithTimeout(ctx, 10*time.Minute)
	defer cancel()
	return withCenterDB(vacuumCtx, func(db *sql.DB, _ string) error {
		switch driver {
		case "sqlite":
			if _, err := db.ExecContext(vacuumCtx, `VACUUM`); err != nil {
				return fmt.Errorf("vacuum sqlite center db: %w", err)
			}
		case "pgsql":
			if runtimeDropped {
				if _, err := db.ExecContext(vacuumCtx, `VACUUM (FULL, ANALYZE) center_runtime_artifacts`); err != nil {
					return fmt.Errorf("vacuum pgsql center_runtime_artifacts: %w", err)
				}
			}
			if appDropped {
				if _, err := db.ExecContext(vacuumCtx, `VACUUM (FULL, ANALYZE) center_app_deploy_packages`); err != nil {
					return fmt.Errorf("vacuum pgsql center_app_deploy_packages: %w", err)
				}
			}
		}
		return nil
	})
}

func centerDBColumnExists(db *sql.DB, driver string, tableName string, columnName string) (bool, error) {
	var count int
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "sqlite":
		rows, err := db.Query(`PRAGMA table_info(` + tableName + `)`)
		if err != nil {
			return false, err
		}
		defer rows.Close()
		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull int
			var defaultValue any
			var pk int
			if err := rows.Scan(&cid, &name, &dataType, &notNull, &defaultValue, &pk); err != nil {
				return false, err
			}
			if strings.EqualFold(name, columnName) {
				return true, nil
			}
		}
		return false, rows.Err()
	case "mysql":
		err := db.QueryRow(`
SELECT COUNT(*)
  FROM information_schema.columns
 WHERE table_schema = DATABASE()
   AND table_name = ?
   AND column_name = ?`, tableName, columnName).Scan(&count)
		return count > 0, err
	case "pgsql":
		err := db.QueryRow(`
SELECT COUNT(*)
  FROM information_schema.columns
 WHERE table_schema = current_schema()
   AND table_name = $1
   AND column_name = $2`, tableName, columnName).Scan(&count)
		return count > 0, err
	default:
		return false, fmt.Errorf("unsupported db driver: %s", driver)
	}
}
