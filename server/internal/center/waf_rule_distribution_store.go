package center

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"strings"
	"time"

	"tukuyomi/internal/config"
	"tukuyomi/internal/edgeartifactbundle"
	"tukuyomi/internal/edgeconfigsnapshot"
)

const WAFRuleAssignmentDispatchLeaseSec = int64(60)

var wafRuleArtifactRebuildTime = time.Unix(0, 0).UTC()

var (
	ErrWAFRuleBundleNotFound       = errors.New("waf rule bundle not found")
	ErrWAFRuleInvalid              = errors.New("invalid waf rules")
	ErrWAFRuleAssignmentDispatched = errors.New("waf rule assignment already dispatched")
)

type WAFRuleSnapshotRecord struct {
	DeviceID              string                `json:"device_id"`
	ConfigRevision        string                `json:"config_revision"`
	DomainETag            string                `json:"domain_etag"`
	BundleRevision        string                `json:"bundle_revision"`
	Assets                []WAFRuleAssetSummary `json:"assets"`
	Error                 string                `json:"error"`
	SnapshotCreatedAtUnix int64                 `json:"snapshot_created_at_unix"`
}

type WAFRuleAssetSummary struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	ETag      string `json:"etag,omitempty"`
	Disabled  bool   `json:"disabled"`
	SizeBytes int64  `json:"size_bytes"`
}

type WAFRuleBundleRecord struct {
	DeviceID            string `json:"device_id"`
	BundleRevision      string `json:"bundle_revision"`
	BundleHash          string `json:"bundle_hash"`
	CompressedSize      int64  `json:"compressed_size"`
	UncompressedSize    int64  `json:"uncompressed_size"`
	FileCount           int    `json:"file_count"`
	CreatedAtUnix       int64  `json:"created_at_unix"`
	CreatedAt           string `json:"created_at"`
	Source              string `json:"source"`
	LocalBundleRevision string `json:"local_bundle_revision,omitempty"`
	ApplyState          string `json:"apply_state,omitempty"`
	ApplyError          string `json:"apply_error,omitempty"`
	LastAttemptAtUnix   int64  `json:"last_attempt_at_unix,omitempty"`
	AppliedAtUnix       int64  `json:"applied_at_unix,omitempty"`
	ApplyUpdatedAtUnix  int64  `json:"apply_updated_at_unix,omitempty"`
}

type WAFRuleBundleFileRecord struct {
	DeviceID       string `json:"device_id"`
	BundleRevision string `json:"bundle_revision"`
	Path           string `json:"path"`
	ArchivePath    string `json:"archive_path"`
	Kind           string `json:"kind"`
	ETag           string `json:"etag,omitempty"`
	Disabled       bool   `json:"disabled"`
	SHA256         string `json:"sha256"`
	SizeBytes      int64  `json:"size_bytes"`
	Body           []byte `json:"-"`
}

type WAFRuleAssignmentUpdate struct {
	DeviceID       string
	BundleRevision string
	Reason         string
	AssignedBy     string
	AssignedAtUnix int64
}

type WAFRuleBundleImport struct {
	DeviceID       string
	Archive        []byte
	Assign         bool
	Reason         string
	Actor          string
	ImportedAtUnix int64
}

type WAFRuleBundleImportResult struct {
	Bundle               WAFRuleBundleRecord      `json:"bundle"`
	Stored               bool                     `json:"stored"`
	Assignment           *WAFRuleAssignmentRecord `json:"assignment,omitempty"`
	StrippedRootPrefixes []string                 `json:"stripped_root_prefixes,omitempty"`
}

type WAFRuleAssignmentRecord struct {
	AssignmentID       int64  `json:"assignment_id"`
	DeviceID           string `json:"device_id"`
	BundleRevision     string `json:"bundle_revision"`
	BaseBundleRevision string `json:"base_bundle_revision"`
	Reason             string `json:"reason"`
	AssignedBy         string `json:"assigned_by"`
	AssignedAtUnix     int64  `json:"assigned_at_unix"`
	UpdatedAtUnix      int64  `json:"updated_at_unix"`
	DispatchedAtUnix   int64  `json:"dispatched_at_unix,omitempty"`
	BundleHash         string `json:"bundle_hash"`
	CompressedSize     int64  `json:"compressed_size"`
	UncompressedSize   int64  `json:"uncompressed_size"`
	FileCount          int    `json:"file_count"`
}

type WAFRuleDeviceAssignment struct {
	BundleRevision     string `json:"bundle_revision"`
	BaseBundleRevision string `json:"base_bundle_revision"`
	CompressedSize     int64  `json:"compressed_size"`
	UncompressedSize   int64  `json:"uncompressed_size"`
	FileCount          int    `json:"file_count"`
	AssignedAtUnix     int64  `json:"assigned_at_unix"`
}

type WAFRuleApplyStatusRecord struct {
	DeviceID              string `json:"device_id"`
	DesiredBundleRevision string `json:"desired_bundle_revision"`
	LocalBundleRevision   string `json:"local_bundle_revision"`
	ApplyState            string `json:"apply_state"`
	ApplyError            string `json:"apply_error"`
	LastAttemptAtUnix     int64  `json:"last_attempt_at_unix"`
	UpdatedAtUnix         int64  `json:"updated_at_unix"`
}

type WAFRulesDeploymentView struct {
	Device      DeviceRecord              `json:"device"`
	Current     *WAFRuleSnapshotRecord    `json:"current"`
	Bundles     []WAFRuleBundleRecord     `json:"bundles"`
	Assignment  *WAFRuleAssignmentRecord  `json:"assignment"`
	ApplyStatus *WAFRuleApplyStatusRecord `json:"apply_status"`
}

type WAFRuleBundleDetail struct {
	Bundle WAFRuleBundleRecord       `json:"bundle"`
	Files  []WAFRuleBundleFileRecord `json:"files"`
}

type wafRuleOperatorArchiveManifest struct {
	SchemaVersion  int                          `json:"schema_version"`
	ArchiveType    string                       `json:"archive_type"`
	BundleRevision string                       `json:"bundle_revision"`
	BundleHash     string                       `json:"bundle_hash"`
	CreatedAtUnix  int64                        `json:"created_at_unix"`
	Files          []wafRuleOperatorArchiveFile `json:"files"`
}

type wafRuleOperatorArchiveFile struct {
	Path      string `json:"path"`
	Kind      string `json:"kind"`
	ETag      string `json:"etag,omitempty"`
	Disabled  bool   `json:"disabled"`
	SHA256    string `json:"sha256"`
	SizeBytes int64  `json:"size_bytes"`
}

type wafRuleUploadFile struct {
	path string
	body []byte
}

type wafRuleUploadParseResult struct {
	RuleFiles            []edgeartifactbundle.RuleFile
	StrippedRootPrefixes []string
}

func WAFRulesDeploymentForDevice(ctx context.Context, deviceID string) (WAFRulesDeploymentView, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return WAFRulesDeploymentView{}, ErrDeviceStatusNotFound
	}
	var out WAFRulesDeploymentView
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		out.Device = device
		if current, found, err := latestWAFRuleSnapshotTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.Current = &current
		}
		bundles, err := listWAFRuleBundlesForDeviceTx(ctx, db, driver, deviceID, 20)
		if err != nil {
			return err
		}
		if out.Current != nil {
			bundles, err = includeCurrentWAFRuleBundleTx(ctx, db, driver, deviceID, out.Current.BundleRevision, bundles)
			if err != nil {
				return err
			}
		}
		out.Bundles = bundles
		if assignment, found, err := loadWAFRuleAssignmentTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.Assignment = &assignment
		}
		if status, found, err := loadWAFRuleApplyStatusTx(ctx, db, driver, deviceID); err != nil {
			return err
		} else if found {
			out.ApplyStatus = &status
			if out.Assignment != nil && wafRuleApplyStatusMatchesTerminal(status, *out.Assignment) {
				if err := deleteWAFRuleAssignmentTx(ctx, db, driver, deviceID); err != nil {
					return err
				}
				out.Assignment = nil
			}
		}
		return nil
	})
	return out, err
}

func WAFRuleArtifactUploadRequiredForDevice(ctx context.Context, deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return false, ErrDeviceStatusNotFound
	}
	required := false
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		current, snapshotFound, err := latestWAFRuleSnapshotTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		if snapshotFound && hex64Pattern.MatchString(current.BundleRevision) {
			if _, bundleFound, err := loadWAFRuleBundleTx(ctx, db, driver, deviceID, current.BundleRevision); err != nil {
				return err
			} else if !bundleFound {
				required = true
				return nil
			}
			return nil
		}
		hasBundle, err := hasAnyWAFRuleBundleTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		required = !hasBundle
		return nil
	})
	return required, err
}

func LoadWAFRuleBundleForDevice(ctx context.Context, deviceID, revision string) (WAFRuleBundleDetail, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return WAFRuleBundleDetail{}, ErrWAFRuleBundleNotFound
	}
	var out WAFRuleBundleDetail
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		bundle, found, err := loadWAFRuleBundleTx(ctx, db, driver, deviceID, revision)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		files, err := listWAFRuleBundleFilesTx(ctx, db, driver, deviceID, revision, false)
		if err != nil {
			return err
		}
		out = WAFRuleBundleDetail{Bundle: bundle, Files: files}
		return nil
	})
	return out, err
}

func LoadWAFRuleBundleFileForDevice(ctx context.Context, deviceID, revision, assetPath string) (WAFRuleBundleFileRecord, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	assetPath = strings.TrimSpace(assetPath)
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) || assetPath == "" {
		return WAFRuleBundleFileRecord{}, ErrWAFRuleBundleNotFound
	}
	var out WAFRuleBundleFileRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		file, found, err := loadWAFRuleBundleFileTx(ctx, db, driver, deviceID, revision, assetPath)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		out = file
		return nil
	})
	return out, err
}

func ImportWAFRuleBundleForDevice(ctx context.Context, in WAFRuleBundleImport) (WAFRuleBundleImportResult, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.Reason = clampString(in.Reason, 512)
	in.Actor = clampString(in.Actor, 128)
	if !deviceIDPattern.MatchString(in.DeviceID) {
		return WAFRuleBundleImportResult{}, ErrDeviceStatusNotFound
	}
	if len(in.Archive) == 0 || len(in.Archive) > edgeartifactbundle.MaxCompressedBytes {
		return WAFRuleBundleImportResult{}, ErrWAFRuleInvalid
	}
	if in.ImportedAtUnix <= 0 {
		in.ImportedAtUnix = time.Now().UTC().Unix()
	}
	upload, err := parseWAFRuleOperatorUploadZip(in.Archive)
	if err != nil {
		return WAFRuleBundleImportResult{}, err
	}
	built, err := edgeartifactbundle.BuildBundle(upload.RuleFiles, time.Unix(in.ImportedAtUnix, 0).UTC())
	if err != nil {
		return WAFRuleBundleImportResult{}, ErrWAFRuleInvalid
	}
	parsed, err := edgeartifactbundle.Parse(built.Compressed)
	if err != nil {
		return WAFRuleBundleImportResult{}, ErrWAFRuleInvalid
	}
	stored, err := StoreRuleArtifactBundle(ctx, RuleArtifactBundleInsert{
		DeviceID:         in.DeviceID,
		BundleRevision:   parsed.Revision,
		BundleHash:       parsed.BundleHash,
		CompressedSize:   parsed.CompressedSize,
		UncompressedSize: parsed.UncompressedSize,
		FileCount:        parsed.FileCount,
		Files:            parsed.Files,
		ReceivedAtUnix:   in.ImportedAtUnix,
		Source:           RuleArtifactBundleSourceCenter,
	})
	if err != nil {
		if errors.Is(err, ErrDeviceStatusNotFound) {
			return WAFRuleBundleImportResult{}, err
		}
		return WAFRuleBundleImportResult{}, ErrWAFRuleInvalid
	}
	out := WAFRuleBundleImportResult{
		Bundle: WAFRuleBundleRecord{
			DeviceID:         stored.DeviceID,
			BundleRevision:   stored.BundleRevision,
			BundleHash:       stored.BundleHash,
			CompressedSize:   stored.CompressedSize,
			UncompressedSize: stored.UncompressedSize,
			FileCount:        stored.FileCount,
			CreatedAtUnix:    stored.CreatedAtUnix,
			CreatedAt:        stored.CreatedAt,
			Source:           stored.Source,
		},
		Stored:               stored.Stored,
		StrippedRootPrefixes: upload.StrippedRootPrefixes,
	}
	if in.Assign {
		reason := in.Reason
		if strings.TrimSpace(reason) == "" {
			reason = "center WAF rule bundle upload"
		}
		assignment, err := AssignWAFRuleBundleToDevice(ctx, WAFRuleAssignmentUpdate{
			DeviceID:       in.DeviceID,
			BundleRevision: stored.BundleRevision,
			Reason:         reason,
			AssignedBy:     in.Actor,
			AssignedAtUnix: in.ImportedAtUnix,
		})
		if err != nil {
			return WAFRuleBundleImportResult{}, err
		}
		out.Assignment = &assignment
	}
	return out, nil
}

func DownloadWAFRuleBundleForDevice(ctx context.Context, deviceID, revision string) (WAFRuleBundleRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(revision) {
		return WAFRuleBundleRecord{}, nil, ErrWAFRuleBundleNotFound
	}
	var bundle WAFRuleBundleRecord
	var files []WAFRuleBundleFileRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, db, driver, deviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		loaded, found, err := loadWAFRuleBundleTx(ctx, db, driver, deviceID, revision)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		loadedFiles, err := listWAFRuleBundleFilesTx(ctx, db, driver, deviceID, revision, true)
		if err != nil {
			return err
		}
		bundle = loaded
		files = loadedFiles
		return nil
	})
	if err != nil {
		return WAFRuleBundleRecord{}, nil, err
	}
	body, size, err := buildWAFRuleOperatorArchive(bundle, files)
	if err != nil {
		return WAFRuleBundleRecord{}, nil, err
	}
	bundle.CompressedSize = size
	bundle.UncompressedSize = 0
	bundle.FileCount = len(files)
	return bundle, body, nil
}

func buildWAFRuleOperatorArchive(bundle WAFRuleBundleRecord, files []WAFRuleBundleFileRecord) ([]byte, int64, error) {
	if len(files) == 0 || len(files) > edgeartifactbundle.MaxFiles {
		return nil, 0, ErrWAFRuleInvalid
	}
	manifest := wafRuleOperatorArchiveManifest{
		SchemaVersion:  1,
		ArchiveType:    "waf-rule-files",
		BundleRevision: bundle.BundleRevision,
		BundleHash:     bundle.BundleHash,
		CreatedAtUnix:  bundle.CreatedAtUnix,
		Files:          make([]wafRuleOperatorArchiveFile, 0, len(files)),
	}
	type zipFile struct {
		path string
		body []byte
	}
	zipFiles := make([]zipFile, 0, len(files))
	usedPaths := make(map[string]struct{}, len(files)+1)
	for _, file := range files {
		zipPath := cleanWAFRuleOperatorArchivePath(file.Path)
		if zipPath == "" {
			return nil, 0, ErrWAFRuleInvalid
		}
		if _, exists := usedPaths[zipPath]; exists {
			return nil, 0, ErrWAFRuleInvalid
		}
		if int64(len(file.Body)) != file.SizeBytes || file.SizeBytes < 0 || file.SizeBytes > edgeartifactbundle.MaxFileBytes {
			return nil, 0, ErrWAFRuleInvalid
		}
		sum := sha256.Sum256(file.Body)
		shaHex := hex.EncodeToString(sum[:])
		if file.SHA256 != "" && !strings.EqualFold(file.SHA256, shaHex) {
			return nil, 0, ErrWAFRuleInvalid
		}
		usedPaths[zipPath] = struct{}{}
		zipFiles = append(zipFiles, zipFile{path: zipPath, body: file.Body})
		manifest.Files = append(manifest.Files, wafRuleOperatorArchiveFile{
			Path:      file.Path,
			Kind:      file.Kind,
			ETag:      file.ETag,
			Disabled:  file.Disabled,
			SHA256:    shaHex,
			SizeBytes: file.SizeBytes,
		})
	}
	manifestPath := chooseWAFRuleOperatorManifestPath(usedPaths, bundle.BundleRevision)
	if manifestPath == "" {
		return nil, 0, ErrWAFRuleInvalid
	}
	manifestRaw, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return nil, 0, err
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	if err := writeWAFRuleOperatorZipFile(zw, manifestPath, manifestRaw); err != nil {
		_ = zw.Close()
		return nil, 0, err
	}
	for _, file := range zipFiles {
		if err := writeWAFRuleOperatorZipFile(zw, file.path, file.body); err != nil {
			_ = zw.Close()
			return nil, 0, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, 0, err
	}
	if buf.Len() > edgeartifactbundle.MaxCompressedBytes {
		return nil, 0, ErrWAFRuleInvalid
	}
	return append([]byte(nil), buf.Bytes()...), int64(buf.Len()), nil
}

func parseWAFRuleOperatorUploadZip(raw []byte) (wafRuleUploadParseResult, error) {
	zr, err := zip.NewReader(bytes.NewReader(raw), int64(len(raw)))
	if err != nil {
		return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
	}
	entries, err := readWAFRuleUploadZipEntries(zr)
	if err != nil {
		return wafRuleUploadParseResult{}, err
	}
	entries, strippedRoots := stripWAFRuleUploadCommonRoots(entries)

	var manifest wafRuleOperatorArchiveManifest
	haveManifest := false
	files := make([]wafRuleUploadFile, 0, len(entries))
	seenPaths := map[string]struct{}{}
	for _, entry := range entries {
		cleaned := cleanWAFRuleOperatorArchivePath(entry.path)
		if cleaned == "" {
			return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
		}
		if strings.HasPrefix(cleaned, "_tukuyomi/") {
			if cleaned == "_tukuyomi/manifest.json" {
				dec := json.NewDecoder(bytes.NewReader(entry.body))
				if err := dec.Decode(&manifest); err != nil {
					return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
				}
				haveManifest = true
			}
			continue
		}
		if _, exists := seenPaths[cleaned]; exists {
			return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
		}
		seenPaths[cleaned] = struct{}{}
		files = append(files, wafRuleUploadFile{path: cleaned, body: entry.body})
	}
	if len(files) == 0 || len(files) > edgeartifactbundle.MaxFiles {
		return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
	}

	metadata := map[string]wafRuleOperatorArchiveFile{}
	if haveManifest {
		for _, file := range manifest.Files {
			path := cleanWAFRuleOperatorArchivePath(file.Path)
			if path == "" {
				return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
			}
			if _, exists := metadata[path]; exists {
				return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
			}
			file.Path = path
			metadata[path] = file
		}
	}

	out := make([]edgeartifactbundle.RuleFile, 0, len(files))
	for _, file := range files {
		if len(file.body) > edgeartifactbundle.MaxFileBytes {
			return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
		}
		meta, hasMeta := metadata[file.path]
		kind := inferWAFRuleUploadKind(file.path)
		etag := ""
		disabled := false
		if hasMeta {
			kind = strings.TrimSpace(meta.Kind)
			etag = strings.TrimSpace(meta.ETag)
			disabled = meta.Disabled
			if meta.SizeBytes != int64(len(file.body)) {
				return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
			}
			sum := sha256.Sum256(file.body)
			if meta.SHA256 == "" || !strings.EqualFold(meta.SHA256, hex.EncodeToString(sum[:])) {
				return wafRuleUploadParseResult{}, ErrWAFRuleInvalid
			}
		}
		if strings.TrimSpace(kind) == "" {
			kind = "base"
		}
		out = append(out, edgeartifactbundle.RuleFile{
			Path:     file.path,
			Kind:     kind,
			ETag:     etag,
			Disabled: disabled,
			Body:     file.body,
		})
	}
	return wafRuleUploadParseResult{
		RuleFiles:            out,
		StrippedRootPrefixes: strippedRoots,
	}, nil
}

func readWAFRuleUploadZipEntries(zr *zip.Reader) ([]wafRuleUploadFile, error) {
	if zr == nil {
		return nil, ErrWAFRuleInvalid
	}
	entries := make([]wafRuleUploadFile, 0, len(zr.File))
	total := int64(0)
	for _, entry := range zr.File {
		if entry == nil {
			continue
		}
		name := strings.TrimSpace(strings.ReplaceAll(entry.Name, "\\", "/"))
		if name == "" || strings.HasSuffix(name, "/") || strings.HasPrefix(name, "__MACOSX/") {
			continue
		}
		if path.Base(name) == ".DS_Store" {
			continue
		}
		if entry.FileInfo().IsDir() {
			continue
		}
		if entry.UncompressedSize64 > uint64(edgeartifactbundle.MaxFileBytes) {
			return nil, ErrWAFRuleInvalid
		}
		rc, err := entry.Open()
		if err != nil {
			return nil, ErrWAFRuleInvalid
		}
		body, readErr := readWAFRuleUploadZipEntry(rc, edgeartifactbundle.MaxFileBytes)
		closeErr := rc.Close()
		if readErr != nil {
			return nil, readErr
		}
		if closeErr != nil {
			return nil, ErrWAFRuleInvalid
		}
		total += int64(len(body))
		if total > edgeartifactbundle.MaxUncompressedBytes {
			return nil, ErrWAFRuleInvalid
		}
		entries = append(entries, wafRuleUploadFile{path: name, body: body})
	}
	if len(entries) == 0 || len(entries) > edgeartifactbundle.MaxFiles+8 {
		return nil, ErrWAFRuleInvalid
	}
	return entries, nil
}

func readWAFRuleUploadZipEntry(r io.Reader, max int64) ([]byte, error) {
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(r, max+1)); err != nil {
		return nil, ErrWAFRuleInvalid
	}
	if int64(buf.Len()) > max {
		return nil, ErrWAFRuleInvalid
	}
	return buf.Bytes(), nil
}

func stripWAFRuleUploadCommonRoots(entries []wafRuleUploadFile) ([]wafRuleUploadFile, []string) {
	stripped := []string{}
	for i := 0; i < 8; i++ {
		next, root, ok := stripWAFRuleUploadCommonRootOnce(entries)
		if !ok {
			break
		}
		entries = next
		stripped = append(stripped, root)
	}
	return entries, stripped
}

func stripWAFRuleUploadCommonRootOnce(entries []wafRuleUploadFile) ([]wafRuleUploadFile, string, bool) {
	if len(entries) == 0 {
		return entries, "", false
	}
	root := ""
	for _, entry := range entries {
		cleaned := cleanWAFRuleOperatorArchivePath(entry.path)
		if cleaned == "" {
			return entries, "", false
		}
		parts := strings.SplitN(cleaned, "/", 2)
		if len(parts) < 2 {
			return entries, "", false
		}
		if root == "" {
			root = parts[0]
		} else if root != parts[0] {
			return entries, "", false
		}
	}
	if root == "" || isKnownWAFRuleUploadRoot(root) {
		return entries, "", false
	}
	out := make([]wafRuleUploadFile, 0, len(entries))
	prefix := root + "/"
	for _, entry := range entries {
		next := entry
		next.path = strings.TrimPrefix(cleanWAFRuleOperatorArchivePath(entry.path), prefix)
		out = append(out, next)
	}
	return out, root, true
}

func isKnownWAFRuleUploadRoot(root string) bool {
	switch strings.ToLower(strings.TrimSpace(root)) {
	case "_tukuyomi", "rules", "crs", "coraza", "data", "conf":
		return true
	default:
		return false
	}
}

func inferWAFRuleUploadKind(assetPath string) string {
	normalized := cleanWAFRuleOperatorArchivePath(assetPath)
	if normalized == "" {
		return "base"
	}
	if sameWAFRuleUploadPath(normalized, config.CRSSetupFile) || strings.EqualFold(path.Base(normalized), "crs-setup.conf") {
		return "crs_setup"
	}
	if hasWAFRuleUploadPathPrefix(normalized, configuredCenterWAFRuleCRSRoot()) ||
		hasWAFRuleUploadPathPrefix(normalized, config.CRSRulesDir) ||
		hasWAFRuleUploadPathPrefix(normalized, "rules/crs") ||
		hasWAFRuleUploadPathPrefix(normalized, "crs") ||
		hasWAFRuleUploadPathPrefix(normalized, "coraza") ||
		hasWAFRuleUploadPathPrefix(normalized, "data") {
		return "crs_asset"
	}
	name := strings.ToLower(path.Base(normalized))
	if !strings.HasSuffix(name, ".conf") || strings.HasSuffix(name, ".conf.example") {
		return "crs_asset"
	}
	return "base"
}

func configuredCenterWAFRuleCRSRoot() string {
	setup := cleanWAFRuleOperatorArchivePath(config.CRSSetupFile)
	if setup != "" {
		dir := path.Dir(setup)
		if dir != "." && dir != "" {
			return dir
		}
	}
	rulesDir := cleanWAFRuleOperatorArchivePath(config.CRSRulesDir)
	if rulesDir == "" {
		return ""
	}
	parent := path.Dir(rulesDir)
	if parent == "." || parent == "" {
		return rulesDir
	}
	return parent
}

func sameWAFRuleUploadPath(left, right string) bool {
	left = cleanWAFRuleOperatorArchivePath(left)
	right = cleanWAFRuleOperatorArchivePath(right)
	return left != "" && right != "" && left == right
}

func hasWAFRuleUploadPathPrefix(assetPath, prefix string) bool {
	assetPath = cleanWAFRuleOperatorArchivePath(assetPath)
	prefix = cleanWAFRuleOperatorArchivePath(prefix)
	if assetPath == "" || prefix == "" {
		return false
	}
	return assetPath == prefix || strings.HasPrefix(assetPath, prefix+"/")
}

func chooseWAFRuleOperatorManifestPath(used map[string]struct{}, revision string) string {
	revision = strings.ToLower(strings.TrimSpace(revision))
	if len(revision) > 12 {
		revision = revision[:12]
	}
	candidates := []string{"_tukuyomi/manifest.json"}
	if revision != "" {
		candidates = append(candidates, "_tukuyomi/manifest-"+revision+".json")
	}
	for i := 1; i <= edgeartifactbundle.MaxFiles+2; i++ {
		candidates = append(candidates, fmt.Sprintf("_tukuyomi/manifest-%04d.json", i))
	}
	for _, candidate := range candidates {
		if _, exists := used[candidate]; !exists {
			return candidate
		}
	}
	return ""
}

func cleanWAFRuleOperatorArchivePath(raw string) string {
	raw = strings.TrimSpace(strings.ReplaceAll(raw, "\\", "/"))
	if raw == "" || len(raw) > 512 || strings.HasPrefix(raw, "/") || strings.Contains(raw, "\x00") || strings.Contains(raw, ":") {
		return ""
	}
	for _, r := range raw {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	cleaned := path.Clean(raw)
	if cleaned == "." || strings.HasPrefix(cleaned, "../") || strings.Contains(cleaned, "/../") {
		return ""
	}
	return cleaned
}

func writeWAFRuleOperatorZipFile(zw *zip.Writer, name string, body []byte) error {
	hdr := &zip.FileHeader{
		Name:   name,
		Method: zip.Deflate,
	}
	hdr.SetMode(0o600)
	hdr.SetModTime(time.Date(1980, 1, 1, 0, 0, 0, 0, time.UTC))
	w, err := zw.CreateHeader(hdr)
	if err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return nil
}

func AssignWAFRuleBundleToDevice(ctx context.Context, in WAFRuleAssignmentUpdate) (WAFRuleAssignmentRecord, error) {
	in.DeviceID = strings.TrimSpace(in.DeviceID)
	in.BundleRevision = strings.ToLower(strings.TrimSpace(in.BundleRevision))
	in.Reason = clampString(in.Reason, 512)
	in.AssignedBy = clampString(in.AssignedBy, 128)
	if !deviceIDPattern.MatchString(in.DeviceID) || !hex64Pattern.MatchString(in.BundleRevision) {
		return WAFRuleAssignmentRecord{}, ErrWAFRuleInvalid
	}
	if in.AssignedAtUnix <= 0 {
		in.AssignedAtUnix = time.Now().UTC().Unix()
	}
	var out WAFRuleAssignmentRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		var device DeviceRecord
		if err := loadDeviceByIDTx(ctx, tx, driver, in.DeviceID, &device); err != nil {
			return err
		}
		if device.Status != DeviceStatusApproved {
			return ErrDeviceStatusNotFound
		}
		bundle, found, err := loadWAFRuleBundleTx(ctx, tx, driver, in.DeviceID, in.BundleRevision)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		if existing, found, err := loadWAFRuleAssignmentTx(ctx, tx, driver, in.DeviceID); err != nil {
			return err
		} else if found && wafRuleAssignmentDispatchActive(existing, in.AssignedAtUnix) {
			return ErrWAFRuleAssignmentDispatched
		}
		baseRevision := ""
		if current, found, err := latestWAFRuleSnapshotTx(ctx, tx, driver, in.DeviceID); err != nil {
			return err
		} else if found {
			baseRevision = current.BundleRevision
		}
		if err := upsertWAFRuleAssignmentTx(ctx, tx, driver, in, bundle, baseRevision); err != nil {
			return err
		}
		assignment, found, err := loadWAFRuleAssignmentTx(ctx, tx, driver, in.DeviceID)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		out = assignment
		return tx.Commit()
	})
	return out, err
}

func ClearWAFRuleAssignment(ctx context.Context, deviceID string) (bool, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return false, ErrDeviceStatusNotFound
	}
	var cleared bool
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		assignment, found, err := loadWAFRuleAssignmentTx(ctx, tx, driver, deviceID)
		if err != nil {
			return err
		}
		if !found {
			return tx.Commit()
		}
		if wafRuleAssignmentDispatchActive(assignment, time.Now().UTC().Unix()) {
			return ErrWAFRuleAssignmentDispatched
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM center_device_waf_rule_assignments WHERE device_id = `+placeholder(driver, 1), deviceID)
		if err != nil {
			return err
		}
		affected, err := result.RowsAffected()
		cleared = err == nil && affected > 0
		return tx.Commit()
	})
	return cleared, err
}

func PendingWAFRuleAssignmentForDevice(ctx context.Context, deviceID string, dispatchedAtUnix int64) (*WAFRuleDeviceAssignment, error) {
	deviceID = strings.TrimSpace(deviceID)
	if !deviceIDPattern.MatchString(deviceID) {
		return nil, ErrDeviceStatusNotFound
	}
	if dispatchedAtUnix <= 0 {
		dispatchedAtUnix = time.Now().UTC().Unix()
	}
	var out *WAFRuleDeviceAssignment
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		assignment, found, err := loadWAFRuleAssignmentTx(ctx, tx, driver, deviceID)
		if err != nil || !found {
			return err
		}
		if wafRuleAssignmentDispatchActive(assignment, dispatchedAtUnix) {
			return nil
		}
		if status, found, err := loadWAFRuleApplyStatusTx(ctx, tx, driver, deviceID); err != nil {
			return err
		} else if found && wafRuleApplyStatusMatchesTerminal(status, assignment) {
			if err := deleteWAFRuleAssignmentTx(ctx, tx, driver, deviceID); err != nil {
				return err
			}
			return tx.Commit()
		}
		files, err := listWAFRuleBundleFilesTx(ctx, tx, driver, deviceID, assignment.BundleRevision, true)
		if err != nil {
			return err
		}
		rebuilt, err := buildWAFRuleArtifactFromStoredFiles(assignment.BundleRevision, files)
		if err != nil {
			return err
		}
		if err := markWAFRuleAssignmentDispatchedTx(ctx, tx, driver, deviceID, dispatchedAtUnix); err != nil {
			return err
		}
		out = &WAFRuleDeviceAssignment{
			BundleRevision:     assignment.BundleRevision,
			BaseBundleRevision: assignment.BaseBundleRevision,
			CompressedSize:     rebuilt.CompressedSize,
			UncompressedSize:   rebuilt.UncompressedSize,
			FileCount:          rebuilt.FileCount,
			AssignedAtUnix:     assignment.AssignedAtUnix,
		}
		return tx.Commit()
	})
	return out, err
}

func WAFRuleArtifactDownloadForDevice(ctx context.Context, deviceID, bundleRevision string) (WAFRuleBundleRecord, []byte, error) {
	deviceID = strings.TrimSpace(deviceID)
	bundleRevision = strings.ToLower(strings.TrimSpace(bundleRevision))
	if !deviceIDPattern.MatchString(deviceID) || !hex64Pattern.MatchString(bundleRevision) {
		return WAFRuleBundleRecord{}, nil, ErrWAFRuleInvalid
	}
	var bundle WAFRuleBundleRecord
	var files []WAFRuleBundleFileRecord
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		assignment, found, err := loadWAFRuleAssignmentTx(ctx, db, driver, deviceID)
		if err != nil {
			return err
		}
		if !found || assignment.BundleRevision != bundleRevision {
			return ErrWAFRuleBundleNotFound
		}
		loaded, found, err := loadWAFRuleBundleTx(ctx, db, driver, deviceID, bundleRevision)
		if err != nil {
			return err
		}
		if !found {
			return ErrWAFRuleBundleNotFound
		}
		loadedFiles, err := listWAFRuleBundleFilesTx(ctx, db, driver, deviceID, bundleRevision, true)
		if err != nil {
			return err
		}
		bundle = loaded
		files = loadedFiles
		return nil
	})
	if err != nil {
		return WAFRuleBundleRecord{}, nil, err
	}
	rebuilt, err := buildWAFRuleArtifactFromStoredFiles(bundleRevision, files)
	if err != nil {
		return WAFRuleBundleRecord{}, nil, err
	}
	bundle.CompressedSize = rebuilt.CompressedSize
	bundle.UncompressedSize = rebuilt.UncompressedSize
	bundle.FileCount = rebuilt.FileCount
	return bundle, rebuilt.Compressed, nil
}

func buildWAFRuleArtifactFromStoredFiles(bundleRevision string, files []WAFRuleBundleFileRecord) (edgeartifactbundle.Build, error) {
	ruleFiles := make([]edgeartifactbundle.RuleFile, 0, len(files))
	for _, file := range files {
		ruleFiles = append(ruleFiles, edgeartifactbundle.RuleFile{
			Path:     file.Path,
			Kind:     file.Kind,
			ETag:     file.ETag,
			Disabled: file.Disabled,
			Body:     file.Body,
		})
	}
	rebuilt, err := edgeartifactbundle.BuildBundle(ruleFiles, wafRuleArtifactRebuildTime)
	if err != nil {
		return edgeartifactbundle.Build{}, err
	}
	if rebuilt.Revision != strings.ToLower(strings.TrimSpace(bundleRevision)) {
		return edgeartifactbundle.Build{}, ErrWAFRuleInvalid
	}
	return rebuilt, nil
}

func UpsertWAFRuleApplyStatus(ctx context.Context, status WAFRuleApplyStatusRecord) error {
	status.DeviceID = strings.TrimSpace(status.DeviceID)
	status.DesiredBundleRevision = strings.ToLower(strings.TrimSpace(status.DesiredBundleRevision))
	status.LocalBundleRevision = strings.ToLower(strings.TrimSpace(status.LocalBundleRevision))
	status.ApplyState = strings.TrimSpace(status.ApplyState)
	status.ApplyError = clampString(status.ApplyError, 512)
	if !deviceIDPattern.MatchString(status.DeviceID) {
		return ErrDeviceStatusNotFound
	}
	if status.DesiredBundleRevision != "" && !hex64Pattern.MatchString(status.DesiredBundleRevision) {
		return ErrWAFRuleInvalid
	}
	if status.LocalBundleRevision != "" && !hex64Pattern.MatchString(status.LocalBundleRevision) {
		return ErrWAFRuleInvalid
	}
	if !metadataPattern.MatchString(status.ApplyState) || len(status.ApplyState) > 32 {
		return ErrWAFRuleInvalid
	}
	if !metadataPattern.MatchString(status.ApplyError) {
		return ErrWAFRuleInvalid
	}
	if status.UpdatedAtUnix <= 0 {
		status.UpdatedAtUnix = time.Now().UTC().Unix()
	}
	if status.LastAttemptAtUnix <= 0 && status.ApplyState != "" {
		status.LastAttemptAtUnix = status.UpdatedAtUnix
	}
	return withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()
		if err := upsertWAFRuleApplyStatusTx(ctx, tx, driver, status); err != nil {
			return err
		}
		if err := deleteTerminalWAFRuleAssignmentForStatusTx(ctx, tx, driver, status); err != nil {
			return err
		}
		return tx.Commit()
	})
}

func latestWAFRuleSnapshotTx(ctx context.Context, q queryer, driver, deviceID string) (WAFRuleSnapshotRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT revision, payload_json, created_at_unix
  FROM center_device_config_snapshots
 WHERE device_id = `+placeholder(driver, 1)+`
 ORDER BY created_at_unix DESC, snapshot_id DESC
 LIMIT 1`, deviceID)
	var revision string
	var payloadRaw string
	var createdAtUnix int64
	if err := row.Scan(&revision, &payloadRaw, &createdAtUnix); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WAFRuleSnapshotRecord{}, false, nil
		}
		return WAFRuleSnapshotRecord{}, false, err
	}
	var payload edgeconfigsnapshot.Payload
	if err := json.Unmarshal([]byte(payloadRaw), &payload); err != nil {
		return WAFRuleSnapshotRecord{}, false, err
	}
	domain, ok := payload.Domains["waf_rule_assets"]
	if !ok {
		return WAFRuleSnapshotRecord{}, false, nil
	}
	rec := WAFRuleSnapshotRecord{
		DeviceID:              deviceID,
		ConfigRevision:        revision,
		DomainETag:            strings.TrimSpace(domain.ETag),
		Error:                 strings.TrimSpace(domain.Error),
		SnapshotCreatedAtUnix: createdAtUnix,
	}
	if len(domain.Raw) > 0 {
		var raw struct {
			BundleRevision string                `json:"bundle_revision"`
			Assets         []WAFRuleAssetSummary `json:"assets"`
		}
		if err := json.Unmarshal(domain.Raw, &raw); err != nil {
			return WAFRuleSnapshotRecord{}, false, err
		}
		rec.BundleRevision = strings.ToLower(strings.TrimSpace(raw.BundleRevision))
		rec.Assets = raw.Assets
	}
	return rec, true, nil
}

func loadWAFRuleBundleTx(ctx context.Context, q queryer, driver, deviceID, revision string) (WAFRuleBundleRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, bundle_revision, bundle_hash, compressed_size_bytes, uncompressed_size_bytes,
       file_count, created_at_unix, created_at, source
  FROM center_rule_artifact_bundles
 WHERE device_id = `+placeholder(driver, 1)+`
   AND bundle_revision = `+placeholder(driver, 2),
		deviceID,
		revision,
	)
	var rec WAFRuleBundleRecord
	if err := row.Scan(
		&rec.DeviceID,
		&rec.BundleRevision,
		&rec.BundleHash,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
		&rec.CreatedAtUnix,
		&rec.CreatedAt,
		&rec.Source,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WAFRuleBundleRecord{}, false, nil
		}
		return WAFRuleBundleRecord{}, false, err
	}
	return rec, true, nil
}

func hasAnyWAFRuleBundleTx(ctx context.Context, q queryer, driver, deviceID string) (bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT 1
  FROM center_rule_artifact_bundles
 WHERE device_id = `+placeholder(driver, 1)+`
 LIMIT 1`,
		deviceID,
	)
	var found int
	if err := row.Scan(&found); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func listWAFRuleBundlesForDeviceTx(ctx context.Context, q queryerWithRows, driver string, deviceID string, limit int) ([]WAFRuleBundleRecord, error) {
	if limit <= 0 || limit > 50 {
		limit = 20
	}
	query := `
SELECT b.device_id, b.bundle_revision, b.bundle_hash, b.compressed_size_bytes, b.uncompressed_size_bytes,
       b.file_count, b.created_at_unix, b.created_at, b.source,
       COALESCE(h.local_bundle_revision, ''), COALESCE(h.apply_state, ''), COALESCE(h.apply_error, ''),
       COALESCE(h.last_attempt_at_unix, 0), COALESCE(h.applied_at_unix, 0), COALESCE(h.updated_at_unix, 0)
  FROM center_rule_artifact_bundles b
  LEFT JOIN center_device_waf_rule_apply_history h
    ON h.device_id = b.device_id AND h.bundle_revision = b.bundle_revision
  LEFT JOIN center_device_waf_rule_assignments a
    ON a.device_id = b.device_id AND a.bundle_revision = b.bundle_revision
 WHERE b.device_id = ` + placeholder(driver, 1) + `
   AND (b.source = 'center' OR h.bundle_revision IS NOT NULL OR a.bundle_revision IS NOT NULL)
 ORDER BY b.created_at_unix DESC, b.bundle_id DESC`
	args := []any{deviceID}
	if driver == "pgsql" {
		query += " LIMIT " + placeholders(driver, 1, 2)
		args = append(args, limit)
	} else {
		query += " LIMIT " + placeholder(driver, 2)
		args = append(args, limit)
	}
	rows, err := q.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFRuleBundleRecord{}
	for rows.Next() {
		var rec WAFRuleBundleRecord
		if err := rows.Scan(
			&rec.DeviceID,
			&rec.BundleRevision,
			&rec.BundleHash,
			&rec.CompressedSize,
			&rec.UncompressedSize,
			&rec.FileCount,
			&rec.CreatedAtUnix,
			&rec.CreatedAt,
			&rec.Source,
			&rec.LocalBundleRevision,
			&rec.ApplyState,
			&rec.ApplyError,
			&rec.LastAttemptAtUnix,
			&rec.AppliedAtUnix,
			&rec.ApplyUpdatedAtUnix,
		); err != nil {
			return nil, err
		}
		out = append(out, rec)
	}
	return out, rows.Err()
}

func includeCurrentWAFRuleBundleTx(ctx context.Context, q queryerWithRows, driver, deviceID, revision string, bundles []WAFRuleBundleRecord) ([]WAFRuleBundleRecord, error) {
	revision = strings.ToLower(strings.TrimSpace(revision))
	if !hex64Pattern.MatchString(revision) {
		return bundles, nil
	}
	for _, bundle := range bundles {
		if bundle.BundleRevision == revision {
			return bundles, nil
		}
	}
	current, found, err := loadWAFRuleBundleTx(ctx, q, driver, deviceID, revision)
	if err != nil || !found {
		return bundles, err
	}
	return append([]WAFRuleBundleRecord{current}, bundles...), nil
}

func listWAFRuleBundleFilesTx(ctx context.Context, q queryerWithRows, driver, deviceID, revision string, includeBody bool) ([]WAFRuleBundleFileRecord, error) {
	bodySelect := "NULL"
	if includeBody {
		bodySelect = "body"
	}
	rows, err := q.QueryContext(ctx, `
SELECT device_id, bundle_revision, asset_path, archive_path, asset_kind, etag,
       CASE WHEN disabled THEN 1 ELSE 0 END, sha256, size_bytes, `+bodySelect+`
  FROM center_rule_artifact_files
 WHERE device_id = `+placeholder(driver, 1)+`
   AND bundle_revision = `+placeholder(driver, 2)+`
 ORDER BY asset_path`,
		deviceID,
		revision,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []WAFRuleBundleFileRecord{}
	for rows.Next() {
		var rec WAFRuleBundleFileRecord
		var disabled int
		var body []byte
		if err := rows.Scan(
			&rec.DeviceID,
			&rec.BundleRevision,
			&rec.Path,
			&rec.ArchivePath,
			&rec.Kind,
			&rec.ETag,
			&disabled,
			&rec.SHA256,
			&rec.SizeBytes,
			&body,
		); err != nil {
			return nil, err
		}
		rec.Disabled = disabled != 0
		rec.Body = append([]byte(nil), body...)
		out = append(out, rec)
	}
	return out, rows.Err()
}

func loadWAFRuleBundleFileTx(ctx context.Context, q queryer, driver, deviceID, revision, assetPath string) (WAFRuleBundleFileRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, bundle_revision, asset_path, archive_path, asset_kind, etag,
       CASE WHEN disabled THEN 1 ELSE 0 END, sha256, size_bytes, body
  FROM center_rule_artifact_files
 WHERE device_id = `+placeholder(driver, 1)+`
   AND bundle_revision = `+placeholder(driver, 2)+`
   AND asset_path = `+placeholder(driver, 3),
		deviceID,
		revision,
		assetPath,
	)
	var rec WAFRuleBundleFileRecord
	var disabled int
	if err := row.Scan(
		&rec.DeviceID,
		&rec.BundleRevision,
		&rec.Path,
		&rec.ArchivePath,
		&rec.Kind,
		&rec.ETag,
		&disabled,
		&rec.SHA256,
		&rec.SizeBytes,
		&rec.Body,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WAFRuleBundleFileRecord{}, false, nil
		}
		return WAFRuleBundleFileRecord{}, false, err
	}
	rec.Disabled = disabled != 0
	return rec, true, nil
}

func upsertWAFRuleAssignmentTx(ctx context.Context, tx *sql.Tx, driver string, in WAFRuleAssignmentUpdate, bundle WAFRuleBundleRecord, baseRevision string) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_waf_rule_assignments
    (device_id, bundle_revision, base_bundle_revision, reason, assigned_by, assigned_at_unix, updated_at_unix, dispatched_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON CONFLICT (device_id) DO UPDATE SET
    bundle_revision = excluded.bundle_revision,
    base_bundle_revision = excluded.base_bundle_revision,
    reason = excluded.reason,
    assigned_by = excluded.assigned_by,
    assigned_at_unix = excluded.assigned_at_unix,
    updated_at_unix = excluded.updated_at_unix,
    dispatched_at_unix = 0`,
		in.DeviceID,
		bundle.BundleRevision,
		strings.ToLower(strings.TrimSpace(baseRevision)),
		in.Reason,
		in.AssignedBy,
		in.AssignedAtUnix,
		in.AssignedAtUnix,
		0,
	)
	return err
}

func loadWAFRuleAssignmentTx(ctx context.Context, q queryer, driver string, deviceID string) (WAFRuleAssignmentRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT a.assignment_id, a.device_id, a.bundle_revision, a.base_bundle_revision, a.reason, a.assigned_by,
       a.assigned_at_unix, a.updated_at_unix, a.dispatched_at_unix,
       b.bundle_hash, b.compressed_size_bytes, b.uncompressed_size_bytes, b.file_count
  FROM center_device_waf_rule_assignments a
  JOIN center_rule_artifact_bundles b ON b.device_id = a.device_id AND b.bundle_revision = a.bundle_revision
 WHERE a.device_id = `+placeholder(driver, 1), deviceID)
	var rec WAFRuleAssignmentRecord
	if err := row.Scan(
		&rec.AssignmentID,
		&rec.DeviceID,
		&rec.BundleRevision,
		&rec.BaseBundleRevision,
		&rec.Reason,
		&rec.AssignedBy,
		&rec.AssignedAtUnix,
		&rec.UpdatedAtUnix,
		&rec.DispatchedAtUnix,
		&rec.BundleHash,
		&rec.CompressedSize,
		&rec.UncompressedSize,
		&rec.FileCount,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WAFRuleAssignmentRecord{}, false, nil
		}
		return WAFRuleAssignmentRecord{}, false, err
	}
	return rec, true, nil
}

func markWAFRuleAssignmentDispatchedTx(ctx context.Context, tx *sql.Tx, driver string, deviceID string, dispatchedAtUnix int64) error {
	_, err := tx.ExecContext(ctx, `
UPDATE center_device_waf_rule_assignments
   SET dispatched_at_unix = `+placeholder(driver, 1)+`
 WHERE device_id = `+placeholder(driver, 2),
		dispatchedAtUnix,
		deviceID,
	)
	return err
}

func deleteWAFRuleAssignmentTx(ctx context.Context, q interface {
	ExecContext(context.Context, string, ...any) (sql.Result, error)
}, driver string, deviceID string) error {
	_, err := q.ExecContext(ctx, `DELETE FROM center_device_waf_rule_assignments WHERE device_id = `+placeholder(driver, 1), deviceID)
	return err
}

func wafRuleAssignmentDispatchActive(assignment WAFRuleAssignmentRecord, nowUnix int64) bool {
	if assignment.DispatchedAtUnix <= 0 {
		return false
	}
	if nowUnix <= assignment.DispatchedAtUnix {
		return true
	}
	return nowUnix-assignment.DispatchedAtUnix < WAFRuleAssignmentDispatchLeaseSec
}

func upsertWAFRuleApplyStatusTx(ctx context.Context, tx *sql.Tx, driver string, status WAFRuleApplyStatusRecord) error {
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_waf_rule_apply_status
    (device_id, desired_bundle_revision, local_bundle_revision, apply_state, apply_error, last_attempt_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 7, 1)+`)
ON CONFLICT (device_id) DO UPDATE SET
    desired_bundle_revision = excluded.desired_bundle_revision,
    local_bundle_revision = excluded.local_bundle_revision,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    updated_at_unix = excluded.updated_at_unix`,
		status.DeviceID,
		status.DesiredBundleRevision,
		status.LocalBundleRevision,
		status.ApplyState,
		status.ApplyError,
		status.LastAttemptAtUnix,
		status.UpdatedAtUnix,
	)
	if err != nil {
		return err
	}
	return upsertWAFRuleApplyHistoryTx(ctx, tx, driver, status)
}

func upsertWAFRuleApplyHistoryTx(ctx context.Context, tx *sql.Tx, driver string, status WAFRuleApplyStatusRecord) error {
	if status.DesiredBundleRevision == "" {
		return nil
	}
	attemptedAt := status.LastAttemptAtUnix
	if attemptedAt <= 0 {
		attemptedAt = status.UpdatedAtUnix
	}
	appliedAt := int64(0)
	if strings.TrimSpace(status.ApplyState) == "applied" {
		appliedAt = attemptedAt
	}
	_, err := tx.ExecContext(ctx, `
INSERT INTO center_device_waf_rule_apply_history
    (device_id, bundle_revision, local_bundle_revision, apply_state, apply_error,
     last_attempt_at_unix, applied_at_unix, updated_at_unix)
VALUES
    (`+placeholders(driver, 8, 1)+`)
ON CONFLICT (device_id, bundle_revision) DO UPDATE SET
    local_bundle_revision = excluded.local_bundle_revision,
    apply_state = excluded.apply_state,
    apply_error = excluded.apply_error,
    last_attempt_at_unix = excluded.last_attempt_at_unix,
    applied_at_unix = CASE
        WHEN excluded.apply_state = 'applied' THEN excluded.applied_at_unix
        ELSE center_device_waf_rule_apply_history.applied_at_unix
    END,
    updated_at_unix = excluded.updated_at_unix`,
		status.DeviceID,
		status.DesiredBundleRevision,
		status.LocalBundleRevision,
		status.ApplyState,
		status.ApplyError,
		attemptedAt,
		appliedAt,
		status.UpdatedAtUnix,
	)
	return err
}

func loadWAFRuleApplyStatusTx(ctx context.Context, q queryer, driver string, deviceID string) (WAFRuleApplyStatusRecord, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT device_id, desired_bundle_revision, local_bundle_revision, apply_state, apply_error, last_attempt_at_unix, updated_at_unix
  FROM center_device_waf_rule_apply_status
 WHERE device_id = `+placeholder(driver, 1), deviceID)
	var rec WAFRuleApplyStatusRecord
	if err := row.Scan(
		&rec.DeviceID,
		&rec.DesiredBundleRevision,
		&rec.LocalBundleRevision,
		&rec.ApplyState,
		&rec.ApplyError,
		&rec.LastAttemptAtUnix,
		&rec.UpdatedAtUnix,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return WAFRuleApplyStatusRecord{}, false, nil
		}
		return WAFRuleApplyStatusRecord{}, false, err
	}
	return rec, true, nil
}

func deleteTerminalWAFRuleAssignmentForStatusTx(ctx context.Context, tx *sql.Tx, driver string, status WAFRuleApplyStatusRecord) error {
	assignment, found, err := loadWAFRuleAssignmentTx(ctx, tx, driver, status.DeviceID)
	if err != nil || !found {
		return err
	}
	if !wafRuleApplyStatusMatchesTerminal(status, assignment) {
		return nil
	}
	return deleteWAFRuleAssignmentTx(ctx, tx, driver, status.DeviceID)
}

func wafRuleApplyStatusMatchesTerminal(status WAFRuleApplyStatusRecord, assignment WAFRuleAssignmentRecord) bool {
	if status.DesiredBundleRevision != assignment.BundleRevision {
		return false
	}
	switch strings.TrimSpace(status.ApplyState) {
	case "applied":
		return status.LocalBundleRevision == assignment.BundleRevision
	case "failed", "blocked":
		return assignment.DispatchedAtUnix > 0
	default:
		return false
	}
}
