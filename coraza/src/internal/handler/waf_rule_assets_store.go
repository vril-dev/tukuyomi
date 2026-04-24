package handler

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

const (
	wafRuleAssetsConfigDomain  = "waf_rule_assets"
	wafRuleAssetsSchemaVersion = 1
	wafRuleAssetKindBase       = "base"
	wafRuleAssetKindCRSSetup   = "crs_setup"
	wafRuleAssetKindCRSAsset   = "crs_asset"
)

type wafRuleAssetVersion struct {
	Path string
	Kind string
	Raw  []byte
	ETag string
}

func init() {
	waf.SetRuleAssetProvider(loadWAFRuleAssetsForWAF)
}

func (s *wafEventStore) loadActiveWAFRuleAssets() ([]wafRuleAssetVersion, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(wafRuleAssetsConfigDomain)
	if err != nil || !found {
		return nil, configVersionRecord{}, false, err
	}
	assets, err := s.loadWAFRuleAssetsVersion(rec.VersionID)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	return assets, rec, true, nil
}

func (s *wafEventStore) writeWAFRuleAssetsVersion(expectedETag string, assets []wafRuleAssetVersion, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, []wafRuleAssetVersion, error) {
	assets = normalizeWAFRuleAssets(assets)
	rec, err := s.writeConfigVersion(
		wafRuleAssetsConfigDomain,
		wafRuleAssetsSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		wafRuleAssetsHash(assets),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			for i, asset := range assets {
				contentHash := configContentHash(string(asset.Raw))
				if _, err := s.txExec(tx, `INSERT INTO waf_rule_assets (version_id, position, asset_path, asset_kind, content_hash, size_bytes) VALUES (?, ?, ?, ?, ?, ?)`, versionID, i, asset.Path, asset.Kind, contentHash, len(asset.Raw)); err != nil {
					return err
				}
				if _, err := s.txExec(tx, `INSERT INTO waf_rule_asset_contents (version_id, asset_path, raw_text, etag) VALUES (?, ?, ?, ?)`, versionID, asset.Path, string(asset.Raw), asset.ETag); err != nil {
					return err
				}
			}
			return nil
		},
	)
	if err != nil {
		return configVersionRecord{}, nil, err
	}
	return rec, assets, nil
}

func (s *wafEventStore) loadWAFRuleAssetsVersion(versionID int64) ([]wafRuleAssetVersion, error) {
	rows, err := s.query(
		`SELECT a.asset_path, a.asset_kind, c.raw_text, c.etag
		   FROM waf_rule_assets a
		   JOIN waf_rule_asset_contents c ON c.version_id = a.version_id AND c.asset_path = a.asset_path
		  WHERE a.version_id = ?
		  ORDER BY a.position`,
		versionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var assets []wafRuleAssetVersion
	for rows.Next() {
		var asset wafRuleAssetVersion
		var raw string
		if err := rows.Scan(&asset.Path, &asset.Kind, &raw, &asset.ETag); err != nil {
			return nil, err
		}
		asset.Raw = []byte(raw)
		assets = append(assets, asset)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return normalizeWAFRuleAssets(assets), nil
}

func loadRuntimeWAFRuleAssets(store *wafEventStore) ([]wafRuleAssetVersion, configVersionRecord, bool, error) {
	assets, rec, found, err := store.loadActiveWAFRuleAssets()
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	if found {
		_ = deleteLegacyRuleFileBlobs(store)
		return assets, rec, true, nil
	}

	legacy, err := legacyRuleFileAssets(store)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	if len(legacy) == 0 {
		return nil, configVersionRecord{}, false, nil
	}
	rec, assets, err = store.writeWAFRuleAssetsVersion("", legacy, configVersionSourceImport, "", "legacy waf rule assets import", 0)
	if err != nil {
		return nil, configVersionRecord{}, false, err
	}
	_ = deleteLegacyRuleFileBlobs(store)
	return assets, rec, true, nil
}

func ImportWAFRuleAssetsStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	assets, err := collectWAFRuleAssetsFromFS()
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		return nil
	}
	if _, _, err := store.writeWAFRuleAssetsVersion("", assets, configVersionSourceImport, "", "waf rule assets seed import", 0); err != nil {
		return fmt.Errorf("import waf rule assets: %w", err)
	}
	_ = deleteLegacyRuleFileBlobs(store)
	return nil
}

func SyncRuleFilesStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	_, _, _, err := loadRuntimeWAFRuleAssets(store)
	return err
}

func loadWAFRuleAssetsForWAF() (waf.RuleAssetBundle, bool, error) {
	store := getLogsStatsStore()
	if store == nil {
		return waf.RuleAssetBundle{}, false, errConfigDBStoreRequired
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil || !found {
		return waf.RuleAssetBundle{}, found, err
	}
	out := waf.RuleAssetBundle{
		ETag:   rec.ETag,
		Assets: make([]waf.RuleAsset, 0, len(assets)),
	}
	for _, asset := range assets {
		out.Assets = append(out.Assets, waf.RuleAsset{
			Path: asset.Path,
			Raw:  append([]byte(nil), asset.Raw...),
		})
	}
	return out, true, nil
}

func collectWAFRuleAssetsFromFS() ([]wafRuleAssetVersion, error) {
	var assets []wafRuleAssetVersion
	for _, path := range configuredRuleFiles() {
		if strings.TrimSpace(path) == "" {
			continue
		}
		asset, ok, err := readWAFRuleAssetFile(path, wafRuleAssetKindBase)
		if err != nil {
			return nil, err
		}
		if ok {
			assets = append(assets, asset)
		}
	}

	crsRoot := configuredCRSRoot()
	if crsRoot != "" {
		crsRootFS := wafRuleAssetSourcePath(crsRoot)
		if err := filepath.WalkDir(crsRootFS, func(path string, entry os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				return nil
			}
			logicalPath := path
			if rel, relErr := filepath.Rel(crsRootFS, path); relErr == nil {
				logicalPath = filepath.Join(crsRoot, rel)
			}
			asset, ok, err := readWAFRuleAssetFile(logicalPath, wafRuleAssetKindCRSAsset)
			if err != nil || !ok {
				return err
			}
			if normalizeWAFRuleAssetPath(logicalPath) == normalizeWAFRuleAssetPath(config.CRSSetupFile) {
				asset.Kind = wafRuleAssetKindCRSSetup
			}
			assets = append(assets, asset)
			return nil
		}); err != nil {
			if config.CRSEnable {
				return nil, fmt.Errorf("read CRS asset tree %s: %w", crsRootFS, err)
			}
		}
	}

	if strings.TrimSpace(config.CRSSetupFile) != "" {
		setup, ok, err := readWAFRuleAssetFile(config.CRSSetupFile, wafRuleAssetKindCRSSetup)
		if err != nil {
			if config.CRSEnable {
				return nil, err
			}
		} else if ok {
			assets = append(assets, setup)
		}
	}

	return normalizeWAFRuleAssets(assets), nil
}

func readWAFRuleAssetFile(path string, kind string) (wafRuleAssetVersion, bool, error) {
	normalized, err := normalizeWAFRuleAssetPathStrict(path)
	if err != nil {
		return wafRuleAssetVersion{}, false, err
	}
	sourcePath := wafRuleAssetSourcePath(normalized)
	raw, hadFile, err := readFileMaybe(sourcePath)
	if err != nil {
		return wafRuleAssetVersion{}, false, fmt.Errorf("read waf rule asset %s: %w", sourcePath, err)
	}
	if !hadFile {
		if kind == wafRuleAssetKindBase || (kind == wafRuleAssetKindCRSSetup && config.CRSEnable) {
			return wafRuleAssetVersion{}, false, fmt.Errorf("waf rule asset not found: %s", sourcePath)
		}
		return wafRuleAssetVersion{}, false, nil
	}
	return wafRuleAssetVersion{
		Path: normalized,
		Kind: normalizeWAFRuleAssetKind(kind),
		Raw:  raw,
		ETag: bypassconf.ComputeETag(raw),
	}, true, nil
}

func wafRuleAssetSourcePath(logicalPath string) string {
	root := strings.TrimSpace(os.Getenv("WAF_RULE_ASSET_FS_ROOT"))
	if root == "" || filepath.IsAbs(logicalPath) {
		return logicalPath
	}
	return filepath.Join(root, filepath.FromSlash(normalizeWAFRuleAssetPath(logicalPath)))
}

func configuredCRSRoot() string {
	setup := strings.TrimSpace(config.CRSSetupFile)
	if setup != "" {
		dir := filepath.Dir(setup)
		if dir != "." && dir != "" {
			return filepath.Clean(dir)
		}
	}
	rulesDir := strings.TrimSpace(config.CRSRulesDir)
	if rulesDir == "" {
		return ""
	}
	parent := filepath.Dir(filepath.Clean(rulesDir))
	if parent == "." {
		return filepath.Clean(rulesDir)
	}
	return parent
}

func normalizeWAFRuleAssets(assets []wafRuleAssetVersion) []wafRuleAssetVersion {
	byPath := make(map[string]wafRuleAssetVersion, len(assets))
	for _, asset := range assets {
		path, err := normalizeWAFRuleAssetPathStrict(asset.Path)
		if err != nil {
			continue
		}
		asset.Path = path
		asset.Kind = normalizeWAFRuleAssetKind(asset.Kind)
		if strings.TrimSpace(asset.ETag) == "" {
			asset.ETag = bypassconf.ComputeETag(asset.Raw)
		}
		byPath[path] = asset
	}
	out := make([]wafRuleAssetVersion, 0, len(byPath))
	for _, asset := range byPath {
		out = append(out, asset)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return wafRuleAssetKindOrder(out[i].Kind) < wafRuleAssetKindOrder(out[j].Kind)
		}
		return out[i].Path < out[j].Path
	})
	return out
}

func wafRuleAssetMap(assets []wafRuleAssetVersion) map[string]wafRuleAssetVersion {
	out := make(map[string]wafRuleAssetVersion, len(assets))
	for _, asset := range normalizeWAFRuleAssets(assets) {
		out[asset.Path] = asset
	}
	return out
}

func wafRuleAssetsHash(assets []wafRuleAssetVersion) string {
	assets = normalizeWAFRuleAssets(assets)
	var b strings.Builder
	for _, asset := range assets {
		b.WriteString(asset.Kind)
		b.WriteByte('\t')
		b.WriteString(asset.Path)
		b.WriteByte('\t')
		b.WriteString(configContentHash(string(asset.Raw)))
		b.WriteByte('\n')
	}
	return configContentHash(b.String())
}

func normalizeWAFRuleAssetPathStrict(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", fmt.Errorf("waf rule asset path is empty")
	}
	if strings.ContainsRune(raw, '\x00') {
		return "", fmt.Errorf("waf rule asset path contains NUL")
	}
	clean := filepath.ToSlash(filepath.Clean(raw))
	if clean == "." || clean == "" {
		return "", fmt.Errorf("waf rule asset path is empty")
	}
	if len(clean) > 512 {
		return "", fmt.Errorf("waf rule asset path is too long")
	}
	return clean, nil
}

func normalizeWAFRuleAssetPath(raw string) string {
	out, err := normalizeWAFRuleAssetPathStrict(raw)
	if err != nil {
		return ""
	}
	return out
}

func normalizeWAFRuleAssetKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case wafRuleAssetKindBase:
		return wafRuleAssetKindBase
	case wafRuleAssetKindCRSSetup:
		return wafRuleAssetKindCRSSetup
	default:
		return wafRuleAssetKindCRSAsset
	}
}

func wafRuleAssetKindOrder(kind string) int {
	switch kind {
	case wafRuleAssetKindBase:
		return 0
	case wafRuleAssetKindCRSSetup:
		return 1
	default:
		return 2
	}
}

func legacyRuleFileAssets(store *wafEventStore) ([]wafRuleAssetVersion, error) {
	if store == nil {
		return nil, nil
	}
	var assets []wafRuleAssetVersion
	for _, path := range configuredRuleFiles() {
		normalized := normalizeWAFRuleAssetPath(path)
		if normalized == "" {
			continue
		}
		raw, etag, found, err := store.GetConfigBlob(ruleFileConfigBlobKey(path))
		if err != nil {
			return nil, err
		}
		if !found {
			continue
		}
		if strings.TrimSpace(etag) == "" {
			etag = bypassconf.ComputeETag(raw)
		}
		assets = append(assets, wafRuleAssetVersion{
			Path: normalized,
			Kind: wafRuleAssetKindBase,
			Raw:  raw,
			ETag: etag,
		})
	}
	return assets, nil
}

func deleteLegacyRuleFileBlobs(store *wafEventStore) error {
	if store == nil {
		return nil
	}
	for _, path := range configuredRuleFiles() {
		if err := store.DeleteConfigBlob(ruleFileConfigBlobKey(path)); err != nil {
			return err
		}
	}
	return nil
}

func writeWAFRuleAssetUpdate(target string, raw []byte, expectedDomainETag string, reason string) (configVersionRecord, wafRuleAssetVersion, error) {
	store := getLogsStatsStore()
	if store == nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, fmt.Errorf("db store is not initialized")
	}
	targetPath, err := normalizeWAFRuleAssetPathStrict(target)
	if err != nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, err
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, err
	}
	if !found {
		return configVersionRecord{}, wafRuleAssetVersion{}, fmt.Errorf("active waf rule assets missing in db; run make crs-install before editing rule assets")
	}
	if found && strings.TrimSpace(expectedDomainETag) == "" {
		expectedDomainETag = rec.ETag
	}
	byPath := wafRuleAssetMap(assets)
	current, ok := byPath[targetPath]
	if !ok {
		current = wafRuleAssetVersion{Path: targetPath, Kind: wafRuleAssetKindBase}
	}
	current.Raw = append([]byte(nil), raw...)
	current.ETag = bypassconf.ComputeETag(raw)
	byPath[targetPath] = current

	next := make([]wafRuleAssetVersion, 0, len(byPath))
	for _, asset := range byPath {
		next = append(next, asset)
	}
	nextRec, nextAssets, err := store.writeWAFRuleAssetsVersion(expectedDomainETag, next, configVersionSourceApply, "", reason, 0)
	if err != nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, err
	}
	return nextRec, wafRuleAssetMap(nextAssets)[targetPath], nil
}

func loadEditableWAFRuleAsset(target string) ([]byte, string, string, bool, error) {
	targetPath, err := normalizeWAFRuleAssetPathStrict(target)
	if err != nil {
		return nil, "", "", false, err
	}
	store := getLogsStatsStore()
	if store == nil {
		return nil, "", "", false, errConfigDBStoreRequired
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return nil, "", "", false, err
	}
	if found {
		if asset, ok := wafRuleAssetMap(assets)[targetPath]; ok {
			etag := strings.TrimSpace(asset.ETag)
			if etag == "" {
				etag = bypassconf.ComputeETag(asset.Raw)
			}
			return append([]byte(nil), asset.Raw...), etag, rec.ETag, true, nil
		}
	}
	return nil, "", "", false, fmt.Errorf("waf rule asset not found in active DB generation: %s", targetPath)
}

func wafRuleAssetSavedAt(rec configVersionRecord, path string) string {
	if rec.VersionID > 0 {
		return configVersionSavedAt(rec)
	}
	return fileSavedAt(path)
}

func wafRuleAssetsStatus() (int, string) {
	store := getLogsStatsStore()
	if store == nil {
		return 0, ""
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil || !found {
		return 0, ""
	}
	return len(assets), rec.ETag
}
