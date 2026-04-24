package handler

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

const (
	wafRuleAssetsConfigDomain   = "waf_rule_assets"
	wafRuleAssetsSchemaVersion  = 1
	wafRuleAssetKindBase        = "base"
	wafRuleAssetKindCRSSetup    = "crs_setup"
	wafRuleAssetKindCRSAsset    = "crs_asset"
	wafRuleAssetKindBypassExtra = "bypass_extra_rule"
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
	return store.loadActiveWAFRuleAssets()
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
			Kind: asset.Kind,
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
	kind = normalizeWAFRuleAssetKind(kind)
	normalized, err := normalizeWAFRuleAssetPathForKind(path, kind)
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
		Kind: kind,
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
	out := make([]wafRuleAssetVersion, 0, len(assets))
	byPath := make(map[string]int, len(assets))
	for _, asset := range assets {
		asset.Kind = normalizeWAFRuleAssetKind(asset.Kind)
		path, err := normalizeWAFRuleAssetPathForKind(asset.Path, asset.Kind)
		if err != nil {
			continue
		}
		asset.Path = path
		if strings.TrimSpace(asset.ETag) == "" {
			asset.ETag = bypassconf.ComputeETag(asset.Raw)
		}
		if idx, ok := byPath[path]; ok {
			out[idx] = asset
			continue
		}
		byPath[path] = len(out)
		out = append(out, asset)
	}
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

func normalizeWAFRuleAssetPathForKind(raw string, kind string) (string, error) {
	kind = normalizeWAFRuleAssetKind(kind)
	switch kind {
	case wafRuleAssetKindBase:
		path, err := normalizeWAFRuleAssetPathStrict(raw)
		if err != nil {
			return "", err
		}
		return config.NormalizeBaseRuleAssetPath(path), nil
	case wafRuleAssetKindBypassExtra:
		name, ok, err := managedOverrideRuleRefName(raw)
		if err != nil {
			return "", err
		}
		if !ok {
			_, target, targetErr := managedOverrideRuleTarget(raw)
			if targetErr != nil {
				return "", targetErr
			}
			return filepath.ToSlash(target), nil
		}
		return filepath.ToSlash(managedOverrideRulePath(name)), nil
	default:
		return normalizeWAFRuleAssetPathStrict(raw)
	}
}

func normalizeWAFRuleAssetKind(kind string) string {
	switch strings.TrimSpace(kind) {
	case "":
		return wafRuleAssetKindBase
	case wafRuleAssetKindBase:
		return wafRuleAssetKindBase
	case wafRuleAssetKindCRSSetup:
		return wafRuleAssetKindCRSSetup
	case wafRuleAssetKindBypassExtra:
		return wafRuleAssetKindBypassExtra
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

func normalizeEditableWAFRuleAssetKind(kind string) (string, error) {
	switch strings.TrimSpace(kind) {
	case "", wafRuleAssetKindBase:
		return wafRuleAssetKindBase, nil
	case wafRuleAssetKindBypassExtra:
		return wafRuleAssetKindBypassExtra, nil
	default:
		return "", fmt.Errorf("unsupported editable rule asset kind: %s", kind)
	}
}

func editableWAFRuleAssets(assets []wafRuleAssetVersion) []wafRuleAssetVersion {
	assets = normalizeWAFRuleAssets(assets)
	out := make([]wafRuleAssetVersion, 0, len(assets))
	for _, asset := range assets {
		if asset.Kind != wafRuleAssetKindBase && asset.Kind != wafRuleAssetKindBypassExtra {
			continue
		}
		out = append(out, asset)
	}
	return out
}

func wafRuleAssetByPath(assets []wafRuleAssetVersion, path string) (wafRuleAssetVersion, bool) {
	for _, asset := range normalizeWAFRuleAssets(assets) {
		if asset.Path == path {
			return asset, true
		}
	}
	return wafRuleAssetVersion{}, false
}

func writeWAFRuleAssetUpdateForKind(target string, kind string, raw []byte, expectedDomainETag string, reason string) (configVersionRecord, wafRuleAssetVersion, error) {
	store := getLogsStatsStore()
	if store == nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, errConfigDBStoreRequired
	}
	targetKind, err := normalizeEditableWAFRuleAssetKind(kind)
	if err != nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, err
	}
	targetPath, err := normalizeWAFRuleAssetPathForKind(target, targetKind)
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
	next := normalizeWAFRuleAssets(assets)
	current := wafRuleAssetVersion{
		Path: targetPath,
		Kind: targetKind,
		Raw:  append([]byte(nil), raw...),
		ETag: bypassconf.ComputeETag(raw),
	}
	replaced := false
	for i := range next {
		if next[i].Path != targetPath {
			continue
		}
		current.Kind = targetKind
		next[i] = current
		replaced = true
		break
	}
	if !replaced {
		next = append(next, current)
	}
	nextRec, nextAssets, err := store.writeWAFRuleAssetsVersion(expectedDomainETag, next, configVersionSourceApply, "", reason, 0)
	if err != nil {
		return configVersionRecord{}, wafRuleAssetVersion{}, err
	}
	asset, _ := wafRuleAssetByPath(nextAssets, targetPath)
	return nextRec, asset, nil
}

func writeWAFRuleAssetUpdate(target string, raw []byte, expectedDomainETag string, reason string) (configVersionRecord, wafRuleAssetVersion, error) {
	return writeWAFRuleAssetUpdateForKind(target, wafRuleAssetKindBase, raw, expectedDomainETag, reason)
}

func deleteWAFRuleAssetForKind(target string, kind string, expectedDomainETag string, reason string) (configVersionRecord, error) {
	store := getLogsStatsStore()
	if store == nil {
		return configVersionRecord{}, errConfigDBStoreRequired
	}
	targetKind, err := normalizeEditableWAFRuleAssetKind(kind)
	if err != nil {
		return configVersionRecord{}, err
	}
	targetPath, err := normalizeWAFRuleAssetPathForKind(target, targetKind)
	if err != nil {
		return configVersionRecord{}, err
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return configVersionRecord{}, err
	}
	if !found {
		return configVersionRecord{}, fmt.Errorf("active waf rule assets missing in db; run make crs-install before editing rule assets")
	}
	if strings.TrimSpace(expectedDomainETag) == "" {
		expectedDomainETag = rec.ETag
	}
	next := normalizeWAFRuleAssets(assets)
	filtered := next[:0]
	deleted := false
	baseCount := 0
	for _, asset := range next {
		if asset.Kind == wafRuleAssetKindBase && asset.Path != targetPath {
			baseCount++
		}
		if asset.Path == targetPath {
			deleted = true
			continue
		}
		filtered = append(filtered, asset)
	}
	if !deleted {
		return configVersionRecord{}, fmt.Errorf("waf rule asset not found in active DB generation: %s", targetPath)
	}
	if targetKind == wafRuleAssetKindBase && baseCount == 0 {
		return configVersionRecord{}, fmt.Errorf("at least one base rule asset is required")
	}
	rec, _, err = store.writeWAFRuleAssetsVersion(expectedDomainETag, filtered, configVersionSourceApply, "", reason, 0)
	if err != nil {
		return configVersionRecord{}, err
	}
	return rec, nil
}

func reorderEditableWAFRuleAssets(order []wafRuleAssetVersion, expectedDomainETag string, reason string) (configVersionRecord, []wafRuleAssetVersion, error) {
	store := getLogsStatsStore()
	if store == nil {
		return configVersionRecord{}, nil, errConfigDBStoreRequired
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return configVersionRecord{}, nil, err
	}
	if !found {
		return configVersionRecord{}, nil, fmt.Errorf("active waf rule assets missing in db; run make crs-install before editing rule assets")
	}
	normalized := normalizeWAFRuleAssets(assets)
	editable := editableWAFRuleAssets(normalized)
	if len(order) != len(editable) {
		return configVersionRecord{}, nil, fmt.Errorf("rule asset order must include every editable rule asset")
	}
	byPath := make(map[string]wafRuleAssetVersion, len(editable))
	for _, asset := range editable {
		byPath[asset.Path] = asset
	}
	seen := make(map[string]struct{}, len(order))
	orderedEditable := make([]wafRuleAssetVersion, 0, len(order))
	for _, item := range order {
		kind, err := normalizeEditableWAFRuleAssetKind(item.Kind)
		if err != nil {
			return configVersionRecord{}, nil, err
		}
		path, err := normalizeWAFRuleAssetPathForKind(item.Path, kind)
		if err != nil {
			return configVersionRecord{}, nil, err
		}
		asset, ok := byPath[path]
		if !ok || asset.Kind != kind {
			return configVersionRecord{}, nil, fmt.Errorf("rule asset is not editable or does not exist: %s", item.Path)
		}
		if _, ok := seen[path]; ok {
			return configVersionRecord{}, nil, fmt.Errorf("duplicate rule asset in order: %s", item.Path)
		}
		seen[path] = struct{}{}
		orderedEditable = append(orderedEditable, asset)
	}
	next := make([]wafRuleAssetVersion, 0, len(normalized))
	next = append(next, orderedEditable...)
	for _, asset := range normalized {
		if asset.Kind == wafRuleAssetKindBase || asset.Kind == wafRuleAssetKindBypassExtra {
			continue
		}
		next = append(next, asset)
	}
	if strings.TrimSpace(expectedDomainETag) == "" {
		expectedDomainETag = rec.ETag
	}
	nextRec, nextAssets, err := store.writeWAFRuleAssetsVersion(expectedDomainETag, next, configVersionSourceApply, "", reason, 0)
	if err != nil {
		return configVersionRecord{}, nil, err
	}
	return nextRec, editableWAFRuleAssets(nextAssets), nil
}

func loadEditableWAFRuleAssetForKind(target string, kind string) ([]byte, string, string, bool, error) {
	targetKind, err := normalizeEditableWAFRuleAssetKind(kind)
	if err != nil {
		return nil, "", "", false, err
	}
	targetPath, err := normalizeWAFRuleAssetPathForKind(target, targetKind)
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
		if asset, ok := wafRuleAssetByPath(assets, targetPath); ok && asset.Kind == targetKind {
			etag := strings.TrimSpace(asset.ETag)
			if etag == "" {
				etag = bypassconf.ComputeETag(asset.Raw)
			}
			return append([]byte(nil), asset.Raw...), etag, rec.ETag, true, nil
		}
	}
	return nil, "", "", false, fmt.Errorf("waf rule asset not found in active DB generation: %s", targetPath)
}

func loadEditableWAFRuleAsset(target string) ([]byte, string, string, bool, error) {
	return loadEditableWAFRuleAssetForKind(target, wafRuleAssetKindBase)
}

func wafRuleAssetExistsForKind(target string, kind string) (string, bool, error) {
	targetKind, err := normalizeEditableWAFRuleAssetKind(kind)
	if err != nil {
		return "", false, err
	}
	targetPath, err := normalizeWAFRuleAssetPathForKind(target, targetKind)
	if err != nil {
		return "", false, err
	}
	store := getLogsStatsStore()
	if store == nil {
		return targetPath, false, errConfigDBStoreRequired
	}
	assets, _, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return targetPath, false, err
	}
	if !found {
		return targetPath, false, fmt.Errorf("active waf rule assets missing in db; run make crs-install before editing rule assets")
	}
	asset, ok := wafRuleAssetByPath(assets, targetPath)
	return targetPath, ok && asset.Kind == targetKind, nil
}

func loadBypassExtraRuleAssetForWAF(rule string) (waf.OverrideRuleSource, bool, error) {
	name, ok, err := managedOverrideRuleRefName(rule)
	if err != nil || !ok {
		return waf.OverrideRuleSource{}, false, err
	}
	target := managedOverrideRulePath(name)
	raw, etag, _, _, err := loadEditableWAFRuleAssetForKind(target, wafRuleAssetKindBypassExtra)
	if err != nil {
		if strings.Contains(err.Error(), "not found") {
			return waf.OverrideRuleSource{}, false, nil
		}
		return waf.OverrideRuleSource{}, false, err
	}
	return waf.OverrideRuleSource{
		Raw:  raw,
		ETag: etag,
		Name: name,
	}, true, nil
}

func migrateManagedOverrideRulesToWAFRuleAssets(store *wafEventStore, rules []managedOverrideRuleVersion) error {
	if len(rules) == 0 {
		return nil
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return err
	}
	if !found {
		return fmt.Errorf("active waf rule assets missing in db; run make crs-install before migrating override rules")
	}
	next := normalizeWAFRuleAssets(assets)
	byPath := make(map[string]int, len(next))
	for i, asset := range next {
		byPath[asset.Path] = i
	}
	changed := false
	for _, rule := range normalizeManagedOverrideRules(rules) {
		target := managedOverrideRulePath(rule.Name)
		path, err := normalizeWAFRuleAssetPathForKind(target, wafRuleAssetKindBypassExtra)
		if err != nil {
			return err
		}
		asset := wafRuleAssetVersion{
			Path: path,
			Kind: wafRuleAssetKindBypassExtra,
			Raw:  append([]byte(nil), rule.Raw...),
			ETag: strings.TrimSpace(rule.ETag),
		}
		if asset.ETag == "" {
			asset.ETag = bypassconf.ComputeETag(asset.Raw)
		}
		if idx, ok := byPath[path]; ok {
			if next[idx].Kind == wafRuleAssetKindBypassExtra && string(next[idx].Raw) == string(asset.Raw) && next[idx].ETag == asset.ETag {
				continue
			}
			next[idx] = asset
			changed = true
			continue
		}
		byPath[path] = len(next)
		next = append(next, asset)
		changed = true
	}
	if !changed {
		return nil
	}
	_, _, err = store.writeWAFRuleAssetsVersion(rec.ETag, next, configVersionSourceApply, "", "migrate override rules to waf rule assets", 0)
	return err
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
