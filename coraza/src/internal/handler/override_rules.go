package handler

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/waf"
)

const overrideRuleConfigBlobPrefix = "override_rule:"

type overrideRuleBody struct {
	Name string `json:"name"`
	Raw  string `json:"raw"`
}

func init() {
	waf.SetOverrideRuleLoader(loadManagedOverrideRuleForWAF)
}

func GetManagedOverrideRules(c *gin.Context) {
	files, err := managedOverrideRuleSnapshot()
	if err != nil {
		if errors.Is(err, errConfigDBStoreRequired) {
			respondConfigDBStoreRequired(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"dir":   managedOverrideRulesDir(),
		"files": files,
	})
}

func ValidateManagedOverrideRule(c *gin.Context) {
	var in overrideRuleBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name, target, err := managedOverrideRuleTarget(in.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := waf.ValidateStandaloneRule(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}, "name": name, "path": target})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "name": name, "path": target})
}

func PutManagedOverrideRule(c *gin.Context) {
	var in overrideRuleBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	name, target, err := managedOverrideRuleTarget(in.Name)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := waf.ValidateStandaloneRule(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	_, curETag, _, _, err := managedOverrideRuleCurrent(name)
	if err != nil && !strings.Contains(err.Error(), "not found") {
		if errors.Is(err, errConfigDBStoreRequired) {
			respondConfigDBStoreRequired(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	rec, asset, err := writeWAFRuleAssetUpdateForKind(target, wafRuleAssetKindBypassExtra, []byte(in.Raw), "", "bypass extra rule update")
	if err != nil {
		if errors.Is(err, errConfigDBStoreRequired) {
			respondConfigDBStoreRequired(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	waf.InvalidateOverrideWAF(target)
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"name":     name,
		"path":     target,
		"etag":     asset.ETag,
		"saved":    true,
		"saved_at": configVersionSavedAt(rec),
	})
}

func DeleteManagedOverrideRule(c *gin.Context) {
	name, target, err := managedOverrideRuleTarget(c.Query("name"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if inUseBy, inUse := managedOverrideRuleInUse(target); inUse {
		c.JSON(http.StatusConflict, gin.H{
			"error":  "override rule is still referenced by bypass rules",
			"name":   name,
			"path":   target,
			"in_use": inUseBy,
		})
		return
	}

	if _, err := deleteWAFRuleAssetForKind(target, wafRuleAssetKindBypassExtra, "", "bypass extra rule delete"); err != nil {
		if errors.Is(err, errConfigDBStoreRequired) {
			respondConfigDBStoreRequired(c)
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	waf.InvalidateOverrideWAF(target)
	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"name":    name,
		"path":    target,
		"deleted": true,
	})
}

func SyncManagedOverrideRulesStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	rules, _, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil || !found {
		return err
	}
	return migrateManagedOverrideRulesToWAFRuleAssets(store, rules)
}

func managedOverrideRuleSnapshot() ([]gin.H, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return nil, err
	}
	assets, rec, found, err := loadRuntimeWAFRuleAssets(store)
	if err != nil {
		return nil, err
	}
	if !found {
		return []gin.H{}, nil
	}
	ruleSavedAt := configVersionSavedAt(rec)
	type snapshotRule struct {
		name  string
		path  string
		asset wafRuleAssetVersion
	}
	rules := make([]snapshotRule, 0, len(assets))
	for _, asset := range editableWAFRuleAssets(assets) {
		if asset.Kind != wafRuleAssetKindBypassExtra {
			continue
		}
		name, ok, _ := managedOverrideRuleRefName(asset.Path)
		if !ok {
			continue
		}
		rules = append(rules, snapshotRule{name: name, path: managedOverrideRulePath(name), asset: asset})
	}
	sort.Slice(rules, func(i, j int) bool { return rules[i].name < rules[j].name })

	out := make([]gin.H, 0, len(rules))
	for _, rule := range rules {
		etag := strings.TrimSpace(rule.asset.ETag)
		if etag == "" {
			etag = bypassconf.ComputeETag(rule.asset.Raw)
		}
		out = append(out, gin.H{
			"name":     rule.name,
			"path":     rule.path,
			"raw":      string(rule.asset.Raw),
			"etag":     etag,
			"saved_at": ruleSavedAt,
		})
	}

	return out, nil
}

func managedOverrideRuleCurrent(name string) ([]byte, string, bool, bool, error) {
	_, target, err := managedOverrideRuleTarget(name)
	if err != nil {
		return nil, "", false, false, err
	}
	raw, etag, _, dbBacked, err := loadEditableWAFRuleAssetForKind(target, wafRuleAssetKindBypassExtra)
	if err == nil {
		return raw, etag, true, dbBacked, nil
	}
	if strings.Contains(err.Error(), "not found") {
		return nil, "", false, true, nil
	}
	if errors.Is(err, errConfigDBStoreRequired) {
		return nil, "", false, false, err
	}
	return nil, "", false, true, err
}

func managedOverrideRuleTarget(raw string) (string, string, error) {
	name := strings.TrimSpace(raw)
	if name == "" {
		return "", "", fmt.Errorf("name is empty")
	}
	if strings.Contains(name, "/") || strings.Contains(name, `\`) {
		return "", "", fmt.Errorf("name must be a single file name")
	}
	name = filepath.Base(name)
	if !strings.HasSuffix(strings.ToLower(name), ".conf") {
		return "", "", fmt.Errorf("override rule name must end with .conf")
	}
	return name, managedOverrideRulePath(name), nil
}

func managedOverrideRulesDir() string {
	dir := strings.TrimSpace(config.OverrideRulesDir)
	if dir == "" {
		dir = "conf/rules"
	}
	return filepath.Clean(dir)
}

func managedOverrideRulePath(name string) string {
	return filepath.Clean(filepath.Join(managedOverrideRulesDir(), name))
}

func overrideRuleConfigBlobKey(name string) string {
	return overrideRuleConfigBlobPrefix + strings.TrimSpace(name)
}

func managedOverrideRuleInUse(target string) ([]string, bool) {
	target = filepath.Clean(strings.TrimSpace(target))
	targetName := filepath.Base(target)
	inUse := []string{}
	for _, entry := range bypassconf.Get() {
		if filepath.Clean(strings.TrimSpace(entry.ExtraRule)) == target {
			inUse = append(inUse, entry.Path)
			continue
		}
		refName, ok, _ := managedOverrideRuleRefName(entry.ExtraRule)
		if !ok || refName != targetName {
			continue
		}
		inUse = append(inUse, entry.Path)
	}
	sort.Strings(inUse)
	return inUse, len(inUse) > 0
}

func loadManagedOverrideRuleForWAF(rule string) (waf.OverrideRuleSource, bool, error) {
	return loadBypassExtraRuleAssetForWAF(rule)
}

func managedOverrideRuleRefName(raw string) (string, bool, error) {
	ref := strings.TrimSpace(raw)
	if ref == "" {
		return "", false, nil
	}
	clean := filepath.Clean(ref)
	name := filepath.Base(clean)
	if name == "." || name == string(filepath.Separator) {
		return "", false, nil
	}
	name, target, err := managedOverrideRuleTarget(name)
	if err != nil {
		return "", false, nil
	}
	if clean == name || clean == filepath.Clean(target) {
		return name, true, nil
	}
	return "", false, nil
}
