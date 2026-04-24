package handler

import (
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"sort"
	"strings"
	"time"

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

	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	_, curETag, _, _, err := managedOverrideRuleCurrent(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}
	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))

	rules, rec, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	byName := managedOverrideRuleMap(rules)
	byName[name] = managedOverrideRuleVersion{Name: name, Raw: []byte(in.Raw), ETag: newETag}
	next := make([]managedOverrideRuleVersion, 0, len(byName))
	for _, rule := range byName {
		next = append(next, rule)
	}
	expectedDomainETag := ""
	if found {
		expectedDomainETag = rec.ETag
	}
	if _, _, err := store.writeManagedOverrideRulesVersion(expectedDomainETag, next, configVersionSourceApply, "", "override rule update", 0); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	waf.InvalidateOverrideWAF(target)
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"name":     name,
		"path":     target,
		"etag":     newETag,
		"saved":    true,
		"saved_at": now.Format(time.RFC3339Nano),
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

	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	var next []managedOverrideRuleVersion
	var expectedDomainETag string
	rules, rec, _, err := loadRuntimeManagedOverrideRules(store)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	expectedDomainETag = rec.ETag
	byName := managedOverrideRuleMap(rules)
	delete(byName, name)
	next = make([]managedOverrideRuleVersion, 0, len(byName))
	for _, rule := range byName {
		next = append(next, rule)
	}
	if _, _, err := store.writeManagedOverrideRulesVersion(expectedDomainETag, next, configVersionSourceApply, "", "override rule delete", 0); err != nil {
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
	_, _, _, err := loadRuntimeManagedOverrideRules(store)
	return err
}

func managedOverrideRuleSnapshot() ([]gin.H, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return nil, err
	}
	rules, rec, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil {
		return nil, err
	}
	if !found {
		return []gin.H{}, nil
	}
	ruleSavedAt := configVersionSavedAt(rec)
	ruleByName := managedOverrideRuleMap(rules)
	nameSet := make(map[string]struct{}, len(ruleByName))
	for name := range ruleByName {
		nameSet[name] = struct{}{}
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]gin.H, 0, len(names))
	for _, name := range names {
		target := managedOverrideRulePath(name)
		rule := ruleByName[name]
		etag := strings.TrimSpace(rule.ETag)
		if etag == "" {
			etag = bypassconf.ComputeETag(rule.Raw)
		}
		out = append(out, gin.H{
			"name":     name,
			"path":     target,
			"raw":      string(rule.Raw),
			"etag":     etag,
			"saved_at": ruleSavedAt,
		})
	}

	return out, nil
}

func managedOverrideRuleCurrent(name string) ([]byte, string, bool, bool, error) {
	store, err := requireConfigDBStore()
	if err != nil {
		return nil, "", false, false, err
	}
	rules, _, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil {
		return nil, "", false, false, err
	}
	if found {
		if rule, ok := managedOverrideRuleMap(rules)[name]; ok {
			etag := strings.TrimSpace(rule.ETag)
			if etag == "" {
				etag = bypassconf.ComputeETag(rule.Raw)
			}
			return rule.Raw, etag, true, true, nil
		}
	}
	return nil, "", false, true, nil
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
	store := getLogsStatsStore()
	if store == nil {
		return waf.OverrideRuleSource{}, false, errConfigDBStoreRequired
	}
	name, ok, err := managedOverrideRuleRefName(rule)
	if err != nil || !ok {
		return waf.OverrideRuleSource{}, false, err
	}
	rules, _, found, err := loadRuntimeManagedOverrideRules(store)
	if err != nil || !found {
		return waf.OverrideRuleSource{}, false, err
	}
	managed, ok := managedOverrideRuleMap(rules)[name]
	if !ok {
		return waf.OverrideRuleSource{}, false, nil
	}
	etag := strings.TrimSpace(managed.ETag)
	if etag == "" {
		etag = bypassconf.ComputeETag(managed.Raw)
	}
	return waf.OverrideRuleSource{
		Raw:  append([]byte(nil), managed.Raw...),
		ETag: etag,
		Name: name,
	}, true, nil
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
