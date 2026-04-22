package handler

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
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

func GetManagedOverrideRules(c *gin.Context) {
	files, err := managedOverrideRuleSnapshot()
	if err != nil {
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

	store := getLogsStatsStore()
	curRaw, curETag, _, _, err := managedOverrideRuleCurrent(name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bypassconf.AtomicWriteWithBackup(target, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	waf.InvalidateOverrideWAF(target)

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(overrideRuleConfigBlobKey(name), []byte(in.Raw), newETag, now); err != nil {
			_ = rollbackRuleFile(target, len(curRaw) > 0, curRaw)
			c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("db sync failed and rollback applied: %v", err)})
			return
		}
	}

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

	store := getLogsStatsStore()
	if store != nil {
		if err := store.DeleteConfigBlob(overrideRuleConfigBlobKey(name)); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}
	if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
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

	fsNames, err := listManagedOverrideRuleNamesFromFS()
	if err != nil {
		return err
	}
	fsSet := make(map[string]struct{}, len(fsNames))
	for _, name := range fsNames {
		fsSet[name] = struct{}{}
	}

	blobs, err := store.ListConfigBlobs(overrideRuleConfigBlobPrefix)
	if err != nil {
		return err
	}
	blobByName := make(map[string]configBlobRecord, len(blobs))
	for _, blob := range blobs {
		name := strings.TrimPrefix(blob.ConfigKey, overrideRuleConfigBlobPrefix)
		if _, _, err := managedOverrideRuleTarget(name); err != nil {
			continue
		}
		blobByName[name] = blob
	}

	for _, name := range fsNames {
		target := managedOverrideRulePath(name)
		fileRaw, hadFile, err := readFileMaybe(target)
		if err != nil {
			return err
		}
		blob, found := blobByName[name]
		if found {
			if strings.TrimSpace(blob.ETag) == "" {
				blob.ETag = bypassconf.ComputeETag(blob.Raw)
				if err := store.UpsertConfigBlob(overrideRuleConfigBlobKey(name), blob.Raw, blob.ETag, time.Now().UTC()); err != nil {
					return err
				}
			}
			if !hadFile || !bytes.Equal(fileRaw, blob.Raw) {
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					return err
				}
				if err := bypassconf.AtomicWriteWithBackup(target, blob.Raw); err != nil {
					return err
				}
				waf.InvalidateOverrideWAF(target)
			}
			continue
		}
		if hadFile && len(fileRaw) > 0 {
			if err := store.UpsertConfigBlob(overrideRuleConfigBlobKey(name), fileRaw, bypassconf.ComputeETag(fileRaw), time.Now().UTC()); err != nil {
				return err
			}
		}
	}

	for name, blob := range blobByName {
		if _, ok := fsSet[name]; ok {
			continue
		}
		target := managedOverrideRulePath(name)
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		if err := bypassconf.AtomicWriteWithBackup(target, blob.Raw); err != nil {
			return err
		}
		waf.InvalidateOverrideWAF(target)
	}

	return nil
}

func managedOverrideRuleSnapshot() ([]gin.H, error) {
	store := getLogsStatsStore()
	fsNames, err := listManagedOverrideRuleNamesFromFS()
	if err != nil {
		return nil, err
	}
	nameSet := make(map[string]struct{}, len(fsNames))
	for _, name := range fsNames {
		nameSet[name] = struct{}{}
	}
	blobByName := map[string]configBlobRecord{}
	if store != nil {
		blobs, err := store.ListConfigBlobs(overrideRuleConfigBlobPrefix)
		if err != nil {
			return nil, err
		}
		for _, blob := range blobs {
			name := strings.TrimPrefix(blob.ConfigKey, overrideRuleConfigBlobPrefix)
			if _, _, err := managedOverrideRuleTarget(name); err != nil {
				continue
			}
			blobByName[name] = blob
			nameSet[name] = struct{}{}
		}
	}

	names := make([]string, 0, len(nameSet))
	for name := range nameSet {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]gin.H, 0, len(names))
	for _, name := range names {
		target := managedOverrideRulePath(name)
		if blob, ok := blobByName[name]; ok {
			etag := strings.TrimSpace(blob.ETag)
			if etag == "" {
				etag = bypassconf.ComputeETag(blob.Raw)
			}
			out = append(out, gin.H{
				"name":     name,
				"path":     target,
				"raw":      string(blob.Raw),
				"etag":     etag,
				"saved_at": strings.TrimSpace(blob.UpdatedAt),
			})
			continue
		}
		raw, err := os.ReadFile(target)
		savedAt := fileSavedAt(target)
		if err != nil {
			out = append(out, gin.H{
				"name":     name,
				"path":     target,
				"raw":      "",
				"etag":     "",
				"error":    err.Error(),
				"saved_at": savedAt,
			})
			continue
		}
		out = append(out, gin.H{
			"name":     name,
			"path":     target,
			"raw":      string(raw),
			"etag":     bypassconf.ComputeETag(raw),
			"saved_at": savedAt,
		})
	}

	return out, nil
}

func listManagedOverrideRuleNamesFromFS() ([]string, error) {
	dir := managedOverrideRulesDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasSuffix(strings.ToLower(name), ".conf") {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func managedOverrideRuleCurrent(name string) ([]byte, string, bool, bool, error) {
	target := managedOverrideRulePath(name)
	store := getLogsStatsStore()
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(overrideRuleConfigBlobKey(name))
		if err != nil {
			return nil, "", false, false, err
		}
		if found {
			if strings.TrimSpace(dbETag) == "" {
				dbETag = bypassconf.ComputeETag(dbRaw)
			}
			return dbRaw, dbETag, true, true, nil
		}
	}
	raw, hadFile, err := readFileMaybe(target)
	if err != nil {
		return nil, "", false, false, err
	}
	return raw, bypassconf.ComputeETag(raw), hadFile, false, nil
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
	inUse := []string{}
	for _, entry := range bypassconf.Get() {
		if filepath.Clean(strings.TrimSpace(entry.ExtraRule)) != target {
			continue
		}
		inUse = append(inUse, entry.Path)
	}
	sort.Strings(inUse)
	return inUse, len(inUse) > 0
}
