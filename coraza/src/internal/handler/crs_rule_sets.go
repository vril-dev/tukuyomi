package handler

import (
	"errors"
	"fmt"
	"net/http"
	"os"
	"sort"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/crsselection"
	"tukuyomi/internal/waf"
)

type crsRuleSetItem struct {
	Name    string `json:"name"`
	Path    string `json:"path"`
	Enabled bool   `json:"enabled"`
}

type crsRuleSetPutBody struct {
	Enabled []string `json:"enabled"`
}

const crsDisabledConfigBlobKey = "crs_disabled_rules"

func init() {
	waf.SetCRSDisabledProvider(loadCRSDisabledForWAF)
}

func loadCRSDisabledForWAF() (map[string]struct{}, bool, error) {
	store := getLogsStatsStore()
	if store == nil {
		return nil, false, nil
	}
	names, _, found, err := loadRuntimeCRSDisabledConfig(store)
	if err != nil {
		return nil, true, err
	}
	disabled := map[string]struct{}{}
	if found {
		for _, name := range names {
			disabled[name] = struct{}{}
		}
	}
	return disabled, true, nil
}

func GetCRSRuleSets(c *gin.Context) {
	var raw []byte
	savedAt := ""
	if store := getLogsStatsStore(); store != nil {
		names, rec, found, err := loadRuntimeCRSDisabledConfig(store)
		if err != nil {
			respondConfigBlobDBError(c, "crs db read failed", err)
			return
		} else if found {
			raw = crsselection.SerializeDisabled(names)
			savedAt = configVersionSavedAt(rec)
		}
	} else {
		raw, _ = os.ReadFile(config.CRSDisabledFile)
		savedAt = fileSavedAt(config.CRSDisabledFile)
	}

	if !config.CRSEnable {
		c.JSON(http.StatusOK, gin.H{
			"crs_enabled":    false,
			"disabled_file":  config.CRSDisabledFile,
			"etag":           currentCRSDisabledETag(raw),
			"rules":          []crsRuleSetItem{},
			"enabled_rules":  []string{},
			"total_rules":    0,
			"enabled_count":  0,
			"disabled_count": 0,
			"saved_at":       savedAt,
		})
		return
	}

	crsFiles, err := waf.DiscoverCRSRuleFiles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	disabledSet := crsselection.ParseDisabled(string(raw))

	items := make([]crsRuleSetItem, 0, len(crsFiles))
	enabled := make([]string, 0, len(crsFiles))
	for _, p := range crsFiles {
		name := crsselection.NormalizeName(p)
		_, off := disabledSet[name]
		items = append(items, crsRuleSetItem{
			Name:    name,
			Path:    p,
			Enabled: !off,
		})
		if !off {
			enabled = append(enabled, name)
		}
	}
	sort.Strings(enabled)

	c.JSON(http.StatusOK, gin.H{
		"crs_enabled":    config.CRSEnable,
		"disabled_file":  config.CRSDisabledFile,
		"etag":           currentCRSDisabledETag(raw),
		"rules":          items,
		"enabled_rules":  enabled,
		"total_rules":    len(items),
		"enabled_count":  len(enabled),
		"disabled_count": len(items) - len(enabled),
		"saved_at":       savedAt,
	})
}

func ValidateCRSRuleSets(c *gin.Context) {
	if !config.CRSEnable {
		c.JSON(http.StatusConflict, gin.H{"error": "CRS is disabled (crs.enable=false)"})
		return
	}

	var in crsRuleSetPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if err := waf.ValidateWithCRSSelection(in.Enabled); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutCRSRuleSets(c *gin.Context) {
	if !config.CRSEnable {
		c.JSON(http.StatusConflict, gin.H{"error": "CRS is disabled (crs.enable=false)"})
		return
	}

	var in crsRuleSetPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
		return
	}
	var curRaw []byte
	expectedETag := c.GetHeader("If-Match")
	names, rec, found, getErr := loadRuntimeCRSDisabledConfig(store)
	if getErr != nil {
		respondConfigBlobDBError(c, "crs db read failed", getErr)
		return
	}
	if found {
		curRaw = crsselection.SerializeDisabled(names)
		translated := policyWriteExpectedETag(expectedETag, curRaw, rec)
		if translated != "" && translated != rec.ETag {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": rec.ETag})
			return
		}
		expectedETag = translated
	}

	crsFiles, err := waf.DiscoverCRSRuleFiles()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	disabledNames, err := crsselection.BuildDisabledFromEnabled(crsFiles, in.Enabled)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := waf.ValidateWithCRSSelection(in.Enabled); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	now := time.Now().UTC()
	rec, err = store.writeCRSDisabledConfigVersion(expectedETag, disabledNames, configVersionSourceApply, "", "crs disabled update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, crsDisabledConfigDomain)})
			return
		}
		respondConfigBlobDBError(c, "crs db update failed", err)
		return
	}
	if err := waf.ReloadBaseWAF(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("reload failed: %v", err)})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":             true,
		"etag":           rec.ETag,
		"hot_reloaded":   true,
		"disabled_count": len(disabledNames),
		"saved_at":       now.Format(time.RFC3339Nano),
	})
}

func SyncCRSDisabledStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	_, _, found, err := loadRuntimeCRSDisabledConfig(store)
	if err != nil || !found {
		return err
	}
	if !config.CRSEnable {
		return nil
	}
	return waf.ReloadBaseWAF()
}

func currentCRSDisabledETag(raw []byte) string {
	if store := getLogsStatsStore(); store != nil {
		rec, found, err := store.loadActiveConfigVersion(crsDisabledConfigDomain)
		if err == nil && found {
			return rec.ETag
		}
	}
	return bypassconf.ComputeETag(raw)
}

func readFileMaybe(path string) ([]byte, bool, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return []byte{}, false, nil
		}
		return nil, false, err
	}
	return b, true, nil
}

func rollbackCRSDisabledFile(path string, hadFile bool, previous []byte) error {
	if hadFile {
		return bypassconf.AtomicWriteWithBackup(path, previous)
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
