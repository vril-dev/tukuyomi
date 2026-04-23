package handler

import (
	"errors"
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

func GetCRSRuleSets(c *gin.Context) {
	raw, _ := os.ReadFile(config.CRSDisabledFile)
	savedAt := fileSavedAt(config.CRSDisabledFile)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(crsDisabledConfigBlobKey)
		if err != nil {
			respondConfigBlobDBError(c, "crs db read failed", err)
			return
		} else if found {
			raw = dbRaw
			if strings.TrimSpace(dbETag) == "" {
				dbETag = bypassconf.ComputeETag(dbRaw)
			}
			savedAt = configBlobSavedAt(store, crsDisabledConfigBlobKey)
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(crsDisabledConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				respondConfigBlobDBError(c, "crs db seed failed", err)
				return
			}
		}
	}

	if !config.CRSEnable {
		c.JSON(http.StatusOK, gin.H{
			"crs_enabled":    false,
			"disabled_file":  config.CRSDisabledFile,
			"etag":           bypassconf.ComputeETag(raw),
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
		"etag":           bypassconf.ComputeETag(raw),
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

	curRaw, hadFile, err := readFileMaybe(config.CRSDisabledFile)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	store := getLogsStatsStore()
	if store != nil {
		dbRaw, dbETag, found, getErr := store.GetConfigBlob(crsDisabledConfigBlobKey)
		if getErr != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": getErr.Error()})
			return
		}
		if found {
			curRaw = dbRaw
			if strings.TrimSpace(dbETag) != "" {
				curETag := bypassconf.ComputeETag(curRaw)
				if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != dbETag && ifMatch != curETag {
					c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": dbETag})
					return
				}
			}
		}
	}
	curETag := bypassconf.ComputeETag(curRaw)
	if ifMatch := c.GetHeader("If-Match"); ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
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

	if err := os.MkdirAll(filepath.Dir(config.CRSDisabledFile), 0o755); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	nextRaw := crsselection.SerializeDisabled(disabledNames)
	if err := bypassconf.AtomicWriteWithBackup(config.CRSDisabledFile, nextRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := waf.ReloadBaseWAF(); err != nil {
		rollbackErr := rollbackCRSDisabledFile(config.CRSDisabledFile, hadFile, curRaw)
		_ = waf.ReloadBaseWAF()
		msg := fmt.Sprintf("reload failed and rollback applied: %v", err)
		if rollbackErr != nil {
			msg = fmt.Sprintf("%s (rollback error: %v)", msg, rollbackErr)
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
		return
	}

	if store != nil {
		now := time.Now().UTC()
		nextETag := bypassconf.ComputeETag(nextRaw)
		if err := store.UpsertConfigBlob(crsDisabledConfigBlobKey, nextRaw, nextETag, now); err != nil {
			rollbackErr := rollbackCRSDisabledFile(config.CRSDisabledFile, hadFile, curRaw)
			_ = waf.ReloadBaseWAF()
			msg := fmt.Sprintf("db sync failed and rollback applied: %v", err)
			if rollbackErr != nil {
				msg = fmt.Sprintf("%s (rollback error: %v)", msg, rollbackErr)
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"ok":             true,
			"etag":           bypassconf.ComputeETag(nextRaw),
			"hot_reloaded":   true,
			"disabled_count": len(disabledNames),
			"saved_at":       now.Format(time.RFC3339Nano),
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":             true,
		"etag":           bypassconf.ComputeETag(nextRaw),
		"hot_reloaded":   true,
		"disabled_count": len(disabledNames),
		"saved_at":       time.Now().UTC().Format(time.RFC3339Nano),
	})
}

func SyncCRSDisabledStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: crsDisabledConfigBlobKey,
		Path:      config.CRSDisabledFile,
		WriteRaw: func(path string, raw []byte) error {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				return err
			}
			return bypassconf.AtomicWriteWithBackup(path, raw)
		},
		Reload: func() error {
			if !config.CRSEnable {
				return nil
			}
			return waf.ReloadBaseWAF()
		},
		SkipWriteIfEqual: true,
	})
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
