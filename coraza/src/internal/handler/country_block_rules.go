package handler

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const countryBlockConfigBlobKey = "country_block_rules"

type countryBlockPutBody struct {
	Raw string `json:"raw"`
}

func bindCountryBlockPutBody(c *gin.Context) (countryBlockPutBody, bool) {
	var in countryBlockPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return countryBlockPutBody{}, false
	}

	return in, true
}

func GetCountryBlockRules(c *gin.Context) {
	path := GetCountryBlockActivePath()
	if strings.TrimSpace(path) == "" {
		path = GetCountryBlockPath()
	}
	raw, _ := os.ReadFile(path)
	displayRaw := string(raw)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(countryBlockConfigBlobKey)
		if err != nil {
			respondConfigBlobDBError(c, "country-block db read failed", err)
			return
		} else if found {
			file, parseErr := ParseCountryBlockRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "country-block db blob parse failed", parseErr)
				return
			} else {
				if normalized, err := MarshalCountryBlockJSON(file); err == nil {
					displayRaw = string(normalized)
				}
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				savedAt = configBlobSavedAt(store, countryBlockConfigBlobKey)
				c.JSON(http.StatusOK, gin.H{
					"etag":     dbETag,
					"raw":      displayRaw,
					"blocked":  flattenCountryBlockCodes(file),
					"saved_at": savedAt,
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(countryBlockConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				respondConfigBlobDBError(c, "country-block db seed failed", err)
				return
			}
		}
	}
	if file, err := ParseCountryBlockRaw(displayRaw); err == nil {
		if normalized, nerr := MarshalCountryBlockJSON(file); nerr == nil {
			displayRaw = string(normalized)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      displayRaw,
		"blocked":  GetBlockedCountries(),
		"saved_at": savedAt,
	})
}

func ValidateCountryBlockRules(c *gin.Context) {
	in, ok := bindCountryBlockPutBody(c)
	if !ok {
		return
	}

	file, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "blocked": flattenCountryBlockCodes(file)})
}

func PutCountryBlockRules(c *gin.Context) {
	path := GetCountryBlockPath()
	currentPath := GetCountryBlockActivePath()
	if strings.TrimSpace(currentPath) == "" {
		currentPath = path
	}
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(currentPath)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(countryBlockConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ParseCountryBlockRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				respondConfigBlobDBError(c, "country-block db blob parse failed for conflict check", parseErr)
				return
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindCountryBlockPutBody(c)
	if !ok {
		return
	}

	file, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	normalizedRaw, err := MarshalCountryBlockJSON(file)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := ReloadCountryBlock(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadCountryBlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag(normalizedRaw)
	if store != nil {
		if err := store.UpsertConfigBlob(countryBlockConfigBlobKey, normalizedRaw, newETag, now); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadCountryBlock()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "country-block db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "blocked": flattenCountryBlockCodes(file), "raw": string(normalizedRaw), "saved_at": now.Format(time.RFC3339Nano)})
}

func SyncCountryBlockStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: countryBlockConfigBlobKey,
		Path:      GetCountryBlockPath(),
		ValidateRaw: func(raw string) error {
			_, err := ParseCountryBlockRaw(raw)
			return err
		},
		Reload:           ReloadCountryBlock,
		SkipWriteIfEqual: true,
	})
}
