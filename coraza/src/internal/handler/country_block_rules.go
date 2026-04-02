package handler

import (
	"log"
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
	path := GetCountryBlockPath()
	raw, _ := os.ReadFile(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(countryBlockConfigBlobKey)
		if err != nil {
			log.Printf("[COUNTRY_BLOCK][DB][WARN] get config blob failed: %v", err)
		} else if found {
			codes, parseErr := ParseCountryBlockRaw(string(dbRaw))
			if parseErr != nil {
				log.Printf("[COUNTRY_BLOCK][DB][WARN] cached blob parse failed (fallback=file): %v", parseErr)
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				c.JSON(http.StatusOK, gin.H{
					"etag":    dbETag,
					"raw":     string(dbRaw),
					"blocked": codes,
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(countryBlockConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				log.Printf("[COUNTRY_BLOCK][DB][WARN] seed config blob failed: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"etag":    bypassconf.ComputeETag(raw),
		"raw":     string(raw),
		"blocked": GetBlockedCountries(),
	})
}

func ValidateCountryBlockRules(c *gin.Context) {
	in, ok := bindCountryBlockPutBody(c)
	if !ok {
		return
	}

	codes, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}, "blocked": codes})
}

func PutCountryBlockRules(c *gin.Context) {
	path := GetCountryBlockPath()
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
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
				log.Printf("[COUNTRY_BLOCK][DB][WARN] cached blob parse failed for conflict check (fallback=file): %v", parseErr)
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

	codes, err := ParseCountryBlockRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := ReloadCountryBlock(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadCountryBlock()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(countryBlockConfigBlobKey, []byte(in.Raw), newETag, time.Now().UTC()); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadCountryBlock()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "country-block db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "blocked": codes})
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
