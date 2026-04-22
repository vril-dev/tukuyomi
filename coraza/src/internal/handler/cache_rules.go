package handler

import (
	"bytes"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
)

const (
	cacheConfPath       = config.DefaultCacheRulesFilePath
	legacyCacheConfPath = config.LegacyDefaultCacheRulesPath
	cacheConfigBlobKey  = "cache_rules"
)

type crPutBody struct {
	RawMode bool                `json:"rawMode"`
	Raw     string              `json:"raw"`
	Rules   cacheconf.RulesFile `json:"rules"`
}

func GetCacheRules(c *gin.Context) {
	readPath := config.ResolveReadablePolicyPath(cacheConfPath, legacyCacheConfPath)
	raw, _ := os.ReadFile(readPath)
	savedAt := fileSavedAt(readPath)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(cacheConfigBlobKey)
		if err != nil {
			log.Printf("[CACHE][DB][WARN] get config blob failed: %v", err)
		} else if found {
			rsDB, parseErr := cacheconf.LoadFromBytes(dbRaw)
			if parseErr != nil {
				log.Printf("[CACHE][DB][WARN] cached blob parse failed (fallback=file): %v", parseErr)
			} else {
				if !bytes.Equal(raw, dbRaw) {
					if err := cacheconf.AtomicWriteWithBackup(cacheConfPath, dbRaw); err != nil {
						log.Printf("[CACHE][DB][WARN] sync file from db failed: %v", err)
					}
				}
				if strings.TrimSpace(dbETag) == "" {
					dbETag = cacheconf.ComputeETag(dbRaw)
				}
				normalizedRaw, _ := cacheconf.RulesetToJSON(rsDB)
				savedAt = configBlobSavedAt(store, cacheConfigBlobKey)
				c.JSON(http.StatusOK, cacheconf.RulesDTO{
					ETag:    dbETag,
					Raw:     string(normalizedRaw),
					Rules:   cacheconf.ToDTO(rsDB),
					SavedAt: savedAt,
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(cacheConfigBlobKey, raw, cacheconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				log.Printf("[CACHE][DB][WARN] seed config blob failed: %v", err)
			}
		}
	}

	rs := cacheconf.Get()
	dto := cacheconf.RulesDTO{
		ETag:    cacheconf.ComputeETag(raw),
		Raw:     string(mustCacheRulesJSON(rs)),
		Rules:   cacheconf.ToDTO(rs),
		SavedAt: savedAt,
	}

	c.JSON(http.StatusOK, dto)
}

func ValidateCacheRules(c *gin.Context) {
	var in crPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if in.RawMode {
		if _, err := cacheconf.LoadFromBytes([]byte(in.Raw)); err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
			return
		}

		c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
		return
	}

	if _, errs := cacheconf.FromDTO(in.Rules); len(errs) > 0 {
		msgs := make([]string, 0, len(errs))
		for _, e := range errs {
			msgs = append(msgs, e.Error())
		}

		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": msgs})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutCacheRules(c *gin.Context) {
	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(config.ResolveReadablePolicyPath(cacheConfPath, legacyCacheConfPath))
	curETag := cacheconf.ComputeETag(curRaw)
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	var in crPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var outBytes []byte
	if in.RawMode {
		rs, err := cacheconf.LoadFromBytes([]byte(in.Raw))
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
			return
		}

		outBytes, err = cacheconf.RulesetToJSON(rs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	} else {
		rs, errs := cacheconf.FromDTO(in.Rules)
		if len(errs) > 0 {
			msgs := make([]string, 0, len(errs))
			for _, e := range errs {
				msgs = append(msgs, e.Error())
			}
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": msgs})
			return
		}

		var err error
		outBytes, err = cacheconf.RulesetToJSON(rs)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	if err := cacheconf.AtomicWriteWithBackup(cacheConfPath, outBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := cacheconf.ComputeETag(outBytes)
	if store := getLogsStatsStore(); store != nil {
		if err := store.UpsertConfigBlob(cacheConfigBlobKey, outBytes, newETag, now); err != nil {
			rollbackErr := cacheconf.AtomicWriteWithBackup(cacheConfPath, curRaw)
			if rollbackErr != nil {
				c.JSON(http.StatusInternalServerError, gin.H{
					"error":          "cache db sync failed and rollback failed",
					"db_error":       err.Error(),
					"rollback_error": rollbackErr.Error(),
				})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "cache db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag, "saved_at": now.Format(time.RFC3339Nano)})
}

func mustCacheRulesJSON(rs *cacheconf.Ruleset) []byte {
	out, err := cacheconf.RulesetToJSON(rs)
	if err != nil {
		return []byte("{\n  \"default\": {\n    \"rules\": []\n  }\n}\n")
	}
	return out
}

func SyncCacheRulesStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: cacheConfigBlobKey,
		Path:      cacheConfPath,
		ValidateRaw: func(raw string) error {
			_, err := cacheconf.LoadFromBytes([]byte(raw))
			return err
		},
		WriteRaw:         cacheconf.AtomicWriteWithBackup,
		ComputeETag:      cacheconf.ComputeETag,
		SkipWriteIfEqual: true,
	})
}
