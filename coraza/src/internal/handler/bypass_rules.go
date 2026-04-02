package handler

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const bypassConfigBlobKey = "bypass_rules"

type bypassPutBody struct {
	Raw string `json:"raw"`
}

func bindBypassPutBody(c *gin.Context) (bypassPutBody, bool) {
	var in bypassPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return bypassPutBody{}, false
	}

	return in, true
}

func GetBypassRules(c *gin.Context) {
	path := config.BypassFile
	raw, _ := os.ReadFile(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(bypassConfigBlobKey)
		if err != nil {
			log.Printf("[BYPASS][DB][WARN] get config blob failed: %v", err)
		} else if found {
			if _, parseErr := validateRaw(string(dbRaw)); parseErr != nil {
				log.Printf("[BYPASS][DB][WARN] cached blob parse failed (fallback=file): %v", parseErr)
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				c.JSON(http.StatusOK, gin.H{
					"etag": dbETag,
					"raw":  string(dbRaw),
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(bypassConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				log.Printf("[BYPASS][DB][WARN] seed config blob failed: %v", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"etag": bypassconf.ComputeETag(raw),
		"raw":  string(raw),
	})
}

func ValidateBypassRules(c *gin.Context) {
	in, ok := bindBypassPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "messages": []string{}})
}

func PutBypassRules(c *gin.Context) {
	path := config.BypassFile
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(bypassConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := validateRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				log.Printf("[BYPASS][DB][WARN] cached blob parse failed for conflict check (fallback=file): %v", parseErr)
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindBypassPutBody(c)
	if !ok {
		return
	}

	if _, err := validateRaw(in.Raw); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := bypassconf.Reload(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = bypassconf.Reload()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(bypassConfigBlobKey, []byte(in.Raw), newETag, time.Now().UTC()); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = bypassconf.Reload()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "bypass db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"ok": true, "etag": newETag})
}

func SyncBypassStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: bypassConfigBlobKey,
		Path:      config.BypassFile,
		ValidateRaw: func(raw string) error {
			_, err := validateRaw(raw)
			return err
		},
		Reload:           bypassconf.Reload,
		SkipWriteIfEqual: true,
	})
}

func validateRaw(s string) (int, error) {
	es, err := bypassconf.Parse(s)
	if err != nil {
		return 0, err
	}
	for _, e := range es {
		if e.ExtraRule == "" {
			continue
		}
		if _, statErr := os.Stat(e.ExtraRule); statErr != nil {
			if errors.Is(statErr, os.ErrNotExist) && !config.StrictOverride {
				continue
			}
			return 0, fmt.Errorf("extra rule not found: %s", e.ExtraRule)
		}
	}

	return len(es), nil
}
