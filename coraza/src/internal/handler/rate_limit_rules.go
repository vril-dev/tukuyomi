package handler

import (
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const rateLimitConfigBlobKey = "rate_limit_rules"

type rateLimitPutBody struct {
	Raw string `json:"raw"`
}

func bindRateLimitPutBody(c *gin.Context) (rateLimitPutBody, bool) {
	var in rateLimitPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return rateLimitPutBody{}, false
	}

	return in, true
}

func GetRateLimitRules(c *gin.Context) {
	path := GetRateLimitPath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(rateLimitConfigBlobKey)
		if err != nil {
			respondConfigBlobDBError(c, "rate-limit db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateRateLimitRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "rate-limit db blob parse failed", parseErr)
				return
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				savedAt = configBlobSavedAt(store, rateLimitConfigBlobKey)
				c.JSON(http.StatusOK, gin.H{
					"etag":     dbETag,
					"raw":      string(dbRaw),
					"enabled":  rateLimitEnabled(rt.Raw),
					"rules":    rateLimitRuleCount(rt.Raw),
					"saved_at": savedAt,
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(rateLimitConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				respondConfigBlobDBError(c, "rate-limit db seed failed", err)
				return
			}
		}
	}

	cfg := GetRateLimitConfig()
	c.JSON(http.StatusOK, gin.H{
		"etag":     bypassconf.ComputeETag(raw),
		"raw":      string(raw),
		"enabled":  rateLimitEnabled(cfg),
		"rules":    rateLimitRuleCount(cfg),
		"saved_at": savedAt,
	})
}

func ValidateRateLimitRules(c *gin.Context) {
	in, ok := bindRateLimitPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateRateLimitRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"enabled":  rateLimitEnabled(rt.Raw),
		"rules":    rateLimitRuleCount(rt.Raw),
	})
}

func PutRateLimitRules(c *gin.Context) {
	path := GetRateLimitPath()
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(rateLimitConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ValidateRateLimitRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				respondConfigBlobDBError(c, "rate-limit db blob parse failed for conflict check", parseErr)
				return
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindRateLimitPutBody(c)
	if !ok {
		return
	}

	rt, err := ValidateRateLimitRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if err := ReloadRateLimit(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadRateLimit()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(rateLimitConfigBlobKey, []byte(in.Raw), newETag, now); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadRateLimit()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "rate-limit db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"etag":     newETag,
		"enabled":  rateLimitEnabled(rt.Raw),
		"rules":    rateLimitRuleCount(rt.Raw),
		"saved_at": now.Format(time.RFC3339Nano),
	})
}

func SyncRateLimitStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: rateLimitConfigBlobKey,
		Path:      GetRateLimitPath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateRateLimitRaw(raw)
			return err
		},
		Reload:           ReloadRateLimit,
		SkipWriteIfEqual: true,
	})
}
