package handler

import (
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"tukuyomi/internal/bypassconf"
)

const notificationConfigBlobKey = "notification_rules"

type notificationPutBody struct {
	Raw string `json:"raw"`
}

func bindNotificationPutBody(c *gin.Context) (notificationPutBody, bool) {
	var in notificationPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return notificationPutBody{}, false
	}
	return in, true
}

func GetNotificationRules(c *gin.Context) {
	path := GetNotificationsPath()
	raw, _ := os.ReadFile(path)
	savedAt := fileSavedAt(path)
	if store := getLogsStatsStore(); store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(notificationConfigBlobKey)
		if err != nil {
			respondConfigBlobDBError(c, "notification db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateNotificationRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "notification db blob parse failed", parseErr)
				return
			} else {
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				savedAt = configBlobSavedAt(store, notificationConfigBlobKey)
				c.JSON(http.StatusOK, gin.H{
					"etag":          dbETag,
					"raw":           string(dbRaw),
					"enabled":       rt.Raw.Enabled,
					"sinks":         len(rt.Raw.Sinks),
					"enabled_sinks": countEnabledNotificationSinks(rt.Raw.Sinks),
					"active_alerts": GetNotificationStatus().ActiveAlerts,
					"saved_at":      savedAt,
				})
				return
			}
		} else if len(raw) > 0 {
			if err := store.UpsertConfigBlob(notificationConfigBlobKey, raw, bypassconf.ComputeETag(raw), time.Now().UTC()); err != nil {
				respondConfigBlobDBError(c, "notification db seed failed", err)
				return
			}
		}
	}

	cfg := GetNotificationConfig()
	status := GetNotificationStatus()
	c.JSON(http.StatusOK, gin.H{
		"etag":          bypassconf.ComputeETag(raw),
		"raw":           string(raw),
		"enabled":       cfg.Enabled,
		"sinks":         len(cfg.Sinks),
		"enabled_sinks": countEnabledNotificationSinks(cfg.Sinks),
		"active_alerts": status.ActiveAlerts,
		"saved_at":      savedAt,
	})
}

func GetNotificationStatusHandler(c *gin.Context) {
	c.JSON(http.StatusOK, GetNotificationStatus())
}

func ValidateNotificationRules(c *gin.Context) {
	in, ok := bindNotificationPutBody(c)
	if !ok {
		return
	}
	rt, err := ValidateNotificationRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"messages":      []string{},
		"enabled":       rt.Raw.Enabled,
		"sinks":         len(rt.Raw.Sinks),
		"enabled_sinks": countEnabledNotificationSinks(rt.Raw.Sinks),
	})
}

func PutNotificationRules(c *gin.Context) {
	path := GetNotificationsPath()
	store := getLogsStatsStore()

	ifMatch := c.GetHeader("If-Match")
	curRaw, _ := os.ReadFile(path)
	curETag := bypassconf.ComputeETag(curRaw)
	if store != nil {
		dbRaw, dbETag, found, err := store.GetConfigBlob(notificationConfigBlobKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		if found {
			if _, parseErr := ValidateNotificationRaw(string(dbRaw)); parseErr == nil {
				curRaw = dbRaw
				if strings.TrimSpace(dbETag) == "" {
					dbETag = bypassconf.ComputeETag(dbRaw)
				}
				curETag = dbETag
			} else {
				respondConfigBlobDBError(c, "notification db blob parse failed for conflict check", parseErr)
				return
			}
		}
	}
	if ifMatch != "" && ifMatch != curETag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": curETag})
		return
	}

	in, ok := bindNotificationPutBody(c)
	if !ok {
		return
	}
	rt, err := ValidateNotificationRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	if err := bypassconf.AtomicWriteWithBackup(path, []byte(in.Raw)); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if err := ReloadNotifications(); err != nil {
		_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
		_ = ReloadNotifications()
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	now := time.Now().UTC()
	newETag := bypassconf.ComputeETag([]byte(in.Raw))
	if store != nil {
		if err := store.UpsertConfigBlob(notificationConfigBlobKey, []byte(in.Raw), newETag, now); err != nil {
			_ = bypassconf.AtomicWriteWithBackup(path, curRaw)
			_ = ReloadNotifications()
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":    "notification db sync failed and rollback applied",
				"db_error": err.Error(),
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          newETag,
		"enabled":       rt.Raw.Enabled,
		"sinks":         len(rt.Raw.Sinks),
		"enabled_sinks": countEnabledNotificationSinks(rt.Raw.Sinks),
		"saved_at":      now.Format(time.RFC3339Nano),
	})
}

func TestNotificationRules(c *gin.Context) {
	var in struct {
		Note string `json:"note"`
	}
	if err := c.ShouldBindJSON(&in); err != nil && err != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := TestNotificationSend(in.Note); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

func SyncNotificationStorage() error {
	return syncConfigBlobFilePath(configBlobSyncOptions{
		ConfigKey: notificationConfigBlobKey,
		Path:      GetNotificationsPath(),
		ValidateRaw: func(raw string) error {
			_, err := ValidateNotificationRaw(raw)
			return err
		},
		Reload:           ReloadNotifications,
		SkipWriteIfEqual: true,
	})
}
