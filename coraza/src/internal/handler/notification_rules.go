package handler

import (
	"errors"
	"io"
	"net/http"
	"os"
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
		dbRaw, rec, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(notificationConfigBlobKey), normalizeNotificationPolicyRaw, "notification rules")
		if err != nil {
			respondConfigBlobDBError(c, "notification db read failed", err)
			return
		} else if found {
			rt, parseErr := ValidateNotificationRaw(string(dbRaw))
			if parseErr != nil {
				respondConfigBlobDBError(c, "notification db rows parse failed", parseErr)
				return
			} else {
				savedAt = configVersionSavedAt(rec)
				c.JSON(http.StatusOK, gin.H{
					"etag":          rec.ETag,
					"raw":           string(dbRaw),
					"enabled":       rt.Raw.Enabled,
					"sinks":         len(rt.Raw.Sinks),
					"enabled_sinks": countEnabledNotificationSinks(rt.Raw.Sinks),
					"active_alerts": GetNotificationStatus().ActiveAlerts,
					"saved_at":      savedAt,
				})
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
	store, err := requireConfigDBStore()
	if err != nil {
		respondConfigDBStoreRequired(c)
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

	normalizedRaw, err := normalizeNotificationPolicyRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	spec := mustPolicyJSONSpec(notificationConfigBlobKey)
	currentRaw, currentRec, _, err := loadRuntimePolicyJSONConfig(store, spec, normalizeNotificationPolicyRaw, "notification rules")
	if err != nil {
		respondConfigBlobDBError(c, "notification db seed failed", err)
		return
	}
	expectedETag := policyWriteExpectedETag(c.GetHeader("If-Match"), currentRaw, currentRec)
	rec, err := store.writePolicyJSONConfigVersion(expectedETag, spec, normalizedRaw, configVersionSourceApply, "", "notification rules update", 0)
	if err != nil {
		if errors.Is(err, errConfigVersionConflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": policyConfigConflictETag(store, notificationConfigBlobKey)})
			return
		}
		respondConfigBlobDBError(c, "notification db update failed", err)
		return
	}
	if err := applyNotificationPolicyRaw(normalizedRaw); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          rec.ETag,
		"enabled":       rt.Raw.Enabled,
		"sinks":         len(rt.Raw.Sinks),
		"enabled_sinks": countEnabledNotificationSinks(rt.Raw.Sinks),
		"saved_at":      rec.ActivatedAt.Format(time.RFC3339Nano),
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
	store := getLogsStatsStore()
	if store == nil {
		return nil
	}
	raw, _, found, err := loadRuntimePolicyJSONConfig(store, mustPolicyJSONSpec(notificationConfigBlobKey), normalizeNotificationPolicyRaw, "notification rules")
	if err != nil || !found {
		return err
	}
	return applyNotificationPolicyRaw(raw)
}
