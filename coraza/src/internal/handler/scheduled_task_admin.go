package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type scheduledTaskConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetScheduledTasks(c *gin.Context) {
	raw, etag, cfg, statuses, rollbackDepth := ScheduledTaskConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"tasks":          cfg,
		"statuses":       statuses,
		"runtime_paths":  CurrentScheduledTaskRuntimePaths(),
		"rollback_depth": rollbackDepth,
	})
}

func ValidateScheduledTasks(c *gin.Context) {
	var in scheduledTaskConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidateScheduledTaskConfigRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"error":    err.Error(),
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"tasks":    cfg,
	})
}

func PutScheduledTasks(c *gin.Context) {
	var in scheduledTaskConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyScheduledTaskConfigRaw(ifMatch, in.Raw)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			c.JSON(http.StatusConflict, gin.H{
				"error":       "scheduled task config changed on disk; reload and retry",
				"currentETag": conflict.CurrentETag,
			})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"error":    err.Error(),
			"messages": []string{err.Error()},
		})
		return
	}
	statuses, _ := ScheduledTaskStatusSnapshot(currentScheduledTaskConfigPath(), cfg)
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"tasks":         cfg,
		"statuses":      statuses,
		"runtime_paths": CurrentScheduledTaskRuntimePaths(),
	})
}

func RollbackScheduledTasks(c *gin.Context) {
	etag, cfg, restored, err := RollbackScheduledTaskConfig()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot available"})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"error":    err.Error(),
			"messages": []string{err.Error()},
		})
		return
	}
	statuses, _ := ScheduledTaskStatusSnapshot(currentScheduledTaskConfigPath(), cfg)
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"tasks":         cfg,
		"statuses":      statuses,
		"runtime_paths": CurrentScheduledTaskRuntimePaths(),
		"rollback":      true,
		"restored_from": restored,
	})
}
