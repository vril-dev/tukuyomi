package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type phpRuntimeConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetPHPRuntimes(c *gin.Context) {
	raw, etag, cfg, rollbackDepth := PHPRuntimeInventorySnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"runtimes":       cfg,
		"materialized":   PHPRuntimeMaterializationSnapshot(),
		"processes":      PHPRuntimeProcessSnapshot(),
		"rollback_depth": rollbackDepth,
	})
}

func ValidatePHPRuntimes(c *gin.Context) {
	var in phpRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidatePHPRuntimeInventoryRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"runtimes": cfg,
	})
}

func PutPHPRuntimes(c *gin.Context) {
	var in phpRuntimeConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyPHPRuntimeInventoryRaw(ifMatch, in.Raw)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": conflict.CurrentETag})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"etag":     etag,
		"runtimes": cfg,
	})
}

func RollbackPHPRuntimes(c *gin.Context) {
	etag, cfg, restored, err := RollbackPHPRuntimeInventory()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot"})
			return
		}
		if respondIfConfigDBStoreRequired(c, err) {
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"runtimes":      cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}

func UpPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := StartPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}

func DownPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := StopPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}

func ReloadPHPRuntimeHandler(c *gin.Context) {
	runtimeID := strings.TrimSpace(c.Param("runtime_id"))
	if err := ReloadPHPRuntimeProcess(runtimeID); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":         true,
		"runtime_id": normalizeConfigToken(runtimeID),
		"processes":  PHPRuntimeProcessSnapshot(),
	})
}
