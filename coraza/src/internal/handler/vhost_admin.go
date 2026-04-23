package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type vhostConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetVhosts(c *gin.Context) {
	raw, etag, cfg, rollbackDepth := VhostConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"vhosts":         cfg,
		"runtime_status": VhostRuntimeStatusSnapshot(),
		"materialized":   PHPRuntimeMaterializationSnapshot(),
		"rollback_depth": rollbackDepth,
	})
}

func ValidateVhosts(c *gin.Context) {
	var in vhostConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidateVhostConfigRawWithInventory(in.Raw, currentPHPRuntimeInventoryConfig())
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	if _, err := prepareProxyRulesRawWithSitesAndVhosts(currentProxyRawConfigRaw(), currentSiteConfig(), cfg); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":       true,
		"messages": []string{},
		"vhosts":   cfg,
	})
}

func PutVhosts(c *gin.Context) {
	var in vhostConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, err := ApplyVhostConfigRaw(ifMatch, in.Raw)
	if err != nil {
		var conflict proxyRulesConflictError
		if asProxyRulesConflict(err, &conflict) {
			c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": conflict.CurrentETag})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":     true,
		"etag":   etag,
		"vhosts": cfg,
	})
}

func RollbackVhosts(c *gin.Context) {
	etag, cfg, restored, err := RollbackVhostConfig()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot"})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"vhosts":        cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}
