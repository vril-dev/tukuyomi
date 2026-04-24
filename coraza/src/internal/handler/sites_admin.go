package handler

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type siteConfigPutBody struct {
	Raw string `json:"raw"`
}

func GetSites(c *gin.Context) {
	raw, etag, cfg, statuses, rollbackDepth := SiteConfigSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"sites":          cfg,
		"site_statuses":  statuses,
		"rollback_depth": rollbackDepth,
	})
}

func ValidateSites(c *gin.Context) {
	var in siteConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, statuses, err := ValidateSiteConfigRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{
			"ok":       false,
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"messages":      []string{},
		"sites":         cfg,
		"site_statuses": statuses,
	})
}

func PutSites(c *gin.Context) {
	var in siteConfigPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}
	etag, cfg, statuses, err := ApplySiteConfigRaw(ifMatch, in.Raw)
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
		"ok":            true,
		"etag":          etag,
		"sites":         cfg,
		"site_statuses": statuses,
	})
}

func RollbackSites(c *gin.Context) {
	etag, cfg, statuses, restored, err := RollbackSiteConfig()
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
		"sites":         cfg,
		"site_statuses": statuses,
		"rollback":      true,
		"restored_from": restored,
	})
}
