package handler

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

type proxyRulesPutBody struct {
	Raw string `json:"raw"`
}

type proxyRulesProbeBody struct {
	Raw          string `json:"raw"`
	UpstreamName string `json:"upstream_name,omitempty"`
	TimeoutMS    int    `json:"timeout_ms"`
}

type proxyRulesDryRunBody struct {
	Raw  string `json:"raw"`
	Host string `json:"host"`
	Path string `json:"path"`
}

func RollbackPreviewProxyRulesHandler(c *gin.Context) {
	entry, err := ProxyRollbackPreview()
	if err != nil {
		if strings.Contains(err.Error(), "no rollback snapshot") {
			c.JSON(http.StatusConflict, gin.H{"error": "no rollback snapshot"})
			return
		}
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":   true,
		"raw":  entry.Raw,
		"etag": entry.ETag,
	})
}

func GetProxyRulesAudit(c *gin.Context) {
	entries, err := readProxyRulesAudit(parseProxyRulesAuditLimit(c.Query("limit")))
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"entries": entries,
	})
}

func GetProxyRules(c *gin.Context) {
	raw, etag, cfg, health, rollbackDepth := ProxyRulesSnapshot()
	c.JSON(http.StatusOK, gin.H{
		"etag":           etag,
		"raw":            raw,
		"proxy":          cfg,
		"health":         health,
		"rollback_depth": rollbackDepth,
	})
}

func ValidateProxyRules(c *gin.Context) {
	var in proxyRulesPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	cfg, err := ValidateProxyRulesRaw(in.Raw)
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
		"proxy":    cfg,
	})
}

func ProbeProxyRules(c *gin.Context) {
	var in proxyRulesProbeBody
	if err := c.ShouldBindJSON(&in); err != nil && err.Error() != "EOF" {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.TimeoutMS < 0 {
		c.JSON(http.StatusBadRequest, gin.H{
			"ok":       false,
			"messages": []string{"timeout_ms must be >= 0"},
		})
		return
	}
	timeout := 2 * time.Second
	if in.TimeoutMS > 0 {
		timeout = time.Duration(in.TimeoutMS) * time.Millisecond
	}

	upstreamName := strings.TrimSpace(in.UpstreamName)
	cfg, address, latencyMS, err := ProxyProbe(in.Raw, upstreamName, timeout)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"ok":    false,
			"error": "upstream probe failed",
			"proxy": cfg,
			"probe": gin.H{
				"upstream_name": upstreamName,
				"address":       address,
				"timeout_ms":    timeout.Milliseconds(),
			},
			"messages": []string{err.Error()},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":    true,
		"proxy": cfg,
		"probe": gin.H{
			"upstream_name": upstreamName,
			"address":       address,
			"latency_ms":    latencyMS,
			"timeout_ms":    timeout.Milliseconds(),
		},
	})
}

func DryRunProxyRulesHandler(c *gin.Context) {
	var in proxyRulesDryRunBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	path := strings.TrimSpace(in.Path)
	if path == "" {
		c.JSON(http.StatusBadRequest, gin.H{"ok": false, "messages": []string{"path is required"}})
		return
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	var (
		cfg    ProxyRulesConfig
		effCfg ProxyRulesConfig
		health *upstreamHealthMonitor
		err    error
	)
	if strings.TrimSpace(in.Raw) == "" {
		_, _, cfg, _, _ = ProxyRulesSnapshot()
		effCfg = currentProxyConfig()
		health = proxyRuntimeHealth()
	} else {
		prepared, prepErr := prepareProxyRulesRaw(in.Raw)
		err = prepErr
		if err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
			return
		}
		cfg = prepared.cfg
		effCfg = prepared.effectiveCfg
	}

	result, err := proxyRouteDryRunWithHealth(effCfg, strings.TrimSpace(in.Host), path, health)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}, "proxy": cfg})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"ok":      true,
		"proxy":   cfg,
		"dry_run": result,
	})
}

func PutProxyRules(c *gin.Context) {
	var in proxyRulesPutBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}

	prevRaw, prevETag, _, _, _ := ProxyRulesSnapshot()
	prepared, err := prepareProxyRulesRaw(in.Raw)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"ok": false, "messages": []string{err.Error()}})
		return
	}

	etag, cfg, err := ApplyProxyRulesRaw(ifMatch, in.Raw)
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
	appendProxyRulesAudit(c, proxyRulesAuditEntry{
		Event:     "proxy_rules_apply",
		PrevETag:  prevETag,
		NextETag:  etag,
		BeforeRaw: prevRaw,
		AfterRaw:  prepared.raw,
	})
	c.JSON(http.StatusOK, gin.H{
		"ok":    true,
		"etag":  etag,
		"proxy": cfg,
	})
}

func RollbackProxyRulesHandler(c *gin.Context) {
	prevRaw, prevETag, _, _, _ := ProxyRulesSnapshot()
	etag, cfg, restored, err := RollbackProxyRules()
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
	appendProxyRulesAudit(c, proxyRulesAuditEntry{
		Event:     "proxy_rules_rollback",
		PrevETag:  prevETag,
		NextETag:  etag,
		BeforeRaw: prevRaw,
		AfterRaw:  restored.Raw,
		RestoredFrom: &proxyRulesAuditRestoredFrom{
			ETag:      restored.ETag,
			Timestamp: restored.Timestamp,
		},
	})
	c.JSON(http.StatusOK, gin.H{
		"ok":            true,
		"etag":          etag,
		"proxy":         cfg,
		"rollback":      true,
		"restored_from": restored,
	})
}
