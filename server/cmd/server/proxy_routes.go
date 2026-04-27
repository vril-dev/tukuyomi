package main

import (
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminhttp"
	"tukuyomi/internal/handler"
)

func proxyRuleAdminEndpoints(apiBasePath string) []string {
	return []string{
		apiBasePath + "/proxy-rules",
		apiBasePath + "/proxy-rules/audit",
		apiBasePath + "/proxy-rules/validate",
		apiBasePath + "/proxy-rules/probe",
		apiBasePath + "/proxy-rules/dry-run",
		apiBasePath + "/proxy-rules/rollback-preview",
		apiBasePath + "/proxy-rules/rollback",
	}
}

// Keep proxy-rules actions slash-based so Gin does not treat them as wildcard params.
func registerProxyRuleAdminRoutes(api *gin.RouterGroup) {
	api.GET("/proxy-rules", handler.GetProxyRules)
	api.GET("/proxy-rules/audit", handler.GetProxyRulesAudit)
	api.POST("/proxy-rules/validate", handler.ValidateProxyRules)
	api.POST("/proxy-rules/probe", handler.ProbeProxyRules)
	api.POST("/proxy-rules/dry-run", handler.DryRunProxyRulesHandler)
	api.GET("/proxy-rules/rollback-preview", handler.RollbackPreviewProxyRulesHandler)
	api.POST("/proxy-rules/rollback", adminhttp.ReadOnlyMutationMiddleware(), handler.RollbackProxyRulesHandler)
	api.PUT("/proxy-rules", adminhttp.ReadOnlyMutationMiddleware(), handler.PutProxyRules)
}
