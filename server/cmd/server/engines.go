package main

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminhttp"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/observability"
)

func newBaseEngine(globalConcurrencyGuard *middleware.ConcurrencyGuard) (*gin.Engine, error) {
	r := gin.New()
	if config.RequestLogEnabled {
		r.Use(gin.Logger())
	}
	r.Use(gin.Recovery())
	r.Use(observability.GinTracingMiddleware())
	if err := r.SetTrustedProxies(nil); err != nil {
		return nil, err
	}
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})
	if globalConcurrencyGuard != nil {
		r.Use(middleware.ConcurrencyGuardMiddleware(globalConcurrencyGuard))
	}
	return r, nil
}

func applyAdminCORS(r *gin.Engine) {
	if r == nil || len(config.APICORSOrigins) == 0 {
		return
	}
	r.Use(cors.New(cors.Config{
		AllowOrigins: config.APICORSOrigins,
		AllowMethods: []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders: []string{"Origin", "Content-Type", "Accept", "Authorization", "If-Match", "X-Tukuyomi-Actor", "X-CSRF-Token"},
	}))
}

func registerAdminSurface(r *gin.Engine) {
	if r == nil {
		return
	}
	handler.RegisterAdminAuthRoutes(r)
	registerAdminAPIRoutes(r)
	handler.RegisterAdminUIRoutes(r)
}

func registerAdminAPIRoutes(r *gin.Engine) {
	if r == nil {
		return
	}
	api := r.Group(
		config.APIBasePath,
		handler.AdminAccessMiddleware("api"),
		handler.AdminRateLimitMiddleware(),
		middleware.AdminAuth(),
	)
	adminMutate := adminhttp.ReadOnlyMutationMiddleware()
	api.GET("/", func(c *gin.Context) {
		endpoints := []string{
			config.APIBasePath + "/status",
			config.APIBasePath + "/logs",
			config.APIBasePath + "/rules",
			config.APIBasePath + "/override-rules",
			config.APIBasePath + "/crs-rule-sets",
			config.APIBasePath + "/bypass-rules",
			config.APIBasePath + "/proxy-backends",
			config.APIBasePath + "/cache-rules",
			config.APIBasePath + "/cache-store",
			config.APIBasePath + "/cache-store/clear",
			config.APIBasePath + "/country-block-rules",
			config.APIBasePath + "/request-country-db",
			config.APIBasePath + "/request-country-mode",
			config.APIBasePath + "/request-country-update",
			config.APIBasePath + "/rate-limit-rules",
			config.APIBasePath + "/notifications",
			config.APIBasePath + "/notifications/status",
			config.APIBasePath + "/ip-reputation",
			config.APIBasePath + "/ip-reputation:validate",
			config.APIBasePath + "/bot-defense-rules",
			config.APIBasePath + "/bot-defense-decisions",
			config.APIBasePath + "/semantic-rules",
			config.APIBasePath + "/sites",
			config.APIBasePath + "/php-runtimes",
			config.APIBasePath + "/vhosts",
			config.APIBasePath + "/scheduled-tasks",
			config.APIBasePath + "/settings/listener-admin",
			config.APIBasePath + "/auth/account",
			config.APIBasePath + "/auth/password",
			config.APIBasePath + "/auth/api-tokens",
		}
		endpoints = append(endpoints, proxyRuleAdminEndpoints(config.APIBasePath)...)
		endpoints = append(endpoints,
			config.APIBasePath+"/php-runtimes/validate",
			config.APIBasePath+"/php-runtimes/rollback",
			config.APIBasePath+"/php-runtimes/:runtime_id/up",
			config.APIBasePath+"/php-runtimes/:runtime_id/down",
			config.APIBasePath+"/php-runtimes/:runtime_id/reload",
			config.APIBasePath+"/vhosts/validate",
			config.APIBasePath+"/vhosts/rollback",
			config.APIBasePath+"/scheduled-tasks/validate",
			config.APIBasePath+"/scheduled-tasks/rollback",
			config.APIBasePath+"/settings/listener-admin/validate",
			config.APIBasePath+"/auth/api-tokens/:token_id/revoke",
			config.APIBasePath+"/request-country-db/upload",
			config.APIBasePath+"/rules:validate",
			config.APIBasePath+"/rules:order",
			config.APIBasePath+"/override-rules:validate",
			config.APIBasePath+"/proxy-backends/:backend_key/runtime-override",
			config.APIBasePath+"/request-country-update/config/upload",
			config.APIBasePath+"/request-country-update/run",
			config.APIBasePath+"/verify-manifest",
			config.APIBasePath+"/fp-tuner/propose",
			config.APIBasePath+"/fp-tuner/apply",
			config.APIBasePath+"/fp-tuner/recent-waf-blocks",
			config.APIBasePath+"/fp-tuner:audit",
			config.APIBasePath+"/logs/read",
			config.APIBasePath+"/logs/security-audit",
			config.APIBasePath+"/logs/security-audit/verify",
			config.APIBasePath+"/logs/security-audit/evidence/:capture_id/metadata",
			config.APIBasePath+"/logs/stats",
			config.APIBasePath+"/logs/download",
			config.APIBasePath+"/metrics",
		)
		c.JSON(http.StatusOK, gin.H{
			"message":   "tukuyomi-admin API",
			"endpoints": endpoints,
		})
	})

	api.GET("/status", handler.StatusHandler)
	api.GET("/metrics", handler.MetricsHandler)
	api.GET("/logs/read", handler.LogsRead)
	api.GET("/logs/security-audit", handler.GetSecurityAudit)
	api.GET("/logs/security-audit/verify", handler.VerifySecurityAudit)
	api.GET("/logs/security-audit/evidence/:capture_id/metadata", handler.GetSecurityAuditEvidenceMetadata)
	api.GET("/logs/stats", handler.LogsStats)
	api.GET("/logs/download", handler.LogsDownload)
	api.GET("/rules", handler.RulesHandler)
	api.POST("/rules:validate", handler.ValidateRules)
	api.PUT("/rules", adminMutate, handler.PutRules)
	api.DELETE("/rules", adminMutate, handler.DeleteRuleAsset)
	api.PUT("/rules:order", adminMutate, handler.PutRuleAssetOrder)
	api.GET("/override-rules", handler.GetManagedOverrideRules)
	api.POST("/override-rules:validate", handler.ValidateManagedOverrideRule)
	api.PUT("/override-rules", adminMutate, handler.PutManagedOverrideRule)
	api.DELETE("/override-rules", adminMutate, handler.DeleteManagedOverrideRule)
	api.GET("/crs-rule-sets", handler.GetCRSRuleSets)
	api.POST("/crs-rule-sets:validate", handler.ValidateCRSRuleSets)
	api.PUT("/crs-rule-sets", adminMutate, handler.PutCRSRuleSets)
	api.GET("/bypass-rules", handler.GetBypassRules)
	api.POST("/bypass-rules:validate", handler.ValidateBypassRules)
	api.PUT("/bypass-rules", adminMutate, handler.PutBypassRules)
	api.GET("/proxy-backends", handler.GetProxyBackends)
	api.PUT("/proxy-backends/:backend_key/runtime-override", adminMutate, handler.PutProxyBackendRuntimeOverride)
	api.DELETE("/proxy-backends/:backend_key/runtime-override", adminMutate, handler.DeleteProxyBackendRuntimeOverride)
	api.GET("/cache-rules", handler.GetCacheRules)
	api.POST("/cache-rules:validate", handler.ValidateCacheRules)
	api.PUT("/cache-rules", adminMutate, handler.PutCacheRules)
	api.GET("/cache-store", handler.GetResponseCacheStore)
	api.POST("/cache-store/validate", handler.ValidateResponseCacheStore)
	api.PUT("/cache-store", adminMutate, handler.PutResponseCacheStore)
	api.POST("/cache-store/clear", adminMutate, handler.ClearResponseCacheStore)
	api.GET("/country-block-rules", handler.GetCountryBlockRules)
	api.POST("/country-block-rules:validate", handler.ValidateCountryBlockRules)
	api.PUT("/country-block-rules", adminMutate, handler.PutCountryBlockRules)
	api.GET("/request-country-db", handler.GetRequestCountryDBStatus)
	api.POST("/request-country-db/upload", adminMutate, handler.UploadRequestCountryDB)
	api.DELETE("/request-country-db", adminMutate, handler.DeleteRequestCountryDB)
	api.PUT("/request-country-mode", adminMutate, handler.PutRequestCountryMode)
	api.GET("/request-country-update", handler.GetRequestCountryUpdateStatus)
	api.POST("/request-country-update/config/upload", adminMutate, handler.UploadRequestCountryUpdateConfig)
	api.DELETE("/request-country-update/config", adminMutate, handler.DeleteRequestCountryUpdateConfig)
	api.POST("/request-country-update/run", adminMutate, handler.RunRequestCountryUpdateNow)
	api.GET("/rate-limit-rules", handler.GetRateLimitRules)
	api.POST("/rate-limit-rules:validate", handler.ValidateRateLimitRules)
	api.PUT("/rate-limit-rules", adminMutate, handler.PutRateLimitRules)
	api.GET("/notifications", handler.GetNotificationRules)
	api.GET("/notifications/status", handler.GetNotificationStatusHandler)
	api.POST("/notifications/validate", handler.ValidateNotificationRules)
	api.POST("/notifications/test", adminMutate, handler.TestNotificationRules)
	api.PUT("/notifications", adminMutate, handler.PutNotificationRules)
	api.GET("/ip-reputation", handler.GetIPReputation)
	api.POST("/ip-reputation:validate", handler.ValidateIPReputation)
	api.PUT("/ip-reputation", adminMutate, handler.PutIPReputation)
	api.GET("/bot-defense-rules", handler.GetBotDefenseRules)
	api.POST("/bot-defense-rules:validate", handler.ValidateBotDefenseRules)
	api.PUT("/bot-defense-rules", adminMutate, handler.PutBotDefenseRules)
	api.GET("/bot-defense-decisions", handler.GetBotDefenseDecisions)
	api.GET("/semantic-rules", handler.GetSemanticRules)
	api.POST("/semantic-rules:validate", handler.ValidateSemanticRules)
	api.PUT("/semantic-rules", adminMutate, handler.PutSemanticRules)
	api.GET("/sites", handler.GetSites)
	api.POST("/sites/validate", handler.ValidateSites)
	api.PUT("/sites", adminMutate, handler.PutSites)
	api.POST("/sites/rollback", adminMutate, handler.RollbackSites)
	api.GET("/php-runtimes", handler.GetPHPRuntimes)
	api.POST("/php-runtimes/validate", handler.ValidatePHPRuntimes)
	api.PUT("/php-runtimes", adminMutate, handler.PutPHPRuntimes)
	api.POST("/php-runtimes/rollback", adminMutate, handler.RollbackPHPRuntimes)
	api.POST("/php-runtimes/:runtime_id/up", adminMutate, handler.UpPHPRuntimeHandler)
	api.POST("/php-runtimes/:runtime_id/down", adminMutate, handler.DownPHPRuntimeHandler)
	api.POST("/php-runtimes/:runtime_id/reload", adminMutate, handler.ReloadPHPRuntimeHandler)
	api.GET("/vhosts", handler.GetVhosts)
	api.POST("/vhosts/validate", handler.ValidateVhosts)
	api.PUT("/vhosts", adminMutate, handler.PutVhosts)
	api.POST("/vhosts/rollback", adminMutate, handler.RollbackVhosts)
	api.GET("/scheduled-tasks", handler.GetScheduledTasks)
	api.POST("/scheduled-tasks/validate", handler.ValidateScheduledTasks)
	api.PUT("/scheduled-tasks", adminMutate, handler.PutScheduledTasks)
	api.POST("/scheduled-tasks/rollback", adminMutate, handler.RollbackScheduledTasks)
	api.GET("/settings/listener-admin", handler.GetSettingsListenerAdmin)
	api.POST("/settings/listener-admin/validate", handler.ValidateSettingsListenerAdmin)
	api.PUT("/settings/listener-admin", adminMutate, handler.PutSettingsListenerAdmin)
	api.GET("/auth/account", handler.GetAdminAccount)
	api.PUT("/auth/account", adminMutate, handler.PutAdminAccount)
	api.PUT("/auth/password", adminMutate, handler.PutAdminPassword)
	api.GET("/auth/api-tokens", handler.GetAdminAPITokens)
	api.POST("/auth/api-tokens", adminMutate, handler.PostAdminAPIToken)
	api.POST("/auth/api-tokens/:token_id/revoke", adminMutate, handler.PostAdminAPITokenRevoke)
	registerProxyRuleAdminRoutes(api)
	api.GET("/verify-manifest", handler.GetVerifyManifest)
	api.POST("/fp-tuner/propose", handler.ProposeFPTuning)
	api.POST("/fp-tuner/apply", adminMutate, handler.ApplyFPTuning)
	api.GET("/fp-tuner/recent-waf-blocks", handler.GetFPTunerRecentWAFBlocks)
	api.GET("/fp-tuner:audit", handler.GetFPTunerAudit)
}

func registerPublicProxySurface(r *gin.Engine, proxyConcurrencyGuard *middleware.ConcurrencyGuard) {
	if r == nil {
		return
	}
	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if pathTargetsAdminSurface(p) {
			c.AbortWithStatus(http.StatusNotFound)
			return
		}
		if proxyConcurrencyGuard != nil {
			alreadyQueued := middleware.RequestAlreadyQueued(c.Request.Context())
			var result middleware.ConcurrencyAcquireResult
			if alreadyQueued {
				result = proxyConcurrencyGuard.AcquireContextNoQueue(c.Request.Context())
			} else {
				result = proxyConcurrencyGuard.AcquireContext(c.Request.Context())
			}
			if !result.Allowed {
				if alreadyQueued {
					result = middleware.MergeRequestQueueResult(c.Request.Context(), result)
				}
				proxyConcurrencyGuard.RejectWithResult(c, result)
				return
			}
			proxyConcurrencyGuard.AnnotateQueuedResponse(c, result)
			defer proxyConcurrencyGuard.Release()
		}

		handler.ProxyHandler(c)
	})
}

type publicProxyHandler struct {
	adminHandler           http.Handler
	proxyHandler           http.Handler
	tracedProxyHandler     http.Handler
	splitAdmin             bool
	globalConcurrencyGuard *middleware.ConcurrencyGuard
	proxyConcurrencyGuard  *middleware.ConcurrencyGuard
}

func buildPublicHandler(globalConcurrencyGuard *middleware.ConcurrencyGuard, proxyConcurrencyGuard *middleware.ConcurrencyGuard, splitAdmin bool) (http.Handler, error) {
	var adminHandler http.Handler
	if !splitAdmin {
		adminEngine, err := buildAdminEngine(globalConcurrencyGuard)
		if err != nil {
			return nil, err
		}
		adminHandler = adminEngine
	}
	h := &publicProxyHandler{
		adminHandler:           adminHandler,
		splitAdmin:             splitAdmin,
		globalConcurrencyGuard: globalConcurrencyGuard,
		proxyConcurrencyGuard:  proxyConcurrencyGuard,
	}
	h.proxyHandler = http.HandlerFunc(h.serveProxy)
	h.tracedProxyHandler = observability.HTTPTracingHandler(h.proxyHandler)
	return h, nil
}

func (h *publicProxyHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h == nil {
		http.NotFound(w, r)
		return
	}
	if r == nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	defer func() {
		if recovered := recover(); recovered != nil {
			log.Printf("[SERVER][RECOVERY] public handler panic: %v", recovered)
			if !httpResponseStatusWritten(w) {
				http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			}
		}
	}()
	if r.URL != nil {
		switch {
		case r.URL.Path == "/healthz":
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		case pathTargetsAdminSurface(r.URL.Path):
			if h.splitAdmin || h.adminHandler == nil {
				http.NotFound(w, r)
				return
			}
			h.adminHandler.ServeHTTP(w, r)
			return
		}
	}
	if observability.TracingEnabled() {
		h.tracedProxyHandler.ServeHTTP(w, r)
		return
	}
	h.proxyHandler.ServeHTTP(w, r)
}

func (h *publicProxyHandler) serveProxy(w http.ResponseWriter, r *http.Request) {
	var globalResult middleware.ConcurrencyAcquireResult
	globalQueued := false
	if guard := h.globalConcurrencyGuard; guard != nil {
		globalResult = guard.AcquireContext(r.Context())
		if !globalResult.Allowed {
			guard.RejectHTTP(w, globalResult)
			return
		}
		globalQueued = globalResult.Queued
		guard.AnnotateQueuedHTTP(w, globalResult)
		defer guard.Release()
	}
	if guard := h.proxyConcurrencyGuard; guard != nil {
		var result middleware.ConcurrencyAcquireResult
		if globalQueued {
			result = guard.AcquireContextNoQueue(r.Context())
		} else {
			result = guard.AcquireContext(r.Context())
		}
		if !result.Allowed {
			if globalQueued {
				result.Queued = true
				result.QueueWait += globalResult.QueueWait
			}
			guard.RejectHTTP(w, result)
			return
		}
		guard.AnnotateQueuedHTTP(w, result)
		defer guard.Release()
	}
	handler.ServeProxyHTTP(w, r)
}

func httpResponseStatusWritten(w http.ResponseWriter) bool {
	if statusWriter, ok := w.(interface{ Status() int }); ok {
		return statusWriter.Status() > 0
	}
	return false
}

func buildPublicEngine(globalConcurrencyGuard *middleware.ConcurrencyGuard, proxyConcurrencyGuard *middleware.ConcurrencyGuard, splitAdmin bool) (*gin.Engine, error) {
	r, err := newBaseEngine(globalConcurrencyGuard)
	if err != nil {
		return nil, err
	}
	if !splitAdmin {
		applyAdminCORS(r)
		registerAdminSurface(r)
	}
	registerPublicProxySurface(r, proxyConcurrencyGuard)
	return r, nil
}

func buildAdminEngine(globalConcurrencyGuard *middleware.ConcurrencyGuard) (*gin.Engine, error) {
	r, err := newBaseEngine(globalConcurrencyGuard)
	if err != nil {
		return nil, err
	}
	applyAdminCORS(r)
	registerAdminSurface(r)
	return r, nil
}

func pathTargetsAdminSurface(requestPath string) bool {
	return pathHasPrefix(requestPath, config.APIBasePath) || pathHasPrefix(requestPath, config.UIBasePath)
}

func pathHasPrefix(requestPath string, base string) bool {
	requestPath = strings.TrimSpace(requestPath)
	base = strings.TrimSpace(base)
	if requestPath == "" || base == "" {
		return false
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	if requestPath == base {
		return true
	}
	return strings.HasPrefix(requestPath, base+"/")
}
