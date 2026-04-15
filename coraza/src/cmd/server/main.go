package main

import (
	"log"
	"strings"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"

	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/waf"
)

func main() {
	config.LoadEnv()
	if err := handler.InitLogsStatsStoreWithBackend(
		config.StorageBackend,
		config.DBDriver,
		config.DBPath,
		config.DBDSN,
		config.DBRetentionDays,
	); err != nil {
		log.Printf("[DB][INIT][WARN] failed to initialize db store (fallback=file): %v", err)
	} else if config.DBEnabled {
		log.Printf("[DB][INIT] db store enabled (backend=%s driver=%s path=%s retention_days=%d)", config.StorageBackend, config.DBDriver, config.DBPath, config.DBRetentionDays)
	} else {
		log.Printf("[DB][INIT] storage backend=%s", config.StorageBackend)
	}
	if err := handler.SyncRuleFilesStorage(); err != nil {
		log.Printf("[RULES][DB][WARN] sync failed (fallback=file): %v", err)
	}
	waf.InitWAF()
	if err := handler.SyncCRSDisabledStorage(); err != nil {
		log.Printf("[CRS][DB][WARN] sync failed (fallback=file): %v", err)
	}
	if err := handler.SyncBypassStorage(); err != nil {
		log.Printf("[BYPASS][DB][WARN] sync failed (fallback=file): %v", err)
	}
	if err := handler.InitCountryBlock(config.CountryBlockFile); err != nil {
		log.Printf("[COUNTRY_BLOCK][INIT][ERR] %v (path=%s)", err, config.CountryBlockFile)
	} else {
		if err := handler.SyncCountryBlockStorage(); err != nil {
			log.Printf("[COUNTRY_BLOCK][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[COUNTRY_BLOCK][INIT] loaded %d countries", len(handler.GetBlockedCountries()))
	}
	if err := handler.InitRateLimit(config.RateLimitFile); err != nil {
		log.Printf("[RATE_LIMIT][INIT][ERR] %v (path=%s)", err, config.RateLimitFile)
	} else {
		if err := handler.SyncRateLimitStorage(); err != nil {
			log.Printf("[RATE_LIMIT][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[RATE_LIMIT][INIT] loaded")
	}
	if err := handler.InitIPReputation(config.IPReputationFile); err != nil {
		log.Printf("[IP_REPUTATION][INIT][ERR] %v (path=%s)", err, config.IPReputationFile)
	} else {
		if err := handler.SyncIPReputationStorage(); err != nil {
			log.Printf("[IP_REPUTATION][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[IP_REPUTATION][INIT] loaded")
	}
	if err := handler.InitBotDefense(config.BotDefenseFile); err != nil {
		log.Printf("[BOT_DEFENSE][INIT][ERR] %v (path=%s)", err, config.BotDefenseFile)
	} else {
		if err := handler.SyncBotDefenseStorage(); err != nil {
			log.Printf("[BOT_DEFENSE][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[BOT_DEFENSE][INIT] loaded")
	}
	if err := handler.InitSemantic(config.SemanticFile); err != nil {
		log.Printf("[SEMANTIC][INIT][ERR] %v (path=%s)", err, config.SemanticFile)
	} else {
		if err := handler.SyncSemanticStorage(); err != nil {
			log.Printf("[SEMANTIC][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[SEMANTIC][INIT] loaded")
	}
	handler.SetNotificationProductLabel("web")
	if err := handler.InitNotifications(config.NotificationFile); err != nil {
		log.Printf("[NOTIFY][INIT][ERR] %v (path=%s)", err, config.NotificationFile)
	} else {
		if err := handler.SyncNotificationStorage(); err != nil {
			log.Printf("[NOTIFY][DB][WARN] sync failed (fallback=file): %v", err)
		}
		log.Printf("[NOTIFY][INIT] loaded")
	}
	if err := handler.InitLogOutput(config.LogOutputFile); err != nil {
		log.Printf("[LOG_OUTPUT][INIT][ERR] %v (path=%s)", err, config.LogOutputFile)
	} else {
		if err := handler.SyncLogOutputStorage(); err != nil {
			log.Printf("[LOG_OUTPUT][DB][WARN] sync failed (fallback=file): %v", err)
		}
		logOutput := handler.GetLogOutputStatus()
		log.Printf("[LOG_OUTPUT][INIT] loaded provider=%s stdout_streams=%d file_streams=%d", logOutput.Provider, logOutput.StdoutStreams, logOutput.FileStreams)
	}

	log.Println("[INFO] WAF upstream target:", config.AppURL)

	r := gin.Default()

	if len(config.TrustedProxyCIDRs) == 0 {
		// Never trust client-sent forwarding headers unless explicitly configured.
		if err := r.SetTrustedProxies(nil); err != nil {
			log.Fatalf("failed to configure trusted proxies: %v", err)
		}
		log.Println("[SECURITY] trusted proxies disabled; forwarded client IP and request ID headers are ignored")
	} else {
		if err := r.SetTrustedProxies(config.TrustedProxyCIDRs); err != nil {
			log.Fatalf("failed to configure trusted proxies: %v", err)
		}
		log.Printf("[SECURITY] trusted proxies enabled: %s", strings.Join(config.TrustedProxyCIDRs, ","))
	}
	if config.ForwardInternalResponseHeaders {
		log.Println("[SECURITY][WARN] forwarding internal WAF response headers is enabled; use only behind a front proxy that strips them")
	}
	for _, warning := range config.AdminExposureWarnings() {
		log.Printf("[SECURITY][WARN] %s", warning)
	}

	// Lightweight unauthenticated probe for container health checks.
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if len(config.APICORSOrigins) > 0 {
		r.Use(cors.New(cors.Config{
			AllowOrigins:     config.APICORSOrigins,
			AllowMethods:     []string{"GET", "POST", "PUT", "OPTIONS"},
			AllowHeaders:     []string{"Origin", "Content-Type", "Accept", "X-API-Key", "X-CSRF-Token"},
			AllowCredentials: true,
		}))
		log.Printf("[SECURITY] CORS enabled for origins: %s", strings.Join(config.APICORSOrigins, ","))
	} else {
		log.Println("[SECURITY] CORS disabled (same-origin only)")
	}

	handler.RegisterAdminAuthRoutes(r)

	api := r.Group(config.APIBasePath, middleware.AdminAccess(middleware.AdminEndpointAPI), middleware.APIKeyAuth())
	{
		api.GET("/", func(c *gin.Context) {
			c.JSON(200, gin.H{
				"message": "tukuyomi-admin API",
				"endpoints": []string{
					config.APIBasePath + "/status",
					config.APIBasePath + "/logs",
					config.APIBasePath + "/rules",
					config.APIBasePath + "/crs-rule-sets",
					config.APIBasePath + "/bypass-rules",
					config.APIBasePath + "/cache-rules",
					config.APIBasePath + "/country-block-rules",
					config.APIBasePath + "/rate-limit-rules",
					config.APIBasePath + "/notifications",
					config.APIBasePath + "/notifications/status",
					config.APIBasePath + "/log-output",
					config.APIBasePath + "/ip-reputation",
					config.APIBasePath + "/ip-reputation:validate",
					config.APIBasePath + "/bot-defense-rules",
					config.APIBasePath + "/bot-defense-decisions",
					config.APIBasePath + "/semantic-rules",
					config.APIBasePath + "/verify-manifest",
					config.APIBasePath + "/fp-tuner/recent-waf-blocks",
					config.APIBasePath + "/fp-tuner/propose",
					config.APIBasePath + "/fp-tuner/apply",
					config.APIBasePath + "/logs/read",
					config.APIBasePath + "/logs/stats",
					config.APIBasePath + "/logs/download",
					config.APIBasePath + "/metrics",
				},
			})
		})

		api.GET("/status", handler.StatusHandler)
		api.GET("/metrics", handler.MetricsHandler)
		api.GET("/logs/read", handler.LogsRead)
		api.GET("/logs/stats", handler.LogsStats)
		api.GET("/logs/download", handler.LogsDownload)
		api.GET("/rules", handler.RulesHandler)
		api.POST("/rules:validate", handler.ValidateRules)
		api.PUT("/rules", handler.PutRules)
		api.GET("/crs-rule-sets", handler.GetCRSRuleSets)
		api.POST("/crs-rule-sets:validate", handler.ValidateCRSRuleSets)
		api.PUT("/crs-rule-sets", handler.PutCRSRuleSets)
		api.GET("/bypass-rules", handler.GetBypassRules)
		api.POST("/bypass-rules:validate", handler.ValidateBypassRules)
		api.PUT("/bypass-rules", handler.PutBypassRules)
		api.GET("/cache-rules", handler.GetCacheRules)
		api.POST("/cache-rules:validate", handler.ValidateCacheRules)
		api.PUT("/cache-rules", handler.PutCacheRules)
		api.GET("/country-block-rules", handler.GetCountryBlockRules)
		api.POST("/country-block-rules:validate", handler.ValidateCountryBlockRules)
		api.PUT("/country-block-rules", handler.PutCountryBlockRules)
		api.GET("/rate-limit-rules", handler.GetRateLimitRules)
		api.POST("/rate-limit-rules:validate", handler.ValidateRateLimitRules)
		api.PUT("/rate-limit-rules", handler.PutRateLimitRules)
		api.GET("/notifications", handler.GetNotificationRules)
		api.GET("/notifications/status", handler.GetNotificationStatusHandler)
		api.POST("/notifications/validate", handler.ValidateNotificationRules)
		api.POST("/notifications/test", handler.TestNotificationRules)
		api.PUT("/notifications", handler.PutNotificationRules)
		api.GET("/log-output", handler.GetLogOutputConfigHandler)
		api.POST("/log-output/validate", handler.ValidateLogOutputConfigHandler)
		api.PUT("/log-output", handler.PutLogOutputConfigHandler)
		api.GET("/ip-reputation", handler.GetIPReputation)
		api.POST("/ip-reputation:validate", handler.ValidateIPReputation)
		api.PUT("/ip-reputation", handler.PutIPReputation)
		api.GET("/bot-defense-rules", handler.GetBotDefenseRules)
		api.POST("/bot-defense-rules:validate", handler.ValidateBotDefenseRules)
		api.PUT("/bot-defense-rules", handler.PutBotDefenseRules)
		api.GET("/bot-defense-decisions", handler.GetBotDefenseDecisions)
		api.GET("/semantic-rules", handler.GetSemanticRules)
		api.POST("/semantic-rules:validate", handler.ValidateSemanticRules)
		api.PUT("/semantic-rules", handler.PutSemanticRules)
		api.GET("/verify-manifest", handler.GetVerifyManifest)
		api.GET("/fp-tuner/recent-waf-blocks", handler.GetFPTunerRecentWAFBlocks)
		api.POST("/fp-tuner/propose", handler.ProposeFPTuning)
		api.POST("/fp-tuner/apply", handler.ApplyFPTuning)
	}

	handler.RegisterAdminUIRoutes(r)
	handler.ConfigureResponseCache()

	r.NoRoute(func(c *gin.Context) {
		p := c.Request.URL.Path
		if strings.HasPrefix(p, config.APIBasePath) {
			c.AbortWithStatus(404)
			return
		}
		if p == config.UIBasePath || strings.HasPrefix(p, config.UIBasePath+"/") {
			c.AbortWithStatus(404)
			return
		}

		handler.ProxyHandler(c)
	})

	const cacheConfPath = "conf/cache.conf"
	if err := handler.SyncCacheRulesStorage(); err != nil {
		log.Printf("[CACHE][DB][WARN] sync failed (fallback=file): %v", err)
	}
	if config.DBEnabled && config.DBSyncInterval > 0 {
		handler.StartStorageSyncLoop(config.DBSyncInterval)
		log.Printf("[DB][SYNC] periodic sync loop enabled interval=%s", config.DBSyncInterval)
	}
	stopWatch, err := cacheconf.Watch(cacheConfPath, func(rs *cacheconf.Ruleset) {
		handler.InvalidateResponseCache()
		if rs != nil {
			log.Printf("[CACHE][RUNTIME] invalidated in-memory response cache after rules reload (%d rules)", len(rs.Rules))
		} else {
			log.Printf("[CACHE][RUNTIME] invalidated in-memory response cache after rules reload")
		}
	})
	if err != nil {
		log.Printf("[CACHE] watch disabled: %v", err)
	} else {
		defer stopWatch()
	}

	r.Run(":9090")
}
