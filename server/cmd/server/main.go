package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/observability"
	"tukuyomi/internal/overloadstate"
	"tukuyomi/internal/serverruntime"
	"tukuyomi/internal/waf"
)

func main() {
	runMain(os.Args)
}

func runMain(args []string) {
	cmd, err := parseServerCommand(args)
	if err != nil {
		log.Fatalf("[FATAL] %v", err)
	}
	switch cmd.kind {
	case serverCommandCenter:
		runCenterCommand()
	case serverCommandReleaseMetadata:
		runReleaseMetadataCommand()
	case serverCommandValidateConfig:
		runValidateConfigCommand()
	case serverCommandReleaseStatus, serverCommandReleaseStage, serverCommandReleaseActivate, serverCommandReleaseRollback:
		runSupervisorReleaseClientCommand(cmd.kind, cmd.args)
	case serverCommandDBMigrate:
		runDBMigrateCommand()
	case serverCommandDBImport:
		runDBImportCommand()
	case serverCommandDBImportPreview:
		runDBImportPreviewCommand()
	case serverCommandDBImportWAFRuleAssets:
		runDBImportWAFRuleAssetsCommand()
	case serverCommandPreviewPrintTopology:
		runPreviewPrintTopologyCommand()
	case serverCommandRunScheduledTasks:
		runScheduledTasksCommand()
	case serverCommandUpdateCountryDB:
		runUpdateCountryDBCommand()
	case serverCommandBootstrapProtectedGateway:
		runBootstrapCenterProtectedGatewayCommand(cmd.args)
	case serverCommandBootstrapProtectedCenter:
		runBootstrapCenterProtectedCenterCommand(cmd.args)
	case serverCommandSupervisor:
		if err := runSupervisorServer(); err != nil {
			log.Fatalf("[SUPERVISOR][FATAL] %v", err)
		}
	case serverCommandWorker:
		notifier, err := newWorkerReadinessFromEnv()
		if err != nil {
			log.Fatalf("[WORKER][FATAL] readiness setup failed: %v", err)
		}
		runServer(notifier)
	default:
		runGatewayCommand()
	}
}

func runServer(workerReady *workerReadyNotifier) {
	runServerWithConfig(workerReady, false)
}

func runGatewayCommand() {
	config.LoadEnv()
	if config.RuntimeProcessModel == config.RuntimeProcessModelSupervised {
		if err := runSupervisorServer(); err != nil {
			log.Fatalf("[SUPERVISOR][FATAL] %v", err)
		}
		return
	}
	runServerWithConfig(nil, true)
}

func runServerWithConfig(workerReady *workerReadyNotifier, configLoaded bool) {
	if !configLoaded {
		config.LoadEnv()
	}
	if err := configureRuntimeAppProcessControllerForWorker(); err != nil {
		log.Fatalf("[RUNTIME_APPS][FATAL] configure process controller: %v", err)
	}
	runtimeAppsLocalOwner := runtimeAppsLocalProcessOwnerFromEnv(os.Environ())
	initRuntimeDBStoreOrFatal("[DB][BOOTSTRAP]")
	if err := handler.SyncAppConfigStorage(); err != nil {
		log.Fatalf("[CONFIG][DB][FATAL] sync failed: %v", err)
	}
	initRuntimeDBStoreOrFatal("[DB][INIT]")
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		log.Fatalf("[ADMIN][BOOTSTRAP][FATAL] %v", err)
	} else if created {
		log.Printf("[ADMIN][BOOTSTRAP] created initial owner from environment")
	}
	applyRuntimeResourceLimits()
	if err := handler.InitRequestCountryRuntime(); err != nil {
		log.Fatalf("[FATAL] failed to initialize request country runtime: %v", err)
	}
	if err := handler.InitPHPRuntimeInventoryRuntime(config.PHPRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[FATAL] failed to initialize php runtime inventory: %v", err)
	}
	if err := handler.InitPSGIRuntimeInventoryRuntime(config.PSGIRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[FATAL] failed to initialize psgi runtime inventory: %v", err)
	}
	if err := handler.InitScheduledTaskRuntime(config.ScheduledTaskConfigFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[FATAL] failed to initialize scheduled task runtime: %v", err)
	}
	if err := handler.InitVhostRuntime(config.VhostConfigFile, config.ProxyRollbackMax); err != nil {
		if handler.IsVhostStartupConfigError(err) {
			log.Printf("[RUNTIME_APPS][WARN] runtime apps degraded at startup: %v", err)
		} else {
			log.Fatalf("[FATAL] failed to initialize runtime apps: %v", err)
		}
	}
	runtimeAppsShutdown := func() {}
	fatalf := func(format string, args ...any) {
		runtimeAppsShutdown()
		log.Fatalf(format, args...)
	}
	if runtimeAppsLocalOwner {
		if err := handler.InitPHPRuntimeSupervisor(); err != nil {
			if shutdownErr := handler.ShutdownPHPRuntimeSupervisor(); shutdownErr != nil {
				log.Printf("[RUNTIME_APPS][WARN] shutdown php runtime supervisor after init failure: %v", shutdownErr)
			}
			log.Fatalf("[FATAL] failed to initialize php runtime supervisor: %v", err)
		}
		if err := handler.InitPSGIRuntimeSupervisor(); err != nil {
			if shutdownErr := handler.ShutdownPSGIRuntimeSupervisor(); shutdownErr != nil {
				log.Printf("[RUNTIME_APPS][WARN] shutdown psgi runtime supervisor after init failure: %v", shutdownErr)
			}
			if shutdownErr := handler.ShutdownPHPRuntimeSupervisor(); shutdownErr != nil {
				log.Printf("[RUNTIME_APPS][WARN] shutdown php runtime supervisor after psgi init failure: %v", shutdownErr)
			}
			log.Fatalf("[FATAL] failed to initialize psgi runtime supervisor: %v", err)
		}
		runtimeAppsShutdown = shutdownRuntimeAppSupervisors
	}
	defer runtimeAppsShutdown()
	if err := handler.InitSiteRuntime(config.SiteConfigFile, config.ProxyRollbackMax); err != nil {
		fatalf("[FATAL] failed to initialize site runtime: %v", err)
	}
	if err := handler.InitProxyRuntime(config.ProxyConfigFile, config.ProxyRollbackMax); err != nil {
		fatalf("[FATAL] failed to initialize proxy runtime: %v", err)
	}
	defer func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := handler.ShutdownWAFEventAsync(ctx); err != nil {
			log.Printf("[WAF_EVENT][WARN] shutdown async event writer: %v", err)
		}
	}()
	if err := handler.InitSecurityAuditRuntime(); err != nil {
		fatalf("[SECURITY_AUDIT][FATAL] failed to initialize runtime: %v", err)
	}
	if err := handler.SyncRuleFilesStorage(); err != nil {
		fatalf("[RULES][DB][FATAL] sync failed: %v", err)
	}
	if err := handler.SyncManagedOverrideRulesStorage(); err != nil {
		fatalf("[OVERRIDE_RULES][DB][FATAL] sync failed: %v", err)
	}
	waf.InitWAF()
	if err := handler.SyncCRSDisabledStorage(); err != nil {
		fatalf("[CRS][DB][FATAL] sync failed: %v", err)
	}
	if err := handler.SyncBypassStorage(); err != nil {
		fatalf("[BYPASS][DB][FATAL] sync failed: %v", err)
	}
	if err := handler.InitCountryBlock(config.CountryBlockFile, config.LegacyCompatPath(config.CountryBlockFile, config.DefaultCountryBlockFilePath, config.LegacyDefaultCountryBlockPath)); err != nil {
		log.Printf("[COUNTRY_BLOCK][INIT][ERR] %v (path=%s)", err, config.CountryBlockFile)
	} else {
		if err := handler.SyncCountryBlockStorage(); err != nil {
			fatalf("[COUNTRY_BLOCK][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[COUNTRY_BLOCK][INIT] configured=%s active=%s countries=%d", config.CountryBlockFile, handler.GetCountryBlockActivePath(), len(handler.GetBlockedCountries()))
	}
	if err := handler.InitRateLimit(config.RateLimitFile); err != nil {
		log.Printf("[RATE_LIMIT][INIT][ERR] %v (path=%s)", err, config.RateLimitFile)
	} else {
		if err := handler.SyncRateLimitStorage(); err != nil {
			fatalf("[RATE_LIMIT][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[RATE_LIMIT][INIT] loaded")
	}
	if err := handler.InitBotDefense(config.BotDefenseFile); err != nil {
		log.Printf("[BOT_DEFENSE][INIT][ERR] %v (path=%s)", err, config.BotDefenseFile)
	} else {
		if err := handler.SyncBotDefenseStorage(); err != nil {
			fatalf("[BOT_DEFENSE][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[BOT_DEFENSE][INIT] loaded")
	}
	if err := handler.InitSemantic(config.SemanticFile); err != nil {
		log.Printf("[SEMANTIC][INIT][ERR] %v (path=%s)", err, config.SemanticFile)
	} else {
		if err := handler.SyncSemanticStorage(); err != nil {
			fatalf("[SEMANTIC][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[SEMANTIC][INIT] loaded")
	}
	handler.SetNotificationProductLabel("proxy")
	if err := handler.InitNotifications(config.NotificationFile); err != nil {
		log.Printf("[NOTIFY][INIT][ERR] %v (path=%s)", err, config.NotificationFile)
	} else {
		if err := handler.SyncNotificationStorage(); err != nil {
			fatalf("[NOTIFY][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[NOTIFY][INIT] loaded")
	}
	if err := handler.InitIPReputation(config.IPReputationFile); err != nil {
		log.Printf("[IP_REPUTATION][INIT][ERR] %v (path=%s)", err, config.IPReputationFile)
	} else {
		if err := handler.SyncIPReputationStorage(); err != nil {
			fatalf("[IP_REPUTATION][DB][FATAL] sync failed: %v", err)
		}
		log.Printf("[IP_REPUTATION][INIT] loaded")
	}
	if err := handler.InitAdminGuards(); err != nil {
		fatalf("[ADMIN][FATAL] failed to initialize admin guards: %v", err)
	}
	shutdownTracing, err := observability.SetupTracing(context.Background(), observability.TracingConfig{
		Enabled:      config.TracingEnabled,
		ServiceName:  config.TracingServiceName,
		OTLPEndpoint: config.TracingOTLPEndpoint,
		Insecure:     config.TracingInsecure,
		SampleRatio:  config.TracingSampleRatio,
	})
	if err != nil {
		fatalf("[TRACING][FATAL] initialize tracing: %v", err)
	}
	defer func() {
		if err := shutdownTracing(context.Background()); err != nil {
			log.Printf("[TRACING][WARN] shutdown tracing: %v", err)
		}
	}()
	shutdownPprof, err := startOptionalPprofServerFromEnv()
	if err != nil {
		fatalf("[PPROF][FATAL] initialize pprof server: %v", err)
	}
	defer func() {
		if err := shutdownPprof(context.Background()); err != nil {
			log.Printf("[PPROF][WARN] shutdown pprof server: %v", err)
		}
	}()

	_, _, proxyCfg, _, _ := handler.ProxyRulesSnapshot()
	log.Printf("[INFO] WAF upstreams configured=%d", len(proxyCfg.Upstreams))

	globalConcurrencyGuard := middleware.NewQueuedConcurrencyGuard(
		config.ServerMaxConcurrentReqs,
		config.ServerMaxQueuedReqs,
		config.ServerQueuedRequestTimeout,
		"global",
	)
	if globalConcurrencyGuard != nil {
		log.Printf(
			"[SERVER] global concurrency guard enabled max=%d queue=%d timeout=%s",
			config.ServerMaxConcurrentReqs,
			config.ServerMaxQueuedReqs,
			queueTimeoutLogValue(config.ServerQueuedRequestTimeout),
		)
	}
	proxyConcurrencyGuard := middleware.NewQueuedConcurrencyGuard(
		config.ServerMaxConcurrentProxy,
		config.ServerMaxQueuedProxy,
		config.ServerQueuedProxyRequestTimeout,
		"proxy",
	)
	if proxyConcurrencyGuard != nil {
		log.Printf(
			"[SERVER] proxy concurrency guard enabled max=%d queue=%d timeout=%s",
			config.ServerMaxConcurrentProxy,
			config.ServerMaxQueuedProxy,
			queueTimeoutLogValue(config.ServerQueuedProxyRequestTimeout),
		)
	}
	overloadstate.SetProvider(func() map[string]middleware.ConcurrencyGuardSnapshot {
		return map[string]middleware.ConcurrencyGuardSnapshot{
			"global": middleware.SnapshotOrDisabled(
				globalConcurrencyGuard,
				"global",
				config.ServerMaxConcurrentReqs,
				config.ServerMaxQueuedReqs,
				config.ServerQueuedRequestTimeout,
			),
			"proxy": middleware.SnapshotOrDisabled(
				proxyConcurrencyGuard,
				"proxy",
				config.ServerMaxConcurrentProxy,
				config.ServerMaxQueuedProxy,
				config.ServerQueuedProxyRequestTimeout,
			),
		}
	})

	if err := handler.InitResponseCacheRuntime(config.CacheStoreFile); err != nil {
		fatalf("[CACHE][FATAL] failed to initialize response cache runtime: %v", err)
	}
	if err := handler.SyncResponseCacheStoreStorage(); err != nil {
		fatalf("[CACHE][DB][FATAL] sync failed: %v", err)
	}

	if err := handler.SyncCacheRulesStorage(); err != nil {
		fatalf("[CACHE][DB][FATAL] sync failed: %v", err)
	}
	if config.DBSyncInterval > 0 {
		if err := runAfterWorkerActivation("storage sync loop", func() {
			handler.StartStorageSyncLoop(config.DBSyncInterval)
			log.Printf("[DB][SYNC] periodic sync loop enabled interval=%s", config.DBSyncInterval)
		}); err != nil {
			fatalf("[WORKER][ACTIVATION][FATAL] storage sync loop activation setup failed: %v", err)
		}
	}
	if err := runAfterWorkerActivation("edge device status refresh loop", func() {
		handler.StartEdgeDeviceStatusRefreshLoop(config.EdgeDeviceStatusRefreshInterval)
	}); err != nil {
		fatalf("[WORKER][ACTIVATION][FATAL] edge status refresh loop activation setup failed: %v", err)
	}
	if !handler.DBStorageActive() {
		cacheConfPath := strings.TrimSpace(config.CacheRulesFile)
		if cacheConfPath == "" {
			cacheConfPath = config.DefaultCacheRulesFilePath
		}
		legacyCacheConfPath := config.LegacyCompatPath(cacheConfPath, config.DefaultCacheRulesFilePath, config.LegacyDefaultCacheRulesPath)
		stopWatch, err := cacheconf.Watch(cacheConfPath, legacyCacheConfPath, func(rs *cacheconf.Ruleset) {
			//
		})
		if err != nil {
			log.Printf("[CACHE] watch disabled: %v", err)
		} else {
			defer stopWatch()
		}
	}

	splitAdminListener := strings.TrimSpace(config.AdminListenAddr) != ""
	if len(config.APICORSOrigins) > 0 {
		log.Printf("[SECURITY] CORS enabled for origins: %s", strings.Join(config.APICORSOrigins, ","))
	} else {
		log.Println("[SECURITY] CORS disabled (same-origin only)")
	}
	publicHandler, err := buildPublicHandler(globalConcurrencyGuard, proxyConcurrencyGuard, splitAdminListener)
	if err != nil {
		fatalf("failed to build public handler: %v", err)
	}
	var adminEngine *gin.Engine
	if splitAdminListener {
		adminEngine, err = buildAdminEngine(globalConcurrencyGuard)
		if err != nil {
			fatalf("failed to build admin engine: %v", err)
		}
	}
	publicListenerRuntime := listenerProxyProtocolRuntime{
		enabled:           config.ServerProxyProtocolEnabled,
		trustedCIDRs:      config.ServerProxyProtocolTrustedCIDRs,
		readHeaderTimeout: config.ServerReadHeaderTimeout,
	}
	adminListenerRuntime := listenerProxyProtocolRuntime{
		enabled:           config.AdminProxyProtocolEnabled,
		trustedCIDRs:      config.AdminProxyProtocolTrustedCIDRs,
		readHeaderTimeout: config.ServerReadHeaderTimeout,
	}
	activation, err := loadSystemdActivationFromEnv()
	if err != nil {
		fatalf("[FATAL] load systemd socket activation: %v", err)
	}
	if activation.Active() {
		log.Printf("[SERVER] systemd socket activation enabled fds=%d", len(activation.fds))
	}
	lifecycle := newManagedServerLifecycle(config.ServerGracefulShutdownTimeout)
	sigCh, cleanupSignals, err := newServerSignalChannel()
	if err != nil {
		fatalf("[FATAL] initialize server signals: %v", err)
	}
	defer cleanupSignals()

	publicSrv := &handler.NativeHTTP1Server{
		Handler:           publicHandler,
		ReadTimeout:       config.ServerReadTimeout,
		ReadHeaderTimeout: config.ServerReadHeaderTimeout,
		WriteTimeout:      config.ServerWriteTimeout,
		IdleTimeout:       config.ServerIdleTimeout,
		MaxHeaderBytes:    config.ServerMaxHeaderBytes,
	}
	handler.RegisterNativeHTTP1ServerMetricsSource(publicSrv)
	serverruntime.ResetHTTP3Status()
	if splitAdminListener {
		adminListener, inherited, err := buildManagedTCPListenerForRole("admin", config.AdminListenAddr, adminListenerRuntime, activation)
		if err != nil {
			fatalf("[FATAL] create admin listener: %v", err)
		}
		adminListener = lifecycle.TrackListener("admin", adminListener)
		adminSrv := &http.Server{
			Addr:              config.AdminListenAddr,
			Handler:           adminEngine,
			ReadTimeout:       config.ServerReadTimeout,
			ReadHeaderTimeout: config.ServerReadHeaderTimeout,
			WriteTimeout:      config.ServerWriteTimeout,
			IdleTimeout:       config.ServerIdleTimeout,
			MaxHeaderBytes:    config.ServerMaxHeaderBytes,
		}
		lifecycle.Go("admin", func() error {
			log.Printf("[INFO] starting admin HTTP server on %s inherited=%t", config.AdminListenAddr, inherited)
			if config.AdminProxyProtocolEnabled {
				log.Printf("[SERVER] admin proxy protocol enabled trusted_cidrs=%s", strings.Join(config.AdminProxyProtocolTrustedCIDRs, ","))
			}
			return adminSrv.Serve(adminListener)
		}, adminSrv.Shutdown, adminSrv.Close)
	}

	publicListener, publicInherited, err := buildManagedTCPListenerForRole("public", config.ListenAddr, publicListenerRuntime, activation)
	if err != nil {
		fatalf("[FATAL] create public listener: %v", err)
	}
	publicListener = lifecycle.TrackListener("public", publicListener)

	if config.ServerTLSEnabled {
		tlsConfig, redirectSrv, err := buildManagedServerTLSConfig()
		if err != nil {
			fatalf("[FATAL] build server tls config: %v", err)
		}
		http3Srv, altSvc, err := buildManagedServerHTTP3Server(tlsConfig, publicHandler)
		if err != nil {
			fatalf("[FATAL] build server http3 config: %v", err)
		}
		if altSvc != "" {
			publicSrv.Handler = wrapHTTP3AltSvcHandler(publicHandler, altSvc)
		}
		if redirectSrv != nil {
			redirectListener, redirectInherited, err := buildManagedTCPListenerForRole("redirect", config.ServerTLSHTTPRedirectAddr, publicListenerRuntime, activation)
			if err != nil {
				fatalf("[FATAL] create redirect listener: %v", err)
			}
			redirectListener = lifecycle.TrackListener("redirect", redirectListener)
			lifecycle.Go("redirect", func() error {
				log.Printf("[INFO] starting HTTP redirect server on %s inherited=%t", config.ServerTLSHTTPRedirectAddr, redirectInherited)
				if config.ServerProxyProtocolEnabled {
					log.Printf("[SERVER] public proxy protocol enabled trusted_cidrs=%s", strings.Join(config.ServerProxyProtocolTrustedCIDRs, ","))
				}
				return redirectSrv.Serve(redirectListener)
			}, redirectSrv.Shutdown, redirectSrv.Close)
		}
		if err := runHTTP3Server(lifecycle, activation, http3Srv); err != nil {
			fatalf("[FATAL] start HTTP/3 server: %v", err)
		}
		log.Printf("[INFO] starting HTTPS server on %s inherited=%t engine=native_http1", config.ListenAddr, publicInherited)
		log.Printf("[SERVER] tls enabled source=%s cert_file=%s acme_domains=%s min_version=%s redirect_http=%t redirect_addr=%s",
			handler.ServerTLSRuntimeStatusSnapshot().Source,
			config.ServerTLSCertFile,
			strings.Join(handler.EffectiveServerTLSACMEDomains(), ","),
			config.ServerTLSMinVersion,
			config.ServerTLSRedirectHTTP,
			config.ServerTLSHTTPRedirectAddr,
		)
		if config.ServerHTTP3Enabled {
			http3Status := serverruntime.HTTP3StatusSnapshot()
			log.Printf("[SERVER] http3 enabled alt_svc_max_age=%d advertised=%t alt_svc=%q",
				config.ServerHTTP3AltSvcMaxAgeSec,
				http3Status.Advertised,
				http3Status.AltSvc,
			)
		}
		log.Printf("[SERVER] read_timeout=%s read_header_timeout=%s write_timeout=%s idle_timeout=%s max_header_bytes=%d",
			config.ServerReadTimeout,
			config.ServerReadHeaderTimeout,
			config.ServerWriteTimeout,
			config.ServerIdleTimeout,
			config.ServerMaxHeaderBytes,
		)
		if config.ServerProxyProtocolEnabled {
			log.Printf("[SERVER] public proxy protocol enabled trusted_cidrs=%s", strings.Join(config.ServerProxyProtocolTrustedCIDRs, ","))
		}
		lifecycle.Go("public", func() error {
			return publicSrv.ServeTLS(publicListener, tlsConfig)
		}, publicSrv.Shutdown, publicSrv.Close)
		activation.CloseUnused()
		if err := notifyWorkerReady(workerReady); err != nil {
			fatalf("[WORKER][FATAL] readiness notify failed: %v", err)
		}
		if err := lifecycle.WaitWithSignals(sigCh); err != nil {
			fatalf("[FATAL] server lifecycle stopped: %v", err)
		}
		return
	}

	log.Printf("[INFO] starting server on %s inherited=%t engine=native_http1", config.ListenAddr, publicInherited)
	log.Printf("[SERVER] read_timeout=%s read_header_timeout=%s write_timeout=%s idle_timeout=%s max_header_bytes=%d",
		config.ServerReadTimeout,
		config.ServerReadHeaderTimeout,
		config.ServerWriteTimeout,
		config.ServerIdleTimeout,
		config.ServerMaxHeaderBytes,
	)
	if config.ServerProxyProtocolEnabled {
		log.Printf("[SERVER] public proxy protocol enabled trusted_cidrs=%s", strings.Join(config.ServerProxyProtocolTrustedCIDRs, ","))
	}
	lifecycle.Go("public", func() error {
		return publicSrv.Serve(publicListener)
	}, publicSrv.Shutdown, publicSrv.Close)
	activation.CloseUnused()
	if err := notifyWorkerReady(workerReady); err != nil {
		fatalf("[WORKER][FATAL] readiness notify failed: %v", err)
	}
	if err := lifecycle.WaitWithSignals(sigCh); err != nil {
		fatalf("[FATAL] server lifecycle stopped: %v", err)
	}
}

func runUpdateCountryDBCommand() {
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[COUNTRY_DB][DB]")
	if err := handler.SyncAppConfigStorage(); err != nil {
		log.Fatalf("[COUNTRY_DB][CONFIG][FATAL] sync failed: %v", err)
	}
	if err := handler.RunManagedRequestCountryUpdateNow(context.Background()); err != nil {
		log.Fatalf("[FATAL] update-country-db failed: %v", err)
	}
	log.Printf("[COUNTRY_DB] update completed")
}

func runDBMigrateCommand() {
	config.LoadEnv()
	if err := handler.MigrateLogsStatsStoreWithBackend(
		"db",
		config.DBDriver,
		config.DBPath,
		config.DBDSN,
	); err != nil {
		log.Fatalf("[DB][MIGRATE][FATAL] %v", err)
	}
	log.Printf("[DB][MIGRATE] completed (driver=%s path=%s)", config.DBDriver, config.DBPath)
}

func runDBImportCommand() {
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[DB][IMPORT]")
	if err := handler.ImportStartupConfigStorage(); err != nil {
		log.Fatalf("[DB][IMPORT][FATAL] %v", err)
	}
	log.Printf("[DB][IMPORT] completed")
}

func runDBImportWAFRuleAssetsCommand() {
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[DB][IMPORT][WAF_RULE_ASSETS]")
	if err := handler.ImportWAFRuleAssetsStorage(); err != nil {
		log.Fatalf("[DB][IMPORT][WAF_RULE_ASSETS][FATAL] %v", err)
	}
	log.Printf("[DB][IMPORT][WAF_RULE_ASSETS] completed")
}

func runScheduledTasksCommand() {
	config.LoadEnv()
	initRuntimeDBStoreOrFatal("[SCHEDULE][DB][BOOTSTRAP]")
	if err := handler.SyncAppConfigStorage(); err != nil {
		log.Fatalf("[SCHEDULE][CONFIG][FATAL] sync failed: %v", err)
	}
	initRuntimeDBStoreOrFatal("[SCHEDULE][DB]")
	if err := handler.InitPHPRuntimeInventoryRuntime(config.PHPRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[SCHEDULE][FATAL] initialize php runtime inventory: %v", err)
	}
	if err := handler.InitPSGIRuntimeInventoryRuntime(config.PSGIRuntimeInventoryFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[SCHEDULE][FATAL] initialize psgi runtime inventory: %v", err)
	}
	if err := handler.InitScheduledTaskRuntime(config.ScheduledTaskConfigFile, config.ProxyRollbackMax); err != nil {
		log.Fatalf("[SCHEDULE][FATAL] initialize scheduled task runtime: %v", err)
	}
	if err := handler.RunDueScheduledTasks(time.Now()); err != nil {
		log.Fatalf("[SCHEDULE][FATAL] %v", err)
	}
}

func applyRuntimeResourceLimits() {
	if config.RuntimeGOMAXPROCS > 0 {
		prev := runtime.GOMAXPROCS(config.RuntimeGOMAXPROCS)
		log.Printf("[RUNTIME] GOMAXPROCS set to %d (previous=%d)", config.RuntimeGOMAXPROCS, prev)
	}
	if config.RuntimeMemoryLimitMB > 0 {
		limitBytes := int64(config.RuntimeMemoryLimitMB) * 1024 * 1024
		prev := debug.SetMemoryLimit(limitBytes)
		log.Printf("[RUNTIME] memory limit set to %d MB (previous=%d MB)", config.RuntimeMemoryLimitMB, prev/(1024*1024))
	}
}

func initRuntimeDBStoreOrFatal(prefix string) {
	if err := handler.InitLogsStatsStoreWithBackend(
		"db",
		config.DBDriver,
		config.DBPath,
		config.DBDSN,
		config.DBRetentionDays,
	); err != nil {
		log.Fatalf("%s[FATAL] failed to initialize db store: %v", prefix, err)
	}
	log.Printf("%s db store enabled (driver=%s path=%s retention_days=%d)", prefix, config.DBDriver, config.DBPath, config.DBRetentionDays)
}

func shutdownRuntimeAppSupervisors() {
	if err := handler.ShutdownPSGIRuntimeSupervisor(); err != nil {
		log.Printf("[RUNTIME_APPS][WARN] shutdown psgi runtime supervisor: %v", err)
	}
	if err := handler.ShutdownPHPRuntimeSupervisor(); err != nil {
		log.Printf("[RUNTIME_APPS][WARN] shutdown php runtime supervisor: %v", err)
	}
}

func queueTimeoutLogValue(timeout time.Duration) string {
	if timeout <= 0 {
		return "disabled"
	}
	return timeout.String()
}
