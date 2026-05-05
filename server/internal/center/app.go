package center

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
	"strconv"
	"strings"
	"syscall"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/adminauth"
	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/config"
	"tukuyomi/internal/handler"
	"tukuyomi/internal/middleware"
	"tukuyomi/internal/observability"
)

const (
	DefaultListenAddr         = "127.0.0.1:9092"
	DefaultAPIBasePath        = "/center-api"
	DefaultGatewayAPIBasePath = "/center-api"
	DefaultUIBasePath         = "/center-ui"

	ListenAddrEnv         = "TUKUYOMI_CENTER_LISTEN_ADDR"
	APIBasePathEnv        = "TUKUYOMI_CENTER_API_BASE_PATH"
	GatewayAPIBasePathEnv = "TUKUYOMI_CENTER_GATEWAY_API_BASE_PATH"
	UIBasePathEnv         = "TUKUYOMI_CENTER_UI_BASE_PATH"

	TLSEnabledEnv    = "TUKUYOMI_CENTER_TLS_ENABLED"
	TLSCertFileEnv   = "TUKUYOMI_CENTER_TLS_CERT_FILE"
	TLSKeyFileEnv    = "TUKUYOMI_CENTER_TLS_KEY_FILE"
	TLSMinVersionEnv = "TUKUYOMI_CENTER_TLS_MIN_VERSION"

	ClientAllowCIDRsEnv    = "TUKUYOMI_CENTER_CLIENT_ALLOW_CIDRS"
	ManageAPIAllowCIDRsEnv = "TUKUYOMI_CENTER_MANAGE_API_ALLOW_CIDRS"
	CenterAPIAllowCIDRsEnv = "TUKUYOMI_CENTER_API_ALLOW_CIDRS"
)

var centerAdminAuthCookieNames = adminauth.CenterCookieNames()

type RuntimeConfig struct {
	ListenAddr          string
	APIBasePath         string
	GatewayAPIBasePath  string
	UIBasePath          string
	TLSEnabled          bool
	TLSCertFile         string
	TLSKeyFile          string
	TLSMinVersion       string
	ClientAllowCIDRs    []string
	ManageAPIAllowCIDRs []string
	CenterAPIAllowCIDRs []string
}

func RuntimeConfigFromEnv() (RuntimeConfig, error) {
	tlsEnabled, err := parseCenterBoolEnv(TLSEnabledEnv, false)
	if err != nil {
		return RuntimeConfig{}, err
	}
	cfg := RuntimeConfig{
		ListenAddr:         strings.TrimSpace(os.Getenv(ListenAddrEnv)),
		APIBasePath:        strings.TrimSpace(os.Getenv(APIBasePathEnv)),
		GatewayAPIBasePath: strings.TrimSpace(os.Getenv(GatewayAPIBasePathEnv)),
		UIBasePath:         strings.TrimSpace(os.Getenv(UIBasePathEnv)),
		TLSEnabled:         tlsEnabled,
		TLSCertFile:        strings.TrimSpace(os.Getenv(TLSCertFileEnv)),
		TLSKeyFile:         strings.TrimSpace(os.Getenv(TLSKeyFileEnv)),
		TLSMinVersion:      normalizeCenterTLSMinVersion(os.Getenv(TLSMinVersionEnv)),
	}
	if err := validateCenterTLSMinVersion(cfg.TLSMinVersion); err != nil {
		return RuntimeConfig{}, fmt.Errorf("%s %w", TLSMinVersionEnv, err)
	}
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = DefaultListenAddr
	}
	apiBase, err := normalizeBasePath(cfg.APIBasePath, DefaultAPIBasePath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("%s: %w", APIBasePathEnv, err)
	}
	uiBase, err := normalizeBasePath(cfg.UIBasePath, DefaultUIBasePath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("%s: %w", UIBasePathEnv, err)
	}
	if apiBase == uiBase {
		return RuntimeConfig{}, fmt.Errorf("center api and ui base paths must differ")
	}
	gatewayAPIBase, err := normalizeBasePath(cfg.GatewayAPIBasePath, DefaultGatewayAPIBasePath)
	if err != nil {
		return RuntimeConfig{}, fmt.Errorf("%s: %w", GatewayAPIBasePathEnv, err)
	}
	if gatewayAPIBase == uiBase {
		return RuntimeConfig{}, fmt.Errorf("center gateway api and ui base paths must differ")
	}
	if cfg.TLSEnabled {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return RuntimeConfig{}, fmt.Errorf("%s and %s are required when %s=true", TLSCertFileEnv, TLSKeyFileEnv, TLSEnabledEnv)
		}
		if _, err := config.BuildServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSMinVersion); err != nil {
			return RuntimeConfig{}, fmt.Errorf("center TLS: %w", err)
		}
	}
	clientAllowCIDRs, err := parseCenterSourceCIDREnv(ClientAllowCIDRsEnv, nil)
	if err != nil {
		return RuntimeConfig{}, err
	}
	manageAPIAllowCIDRs, err := parseCenterSourceCIDREnv(ManageAPIAllowCIDRsEnv, defaultCenterManageAPIAllowCIDRs)
	if err != nil {
		return RuntimeConfig{}, err
	}
	centerAPIAllowCIDRs, err := parseCenterSourceCIDREnv(CenterAPIAllowCIDRsEnv, nil)
	if err != nil {
		return RuntimeConfig{}, err
	}
	cfg.APIBasePath = apiBase
	cfg.GatewayAPIBasePath = gatewayAPIBase
	cfg.UIBasePath = uiBase
	cfg.ClientAllowCIDRs = clientAllowCIDRs
	cfg.ManageAPIAllowCIDRs = manageAPIAllowCIDRs
	cfg.CenterAPIAllowCIDRs = centerAPIAllowCIDRs
	return cfg, nil
}

func parseCenterBoolEnv(name string, fallback bool) (bool, error) {
	raw := strings.TrimSpace(os.Getenv(name))
	if raw == "" {
		return fallback, nil
	}
	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s must be a boolean", name)
	}
	return parsed, nil
}

func InitializeRuntime() error {
	if err := handler.InitLogsStatsStoreWithBackend(
		"db",
		config.DBDriver,
		config.DBPath,
		config.DBDSN,
		config.DBRetentionDays,
	); err != nil {
		return fmt.Errorf("initialize center db store: %w", err)
	}
	if created, err := handler.EnsureAdminBootstrapOwnerFromEnv(); err != nil {
		return fmt.Errorf("bootstrap center admin owner: %w", err)
	} else if created {
		log.Printf("[CENTER][ADMIN] created initial owner from environment")
	}
	if err := handler.InitAdminGuards(); err != nil {
		return fmt.Errorf("initialize center admin guards: %w", err)
	}
	return nil
}

func NewEngine(cfg RuntimeConfig) (*gin.Engine, error) {
	apiBase, err := normalizeBasePath(cfg.APIBasePath, DefaultAPIBasePath)
	if err != nil {
		return nil, err
	}
	uiBase, err := normalizeBasePath(cfg.UIBasePath, DefaultUIBasePath)
	if err != nil {
		return nil, err
	}
	if apiBase == uiBase {
		return nil, fmt.Errorf("center api and ui base paths must differ")
	}
	gatewayAPIBase, err := normalizeBasePath(cfg.GatewayAPIBasePath, DefaultGatewayAPIBasePath)
	if err != nil {
		return nil, err
	}
	if gatewayAPIBase == uiBase {
		return nil, fmt.Errorf("center gateway api and ui base paths must differ")
	}
	allowlists, err := compileCenterSourceAllowlists(RuntimeConfig{
		ClientAllowCIDRs:    cfg.ClientAllowCIDRs,
		ManageAPIAllowCIDRs: cfg.ManageAPIAllowCIDRs,
		CenterAPIAllowCIDRs: cfg.CenterAPIAllowCIDRs,
	})
	if err != nil {
		return nil, err
	}

	r := gin.New()
	if config.RequestLogEnabled {
		r.Use(gin.Logger())
	}
	r.Use(gin.Recovery())
	r.Use(observability.GinTracingMiddleware())
	r.Use(centerSourceAllowlistMiddleware(apiBase, uiBase, allowlists))
	if err := r.SetTrustedProxies(nil); err != nil {
		return nil, err
	}
	r.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": "center"})
	})

	registerDeviceEnrollmentRoutes(r)
	handler.RegisterRequiredAdminAuthRoutesAtWithCookieNames(r, apiBase, centerAdminAuthCookieNames)
	registerCenterAPI(r, RuntimeConfig{
		ListenAddr:          strings.TrimSpace(cfg.ListenAddr),
		APIBasePath:         apiBase,
		GatewayAPIBasePath:  gatewayAPIBase,
		UIBasePath:          uiBase,
		TLSEnabled:          cfg.TLSEnabled,
		TLSCertFile:         strings.TrimSpace(cfg.TLSCertFile),
		TLSKeyFile:          strings.TrimSpace(cfg.TLSKeyFile),
		TLSMinVersion:       cfg.TLSMinVersion,
		ClientAllowCIDRs:    append([]string(nil), cfg.ClientAllowCIDRs...),
		ManageAPIAllowCIDRs: append([]string(nil), cfg.ManageAPIAllowCIDRs...),
		CenterAPIAllowCIDRs: append([]string(nil), cfg.CenterAPIAllowCIDRs...),
	})
	registerCenterUI(r, apiBase, gatewayAPIBase, uiBase)
	return r, nil
}

func Run(ctx context.Context, cfg RuntimeConfig) error {
	if err := InitializeRuntime(); err != nil {
		return err
	}
	settings, _, found, err := loadCenterSettings(ctx)
	if err != nil {
		return fmt.Errorf("load center settings: %w", err)
	}
	if found {
		if err := applyCenterMutableSettings(settings); err != nil {
			return err
		}
		cfg, err = applyCenterRuntimeSettings(cfg, settings)
		if err != nil {
			return err
		}
	}
	r, err := NewEngine(cfg)
	if err != nil {
		return err
	}

	addr := strings.TrimSpace(cfg.ListenAddr)
	if addr == "" {
		addr = DefaultListenAddr
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen center: %w", err)
	}
	defer listener.Close()

	srv := &http.Server{
		Addr:              addr,
		Handler:           r,
		ReadTimeout:       config.ServerReadTimeout,
		ReadHeaderTimeout: config.ServerReadHeaderTimeout,
		WriteTimeout:      config.ServerWriteTimeout,
		IdleTimeout:       config.ServerIdleTimeout,
		MaxHeaderBytes:    config.ServerMaxHeaderBytes,
	}

	runCtx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		if cfg.TLSEnabled {
			tlsConfig, err := config.BuildServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSMinVersion)
			if err != nil {
				errCh <- fmt.Errorf("center TLS: %w", err)
				return
			}
			srv.TLSConfig = tlsConfig
			log.Printf("[CENTER] starting center TLS server on %s ui=%s api=%s gateway_api=%s", addr, cfg.UIBasePath, cfg.APIBasePath, cfg.GatewayAPIBasePath)
			errCh <- srv.Serve(tls.NewListener(listener, tlsConfig))
			return
		}
		log.Printf("[CENTER] starting center server on %s ui=%s api=%s gateway_api=%s", addr, cfg.UIBasePath, cfg.APIBasePath, cfg.GatewayAPIBasePath)
		errCh <- srv.Serve(listener)
	}()

	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-runCtx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), config.ServerGracefulShutdownTimeout)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			_ = srv.Close()
			return err
		}
		return nil
	}
}

func registerCenterAPI(r *gin.Engine, runtimeCfg RuntimeConfig) {
	apiBase := runtimeCfg.APIBasePath
	api := r.Group(
		apiBase,
		handler.AdminAccessMiddleware("api"),
		handler.AdminRateLimitMiddleware(),
		handler.AdminAuthCookieNamesMiddleware(centerAdminAuthCookieNames),
		middleware.AdminAuthRequiredWithResolver(handler.DBAdminAuthResolverWithCookieNames(centerAdminAuthCookieNames)),
	)
	api.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"message": "tukuyomi-center API",
			"endpoints": []string{
				apiBase + "/status",
				apiBase + "/auth/session",
				apiBase + "/auth/login",
				apiBase + "/auth/logout",
				apiBase + "/auth/account",
				apiBase + "/auth/password",
				apiBase + "/auth/api-tokens",
				apiBase + "/settings",
				apiBase + "/devices",
				apiBase + "/devices/enrollments",
				apiBase + "/enrollment-tokens",
			},
		})
	})
	api.GET("/status", func(c *gin.Context) {
		counts, err := CenterCounts(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load center status"})
			return
		}
		c.JSON(http.StatusOK, gin.H{
			"status":               "running",
			"mode":                 "center",
			"version":              buildinfo.Version,
			"total_devices":        counts.TotalDevices,
			"approved_devices":     counts.ApprovedDevices,
			"pending_enrollments":  counts.PendingEnrollments,
			"rejected_enrollments": counts.RejectedEnrollments,
		})
	})
	api.GET("/settings", getCenterSettings(runtimeCfg))
	api.PUT("/settings", putCenterSettings(runtimeCfg))
	api.GET("/auth/account", handler.GetAdminAccount)
	api.PUT("/auth/account", handler.PutAdminAccount)
	api.PUT("/auth/password", handler.PutAdminPassword)
	api.GET("/auth/api-tokens", handler.GetAdminAPITokens)
	api.POST("/auth/api-tokens", handler.PostAdminAPIToken)
	api.POST("/auth/api-tokens/:token_id/revoke", handler.PostAdminAPITokenRevoke)
	registerCenterDeviceAdminRoutes(api)
}

func normalizeBasePath(raw, fallback string) (string, error) {
	base := strings.TrimSpace(raw)
	if base == "" {
		base = fallback
	}
	if base == "" {
		return "", fmt.Errorf("base path is empty")
	}
	if !strings.HasPrefix(base, "/") {
		base = "/" + base
	}
	for _, segment := range strings.Split(base, "/") {
		switch segment {
		case ".", "..":
			return "", fmt.Errorf("base path must not contain dot segments")
		}
	}
	clean := path.Clean(base)
	if clean == "." || clean == "/" {
		return "", fmt.Errorf("base path must not be root")
	}
	if strings.Contains(clean, "*") {
		return "", fmt.Errorf("base path must not contain wildcard")
	}
	return clean, nil
}
