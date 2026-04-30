package center

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path"
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
	DefaultListenAddr  = "127.0.0.1:9092"
	DefaultAPIBasePath = "/center-api"
	DefaultUIBasePath  = "/center-ui"

	ListenAddrEnv  = "TUKUYOMI_CENTER_LISTEN_ADDR"
	APIBasePathEnv = "TUKUYOMI_CENTER_API_BASE_PATH"
	UIBasePathEnv  = "TUKUYOMI_CENTER_UI_BASE_PATH"
)

var centerAdminAuthCookieNames = adminauth.CenterCookieNames()

type RuntimeConfig struct {
	ListenAddr  string
	APIBasePath string
	UIBasePath  string
}

func RuntimeConfigFromEnv() (RuntimeConfig, error) {
	cfg := RuntimeConfig{
		ListenAddr:  strings.TrimSpace(os.Getenv(ListenAddrEnv)),
		APIBasePath: strings.TrimSpace(os.Getenv(APIBasePathEnv)),
		UIBasePath:  strings.TrimSpace(os.Getenv(UIBasePathEnv)),
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
	cfg.APIBasePath = apiBase
	cfg.UIBasePath = uiBase
	return cfg, nil
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
		c.JSON(http.StatusOK, gin.H{"status": "ok", "mode": "center"})
	})

	registerDeviceEnrollmentRoutes(r)
	handler.RegisterAdminAuthRoutesAtWithCookieNames(r, apiBase, centerAdminAuthCookieNames)
	registerCenterAPI(r, apiBase)
	registerCenterUI(r, apiBase, uiBase)
	return r, nil
}

func Run(ctx context.Context, cfg RuntimeConfig) error {
	if err := InitializeRuntime(); err != nil {
		return err
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
		log.Printf("[CENTER] starting center server on %s ui=%s api=%s", addr, cfg.UIBasePath, cfg.APIBasePath)
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

func registerCenterAPI(r *gin.Engine, apiBase string) {
	api := r.Group(
		apiBase,
		handler.AdminAccessMiddleware("api"),
		handler.AdminRateLimitMiddleware(),
		handler.AdminAuthCookieNamesMiddleware(centerAdminAuthCookieNames),
		middleware.AdminAuthWithResolver(handler.DBAdminAuthResolverWithCookieNames(centerAdminAuthCookieNames)),
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
	api.GET("/auth/account", handler.GetAdminAccount)
	api.PUT("/auth/account", handler.PutAdminAccount)
	api.PUT("/auth/password", handler.PutAdminPassword)
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
