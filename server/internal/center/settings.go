package center

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"

	"tukuyomi/internal/buildinfo"
	"tukuyomi/internal/config"
)

type centerSettingsRuntime struct {
	Mode          string `json:"mode"`
	Version       string `json:"version"`
	ListenAddr    string `json:"listen_addr"`
	APIBasePath   string `json:"api_base_path"`
	UIBasePath    string `json:"ui_base_path"`
	TLSEnabled    bool   `json:"tls_enabled"`
	TLSCertFile   string `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string `json:"tls_key_file,omitempty"`
	TLSMinVersion string `json:"tls_min_version"`
}

type centerSettingsStorage struct {
	DBDriver          string `json:"db_driver"`
	DBPath            string `json:"db_path"`
	DBRetentionDays   int    `json:"db_retention_days"`
	FileRetentionDays int    `json:"file_retention_days"`
}

type centerSettingsAccess struct {
	ReadOnly bool `json:"read_only"`
}

type centerSettingsPayload struct {
	ETag            string                `json:"etag"`
	RestartRequired bool                  `json:"restart_required"`
	Runtime         centerSettingsRuntime `json:"runtime"`
	Storage         centerSettingsStorage `json:"storage"`
	Access          centerSettingsAccess  `json:"access"`
	Config          CenterSettingsConfig  `json:"config"`
}

type centerSettingsPutBody struct {
	Config CenterSettingsConfig `json:"config"`
}

func getCenterSettings(runtimeCfg RuntimeConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		cfg, etag, err := LoadCenterSettings(c.Request.Context())
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to load center settings"})
			return
		}
		c.JSON(http.StatusOK, buildCenterSettingsResponse(runtimeCfg, cfg, etag))
	}
}

func putCenterSettings(runtimeCfg RuntimeConfig) gin.HandlerFunc {
	return func(c *gin.Context) {
		if config.AdminReadOnly {
			c.JSON(http.StatusForbidden, gin.H{"error": "admin is read-only"})
			return
		}
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxCenterSettingsJSONBytes)
		decoder := json.NewDecoder(c.Request.Body)
		decoder.DisallowUnknownFields()
		var in centerSettingsPutBody
		if err := decoder.Decode(&in); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid settings payload"})
			return
		}
		if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid settings payload"})
			return
		}
		expectedETag := strings.TrimSpace(c.GetHeader("If-Match"))
		if expectedETag == "" {
			c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
			return
		}
		next, etag, err := SaveCenterSettings(c.Request.Context(), expectedETag, in.Config)
		if err != nil {
			if errors.Is(err, ErrCenterSettingsConflict) {
				_, currentETag, loadErr := LoadCenterSettings(c.Request.Context())
				if loadErr != nil {
					c.JSON(http.StatusConflict, gin.H{"error": "conflict"})
					return
				}
				c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": currentETag})
				return
			}
			if errors.Is(err, ErrCenterSettingsInvalid) {
				c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
				return
			}
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to save center settings"})
			return
		}
		if err := applyCenterMutableSettings(next); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to apply center settings"})
			return
		}
		c.JSON(http.StatusOK, buildCenterSettingsResponse(runtimeCfg, next, etag))
	}
}

func buildCenterSettingsResponse(runtimeCfg RuntimeConfig, cfg CenterSettingsConfig, etag string) centerSettingsPayload {
	displayCfg := displayCenterSettingsConfig(runtimeCfg, cfg)
	return centerSettingsPayload{
		ETag:            etag,
		RestartRequired: centerSettingsRestartRequired(runtimeCfg, displayCfg),
		Runtime: centerSettingsRuntime{
			Mode:          "center",
			Version:       buildinfo.Version,
			ListenAddr:    runtimeCfg.normalizedListenAddr(),
			APIBasePath:   runtimeCfg.APIBasePath,
			UIBasePath:    runtimeCfg.UIBasePath,
			TLSEnabled:    runtimeCfg.TLSEnabled,
			TLSCertFile:   runtimeCfg.TLSCertFile,
			TLSKeyFile:    runtimeCfg.TLSKeyFile,
			TLSMinVersion: effectiveCenterTLSMinVersion(runtimeCfg.TLSMinVersion),
		},
		Storage: centerSettingsStorage{
			DBDriver:          config.DBDriver,
			DBPath:            config.DBPath,
			DBRetentionDays:   config.DBRetentionDays,
			FileRetentionDays: int(config.FileRetention.Hours() / 24),
		},
		Access: centerSettingsAccess{
			ReadOnly: config.AdminReadOnly,
		},
		Config: displayCfg,
	}
}

func displayCenterSettingsConfig(runtimeCfg RuntimeConfig, cfg CenterSettingsConfig) CenterSettingsConfig {
	if cfg.AdminSessionTTLSeconds == 0 {
		cfg.AdminSessionTTLSeconds = int64(config.AdminSessionTTL.Seconds())
	}
	cfg.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	if cfg.ListenAddr == "" {
		cfg.ListenAddr = runtimeCfg.normalizedListenAddr()
	}
	cfg.APIBasePath = strings.TrimSpace(cfg.APIBasePath)
	if cfg.APIBasePath == "" {
		cfg.APIBasePath = runtimeCfg.APIBasePath
	}
	cfg.UIBasePath = strings.TrimSpace(cfg.UIBasePath)
	if cfg.UIBasePath == "" {
		cfg.UIBasePath = runtimeCfg.UIBasePath
	}
	cfg.TLSMode = strings.TrimSpace(cfg.TLSMode)
	if cfg.TLSMode == "" {
		if runtimeCfg.TLSEnabled {
			cfg.TLSMode = centerSettingsTLSModeManual
		} else {
			cfg.TLSMode = centerSettingsTLSModeOff
		}
	}
	if cfg.TLSCertFile == "" {
		cfg.TLSCertFile = runtimeCfg.TLSCertFile
	}
	if cfg.TLSKeyFile == "" {
		cfg.TLSKeyFile = runtimeCfg.TLSKeyFile
	}
	if cfg.TLSMinVersion == "" {
		cfg.TLSMinVersion = runtimeCfg.TLSMinVersion
	}
	cfg.TLSMinVersion = effectiveCenterTLSMinVersion(cfg.TLSMinVersion)
	return cfg
}

func applyCenterMutableSettings(cfg CenterSettingsConfig) error {
	cfg, err := normalizeCenterSettingsConfig(cfg)
	if err != nil {
		return err
	}
	if cfg.AdminSessionTTLSeconds != 0 {
		config.AdminSessionTTL = time.Duration(cfg.AdminSessionTTLSeconds) * time.Second
	}
	return nil
}

func centerSettingsRestartRequired(runtimeCfg RuntimeConfig, cfg CenterSettingsConfig) bool {
	desired, err := applyCenterRuntimeSettings(runtimeCfg, cfg)
	if err != nil {
		return true
	}
	return runtimeCfg.normalizedListenAddr() != desired.normalizedListenAddr() ||
		runtimeCfg.APIBasePath != desired.APIBasePath ||
		runtimeCfg.UIBasePath != desired.UIBasePath ||
		runtimeCfg.TLSEnabled != desired.TLSEnabled ||
		strings.TrimSpace(runtimeCfg.TLSCertFile) != strings.TrimSpace(desired.TLSCertFile) ||
		strings.TrimSpace(runtimeCfg.TLSKeyFile) != strings.TrimSpace(desired.TLSKeyFile) ||
		effectiveCenterTLSMinVersion(runtimeCfg.TLSMinVersion) != effectiveCenterTLSMinVersion(desired.TLSMinVersion)
}

func applyCenterRuntimeSettings(runtimeCfg RuntimeConfig, cfg CenterSettingsConfig) (RuntimeConfig, error) {
	cfg, err := normalizeCenterSettingsConfig(cfg)
	if err != nil {
		return RuntimeConfig{}, err
	}
	if cfg.ListenAddr != "" {
		runtimeCfg.ListenAddr = cfg.ListenAddr
	}
	if cfg.APIBasePath != "" {
		runtimeCfg.APIBasePath = cfg.APIBasePath
	}
	if cfg.UIBasePath != "" {
		runtimeCfg.UIBasePath = cfg.UIBasePath
	}
	switch cfg.TLSMode {
	case centerSettingsTLSModeOff:
		runtimeCfg.TLSEnabled = false
	case centerSettingsTLSModeManual:
		runtimeCfg.TLSEnabled = true
		runtimeCfg.TLSCertFile = cfg.TLSCertFile
		runtimeCfg.TLSKeyFile = cfg.TLSKeyFile
	case "":
	default:
		return RuntimeConfig{}, fmt.Errorf("%w: tls_mode must be off or manual", ErrCenterSettingsInvalid)
	}
	if cfg.TLSMinVersion != "" {
		runtimeCfg.TLSMinVersion = cfg.TLSMinVersion
	}
	if runtimeCfg.TLSMinVersion == "" {
		runtimeCfg.TLSMinVersion = "tls1.2"
	}
	if runtimeCfg.ListenAddr == "" {
		runtimeCfg.ListenAddr = DefaultListenAddr
	}
	if runtimeCfg.APIBasePath == "" {
		runtimeCfg.APIBasePath = DefaultAPIBasePath
	}
	if runtimeCfg.UIBasePath == "" {
		runtimeCfg.UIBasePath = DefaultUIBasePath
	}
	if runtimeCfg.APIBasePath == runtimeCfg.UIBasePath {
		return RuntimeConfig{}, fmt.Errorf("%w: api_base_path and ui_base_path must differ", ErrCenterSettingsInvalid)
	}
	return runtimeCfg, nil
}

func effectiveCenterTLSMinVersion(value string) string {
	normalized := normalizeCenterTLSMinVersion(value)
	if normalized == "" {
		return "tls1.2"
	}
	return normalized
}

func (cfg RuntimeConfig) normalizedListenAddr() string {
	addr := strings.TrimSpace(cfg.ListenAddr)
	if addr == "" {
		return DefaultListenAddr
	}
	return addr
}
