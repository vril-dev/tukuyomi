package handler

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/oschwald/maxminddb-golang"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const maxRequestCountryDBUploadBytes = 128 << 20

type requestCountryDBStatusResponse struct {
	ManagedPath    string `json:"managed_path"`
	ConfigETag     string `json:"config_etag,omitempty"`
	ConfiguredMode string `json:"configured_mode"`
	EffectiveMode  string `json:"effective_mode"`
	Installed      bool   `json:"installed"`
	Loaded         bool   `json:"loaded"`
	SizeBytes      int64  `json:"size_bytes"`
	ModTime        string `json:"mod_time,omitempty"`
	LastError      string `json:"last_error,omitempty"`
}

type putRequestCountryModeBody struct {
	Mode string `json:"mode"`
}

func GetRequestCountryDBStatus(c *gin.Context) {
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func PutRequestCountryMode(c *gin.Context) {
	var in putRequestCountryModeBody
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	ifMatch := strings.TrimSpace(c.GetHeader("If-Match"))
	if ifMatch == "" {
		c.JSON(http.StatusPreconditionRequired, gin.H{"error": "If-Match header is required"})
		return
	}

	raw, etag, current, err := loadSettingsAppConfig()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if ifMatch != etag {
		c.JSON(http.StatusConflict, gin.H{"error": "conflict", "currentETag": etag})
		return
	}

	current.RequestMeta.Country.Mode = strings.ToLower(strings.TrimSpace(in.Mode))
	normalized, err := config.NormalizeAndValidateAppConfigFile(current)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	if err := ValidateRequestCountryRuntimeConfig(normalized); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	nextRaw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	nextETag := etag
	if nextRaw != raw {
		if err := persistSettingsAppConfigRaw(currentSettingsConfigPath(), nextRaw); err != nil {
			c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
			return
		}
		nextETag = bypassconf.ComputeETag([]byte(nextRaw))
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatusWithETag(nextETag))
}

func UploadRequestCountryDB(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart form field 'file' is required"})
		return
	}
	src, err := file.Open()
	if err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	defer src.Close()

	if err := replaceManagedCountryMMDB(src); err != nil {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func DeleteRequestCountryDB(c *gin.Context) {
	if strings.EqualFold(currentConfiguredRequestCountryMode(), "mmdb") {
		c.JSON(http.StatusConflict, gin.H{
			"error": "country db removal requires request_metadata.country.mode=header",
		})
		return
	}
	if err := os.Remove(managedRequestCountryMMDBPath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		c.JSON(http.StatusUnprocessableEntity, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, buildRequestCountryDBStatus())
}

func buildRequestCountryDBStatus() requestCountryDBStatusResponse {
	return buildRequestCountryDBStatusWithETag("")
}

func buildRequestCountryDBStatusWithETag(etag string) requestCountryDBStatusResponse {
	runtime := RequestCountryRuntimeStatusSnapshot()
	out := requestCountryDBStatusResponse{
		ManagedPath:    runtime.ManagedPath,
		ConfigETag:     etag,
		ConfiguredMode: currentConfiguredRequestCountryMode(),
		EffectiveMode:  runtime.EffectiveMode,
		Loaded:         runtime.Loaded,
		LastError:      runtime.LastError,
	}
	if out.ConfigETag == "" {
		if _, currentETag, _, err := loadSettingsAppConfig(); err == nil {
			out.ConfigETag = currentETag
		}
	}
	info, err := os.Stat(managedRequestCountryMMDBPath())
	if err == nil && !info.IsDir() {
		out.Installed = true
		out.SizeBytes = info.Size()
		out.ModTime = info.ModTime().UTC().Format(time.RFC3339Nano)
		return out
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) && out.LastError == "" {
		out.LastError = err.Error()
	}
	return out
}

func currentConfiguredRequestCountryMode() string {
	cfg, err := loadSettingsAppConfigOnly()
	if err == nil {
		mode := strings.ToLower(strings.TrimSpace(cfg.RequestMeta.Country.Mode))
		if mode == "" {
			return "header"
		}
		return mode
	}
	mode := strings.ToLower(strings.TrimSpace(config.RequestCountryMode))
	if mode == "" {
		return "header"
	}
	return mode
}

func replaceManagedCountryMMDB(src io.Reader) error {
	if src == nil {
		return fmt.Errorf("country db upload source is required")
	}
	tmp, err := os.CreateTemp("", "tukuyomi-country-db-*.mmdb")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpPath)
	}()
	written, err := io.Copy(tmp, io.LimitReader(src, maxRequestCountryDBUploadBytes+1))
	if err != nil {
		return err
	}
	if written > maxRequestCountryDBUploadBytes {
		return fmt.Errorf("country db upload exceeds %d bytes", maxRequestCountryDBUploadBytes)
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	reader, err := maxminddb.Open(tmpPath)
	if err != nil {
		return fmt.Errorf("invalid country mmdb: %w", err)
	}
	_ = reader.Close()
	payload, err := os.ReadFile(tmpPath)
	if err != nil {
		return err
	}
	target := managedRequestCountryMMDBPath()
	if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
		return err
	}
	if err := bypassconf.AtomicWriteWithBackup(target, payload); err != nil {
		return err
	}
	if strings.EqualFold(config.RequestCountryMode, "mmdb") {
		if err := reloadRequestCountryRuntime(config.RequestCountryMode); err != nil {
			return err
		}
	}
	return nil
}
