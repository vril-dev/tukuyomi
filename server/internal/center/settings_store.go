package center

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"tukuyomi/internal/config"
)

const (
	centerSettingsBlobKey = "center_settings"

	maxCenterSettingsJSONBytes  = 8192
	maxEnrollmentTokenTTLDays   = 3650
	minCenterAdminSessionTTL    = 300
	maxCenterAdminSessionTTL    = 604800
	centerSettingsTLSModeOff    = "off"
	centerSettingsTLSModeManual = "manual"
)

var (
	ErrCenterSettingsConflict = errors.New("center settings conflict")
	ErrCenterSettingsInvalid  = errors.New("invalid center settings")
)

type CenterSettingsConfig struct {
	EnrollmentTokenDefaultMaxUses    int64                          `json:"enrollment_token_default_max_uses"`
	EnrollmentTokenDefaultTTLSeconds int64                          `json:"enrollment_token_default_ttl_seconds"`
	AdminSessionTTLSeconds           int64                          `json:"admin_session_ttl_seconds,omitempty"`
	ListenAddr                       string                         `json:"listen_addr,omitempty"`
	APIBasePath                      string                         `json:"api_base_path,omitempty"`
	GatewayAPIBasePath               string                         `json:"gateway_api_base_path,omitempty"`
	UIBasePath                       string                         `json:"ui_base_path,omitempty"`
	TLSMode                          string                         `json:"tls_mode,omitempty"`
	TLSCertFile                      string                         `json:"tls_cert_file,omitempty"`
	TLSKeyFile                       string                         `json:"tls_key_file,omitempty"`
	TLSMinVersion                    string                         `json:"tls_min_version,omitempty"`
	ClientAllowCIDRs                 []string                       `json:"client_allow_cidrs,omitempty"`
	ManageAPIAllowCIDRs              []string                       `json:"manage_api_allow_cidrs,omitempty"`
	CenterAPIAllowCIDRs              []string                       `json:"center_api_allow_cidrs,omitempty"`
	RemoteSSH                        *CenterSettingsRemoteSSHConfig `json:"remote_ssh,omitempty"`
}

type CenterSettingsRemoteSSHConfig struct {
	Center CenterSettingsRemoteSSHCenterConfig `json:"center"`
}

type CenterSettingsRemoteSSHCenterConfig struct {
	Enabled              bool  `json:"enabled"`
	MaxTTLSec            int64 `json:"max_ttl_sec"`
	IdleTimeoutSec       int64 `json:"idle_timeout_sec"`
	MaxSessionsTotal     int   `json:"max_sessions_total"`
	MaxSessionsPerDevice int   `json:"max_sessions_per_device"`
}

func defaultCenterSettingsConfig() CenterSettingsConfig {
	return CenterSettingsConfig{
		EnrollmentTokenDefaultMaxUses:    EnrollmentTokenDefaultMaxUses,
		EnrollmentTokenDefaultTTLSeconds: 0,
	}
}

func LoadCenterSettings(ctx context.Context) (CenterSettingsConfig, string, error) {
	cfg, etag, _, err := loadCenterSettings(ctx)
	return cfg, etag, err
}

func loadCenterSettings(ctx context.Context) (CenterSettingsConfig, string, bool, error) {
	cfg := defaultCenterSettingsConfig()
	etag := centerSettingsETag(cfg)
	found := false
	err := withCenterDB(ctx, func(db *sql.DB, driver string) error {
		loaded, loadedETag, loadedFound, err := loadCenterSettingsTx(ctx, db, driver)
		if err != nil {
			return err
		}
		if loadedFound {
			cfg = loaded
			etag = loadedETag
		}
		found = loadedFound
		return nil
	})
	return cfg, etag, found, err
}

func SaveCenterSettings(ctx context.Context, expectedETag string, next CenterSettingsConfig) (CenterSettingsConfig, string, error) {
	expectedETag = strings.TrimSpace(expectedETag)
	if expectedETag == "" {
		return CenterSettingsConfig{}, "", ErrCenterSettingsConflict
	}
	next, err := normalizeCenterSettingsConfig(next)
	if err != nil {
		return CenterSettingsConfig{}, "", err
	}
	nextETag := centerSettingsETag(next)
	err = withCenterDB(ctx, func(db *sql.DB, driver string) error {
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return err
		}
		defer tx.Rollback()

		_, currentETag, found, err := loadCenterSettingsTx(ctx, tx, driver)
		if err != nil {
			return err
		}
		if currentETag != expectedETag {
			return ErrCenterSettingsConflict
		}
		if currentETag == nextETag {
			return tx.Commit()
		}

		raw, err := marshalCenterSettings(next)
		if err != nil {
			return err
		}
		now := time.Now().UTC()
		nowText := now.Format(time.RFC3339Nano)
		if found {
			_, err = tx.ExecContext(ctx, `
UPDATE config_blobs
   SET raw_text = `+placeholder(driver, 1)+`,
       etag = `+placeholder(driver, 2)+`,
       updated_at_unix = `+placeholder(driver, 3)+`,
       updated_at = `+placeholder(driver, 4)+`
 WHERE config_key = `+placeholder(driver, 5),
				raw,
				nextETag,
				now.Unix(),
				nowText,
				centerSettingsBlobKey,
			)
			if err != nil {
				return err
			}
			return tx.Commit()
		}
		_, err = tx.ExecContext(ctx, `
INSERT INTO config_blobs (config_key, raw_text, etag, updated_at_unix, updated_at)
VALUES (`+placeholders(driver, 5, 1)+`)`,
			centerSettingsBlobKey,
			raw,
			nextETag,
			now.Unix(),
			nowText,
		)
		if err != nil {
			return err
		}
		return tx.Commit()
	})
	if err != nil {
		return CenterSettingsConfig{}, "", err
	}
	return next, nextETag, nil
}

func loadCenterSettingsTx(ctx context.Context, q queryer, driver string) (CenterSettingsConfig, string, bool, error) {
	row := q.QueryRowContext(ctx, `
SELECT raw_text
  FROM config_blobs
 WHERE config_key = `+placeholder(driver, 1),
		centerSettingsBlobKey,
	)
	var raw string
	if err := row.Scan(&raw); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			cfg := defaultCenterSettingsConfig()
			return cfg, centerSettingsETag(cfg), false, nil
		}
		return CenterSettingsConfig{}, "", false, err
	}
	if len(raw) > maxCenterSettingsJSONBytes {
		return CenterSettingsConfig{}, "", false, fmt.Errorf("%w: payload too large", ErrCenterSettingsInvalid)
	}
	cfg, err := decodeCenterSettings([]byte(raw))
	if err != nil {
		return CenterSettingsConfig{}, "", false, err
	}
	return cfg, centerSettingsETag(cfg), true, nil
}

func decodeCenterSettings(raw []byte) (CenterSettingsConfig, error) {
	var cfg CenterSettingsConfig
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&cfg); err != nil {
		return CenterSettingsConfig{}, fmt.Errorf("%w: decode config", ErrCenterSettingsInvalid)
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return CenterSettingsConfig{}, fmt.Errorf("%w: decode config", ErrCenterSettingsInvalid)
	}
	return normalizeCenterSettingsConfig(cfg)
}

func normalizeCenterSettingsConfig(cfg CenterSettingsConfig) (CenterSettingsConfig, error) {
	cfg.ListenAddr = strings.TrimSpace(cfg.ListenAddr)
	cfg.APIBasePath = strings.TrimSpace(cfg.APIBasePath)
	cfg.GatewayAPIBasePath = strings.TrimSpace(cfg.GatewayAPIBasePath)
	cfg.UIBasePath = strings.TrimSpace(cfg.UIBasePath)
	cfg.TLSMode = strings.ToLower(strings.TrimSpace(cfg.TLSMode))
	cfg.TLSCertFile = strings.TrimSpace(cfg.TLSCertFile)
	cfg.TLSKeyFile = strings.TrimSpace(cfg.TLSKeyFile)
	cfg.TLSMinVersion = normalizeCenterTLSMinVersion(cfg.TLSMinVersion)
	var err error
	if cfg.ClientAllowCIDRs, err = normalizeCenterSourceCIDRStrings("client_allow_cidrs", cfg.ClientAllowCIDRs); err != nil {
		return CenterSettingsConfig{}, fmt.Errorf("%w: %v", ErrCenterSettingsInvalid, err)
	}
	if cfg.ManageAPIAllowCIDRs, err = normalizeCenterSourceCIDRStrings("manage_api_allow_cidrs", cfg.ManageAPIAllowCIDRs); err != nil {
		return CenterSettingsConfig{}, fmt.Errorf("%w: %v", ErrCenterSettingsInvalid, err)
	}
	if cfg.CenterAPIAllowCIDRs, err = normalizeCenterSourceCIDRStrings("center_api_allow_cidrs", cfg.CenterAPIAllowCIDRs); err != nil {
		return CenterSettingsConfig{}, fmt.Errorf("%w: %v", ErrCenterSettingsInvalid, err)
	}
	if cfg.RemoteSSH != nil {
		remoteSSH, err := normalizeCenterSettingsRemoteSSH(*cfg.RemoteSSH)
		if err != nil {
			return CenterSettingsConfig{}, err
		}
		cfg.RemoteSSH = &remoteSSH
	}
	if err := validateCenterTLSMinVersion(cfg.TLSMinVersion); err != nil {
		return CenterSettingsConfig{}, fmt.Errorf("%w: tls_min_version %v", ErrCenterSettingsInvalid, err)
	}

	if cfg.EnrollmentTokenDefaultMaxUses <= 0 {
		cfg.EnrollmentTokenDefaultMaxUses = EnrollmentTokenDefaultMaxUses
	}
	if cfg.EnrollmentTokenDefaultMaxUses > 1000000 {
		return CenterSettingsConfig{}, fmt.Errorf("%w: enrollment_token_default_max_uses out of range", ErrCenterSettingsInvalid)
	}
	if cfg.EnrollmentTokenDefaultTTLSeconds < 0 {
		return CenterSettingsConfig{}, fmt.Errorf("%w: enrollment_token_default_ttl_seconds out of range", ErrCenterSettingsInvalid)
	}
	maxTTL := int64(maxEnrollmentTokenTTLDays * 24 * 60 * 60)
	if cfg.EnrollmentTokenDefaultTTLSeconds > maxTTL {
		return CenterSettingsConfig{}, fmt.Errorf("%w: enrollment_token_default_ttl_seconds out of range", ErrCenterSettingsInvalid)
	}
	if cfg.AdminSessionTTLSeconds != 0 && (cfg.AdminSessionTTLSeconds < minCenterAdminSessionTTL || cfg.AdminSessionTTLSeconds > maxCenterAdminSessionTTL) {
		return CenterSettingsConfig{}, fmt.Errorf("%w: admin_session_ttl_seconds out of range", ErrCenterSettingsInvalid)
	}
	if cfg.ListenAddr != "" {
		if err := validateCenterListenAddr(cfg.ListenAddr); err != nil {
			return CenterSettingsConfig{}, fmt.Errorf("%w: listen_addr %v", ErrCenterSettingsInvalid, err)
		}
	}
	if cfg.APIBasePath != "" {
		apiBase, err := normalizeBasePath(cfg.APIBasePath, DefaultAPIBasePath)
		if err != nil {
			return CenterSettingsConfig{}, fmt.Errorf("%w: api_base_path %v", ErrCenterSettingsInvalid, err)
		}
		cfg.APIBasePath = apiBase
	}
	if cfg.GatewayAPIBasePath != "" {
		gatewayAPIBase, err := normalizeBasePath(cfg.GatewayAPIBasePath, DefaultGatewayAPIBasePath)
		if err != nil {
			return CenterSettingsConfig{}, fmt.Errorf("%w: gateway_api_base_path %v", ErrCenterSettingsInvalid, err)
		}
		cfg.GatewayAPIBasePath = gatewayAPIBase
	}
	if cfg.UIBasePath != "" {
		uiBase, err := normalizeBasePath(cfg.UIBasePath, DefaultUIBasePath)
		if err != nil {
			return CenterSettingsConfig{}, fmt.Errorf("%w: ui_base_path %v", ErrCenterSettingsInvalid, err)
		}
		cfg.UIBasePath = uiBase
	}
	if cfg.APIBasePath != "" && cfg.UIBasePath != "" && cfg.APIBasePath == cfg.UIBasePath {
		return CenterSettingsConfig{}, fmt.Errorf("%w: api_base_path and ui_base_path must differ", ErrCenterSettingsInvalid)
	}
	if cfg.GatewayAPIBasePath != "" && cfg.UIBasePath != "" && cfg.GatewayAPIBasePath == cfg.UIBasePath {
		return CenterSettingsConfig{}, fmt.Errorf("%w: gateway_api_base_path and ui_base_path must differ", ErrCenterSettingsInvalid)
	}
	if cfg.TLSMode != "" && cfg.TLSMode != centerSettingsTLSModeOff && cfg.TLSMode != centerSettingsTLSModeManual {
		return CenterSettingsConfig{}, fmt.Errorf("%w: tls_mode must be off or manual", ErrCenterSettingsInvalid)
	}
	if err := validateCenterOptionalPath("tls_cert_file", cfg.TLSCertFile); err != nil {
		return CenterSettingsConfig{}, err
	}
	if err := validateCenterOptionalPath("tls_key_file", cfg.TLSKeyFile); err != nil {
		return CenterSettingsConfig{}, err
	}
	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return CenterSettingsConfig{}, fmt.Errorf("%w: tls_cert_file and tls_key_file must be set together", ErrCenterSettingsInvalid)
	}
	if cfg.TLSMode == centerSettingsTLSModeManual {
		if cfg.TLSCertFile == "" || cfg.TLSKeyFile == "" {
			return CenterSettingsConfig{}, fmt.Errorf("%w: tls_cert_file and tls_key_file are required for manual TLS", ErrCenterSettingsInvalid)
		}
		if _, err := config.BuildServerTLSConfig(cfg.TLSCertFile, cfg.TLSKeyFile, cfg.TLSMinVersion); err != nil {
			return CenterSettingsConfig{}, fmt.Errorf("%w: tls %v", ErrCenterSettingsInvalid, err)
		}
	}
	return cfg, nil
}

func normalizeCenterSettingsRemoteSSH(in CenterSettingsRemoteSSHConfig) (CenterSettingsRemoteSSHConfig, error) {
	center := in.Center
	if center.MaxTTLSec == 0 {
		center.MaxTTLSec = config.DefaultRemoteSSHMaxTTLSec
	}
	if center.IdleTimeoutSec == 0 {
		center.IdleTimeoutSec = config.DefaultRemoteSSHIdleTimeoutSec
	}
	if center.MaxSessionsTotal == 0 {
		center.MaxSessionsTotal = config.DefaultRemoteSSHMaxSessionsTotal
	}
	if center.MaxSessionsPerDevice == 0 {
		center.MaxSessionsPerDevice = config.DefaultRemoteSSHMaxSessionsPerDevice
	}
	if center.MaxTTLSec < config.MinRemoteSSHMaxTTLSec || center.MaxTTLSec > config.MaxRemoteSSHMaxTTLSec {
		return CenterSettingsRemoteSSHConfig{}, fmt.Errorf("%w: remote_ssh.center.max_ttl_sec must be between %d and %d", ErrCenterSettingsInvalid, config.MinRemoteSSHMaxTTLSec, config.MaxRemoteSSHMaxTTLSec)
	}
	if center.IdleTimeoutSec < config.MinRemoteSSHIdleTimeoutSec || center.IdleTimeoutSec > config.MaxRemoteSSHIdleTimeoutSec || center.IdleTimeoutSec > center.MaxTTLSec {
		return CenterSettingsRemoteSSHConfig{}, fmt.Errorf("%w: remote_ssh.center.idle_timeout_sec must be between %d and min(%d, remote_ssh.center.max_ttl_sec)", ErrCenterSettingsInvalid, config.MinRemoteSSHIdleTimeoutSec, config.MaxRemoteSSHIdleTimeoutSec)
	}
	if center.MaxSessionsTotal < 1 || center.MaxSessionsTotal > config.MaxRemoteSSHMaxSessionsTotal {
		return CenterSettingsRemoteSSHConfig{}, fmt.Errorf("%w: remote_ssh.center.max_sessions_total must be between 1 and %d", ErrCenterSettingsInvalid, config.MaxRemoteSSHMaxSessionsTotal)
	}
	if center.MaxSessionsPerDevice < 1 || center.MaxSessionsPerDevice > config.MaxRemoteSSHMaxSessionsPerDevice {
		return CenterSettingsRemoteSSHConfig{}, fmt.Errorf("%w: remote_ssh.center.max_sessions_per_device must be between 1 and %d", ErrCenterSettingsInvalid, config.MaxRemoteSSHMaxSessionsPerDevice)
	}
	in.Center = center
	return in, nil
}

func normalizeCenterTLSMinVersion(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "":
		return ""
	case "tls1.2", "1.2", "tls12", "1_2":
		return "tls1.2"
	case "tls1.3", "1.3", "tls13", "1_3":
		return "tls1.3"
	default:
		return strings.TrimSpace(value)
	}
}

func validateCenterTLSMinVersion(value string) error {
	switch value {
	case "", "tls1.2", "tls1.3":
		return nil
	default:
		return fmt.Errorf("must be tls1.2 or tls1.3")
	}
}

func validateCenterListenAddr(addr string) error {
	if len(addr) > 255 {
		return fmt.Errorf("is too long")
	}
	if strings.ContainsAny(addr, "\x00\r\n\t ") {
		return fmt.Errorf("contains invalid whitespace")
	}
	resolved, err := net.ResolveTCPAddr("tcp", addr)
	if err != nil {
		return err
	}
	if resolved.Port <= 0 || resolved.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535")
	}
	return nil
}

func validateCenterOptionalPath(label string, value string) error {
	if value == "" {
		return nil
	}
	if len(value) > 4096 {
		return fmt.Errorf("%w: %s is too long", ErrCenterSettingsInvalid, label)
	}
	if strings.ContainsAny(value, "\x00\r\n") {
		return fmt.Errorf("%w: %s contains invalid control characters", ErrCenterSettingsInvalid, label)
	}
	return nil
}

func marshalCenterSettings(cfg CenterSettingsConfig) (string, error) {
	cfg, err := normalizeCenterSettingsConfig(cfg)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		return "", err
	}
	if len(raw) > maxCenterSettingsJSONBytes {
		return "", fmt.Errorf("%w: payload too large", ErrCenterSettingsInvalid)
	}
	return string(raw), nil
}

func centerSettingsETag(cfg CenterSettingsConfig) string {
	raw, err := marshalCenterSettings(cfg)
	if err != nil {
		raw = "{}"
	}
	sum := sha256.Sum256([]byte(raw))
	return `"` + hex.EncodeToString(sum[:]) + `"`
}
