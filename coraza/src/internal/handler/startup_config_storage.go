package handler

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/config"
)

const (
	appConfigBlobKey        = "app_config"
	proxyRulesConfigBlobKey = "proxy_rules"
)

func SyncAppConfigStorage() error {
	_, _, cfg, err := loadAppConfigStorage(true)
	if err != nil {
		return err
	}
	return config.ApplyAppConfigFile(cfg)
}

func ImportStartupConfigStorage() error {
	if err := importAppConfigStorage(); err != nil {
		return err
	}
	if err := importProxyRulesStorage(); err != nil {
		return err
	}
	return nil
}

func loadAppConfigStorage(seedIfMissing bool) (string, string, config.AppConfigFile, error) {
	_, bootstrapCfg, err := loadBootstrapAppConfig()
	if err != nil {
		return "", "", config.AppConfigFile{}, err
	}
	store := getLogsStatsStore()
	if store == nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("db store is not initialized")
	}

	dbRaw, dbETag, found, err := store.GetConfigBlob(appConfigBlobKey)
	if err != nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("read app_config from db: %w", err)
	}
	if !found {
		cfg, normalizedRaw, err := appConfigBlobRawFromCandidate(bootstrapCfg, bootstrapCfg)
		if err != nil {
			return "", "", config.AppConfigFile{}, err
		}
		if seedIfMissing {
			if err := store.UpsertConfigBlob(appConfigBlobKey, []byte(normalizedRaw), bypassconf.ComputeETag([]byte(normalizedRaw)), time.Now().UTC()); err != nil {
				return "", "", config.AppConfigFile{}, fmt.Errorf("seed app_config db blob: %w", err)
			}
		}
		return normalizedRaw, bypassconf.ComputeETag([]byte(normalizedRaw)), cfg, nil
	}

	candidate, err := config.DecodeAppConfigRaw(dbRaw)
	if err != nil {
		return "", "", config.AppConfigFile{}, fmt.Errorf("decode app_config db blob: %w", err)
	}
	cfg, normalizedRaw, err := appConfigBlobRawFromCandidate(candidate, bootstrapCfg)
	if err != nil {
		return "", "", config.AppConfigFile{}, err
	}
	normalizedETag := bypassconf.ComputeETag([]byte(normalizedRaw))
	if string(dbRaw) != normalizedRaw && seedIfMissing {
		if err := store.UpsertConfigBlob(appConfigBlobKey, []byte(normalizedRaw), normalizedETag, time.Now().UTC()); err != nil {
			return "", "", config.AppConfigFile{}, fmt.Errorf("sanitize app_config db blob: %w", err)
		}
		dbETag = normalizedETag
	}
	if strings.TrimSpace(dbETag) == "" {
		dbETag = normalizedETag
	}
	return normalizedRaw, dbETag, cfg, nil
}

func importAppConfigStorage() error {
	_, bootstrapCfg, err := loadBootstrapAppConfig()
	if err != nil {
		return err
	}
	_, raw, err := appConfigBlobRawFromCandidate(bootstrapCfg, bootstrapCfg)
	if err != nil {
		return err
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if err := store.UpsertConfigBlob(appConfigBlobKey, []byte(raw), bypassconf.ComputeETag([]byte(raw)), time.Now().UTC()); err != nil {
		return fmt.Errorf("import app_config db blob: %w", err)
	}
	return nil
}

func importProxyRulesStorage() error {
	raw, _, err := readFileMaybe(config.ProxyConfigFile)
	if err != nil {
		return fmt.Errorf("read proxy seed file: %w", err)
	}
	prepared, err := prepareProxyRulesRaw(string(raw))
	if err != nil {
		return fmt.Errorf("validate proxy seed file: %w", err)
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if err := store.UpsertConfigBlob(proxyRulesConfigBlobKey, []byte(prepared.raw), prepared.etag, time.Now().UTC()); err != nil {
		return fmt.Errorf("import proxy_rules db blob: %w", err)
	}
	return nil
}

func loadBootstrapAppConfig() ([]byte, config.AppConfigFile, error) {
	path := currentSettingsConfigPath()
	raw, _, err := readFileMaybe(path)
	if err != nil {
		return nil, config.AppConfigFile{}, fmt.Errorf("read bootstrap config.json: %w", err)
	}
	cfg, err := config.LoadAppConfigFile(path)
	if err != nil {
		return nil, config.AppConfigFile{}, fmt.Errorf("load bootstrap config.json: %w", err)
	}
	return raw, cfg, nil
}

func appConfigBlobRawFromCandidate(candidate config.AppConfigFile, bootstrap config.AppConfigFile) (config.AppConfigFile, string, error) {
	preserveBootstrapDBConnection(&candidate, bootstrap)
	normalized, err := config.NormalizeAndValidateAppConfigFile(candidate)
	if err != nil {
		return config.AppConfigFile{}, "", err
	}
	raw, err := marshalAppConfigBlob(normalized)
	if err != nil {
		return config.AppConfigFile{}, "", err
	}
	return normalized, raw, nil
}

func preserveBootstrapDBConnection(cfg *config.AppConfigFile, bootstrap config.AppConfigFile) {
	if cfg == nil {
		return
	}
	cfg.Storage.Backend = ""
	cfg.Storage.DBDriver = bootstrap.Storage.DBDriver
	cfg.Storage.DBDSN = bootstrap.Storage.DBDSN
	cfg.Storage.DBPath = bootstrap.Storage.DBPath
}

func marshalAppConfigBlob(cfg config.AppConfigFile) (string, error) {
	raw, err := config.MarshalAppConfigFile(cfg)
	if err != nil {
		return "", err
	}
	var obj map[string]any
	if err := json.Unmarshal([]byte(raw), &obj); err != nil {
		return "", err
	}
	if storage, ok := obj["storage"].(map[string]any); ok {
		delete(storage, "backend")
		delete(storage, "db_driver")
		delete(storage, "db_dsn")
		delete(storage, "db_path")
	}
	body, err := json.MarshalIndent(obj, "", "  ")
	if err != nil {
		return "", err
	}
	return string(body) + "\n", nil
}
