package handler

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"tukuyomi/internal/bypassconf"
	"tukuyomi/internal/cacheconf"
	"tukuyomi/internal/config"
)

const previewDefaultProxyConfigRaw = "{}\n"

type PreviewBootstrapOptions struct {
	PublicListenAddr string
	AdminListenAddr  string
}

type PreviewTopology struct {
	PublicListenAddr string
	PublicPort       int
	AdminListenAddr  string
	AdminPort        int
	SplitAdmin       bool
	HealthPort       int
	APIBasePath      string
	UIBasePath       string
	PublicURL        string
	AdminUIURL       string
	AdminAPIURL      string
}

type previewListenBinding struct {
	raw  string
	port int
}

func ImportPreviewConfigStorage(opts PreviewBootstrapOptions) error {
	bootstrapCfg, err := previewBootstrapAppConfig(opts)
	if err != nil {
		return err
	}
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	if _, _, err := store.writeAppConfigVersion("", bootstrapCfg, bootstrapCfg, configVersionSourceImport, "", "preview app config seed import", 0); err != nil {
		return fmt.Errorf("import preview app_config: %w", err)
	}
	_ = store.DeleteConfigBlob(appConfigBlobKey)

	if err := importAdminUsersSeedStorage(); err != nil {
		return err
	}

	sitePrepared, err := prepareSiteConfigRaw(defaultSiteConfigRaw)
	if err != nil {
		return err
	}
	if _, err := store.writeSiteConfigVersion("", sitePrepared.cfg, configVersionSourceImport, "", "preview sites seed import", 0); err != nil {
		return fmt.Errorf("import preview sites config: %w", err)
	}
	_ = store.DeleteConfigBlob(siteConfigBlobKey)

	inventoryPrepared, err := preparePHPRuntimeInventoryRaw(defaultPHPRuntimeInventoryRaw, config.PHPRuntimeInventoryFile)
	if err != nil {
		return err
	}
	if _, err := store.writePHPRuntimeInventoryPreparedConfigVersion("", inventoryPrepared, configVersionSourceImport, "", "preview php runtime inventory seed import", 0); err != nil {
		return fmt.Errorf("import preview php runtime inventory: %w", err)
	}

	psgiInventoryPrepared, err := preparePSGIRuntimeInventoryRaw(defaultPSGIRuntimeInventoryRaw, config.PSGIRuntimeInventoryFile)
	if err != nil {
		return err
	}
	if _, err := store.writePSGIRuntimeInventoryPreparedConfigVersion("", psgiInventoryPrepared, configVersionSourceImport, "", "preview psgi runtime inventory seed import", 0); err != nil {
		return fmt.Errorf("import preview psgi runtime inventory: %w", err)
	}

	vhostPrepared, err := prepareVhostConfigRawWithInventories(defaultVhostConfigRaw, inventoryPrepared.cfg, psgiInventoryPrepared.cfg)
	if err != nil {
		return err
	}
	if _, err := store.writeVhostConfigVersion("", vhostPrepared.cfg, configVersionSourceImport, "", "preview Runtime Apps seed import", 0); err != nil {
		return fmt.Errorf("import preview Runtime Apps config: %w", err)
	}

	scheduledPrepared, err := prepareScheduledTaskConfigRaw(defaultScheduledTaskConfigRaw, inventoryPrepared.cfg)
	if err != nil {
		return err
	}
	if _, err := store.writeScheduledTaskConfigVersion("", scheduledPrepared.cfg, configVersionSourceImport, "", "preview scheduled tasks seed import", 0); err != nil {
		return fmt.Errorf("import preview scheduled tasks config: %w", err)
	}
	_ = store.DeleteConfigBlob(scheduledTaskConfigBlobKey)

	proxyPrepared, err := prepareProxyRulesRawWithSitesAndVhosts(previewDefaultProxyConfigRaw, sitePrepared.cfg, vhostPrepared.cfg)
	if err != nil {
		return err
	}
	if _, err := store.writeProxyConfigVersion("", proxyPrepared.cfg, configVersionSourceImport, "", "preview proxy seed import", 0); err != nil {
		return fmt.Errorf("import preview proxy config: %w", err)
	}
	_ = store.DeleteConfigBlob(proxyRulesConfigBlobKey)

	upstreamParsed, err := ParseUpstreamRuntimeRaw("")
	if err != nil {
		return err
	}
	if _, _, err := store.writeUpstreamRuntimeConfigVersion("", upstreamParsed, configuredManagedBackendKeys(proxyPrepared.cfg), configVersionSourceImport, "", "preview upstream runtime seed import", 0); err != nil {
		return fmt.Errorf("import preview upstream runtime config: %w", err)
	}
	_ = store.DeleteConfigBlob(upstreamRuntimeConfigBlobKey)

	if err := importPreviewPolicyConfigStorage(); err != nil {
		return err
	}
	if err := importResponseCacheConfigStorage(); err != nil {
		return err
	}
	return nil
}

func importPreviewPolicyConfigStorage() error {
	store := getLogsStatsStore()
	if store == nil {
		return fmt.Errorf("db store is not initialized")
	}
	imports := []struct {
		domain    string
		raw       func() (string, error)
		normalize func(string) ([]byte, error)
		reason    string
	}{
		{domain: cacheConfigBlobKey, raw: previewDefaultCacheRulesPolicyRaw, normalize: normalizeCacheRulesPolicyRaw, reason: "preview cache rules seed import"},
		{domain: bypassConfigBlobKey, raw: previewDefaultBypassPolicyRaw, normalize: normalizeBypassPolicyRaw, reason: "preview bypass rules seed import"},
		{domain: countryBlockConfigBlobKey, raw: previewDefaultCountryBlockPolicyRaw, normalize: normalizeCountryBlockPolicyRaw, reason: "preview country block seed import"},
		{domain: rateLimitConfigBlobKey, raw: previewDefaultRateLimitPolicyRaw, normalize: normalizeRateLimitPolicyRaw, reason: "preview rate limit seed import"},
		{domain: botDefenseConfigBlobKey, raw: previewDefaultBotDefensePolicyRaw, normalize: normalizeBotDefensePolicyRaw, reason: "preview bot defense seed import"},
		{domain: semanticConfigBlobKey, raw: previewDefaultSemanticPolicyRaw, normalize: normalizeSemanticPolicyRaw, reason: "preview semantic seed import"},
		{domain: notificationConfigBlobKey, raw: previewDefaultNotificationPolicyRaw, normalize: normalizeNotificationPolicyRaw, reason: "preview notification seed import"},
		{domain: ipReputationConfigBlobKey, raw: previewDefaultIPReputationPolicyRaw, normalize: normalizeIPReputationPolicyRaw, reason: "preview ip reputation seed import"},
	}
	for _, item := range imports {
		raw, err := item.raw()
		if err != nil {
			return fmt.Errorf("build %s preview seed: %w", item.domain, err)
		}
		normalized, err := item.normalize(raw)
		if err != nil {
			return fmt.Errorf("normalize %s preview seed: %w", item.domain, err)
		}
		if _, err := store.writePolicyJSONConfigVersion("", mustPolicyJSONSpec(item.domain), normalized, configVersionSourceImport, "", item.reason, 0); err != nil {
			return fmt.Errorf("import preview %s: %w", item.domain, err)
		}
		_ = store.DeleteConfigBlob(item.domain)
	}
	if err := importCRSDisabledStorage(); err != nil {
		return err
	}
	if err := importManagedOverrideRulesStorage(); err != nil {
		return err
	}
	return nil
}

func previewDefaultCacheRulesPolicyRaw() (string, error) {
	return string(mustCacheRulesJSON(&cacheconf.Ruleset{})), nil
}

func previewDefaultBypassPolicyRaw() (string, error) {
	raw, err := bypassconf.MarshalJSON(bypassconf.File{Default: bypassconf.Scope{Entries: []bypassconf.Entry{}}})
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func previewDefaultCountryBlockPolicyRaw() (string, error) {
	raw, err := defaultCountryBlockPolicyRaw()
	if err != nil {
		return "", err
	}
	return string(raw), nil
}

func previewDefaultRateLimitPolicyRaw() (string, error) {
	return defaultRateLimitPolicyRaw(), nil
}

func previewDefaultBotDefensePolicyRaw() (string, error) {
	return defaultBotDefensePolicyRaw(), nil
}

func previewDefaultSemanticPolicyRaw() (string, error) {
	return defaultSemanticPolicyRaw(), nil
}

func previewDefaultNotificationPolicyRaw() (string, error) {
	return defaultNotificationPolicyRaw(), nil
}

func previewDefaultIPReputationPolicyRaw() (string, error) {
	return defaultIPReputationPolicyRaw(), nil
}

func LoadPreviewTopology(opts PreviewBootstrapOptions) (PreviewTopology, error) {
	cfg, err := previewBootstrapAppConfig(opts)
	if err != nil {
		return PreviewTopology{}, err
	}
	if store := getLogsStatsStore(); store != nil {
		if active, _, found, err := store.loadActiveAppConfig(cfg); err != nil {
			return PreviewTopology{}, fmt.Errorf("load preview app_config from db: %w", err)
		} else if found {
			cfg = active
		}
	}
	return previewTopologyFromAppConfig(cfg)
}

func previewBootstrapAppConfig(opts PreviewBootstrapOptions) (config.AppConfigFile, error) {
	_, bootstrapCfg, err := loadBootstrapAppConfig()
	if err != nil {
		return config.AppConfigFile{}, err
	}
	cfg := bootstrapCfg
	publicAddr := strings.TrimSpace(opts.PublicListenAddr)
	if publicAddr != "" {
		cfg.Server.ListenAddr = publicAddr
	}
	adminAddr := strings.TrimSpace(opts.AdminListenAddr)
	cfg.Admin.ListenAddr = adminAddr
	return config.NormalizeAndValidateAppConfigFile(cfg)
}

func previewTopologyFromAppConfig(cfg config.AppConfigFile) (PreviewTopology, error) {
	publicBinding, err := parsePreviewListenBinding(cfg.Server.ListenAddr, false)
	if err != nil {
		return PreviewTopology{}, fmt.Errorf("preview config server.listen_addr: %w", err)
	}
	adminBinding, err := parsePreviewListenBinding(cfg.Admin.ListenAddr, true)
	if err != nil {
		return PreviewTopology{}, fmt.Errorf("preview config admin.listen_addr: %w", err)
	}
	split := adminBinding.raw != ""
	healthPort := publicBinding.port
	adminPort := 0
	adminListen := ""
	adminUIURL := fmt.Sprintf("http://127.0.0.1:%d%s", publicBinding.port, cfg.Admin.UIBasePath)
	adminAPIURL := fmt.Sprintf("http://127.0.0.1:%d%s", publicBinding.port, cfg.Admin.APIBasePath)
	if split {
		healthPort = adminBinding.port
		adminPort = adminBinding.port
		adminListen = adminBinding.raw
		adminUIURL = fmt.Sprintf("http://127.0.0.1:%d%s", adminBinding.port, cfg.Admin.UIBasePath)
		adminAPIURL = fmt.Sprintf("http://127.0.0.1:%d%s", adminBinding.port, cfg.Admin.APIBasePath)
	}
	return PreviewTopology{
		PublicListenAddr: publicBinding.raw,
		PublicPort:       publicBinding.port,
		AdminListenAddr:  adminListen,
		AdminPort:        adminPort,
		SplitAdmin:       split,
		HealthPort:       healthPort,
		APIBasePath:      cfg.Admin.APIBasePath,
		UIBasePath:       cfg.Admin.UIBasePath,
		PublicURL:        fmt.Sprintf("http://127.0.0.1:%d", publicBinding.port),
		AdminUIURL:       adminUIURL,
		AdminAPIURL:      adminAPIURL,
	}, nil
}

func parsePreviewListenBinding(raw string, allowEmpty bool) (previewListenBinding, error) {
	normalized := strings.TrimSpace(raw)
	if normalized == "" {
		if allowEmpty {
			return previewListenBinding{}, nil
		}
		normalized = ":9090"
	}
	if strings.HasPrefix(normalized, ":") {
		port, err := strconv.Atoi(strings.TrimPrefix(normalized, ":"))
		if err != nil || port < 1 || port > 65535 {
			return previewListenBinding{}, fmt.Errorf("port must be between 1 and 65535")
		}
		return previewListenBinding{raw: normalized, port: port}, nil
	}
	if _, err := strconv.Atoi(normalized); err == nil {
		port, _ := strconv.Atoi(normalized)
		if port < 1 || port > 65535 {
			return previewListenBinding{}, fmt.Errorf("port must be between 1 and 65535")
		}
		return previewListenBinding{raw: ":" + normalized, port: port}, nil
	}
	host, portStr, err := net.SplitHostPort(normalized)
	if err != nil {
		return previewListenBinding{}, fmt.Errorf("listener address must include host:port or :port: %s", normalized)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return previewListenBinding{}, fmt.Errorf("port must be between 1 and 65535")
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if strings.EqualFold(host, "localhost") {
		return previewListenBinding{}, fmt.Errorf("uses loopback host %s; use :%d or 0.0.0.0:%d instead", host, port, port)
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return previewListenBinding{}, fmt.Errorf("uses loopback host %s; use :%d or 0.0.0.0:%d instead", host, port, port)
	}
	return previewListenBinding{raw: normalized, port: port}, nil
}
