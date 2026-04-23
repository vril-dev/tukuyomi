package handler

import (
	"database/sql"
	"errors"
	"sort"
)

const (
	proxyConfigDomain        = "proxy"
	proxyConfigSchemaVersion = 1

	proxyRouteKindRoute   = "route"
	proxyRouteKindDefault = "default"
)

func boolToDB(v bool) int {
	if v {
		return 1
	}
	return 0
}

func boolFromDB(v int) bool {
	return v != 0
}

func boolPtrToDB(v *bool) (int, int) {
	if v == nil {
		return 0, 0
	}
	return 1, boolToDB(*v)
}

func boolPtrFromDB(set int, value int) *bool {
	if set == 0 {
		return nil
	}
	v := boolFromDB(value)
	return &v
}

func proxyConfigHash(cfg ProxyRulesConfig) string {
	normalized := normalizeProxyRulesConfig(cfg)
	return configContentHash(mustJSON(normalized))
}

func (s *wafEventStore) loadActiveProxyConfig() (ProxyRulesConfig, configVersionRecord, bool, error) {
	rec, found, err := s.loadActiveConfigVersion(proxyConfigDomain)
	if err != nil || !found {
		return ProxyRulesConfig{}, configVersionRecord{}, false, err
	}
	cfg, err := s.loadProxyConfigVersion(rec.VersionID)
	if err != nil {
		return ProxyRulesConfig{}, configVersionRecord{}, false, err
	}
	return normalizeProxyRulesConfig(cfg), rec, true, nil
}

func (s *wafEventStore) writeProxyConfigVersion(expectedETag string, cfg ProxyRulesConfig, source string, actor string, reason string, restoredFromVersionID int64) (configVersionRecord, error) {
	normalized := normalizeProxyRulesConfig(cfg)
	return s.writeConfigVersion(
		proxyConfigDomain,
		proxyConfigSchemaVersion,
		expectedETag,
		source,
		actor,
		reason,
		proxyConfigHash(normalized),
		restoredFromVersionID,
		func(tx *sql.Tx, versionID int64) error {
			return s.insertProxyConfigRowsTx(tx, versionID, normalized)
		},
	)
}

func (s *wafEventStore) findProxyVersionIDByETag(etag string) (int64, bool, error) {
	return s.findConfigVersionIDByETag(proxyConfigDomain, etag)
}

func (s *wafEventStore) insertProxyConfigRowsTx(tx *sql.Tx, versionID int64, cfg ProxyRulesConfig) error {
	if err := s.insertProxySettingsTx(tx, versionID, cfg); err != nil {
		return err
	}
	if err := s.insertProxyValueListTx(tx, versionID, "response_compression_algorithms", cfg.ResponseCompression.Algorithms); err != nil {
		return err
	}
	if err := s.insertProxyValueListTx(tx, versionID, "response_compression_mime_types", cfg.ResponseCompression.MIMETypes); err != nil {
		return err
	}
	if err := s.insertProxyValueListTx(tx, versionID, "response_header_sanitize_custom_remove", cfg.ResponseHeaderSanitize.CustomRemove); err != nil {
		return err
	}
	if err := s.insertProxyValueListTx(tx, versionID, "response_header_sanitize_custom_keep", cfg.ResponseHeaderSanitize.CustomKeep); err != nil {
		return err
	}
	if err := s.insertProxyValueListTx(tx, versionID, "retry_methods", cfg.RetryMethods); err != nil {
		return err
	}
	if err := s.insertProxyIntListTx(tx, versionID, "retry_status_codes", cfg.RetryStatusCodes); err != nil {
		return err
	}
	if err := s.insertProxyIntListTx(tx, versionID, "passive_unhealthy_status_codes", cfg.PassiveUnhealthyStatusCodes); err != nil {
		return err
	}
	if err := s.insertProxyKeyValuesTx(tx, versionID, "health_check_headers", cfg.HealthCheckHeaders); err != nil {
		return err
	}
	if err := s.insertProxyUpstreamsTx(tx, versionID, cfg.Upstreams); err != nil {
		return err
	}
	if err := s.insertProxyBackendPoolsTx(tx, versionID, cfg.BackendPools); err != nil {
		return err
	}
	if err := s.insertProxyRoutesTx(tx, versionID, proxyRouteKindRoute, cfg.Routes); err != nil {
		return err
	}
	if cfg.DefaultRoute != nil {
		if err := s.insertProxyDefaultRouteTx(tx, versionID, *cfg.DefaultRoute); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxySettingsTx(tx *sql.Tx, versionID int64, cfg ProxyRulesConfig) error {
	_, err := s.txExec(
		tx,
		`INSERT INTO proxy_settings (
			version_id, load_balancing_strategy, hash_policy, hash_key,
			dial_timeout, response_header_timeout, idle_conn_timeout,
			upstream_keepalive_sec, max_idle_conns, max_idle_conns_per_host,
			max_conns_per_host, force_http2, h2c_upstream, disable_compression,
			expose_waf_debug_headers, emit_upstream_name_request_header,
			access_log_mode, response_compression_enabled,
			response_compression_min_bytes, expect_continue_timeout,
			response_header_sanitize_mode, response_header_sanitize_debug_log,
			tls_insecure_skip_verify, tls_ca_bundle, tls_min_version,
			tls_max_version, tls_client_cert, tls_client_key, retry_attempts,
			retry_backoff_ms, retry_per_try_timeout_ms, passive_health_enabled,
			passive_failure_threshold, circuit_breaker_enabled,
			circuit_breaker_open_sec, circuit_breaker_half_open_requests,
			buffer_request_body, max_response_buffer_bytes, flush_interval_ms,
			health_check_path, health_check_interval_sec, health_check_timeout_sec,
			health_check_expected_body, health_check_expected_body_regex,
			error_html_file, error_redirect_url
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		versionID,
		cfg.LoadBalancingStrategy,
		cfg.HashPolicy,
		cfg.HashKey,
		cfg.DialTimeout,
		cfg.ResponseHeaderTimeout,
		cfg.IdleConnTimeout,
		cfg.UpstreamKeepAliveSec,
		cfg.MaxIdleConns,
		cfg.MaxIdleConnsPerHost,
		cfg.MaxConnsPerHost,
		boolToDB(cfg.ForceHTTP2),
		boolToDB(cfg.H2CUpstream),
		boolToDB(cfg.DisableCompression),
		boolToDB(cfg.ExposeWAFDebugHeaders),
		boolToDB(cfg.EmitUpstreamNameRequestHeader),
		cfg.AccessLogMode,
		boolToDB(cfg.ResponseCompression.Enabled),
		cfg.ResponseCompression.MinBytes,
		cfg.ExpectContinueTimeout,
		cfg.ResponseHeaderSanitize.Mode,
		boolToDB(cfg.ResponseHeaderSanitize.DebugLog),
		boolToDB(cfg.TLSInsecureSkipVerify),
		cfg.TLSCABundle,
		cfg.TLSMinVersion,
		cfg.TLSMaxVersion,
		cfg.TLSClientCert,
		cfg.TLSClientKey,
		cfg.RetryAttempts,
		cfg.RetryBackoffMS,
		cfg.RetryPerTryTimeoutMS,
		boolToDB(cfg.PassiveHealthEnabled),
		cfg.PassiveFailureThreshold,
		boolToDB(cfg.CircuitBreakerEnabled),
		cfg.CircuitBreakerOpenSec,
		cfg.CircuitBreakerHalfOpenRequests,
		boolToDB(cfg.BufferRequestBody),
		cfg.MaxResponseBufferBytes,
		cfg.FlushIntervalMS,
		cfg.HealthCheckPath,
		cfg.HealthCheckInterval,
		cfg.HealthCheckTimeout,
		cfg.HealthCheckExpectedBody,
		cfg.HealthCheckExpectedBodyRegex,
		cfg.ErrorHTMLFile,
		cfg.ErrorRedirectURL,
	)
	return err
}

func (s *wafEventStore) insertProxyValueListTx(tx *sql.Tx, versionID int64, listName string, values []string) error {
	for i, value := range values {
		if _, err := s.txExec(tx, `INSERT INTO proxy_value_list (version_id, list_name, position, value) VALUES (?, ?, ?, ?)`, versionID, listName, i, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyIntListTx(tx *sql.Tx, versionID int64, listName string, values []int) error {
	for i, value := range values {
		if _, err := s.txExec(tx, `INSERT INTO proxy_int_list (version_id, list_name, position, value) VALUES (?, ?, ?, ?)`, versionID, listName, i, value); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyKeyValuesTx(tx *sql.Tx, versionID int64, mapName string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if _, err := s.txExec(tx, `INSERT INTO proxy_key_values (version_id, map_name, position, name, value) VALUES (?, ?, ?, ?, ?)`, versionID, mapName, i, key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyUpstreamsTx(tx *sql.Tx, versionID int64, upstreams []ProxyUpstream) error {
	for i, upstream := range upstreams {
		if _, err := s.txExec(
			tx,
			`INSERT INTO proxy_upstreams (
				version_id, position, name, url, weight, enabled, http2_mode,
				generated, generated_kind, provider_class, managed_by_vhost
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID,
			i,
			upstream.Name,
			upstream.URL,
			upstream.Weight,
			boolToDB(upstream.Enabled),
			upstream.HTTP2Mode,
			boolToDB(upstream.Generated),
			upstream.GeneratedKind,
			upstream.ProviderClass,
			upstream.ManagedByVhost,
		); err != nil {
			return err
		}
		if proxyUpstreamHasTLSConfig(upstream) {
			if _, err := s.txExec(
				tx,
				`INSERT INTO proxy_upstream_tls (
					version_id, upstream_position, server_name, ca_bundle,
					min_version, max_version, client_cert, client_key
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
				versionID,
				i,
				upstream.TLS.ServerName,
				upstream.TLS.CABundle,
				upstream.TLS.MinVersion,
				upstream.TLS.MaxVersion,
				upstream.TLS.ClientCert,
				upstream.TLS.ClientKey,
			); err != nil {
				return err
			}
		}
		if proxyUpstreamDiscoveryEnabled(upstream) {
			if _, err := s.txExec(
				tx,
				`INSERT INTO proxy_upstream_discovery (
					version_id, upstream_position, type, hostname, scheme, port,
					service, proto, name, refresh_interval_sec, timeout_ms, max_targets
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				versionID,
				i,
				upstream.Discovery.Type,
				upstream.Discovery.Hostname,
				upstream.Discovery.Scheme,
				upstream.Discovery.Port,
				upstream.Discovery.Service,
				upstream.Discovery.Proto,
				upstream.Discovery.Name,
				upstream.Discovery.RefreshIntervalSec,
				upstream.Discovery.TimeoutMS,
				upstream.Discovery.MaxTargets,
			); err != nil {
				return err
			}
			for j, recordType := range upstream.Discovery.RecordTypes {
				if _, err := s.txExec(tx, `INSERT INTO proxy_upstream_discovery_records (version_id, upstream_position, position, record_type) VALUES (?, ?, ?, ?)`, versionID, i, j, recordType); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyBackendPoolsTx(tx *sql.Tx, versionID int64, pools []ProxyBackendPool) error {
	for i, pool := range pools {
		httpOnlySet, httpOnly := boolPtrToDB(pool.StickySession.HTTPOnly)
		if _, err := s.txExec(
			tx,
			`INSERT INTO proxy_backend_pools (
				version_id, position, name, strategy, hash_policy, hash_key,
				sticky_enabled, sticky_cookie_name, sticky_ttl_seconds,
				sticky_path, sticky_domain, sticky_secure, sticky_http_only_set,
				sticky_http_only, sticky_same_site
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			versionID,
			i,
			pool.Name,
			pool.Strategy,
			pool.HashPolicy,
			pool.HashKey,
			boolToDB(pool.StickySession.Enabled),
			pool.StickySession.CookieName,
			pool.StickySession.TTLSeconds,
			pool.StickySession.Path,
			pool.StickySession.Domain,
			boolToDB(pool.StickySession.Secure),
			httpOnlySet,
			httpOnly,
			pool.StickySession.SameSite,
		); err != nil {
			return err
		}
		for j, member := range pool.Members {
			if _, err := s.txExec(tx, `INSERT INTO proxy_backend_pool_members (version_id, pool_position, position, upstream_name) VALUES (?, ?, ?, ?)`, versionID, i, j, member); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyRoutesTx(tx *sql.Tx, versionID int64, routeKind string, routes []ProxyRoute) error {
	for i, route := range routes {
		if err := s.insertProxyRouteTx(tx, versionID, routeKind, i, route.Name, route.Enabled, route.Priority, route.Generated, route.Match, route.Action); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyDefaultRouteTx(tx *sql.Tx, versionID int64, route ProxyDefaultRoute) error {
	return s.insertProxyRouteTx(tx, versionID, proxyRouteKindDefault, 0, route.Name, route.Enabled, 0, false, ProxyRouteMatch{}, route.Action)
}

func (s *wafEventStore) insertProxyRouteTx(tx *sql.Tx, versionID int64, routeKind string, position int, name string, enabled *bool, priority int, generated bool, match ProxyRouteMatch, action ProxyRouteAction) error {
	enabledSet, enabledValue := boolPtrToDB(enabled)
	pathType := ""
	pathValue := ""
	if match.Path != nil {
		pathType = match.Path.Type
		pathValue = match.Path.Value
	}
	pathRewritePrefix := ""
	if action.PathRewrite != nil {
		pathRewritePrefix = action.PathRewrite.Prefix
	}
	if _, err := s.txExec(
		tx,
		`INSERT INTO proxy_routes (
			version_id, route_kind, position, name, enabled_set, enabled, priority,
			generated, match_path_type, match_path_value, action_upstream,
			action_backend_pool, action_upstream_http2_mode, action_canary_upstream,
			action_canary_upstream_http2_mode, action_canary_weight_percent,
			action_hash_policy, action_hash_key, action_host_rewrite,
			action_path_rewrite_prefix
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		versionID,
		routeKind,
		position,
		name,
		enabledSet,
		enabledValue,
		priority,
		boolToDB(generated),
		pathType,
		pathValue,
		action.Upstream,
		action.BackendPool,
		action.UpstreamHTTP2Mode,
		action.CanaryUpstream,
		action.CanaryUpstreamHTTP2Mode,
		action.CanaryWeightPct,
		action.HashPolicy,
		action.HashKey,
		action.HostRewrite,
		pathRewritePrefix,
	); err != nil {
		return err
	}
	for i, host := range match.Hosts {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_match_hosts (version_id, route_kind, route_position, position, host) VALUES (?, ?, ?, ?, ?)`, versionID, routeKind, position, i, host); err != nil {
			return err
		}
	}
	if err := s.insertProxyRouteHeaderOpsTx(tx, versionID, routeKind, position, "request", action.RequestHeaders); err != nil {
		return err
	}
	if err := s.insertProxyRouteHeaderOpsTx(tx, versionID, routeKind, position, "response", action.ResponseHeaders); err != nil {
		return err
	}
	return s.insertProxyRouteQueryOpsTx(tx, versionID, routeKind, position, action.QueryRewrite)
}

func (s *wafEventStore) insertProxyRouteHeaderOpsTx(tx *sql.Tx, versionID int64, routeKind string, routePosition int, direction string, ops *ProxyRouteHeaderOperations) error {
	if ops == nil {
		return nil
	}
	if err := s.insertProxyRouteHeaderMapTx(tx, versionID, routeKind, routePosition, direction, "set", ops.Set); err != nil {
		return err
	}
	if err := s.insertProxyRouteHeaderMapTx(tx, versionID, routeKind, routePosition, direction, "add", ops.Add); err != nil {
		return err
	}
	for i, name := range ops.Remove {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_header_ops (version_id, route_kind, route_position, direction, operation, position, header_name, header_value) VALUES (?, ?, ?, ?, ?, ?, ?, '')`, versionID, routeKind, routePosition, direction, "remove", i, name); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyRouteHeaderMapTx(tx *sql.Tx, versionID int64, routeKind string, routePosition int, direction string, operation string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_header_ops (version_id, route_kind, route_position, direction, operation, position, header_name, header_value) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`, versionID, routeKind, routePosition, direction, operation, i, key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyRouteQueryOpsTx(tx *sql.Tx, versionID int64, routeKind string, routePosition int, ops *ProxyRouteQueryOperations) error {
	if ops == nil {
		return nil
	}
	if err := s.insertProxyRouteQueryMapTx(tx, versionID, routeKind, routePosition, "set", ops.Set); err != nil {
		return err
	}
	if err := s.insertProxyRouteQueryMapTx(tx, versionID, routeKind, routePosition, "add", ops.Add); err != nil {
		return err
	}
	for i, name := range ops.Remove {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_query_ops (version_id, route_kind, route_position, operation, position, query_name, query_value) VALUES (?, ?, ?, ?, ?, ?, '')`, versionID, routeKind, routePosition, "remove", i, name); err != nil {
			return err
		}
	}
	for i, prefix := range ops.RemovePrefixes {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_query_ops (version_id, route_kind, route_position, operation, position, query_name, query_value) VALUES (?, ?, ?, ?, ?, ?, '')`, versionID, routeKind, routePosition, "remove_prefix", i, prefix); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) insertProxyRouteQueryMapTx(tx *sql.Tx, versionID int64, routeKind string, routePosition int, operation string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for i, key := range keys {
		if _, err := s.txExec(tx, `INSERT INTO proxy_route_query_ops (version_id, route_kind, route_position, operation, position, query_name, query_value) VALUES (?, ?, ?, ?, ?, ?, ?)`, versionID, routeKind, routePosition, operation, i, key, values[key]); err != nil {
			return err
		}
	}
	return nil
}

func (s *wafEventStore) loadProxyConfigVersion(versionID int64) (ProxyRulesConfig, error) {
	cfg, err := s.loadProxySettings(versionID)
	if err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.ResponseCompression.Algorithms, err = s.loadProxyValueList(versionID, "response_compression_algorithms"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.ResponseCompression.MIMETypes, err = s.loadProxyValueList(versionID, "response_compression_mime_types"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.ResponseHeaderSanitize.CustomRemove, err = s.loadProxyValueList(versionID, "response_header_sanitize_custom_remove"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.ResponseHeaderSanitize.CustomKeep, err = s.loadProxyValueList(versionID, "response_header_sanitize_custom_keep"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.RetryMethods, err = s.loadProxyValueList(versionID, "retry_methods"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.RetryStatusCodes, err = s.loadProxyIntList(versionID, "retry_status_codes"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.PassiveUnhealthyStatusCodes, err = s.loadProxyIntList(versionID, "passive_unhealthy_status_codes"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.HealthCheckHeaders, err = s.loadProxyKeyValues(versionID, "health_check_headers"); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.Upstreams, err = s.loadProxyUpstreams(versionID); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.BackendPools, err = s.loadProxyBackendPools(versionID); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.Routes, err = s.loadProxyRoutes(versionID); err != nil {
		return ProxyRulesConfig{}, err
	}
	if cfg.DefaultRoute, err = s.loadProxyDefaultRoute(versionID); err != nil {
		return ProxyRulesConfig{}, err
	}
	return normalizeProxyRulesConfig(cfg), nil
}

func (s *wafEventStore) loadProxySettings(versionID int64) (ProxyRulesConfig, error) {
	var cfg ProxyRulesConfig
	var forceHTTP2, h2cUpstream, disableCompression, exposeDebug, emitUpstreamName int
	var responseCompressionEnabled, responseSanitizeDebug int
	var tlsInsecure, passiveHealth, circuitBreaker, bufferRequestBody int
	row := s.queryRow(
		`SELECT load_balancing_strategy, hash_policy, hash_key,
		        dial_timeout, response_header_timeout, idle_conn_timeout,
		        upstream_keepalive_sec, max_idle_conns, max_idle_conns_per_host,
		        max_conns_per_host, force_http2, h2c_upstream, disable_compression,
		        expose_waf_debug_headers, emit_upstream_name_request_header,
		        access_log_mode, response_compression_enabled,
		        response_compression_min_bytes, expect_continue_timeout,
		        response_header_sanitize_mode, response_header_sanitize_debug_log,
		        tls_insecure_skip_verify, tls_ca_bundle, tls_min_version,
		        tls_max_version, tls_client_cert, tls_client_key, retry_attempts,
		        retry_backoff_ms, retry_per_try_timeout_ms, passive_health_enabled,
		        passive_failure_threshold, circuit_breaker_enabled,
		        circuit_breaker_open_sec, circuit_breaker_half_open_requests,
		        buffer_request_body, max_response_buffer_bytes, flush_interval_ms,
		        health_check_path, health_check_interval_sec, health_check_timeout_sec,
		        health_check_expected_body, health_check_expected_body_regex,
		        error_html_file, error_redirect_url
		   FROM proxy_settings
		  WHERE version_id = ?`,
		versionID,
	)
	if err := row.Scan(
		&cfg.LoadBalancingStrategy,
		&cfg.HashPolicy,
		&cfg.HashKey,
		&cfg.DialTimeout,
		&cfg.ResponseHeaderTimeout,
		&cfg.IdleConnTimeout,
		&cfg.UpstreamKeepAliveSec,
		&cfg.MaxIdleConns,
		&cfg.MaxIdleConnsPerHost,
		&cfg.MaxConnsPerHost,
		&forceHTTP2,
		&h2cUpstream,
		&disableCompression,
		&exposeDebug,
		&emitUpstreamName,
		&cfg.AccessLogMode,
		&responseCompressionEnabled,
		&cfg.ResponseCompression.MinBytes,
		&cfg.ExpectContinueTimeout,
		&cfg.ResponseHeaderSanitize.Mode,
		&responseSanitizeDebug,
		&tlsInsecure,
		&cfg.TLSCABundle,
		&cfg.TLSMinVersion,
		&cfg.TLSMaxVersion,
		&cfg.TLSClientCert,
		&cfg.TLSClientKey,
		&cfg.RetryAttempts,
		&cfg.RetryBackoffMS,
		&cfg.RetryPerTryTimeoutMS,
		&passiveHealth,
		&cfg.PassiveFailureThreshold,
		&circuitBreaker,
		&cfg.CircuitBreakerOpenSec,
		&cfg.CircuitBreakerHalfOpenRequests,
		&bufferRequestBody,
		&cfg.MaxResponseBufferBytes,
		&cfg.FlushIntervalMS,
		&cfg.HealthCheckPath,
		&cfg.HealthCheckInterval,
		&cfg.HealthCheckTimeout,
		&cfg.HealthCheckExpectedBody,
		&cfg.HealthCheckExpectedBodyRegex,
		&cfg.ErrorHTMLFile,
		&cfg.ErrorRedirectURL,
	); err != nil {
		return ProxyRulesConfig{}, err
	}
	cfg.ForceHTTP2 = boolFromDB(forceHTTP2)
	cfg.H2CUpstream = boolFromDB(h2cUpstream)
	cfg.DisableCompression = boolFromDB(disableCompression)
	cfg.ExposeWAFDebugHeaders = boolFromDB(exposeDebug)
	cfg.EmitUpstreamNameRequestHeader = boolFromDB(emitUpstreamName)
	cfg.ResponseCompression.Enabled = boolFromDB(responseCompressionEnabled)
	cfg.ResponseHeaderSanitize.DebugLog = boolFromDB(responseSanitizeDebug)
	cfg.TLSInsecureSkipVerify = boolFromDB(tlsInsecure)
	cfg.PassiveHealthEnabled = boolFromDB(passiveHealth)
	cfg.CircuitBreakerEnabled = boolFromDB(circuitBreaker)
	cfg.BufferRequestBody = boolFromDB(bufferRequestBody)
	return cfg, nil
}

func (s *wafEventStore) loadProxyValueList(versionID int64, listName string) ([]string, error) {
	rows, err := s.query(`SELECT value FROM proxy_value_list WHERE version_id = ? AND list_name = ? ORDER BY position`, versionID, listName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var value string
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadProxyIntList(versionID int64, listName string) ([]int, error) {
	rows, err := s.query(`SELECT value FROM proxy_int_list WHERE version_id = ? AND list_name = ? ORDER BY position`, versionID, listName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []int
	for rows.Next() {
		var value int
		if err := rows.Scan(&value); err != nil {
			return nil, err
		}
		out = append(out, value)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadProxyKeyValues(versionID int64, mapName string) (map[string]string, error) {
	rows, err := s.query(`SELECT name, value FROM proxy_key_values WHERE version_id = ? AND map_name = ? ORDER BY position`, versionID, mapName)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var name, value string
		if err := rows.Scan(&name, &value); err != nil {
			return nil, err
		}
		out[name] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func (s *wafEventStore) loadProxyUpstreams(versionID int64) ([]ProxyUpstream, error) {
	rows, err := s.query(
		`SELECT position, name, url, weight, enabled, http2_mode,
		        generated, generated_kind, provider_class, managed_by_vhost
		   FROM proxy_upstreams
		  WHERE version_id = ?
		  ORDER BY position`,
		versionID,
	)
	if err != nil {
		return nil, err
	}
	type upstreamRow struct {
		position int
		upstream ProxyUpstream
	}
	var scanned []upstreamRow
	var scanErr error
	for rows.Next() {
		var pos int
		var enabled, generated int
		var upstream ProxyUpstream
		if err := rows.Scan(
			&pos,
			&upstream.Name,
			&upstream.URL,
			&upstream.Weight,
			&enabled,
			&upstream.HTTP2Mode,
			&generated,
			&upstream.GeneratedKind,
			&upstream.ProviderClass,
			&upstream.ManagedByVhost,
		); err != nil {
			scanErr = err
			break
		}
		upstream.Enabled = boolFromDB(enabled)
		upstream.Generated = boolFromDB(generated)
		scanned = append(scanned, upstreamRow{position: pos, upstream: upstream})
	}
	if scanErr == nil {
		scanErr = rows.Err()
	}
	closeErr := rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	out := make([]ProxyUpstream, 0, len(scanned))
	for _, item := range scanned {
		tlsCfg, err := s.loadProxyUpstreamTLS(versionID, item.position)
		if err != nil {
			return nil, err
		}
		item.upstream.TLS = tlsCfg
		discovery, err := s.loadProxyUpstreamDiscovery(versionID, item.position)
		if err != nil {
			return nil, err
		}
		item.upstream.Discovery = discovery
		out = append(out, item.upstream)
	}
	return out, nil
}

func (s *wafEventStore) loadProxyUpstreamTLS(versionID int64, upstreamPosition int) (ProxyUpstreamTLSConfig, error) {
	row := s.queryRow(
		`SELECT server_name, ca_bundle, min_version, max_version, client_cert, client_key
		   FROM proxy_upstream_tls
		  WHERE version_id = ? AND upstream_position = ?`,
		versionID,
		upstreamPosition,
	)
	var out ProxyUpstreamTLSConfig
	if err := row.Scan(&out.ServerName, &out.CABundle, &out.MinVersion, &out.MaxVersion, &out.ClientCert, &out.ClientKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyUpstreamTLSConfig{}, nil
		}
		return ProxyUpstreamTLSConfig{}, err
	}
	return out, nil
}

func (s *wafEventStore) loadProxyUpstreamDiscovery(versionID int64, upstreamPosition int) (ProxyDiscoveryConfig, error) {
	row := s.queryRow(
		`SELECT type, hostname, scheme, port, service, proto, name,
		        refresh_interval_sec, timeout_ms, max_targets
		   FROM proxy_upstream_discovery
		  WHERE version_id = ? AND upstream_position = ?`,
		versionID,
		upstreamPosition,
	)
	var out ProxyDiscoveryConfig
	if err := row.Scan(
		&out.Type,
		&out.Hostname,
		&out.Scheme,
		&out.Port,
		&out.Service,
		&out.Proto,
		&out.Name,
		&out.RefreshIntervalSec,
		&out.TimeoutMS,
		&out.MaxTargets,
	); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ProxyDiscoveryConfig{}, nil
		}
		return ProxyDiscoveryConfig{}, err
	}
	records, err := s.loadProxyDiscoveryRecordTypes(versionID, upstreamPosition)
	if err != nil {
		return ProxyDiscoveryConfig{}, err
	}
	out.RecordTypes = records
	return out, nil
}

func (s *wafEventStore) loadProxyDiscoveryRecordTypes(versionID int64, upstreamPosition int) ([]string, error) {
	rows, err := s.query(`SELECT record_type FROM proxy_upstream_discovery_records WHERE version_id = ? AND upstream_position = ? ORDER BY position`, versionID, upstreamPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var recordType string
		if err := rows.Scan(&recordType); err != nil {
			return nil, err
		}
		out = append(out, recordType)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadProxyBackendPools(versionID int64) ([]ProxyBackendPool, error) {
	rows, err := s.query(
		`SELECT position, name, strategy, hash_policy, hash_key,
		        sticky_enabled, sticky_cookie_name, sticky_ttl_seconds,
		        sticky_path, sticky_domain, sticky_secure, sticky_http_only_set,
		        sticky_http_only, sticky_same_site
		   FROM proxy_backend_pools
		  WHERE version_id = ?
		  ORDER BY position`,
		versionID,
	)
	if err != nil {
		return nil, err
	}
	type poolRow struct {
		position int
		pool     ProxyBackendPool
	}
	var scanned []poolRow
	var scanErr error
	for rows.Next() {
		var pos int
		var stickyEnabled, stickySecure, httpOnlySet, httpOnly int
		var pool ProxyBackendPool
		if err := rows.Scan(
			&pos,
			&pool.Name,
			&pool.Strategy,
			&pool.HashPolicy,
			&pool.HashKey,
			&stickyEnabled,
			&pool.StickySession.CookieName,
			&pool.StickySession.TTLSeconds,
			&pool.StickySession.Path,
			&pool.StickySession.Domain,
			&stickySecure,
			&httpOnlySet,
			&httpOnly,
			&pool.StickySession.SameSite,
		); err != nil {
			scanErr = err
			break
		}
		pool.StickySession.Enabled = boolFromDB(stickyEnabled)
		pool.StickySession.Secure = boolFromDB(stickySecure)
		pool.StickySession.HTTPOnly = boolPtrFromDB(httpOnlySet, httpOnly)
		scanned = append(scanned, poolRow{position: pos, pool: pool})
	}
	if scanErr == nil {
		scanErr = rows.Err()
	}
	closeErr := rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	out := make([]ProxyBackendPool, 0, len(scanned))
	for _, item := range scanned {
		members, err := s.loadProxyBackendPoolMembers(versionID, item.position)
		if err != nil {
			return nil, err
		}
		item.pool.Members = members
		out = append(out, item.pool)
	}
	return out, nil
}

func (s *wafEventStore) loadProxyBackendPoolMembers(versionID int64, poolPosition int) ([]string, error) {
	rows, err := s.query(`SELECT upstream_name FROM proxy_backend_pool_members WHERE version_id = ? AND pool_position = ? ORDER BY position`, versionID, poolPosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var member string
		if err := rows.Scan(&member); err != nil {
			return nil, err
		}
		out = append(out, member)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadProxyRoutes(versionID int64) ([]ProxyRoute, error) {
	rows, err := s.query(
		`SELECT position, name, enabled_set, enabled, priority, generated,
		        match_path_type, match_path_value, action_upstream,
		        action_backend_pool, action_upstream_http2_mode,
		        action_canary_upstream, action_canary_upstream_http2_mode,
		        action_canary_weight_percent, action_hash_policy,
		        action_hash_key, action_host_rewrite, action_path_rewrite_prefix
		   FROM proxy_routes
		  WHERE version_id = ? AND route_kind = ?
		  ORDER BY position`,
		versionID,
		proxyRouteKindRoute,
	)
	if err != nil {
		return nil, err
	}
	type routeRow struct {
		position int
		route    ProxyRoute
	}
	var scanned []routeRow
	var scanErr error
	for rows.Next() {
		position, route, err := scanProxyRouteBaseRow(rows)
		if err != nil {
			scanErr = err
			break
		}
		scanned = append(scanned, routeRow{position: position, route: route})
	}
	if scanErr == nil {
		scanErr = rows.Err()
	}
	closeErr := rows.Close()
	if scanErr != nil {
		return nil, scanErr
	}
	if closeErr != nil {
		return nil, closeErr
	}

	out := make([]ProxyRoute, 0, len(scanned))
	for _, item := range scanned {
		route, err := s.attachProxyRouteRelations(versionID, proxyRouteKindRoute, item.position, item.route)
		if err != nil {
			return nil, err
		}
		out = append(out, route)
	}
	return out, nil
}

func (s *wafEventStore) loadProxyDefaultRoute(versionID int64) (*ProxyDefaultRoute, error) {
	row := s.queryRow(
		`SELECT position, name, enabled_set, enabled, priority, generated,
		        match_path_type, match_path_value, action_upstream,
		        action_backend_pool, action_upstream_http2_mode,
		        action_canary_upstream, action_canary_upstream_http2_mode,
		        action_canary_weight_percent, action_hash_policy,
		        action_hash_key, action_host_rewrite, action_path_rewrite_prefix
		   FROM proxy_routes
		  WHERE version_id = ? AND route_kind = ? AND position = 0`,
		versionID,
		proxyRouteKindDefault,
	)
	route, err := s.scanProxyRouteRow(row, versionID, proxyRouteKindDefault)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &ProxyDefaultRoute{
		Name:    route.Name,
		Enabled: route.Enabled,
		Action:  route.Action,
	}, nil
}

func (s *wafEventStore) scanProxyRouteRow(scanner configVersionScanner, versionID int64, routeKind string) (ProxyRoute, error) {
	position, route, err := scanProxyRouteBaseRow(scanner)
	if err != nil {
		return ProxyRoute{}, err
	}
	return s.attachProxyRouteRelations(versionID, routeKind, position, route)
}

func scanProxyRouteBaseRow(scanner configVersionScanner) (int, ProxyRoute, error) {
	var route ProxyRoute
	var position int
	var enabledSet, enabled, generated int
	var pathType, pathValue, pathRewritePrefix string
	if err := scanner.Scan(
		&position,
		&route.Name,
		&enabledSet,
		&enabled,
		&route.Priority,
		&generated,
		&pathType,
		&pathValue,
		&route.Action.Upstream,
		&route.Action.BackendPool,
		&route.Action.UpstreamHTTP2Mode,
		&route.Action.CanaryUpstream,
		&route.Action.CanaryUpstreamHTTP2Mode,
		&route.Action.CanaryWeightPct,
		&route.Action.HashPolicy,
		&route.Action.HashKey,
		&route.Action.HostRewrite,
		&pathRewritePrefix,
	); err != nil {
		return 0, ProxyRoute{}, err
	}
	route.Enabled = boolPtrFromDB(enabledSet, enabled)
	route.Generated = boolFromDB(generated)
	if pathType != "" || pathValue != "" {
		route.Match.Path = &ProxyRoutePathMatch{Type: pathType, Value: pathValue}
	}
	if pathRewritePrefix != "" {
		route.Action.PathRewrite = &ProxyRoutePathRewrite{Prefix: pathRewritePrefix}
	}
	return position, route, nil
}

func (s *wafEventStore) attachProxyRouteRelations(versionID int64, routeKind string, position int, route ProxyRoute) (ProxyRoute, error) {
	hosts, err := s.loadProxyRouteHosts(versionID, routeKind, position)
	if err != nil {
		return ProxyRoute{}, err
	}
	route.Match.Hosts = hosts
	requestHeaders, err := s.loadProxyRouteHeaderOps(versionID, routeKind, position, "request")
	if err != nil {
		return ProxyRoute{}, err
	}
	route.Action.RequestHeaders = requestHeaders
	responseHeaders, err := s.loadProxyRouteHeaderOps(versionID, routeKind, position, "response")
	if err != nil {
		return ProxyRoute{}, err
	}
	route.Action.ResponseHeaders = responseHeaders
	queryOps, err := s.loadProxyRouteQueryOps(versionID, routeKind, position)
	if err != nil {
		return ProxyRoute{}, err
	}
	route.Action.QueryRewrite = queryOps
	return route, nil
}

func (s *wafEventStore) loadProxyRouteHosts(versionID int64, routeKind string, routePosition int) ([]string, error) {
	rows, err := s.query(`SELECT host FROM proxy_route_match_hosts WHERE version_id = ? AND route_kind = ? AND route_position = ? ORDER BY position`, versionID, routeKind, routePosition)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var host string
		if err := rows.Scan(&host); err != nil {
			return nil, err
		}
		out = append(out, host)
	}
	return out, rows.Err()
}

func (s *wafEventStore) loadProxyRouteHeaderOps(versionID int64, routeKind string, routePosition int, direction string) (*ProxyRouteHeaderOperations, error) {
	rows, err := s.query(
		`SELECT operation, header_name, header_value
		   FROM proxy_route_header_ops
		  WHERE version_id = ? AND route_kind = ? AND route_position = ? AND direction = ?
		  ORDER BY operation, position`,
		versionID,
		routeKind,
		routePosition,
		direction,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := &ProxyRouteHeaderOperations{}
	for rows.Next() {
		var operation, name, value string
		if err := rows.Scan(&operation, &name, &value); err != nil {
			return nil, err
		}
		switch operation {
		case "set":
			if ops.Set == nil {
				ops.Set = map[string]string{}
			}
			ops.Set[name] = value
		case "add":
			if ops.Add == nil {
				ops.Add = map[string]string{}
			}
			ops.Add[name] = value
		case "remove":
			ops.Remove = append(ops.Remove, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if proxyRouteHeaderOperationsIsZero(*ops) {
		return nil, nil
	}
	return ops, nil
}

func (s *wafEventStore) loadProxyRouteQueryOps(versionID int64, routeKind string, routePosition int) (*ProxyRouteQueryOperations, error) {
	rows, err := s.query(
		`SELECT operation, query_name, query_value
		   FROM proxy_route_query_ops
		  WHERE version_id = ? AND route_kind = ? AND route_position = ?
		  ORDER BY operation, position`,
		versionID,
		routeKind,
		routePosition,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ops := &ProxyRouteQueryOperations{}
	for rows.Next() {
		var operation, name, value string
		if err := rows.Scan(&operation, &name, &value); err != nil {
			return nil, err
		}
		switch operation {
		case "set":
			if ops.Set == nil {
				ops.Set = map[string]string{}
			}
			ops.Set[name] = value
		case "add":
			if ops.Add == nil {
				ops.Add = map[string]string{}
			}
			ops.Add[name] = value
		case "remove":
			ops.Remove = append(ops.Remove, name)
		case "remove_prefix":
			ops.RemovePrefixes = append(ops.RemovePrefixes, name)
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if len(ops.Set) == 0 && len(ops.Add) == 0 && len(ops.Remove) == 0 && len(ops.RemovePrefixes) == 0 {
		return nil, nil
	}
	return ops, nil
}
