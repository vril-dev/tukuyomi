CREATE TABLE IF NOT EXISTS config_domains (
	domain VARCHAR(128) NOT NULL PRIMARY KEY,
	active_version_id BIGINT NULL,
	current_generation BIGINT NOT NULL DEFAULT 0,
	current_etag VARCHAR(256) NOT NULL DEFAULT '',
	config_schema_version INT NOT NULL DEFAULT 1,
	updated_at_unix BIGINT NOT NULL,
	updated_at VARCHAR(64) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS config_versions (
	version_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	domain VARCHAR(128) NOT NULL,
	generation BIGINT NOT NULL,
	config_schema_version INT NOT NULL,
	parent_version_id BIGINT NULL,
	restored_from_version_id BIGINT NULL,
	source VARCHAR(64) NOT NULL,
	actor VARCHAR(255) NOT NULL,
	reason VARCHAR(1024) NOT NULL,
	content_hash CHAR(64) NOT NULL,
	etag VARCHAR(256) NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	activated_at_unix BIGINT NOT NULL,
	activated_at VARCHAR(64) NOT NULL,
	UNIQUE KEY uq_config_versions_domain_generation (domain, generation),
	UNIQUE KEY uq_config_versions_domain_etag (domain, etag),
	KEY idx_config_versions_domain_created (domain, created_at_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS config_rollbacks (
	rollback_id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	domain VARCHAR(128) NOT NULL,
	from_version_id BIGINT NOT NULL,
	restored_version_id BIGINT NOT NULL,
	new_version_id BIGINT NOT NULL,
	actor VARCHAR(255) NOT NULL,
	reason VARCHAR(1024) NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at VARCHAR(64) NOT NULL,
	KEY idx_config_rollbacks_domain_created (domain, created_at_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_settings (
	version_id BIGINT NOT NULL PRIMARY KEY,
	load_balancing_strategy VARCHAR(64) NOT NULL,
	hash_policy VARCHAR(64) NOT NULL,
	hash_key VARCHAR(255) NOT NULL,
	dial_timeout BIGINT NOT NULL,
	response_header_timeout BIGINT NOT NULL,
	idle_conn_timeout BIGINT NOT NULL,
	upstream_keepalive_sec BIGINT NOT NULL,
	max_idle_conns BIGINT NOT NULL,
	max_idle_conns_per_host BIGINT NOT NULL,
	max_conns_per_host BIGINT NOT NULL,
	force_http2 INT NOT NULL,
	h2c_upstream INT NOT NULL,
	disable_compression INT NOT NULL,
	expose_waf_debug_headers INT NOT NULL,
	emit_upstream_name_request_header INT NOT NULL,
	access_log_mode VARCHAR(64) NOT NULL,
	response_compression_enabled INT NOT NULL,
	response_compression_min_bytes BIGINT NOT NULL,
	expect_continue_timeout BIGINT NOT NULL,
	response_header_sanitize_mode VARCHAR(64) NOT NULL,
	response_header_sanitize_debug_log INT NOT NULL,
	tls_insecure_skip_verify INT NOT NULL,
	tls_ca_bundle LONGTEXT NOT NULL,
	tls_min_version VARCHAR(64) NOT NULL,
	tls_max_version VARCHAR(64) NOT NULL,
	tls_client_cert LONGTEXT NOT NULL,
	tls_client_key LONGTEXT NOT NULL,
	retry_attempts BIGINT NOT NULL,
	retry_backoff_ms BIGINT NOT NULL,
	retry_per_try_timeout_ms BIGINT NOT NULL,
	passive_health_enabled INT NOT NULL,
	passive_failure_threshold BIGINT NOT NULL,
	circuit_breaker_enabled INT NOT NULL,
	circuit_breaker_open_sec BIGINT NOT NULL,
	circuit_breaker_half_open_requests BIGINT NOT NULL,
	buffer_request_body INT NOT NULL,
	max_response_buffer_bytes BIGINT NOT NULL,
	flush_interval_ms BIGINT NOT NULL,
	health_check_path VARCHAR(2048) NOT NULL,
	health_check_interval_sec BIGINT NOT NULL,
	health_check_timeout_sec BIGINT NOT NULL,
	health_check_expected_body LONGTEXT NOT NULL,
	health_check_expected_body_regex LONGTEXT NOT NULL,
	error_html_file VARCHAR(2048) NOT NULL,
	error_redirect_url VARCHAR(2048) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_value_list (
	version_id BIGINT NOT NULL,
	list_name VARCHAR(128) NOT NULL,
	position BIGINT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY(version_id, list_name, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_int_list (
	version_id BIGINT NOT NULL,
	list_name VARCHAR(128) NOT NULL,
	position BIGINT NOT NULL,
	value BIGINT NOT NULL,
	PRIMARY KEY(version_id, list_name, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_key_values (
	version_id BIGINT NOT NULL,
	map_name VARCHAR(128) NOT NULL,
	position BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY(version_id, map_name, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_upstreams (
	version_id BIGINT NOT NULL,
	position BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	url TEXT NOT NULL,
	weight BIGINT NOT NULL,
	enabled INT NOT NULL,
	http2_mode VARCHAR(64) NOT NULL,
	generated INT NOT NULL,
	generated_kind VARCHAR(128) NOT NULL,
	provider_class VARCHAR(128) NOT NULL,
	managed_by_vhost VARCHAR(255) NOT NULL,
	PRIMARY KEY(version_id, position),
	KEY idx_proxy_upstreams_name (version_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_upstream_tls (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	server_name VARCHAR(255) NOT NULL,
	ca_bundle LONGTEXT NOT NULL,
	min_version VARCHAR(64) NOT NULL,
	max_version VARCHAR(64) NOT NULL,
	client_cert LONGTEXT NOT NULL,
	client_key LONGTEXT NOT NULL,
	PRIMARY KEY(version_id, upstream_position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_upstream_discovery (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	type VARCHAR(64) NOT NULL,
	hostname VARCHAR(255) NOT NULL,
	scheme VARCHAR(32) NOT NULL,
	port BIGINT NOT NULL,
	service VARCHAR(255) NOT NULL,
	proto VARCHAR(64) NOT NULL,
	name VARCHAR(255) NOT NULL,
	refresh_interval_sec BIGINT NOT NULL,
	timeout_ms BIGINT NOT NULL,
	max_targets BIGINT NOT NULL,
	PRIMARY KEY(version_id, upstream_position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_upstream_discovery_records (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	record_type VARCHAR(32) NOT NULL,
	PRIMARY KEY(version_id, upstream_position, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_backend_pools (
	version_id BIGINT NOT NULL,
	position BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	strategy VARCHAR(64) NOT NULL,
	hash_policy VARCHAR(64) NOT NULL,
	hash_key VARCHAR(255) NOT NULL,
	sticky_enabled INT NOT NULL,
	sticky_cookie_name VARCHAR(255) NOT NULL,
	sticky_ttl_seconds BIGINT NOT NULL,
	sticky_path VARCHAR(2048) NOT NULL,
	sticky_domain VARCHAR(255) NOT NULL,
	sticky_secure INT NOT NULL,
	sticky_http_only_set INT NOT NULL,
	sticky_http_only INT NOT NULL,
	sticky_same_site VARCHAR(64) NOT NULL,
	PRIMARY KEY(version_id, position),
	KEY idx_proxy_backend_pools_name (version_id, name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_backend_pool_members (
	version_id BIGINT NOT NULL,
	pool_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	upstream_name VARCHAR(255) NOT NULL,
	PRIMARY KEY(version_id, pool_position, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_routes (
	version_id BIGINT NOT NULL,
	route_kind VARCHAR(32) NOT NULL,
	position BIGINT NOT NULL,
	name VARCHAR(255) NOT NULL,
	enabled_set INT NOT NULL,
	enabled INT NOT NULL,
	priority BIGINT NOT NULL,
	generated INT NOT NULL,
	match_path_type VARCHAR(64) NOT NULL,
	match_path_value TEXT NOT NULL,
	action_upstream VARCHAR(255) NOT NULL,
	action_backend_pool VARCHAR(255) NOT NULL,
	action_upstream_http2_mode VARCHAR(64) NOT NULL,
	action_canary_upstream VARCHAR(255) NOT NULL,
	action_canary_upstream_http2_mode VARCHAR(64) NOT NULL,
	action_canary_weight_percent BIGINT NOT NULL,
	action_hash_policy VARCHAR(64) NOT NULL,
	action_hash_key VARCHAR(255) NOT NULL,
	action_host_rewrite VARCHAR(255) NOT NULL,
	action_path_rewrite_prefix VARCHAR(2048) NOT NULL,
	PRIMARY KEY(version_id, route_kind, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_route_match_hosts (
	version_id BIGINT NOT NULL,
	route_kind VARCHAR(32) NOT NULL,
	route_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	host VARCHAR(255) NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_route_header_ops (
	version_id BIGINT NOT NULL,
	route_kind VARCHAR(32) NOT NULL,
	route_position BIGINT NOT NULL,
	direction VARCHAR(32) NOT NULL,
	operation VARCHAR(32) NOT NULL,
	position BIGINT NOT NULL,
	header_name VARCHAR(255) NOT NULL,
	header_value TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, direction, operation, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS proxy_route_query_ops (
	version_id BIGINT NOT NULL,
	route_kind VARCHAR(32) NOT NULL,
	route_position BIGINT NOT NULL,
	operation VARCHAR(32) NOT NULL,
	position BIGINT NOT NULL,
	query_name VARCHAR(255) NOT NULL,
	query_value TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, operation, position)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
