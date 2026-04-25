CREATE TABLE IF NOT EXISTS config_domains (
	domain TEXT PRIMARY KEY,
	active_version_id BIGINT,
	current_generation BIGINT NOT NULL DEFAULT 0,
	current_etag TEXT NOT NULL DEFAULT '',
	config_schema_version INTEGER NOT NULL DEFAULT 1,
	updated_at_unix BIGINT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_versions (
	version_id BIGSERIAL PRIMARY KEY,
	domain TEXT NOT NULL,
	generation BIGINT NOT NULL,
	config_schema_version INTEGER NOT NULL,
	parent_version_id BIGINT,
	restored_from_version_id BIGINT,
	source TEXT NOT NULL,
	actor TEXT NOT NULL,
	reason TEXT NOT NULL,
	content_hash TEXT NOT NULL,
	etag TEXT NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL,
	activated_at_unix BIGINT NOT NULL,
	activated_at TEXT NOT NULL,
	UNIQUE(domain, generation),
	UNIQUE(domain, etag)
);

CREATE INDEX IF NOT EXISTS idx_config_versions_domain_created ON config_versions(domain, created_at_unix);

CREATE TABLE IF NOT EXISTS config_rollbacks (
	rollback_id BIGSERIAL PRIMARY KEY,
	domain TEXT NOT NULL,
	from_version_id BIGINT NOT NULL,
	restored_version_id BIGINT NOT NULL,
	new_version_id BIGINT NOT NULL,
	actor TEXT NOT NULL,
	reason TEXT NOT NULL,
	created_at_unix BIGINT NOT NULL,
	created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_rollbacks_domain_created ON config_rollbacks(domain, created_at_unix);

CREATE TABLE IF NOT EXISTS proxy_settings (
	version_id BIGINT PRIMARY KEY,
	load_balancing_strategy TEXT NOT NULL,
	hash_policy TEXT NOT NULL,
	hash_key TEXT NOT NULL,
	dial_timeout BIGINT NOT NULL,
	response_header_timeout BIGINT NOT NULL,
	idle_conn_timeout BIGINT NOT NULL,
	upstream_keepalive_sec BIGINT NOT NULL,
	max_idle_conns BIGINT NOT NULL,
	max_idle_conns_per_host BIGINT NOT NULL,
	max_conns_per_host BIGINT NOT NULL,
	force_http2 INTEGER NOT NULL,
	h2c_upstream INTEGER NOT NULL,
	disable_compression INTEGER NOT NULL,
	expose_waf_debug_headers INTEGER NOT NULL,
	emit_upstream_name_request_header INTEGER NOT NULL,
	access_log_mode TEXT NOT NULL,
	response_compression_enabled INTEGER NOT NULL,
	response_compression_min_bytes BIGINT NOT NULL,
	expect_continue_timeout BIGINT NOT NULL,
	response_header_sanitize_mode TEXT NOT NULL,
	response_header_sanitize_debug_log INTEGER NOT NULL,
	tls_insecure_skip_verify INTEGER NOT NULL,
	tls_ca_bundle TEXT NOT NULL,
	tls_min_version TEXT NOT NULL,
	tls_max_version TEXT NOT NULL,
	tls_client_cert TEXT NOT NULL,
	tls_client_key TEXT NOT NULL,
	retry_attempts BIGINT NOT NULL,
	retry_backoff_ms BIGINT NOT NULL,
	retry_per_try_timeout_ms BIGINT NOT NULL,
	passive_health_enabled INTEGER NOT NULL,
	passive_failure_threshold BIGINT NOT NULL,
	circuit_breaker_enabled INTEGER NOT NULL,
	circuit_breaker_open_sec BIGINT NOT NULL,
	circuit_breaker_half_open_requests BIGINT NOT NULL,
	buffer_request_body INTEGER NOT NULL,
	max_response_buffer_bytes BIGINT NOT NULL,
	flush_interval_ms BIGINT NOT NULL,
	health_check_path TEXT NOT NULL,
	health_check_interval_sec BIGINT NOT NULL,
	health_check_timeout_sec BIGINT NOT NULL,
	health_check_expected_body TEXT NOT NULL,
	health_check_expected_body_regex TEXT NOT NULL,
	error_html_file TEXT NOT NULL,
	error_redirect_url TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS proxy_value_list (
	version_id BIGINT NOT NULL,
	list_name TEXT NOT NULL,
	position BIGINT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY(version_id, list_name, position)
);

CREATE TABLE IF NOT EXISTS proxy_int_list (
	version_id BIGINT NOT NULL,
	list_name TEXT NOT NULL,
	position BIGINT NOT NULL,
	value BIGINT NOT NULL,
	PRIMARY KEY(version_id, list_name, position)
);

CREATE TABLE IF NOT EXISTS proxy_key_values (
	version_id BIGINT NOT NULL,
	map_name TEXT NOT NULL,
	position BIGINT NOT NULL,
	name TEXT NOT NULL,
	value TEXT NOT NULL,
	PRIMARY KEY(version_id, map_name, position)
);

CREATE TABLE IF NOT EXISTS proxy_upstreams (
	version_id BIGINT NOT NULL,
	position BIGINT NOT NULL,
	name TEXT NOT NULL,
	url TEXT NOT NULL,
	weight BIGINT NOT NULL,
	enabled INTEGER NOT NULL,
	http2_mode TEXT NOT NULL,
	is_generated INTEGER NOT NULL,
	generated_kind TEXT NOT NULL,
	provider_class TEXT NOT NULL,
	managed_by_vhost TEXT NOT NULL,
	PRIMARY KEY(version_id, position)
);

CREATE INDEX IF NOT EXISTS idx_proxy_upstreams_name ON proxy_upstreams(version_id, name);

CREATE TABLE IF NOT EXISTS proxy_upstream_tls (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	server_name TEXT NOT NULL,
	ca_bundle TEXT NOT NULL,
	min_version TEXT NOT NULL,
	max_version TEXT NOT NULL,
	client_cert TEXT NOT NULL,
	client_key TEXT NOT NULL,
	PRIMARY KEY(version_id, upstream_position)
);

CREATE TABLE IF NOT EXISTS proxy_upstream_discovery (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	type TEXT NOT NULL,
	hostname TEXT NOT NULL,
	scheme TEXT NOT NULL,
	port BIGINT NOT NULL,
	service TEXT NOT NULL,
	proto TEXT NOT NULL,
	name TEXT NOT NULL,
	refresh_interval_sec BIGINT NOT NULL,
	timeout_ms BIGINT NOT NULL,
	max_targets BIGINT NOT NULL,
	PRIMARY KEY(version_id, upstream_position)
);

CREATE TABLE IF NOT EXISTS proxy_upstream_discovery_records (
	version_id BIGINT NOT NULL,
	upstream_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	record_type TEXT NOT NULL,
	PRIMARY KEY(version_id, upstream_position, position)
);

CREATE TABLE IF NOT EXISTS proxy_backend_pools (
	version_id BIGINT NOT NULL,
	position BIGINT NOT NULL,
	name TEXT NOT NULL,
	strategy TEXT NOT NULL,
	hash_policy TEXT NOT NULL,
	hash_key TEXT NOT NULL,
	sticky_enabled INTEGER NOT NULL,
	sticky_cookie_name TEXT NOT NULL,
	sticky_ttl_seconds BIGINT NOT NULL,
	sticky_path TEXT NOT NULL,
	sticky_domain TEXT NOT NULL,
	sticky_secure INTEGER NOT NULL,
	sticky_http_only_set INTEGER NOT NULL,
	sticky_http_only INTEGER NOT NULL,
	sticky_same_site TEXT NOT NULL,
	PRIMARY KEY(version_id, position)
);

CREATE INDEX IF NOT EXISTS idx_proxy_backend_pools_name ON proxy_backend_pools(version_id, name);

CREATE TABLE IF NOT EXISTS proxy_backend_pool_members (
	version_id BIGINT NOT NULL,
	pool_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	upstream_name TEXT NOT NULL,
	PRIMARY KEY(version_id, pool_position, position)
);

CREATE TABLE IF NOT EXISTS proxy_routes (
	version_id BIGINT NOT NULL,
	route_kind TEXT NOT NULL,
	position BIGINT NOT NULL,
	name TEXT NOT NULL,
	enabled_set INTEGER NOT NULL,
	enabled INTEGER NOT NULL,
	priority BIGINT NOT NULL,
	is_generated INTEGER NOT NULL,
	match_path_type TEXT NOT NULL,
	match_path_value TEXT NOT NULL,
	action_upstream TEXT NOT NULL,
	action_backend_pool TEXT NOT NULL,
	action_upstream_http2_mode TEXT NOT NULL,
	action_canary_upstream TEXT NOT NULL,
	action_canary_upstream_http2_mode TEXT NOT NULL,
	action_canary_weight_percent BIGINT NOT NULL,
	action_hash_policy TEXT NOT NULL,
	action_hash_key TEXT NOT NULL,
	action_host_rewrite TEXT NOT NULL,
	action_path_rewrite_prefix TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, position)
);

CREATE TABLE IF NOT EXISTS proxy_route_match_hosts (
	version_id BIGINT NOT NULL,
	route_kind TEXT NOT NULL,
	route_position BIGINT NOT NULL,
	position BIGINT NOT NULL,
	host TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, position)
);

CREATE TABLE IF NOT EXISTS proxy_route_header_ops (
	version_id BIGINT NOT NULL,
	route_kind TEXT NOT NULL,
	route_position BIGINT NOT NULL,
	direction TEXT NOT NULL,
	operation TEXT NOT NULL,
	position BIGINT NOT NULL,
	header_name TEXT NOT NULL,
	header_value TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, direction, operation, position)
);

CREATE TABLE IF NOT EXISTS proxy_route_query_ops (
	version_id BIGINT NOT NULL,
	route_kind TEXT NOT NULL,
	route_position BIGINT NOT NULL,
	operation TEXT NOT NULL,
	position BIGINT NOT NULL,
	query_name TEXT NOT NULL,
	query_value TEXT NOT NULL,
	PRIMARY KEY(version_id, route_kind, route_position, operation, position)
);
