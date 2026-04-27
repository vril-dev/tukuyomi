CREATE TABLE IF NOT EXISTS cache_rule_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rules (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    position INT NOT NULL,
    kind VARCHAR(32) NOT NULL,
    match_type VARCHAR(32) NOT NULL,
    match_value VARCHAR(1024) NOT NULL,
    ttl INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rule_methods (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    rule_position INT NOT NULL,
    position INT NOT NULL,
    method VARCHAR(32) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rule_vary_headers (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    rule_position INT NOT NULL,
    position INT NOT NULL,
    header_name VARCHAR(255) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bypass_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bypass_entries (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    position INT NOT NULL,
    path VARCHAR(1024) NOT NULL,
    extra_rule VARCHAR(1024) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS country_block_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS country_block_countries (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    position INT NOT NULL,
    country_code VARCHAR(16) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    enabled INT NOT NULL DEFAULT 0,
    adaptive_enabled INT NOT NULL DEFAULT 0,
    adaptive_score_threshold INT NOT NULL DEFAULT 0,
    adaptive_limit_factor_percent INT NOT NULL DEFAULT 0,
    adaptive_burst_factor_percent INT NOT NULL DEFAULT 0,
    feedback_enabled INT NOT NULL DEFAULT 0,
    feedback_strikes_required INT NOT NULL DEFAULT 0,
    feedback_strike_window_seconds INT NOT NULL DEFAULT 0,
    feedback_adaptive_only INT NOT NULL DEFAULT 0,
    feedback_dry_run INT NOT NULL DEFAULT 0,
    default_enabled INT NOT NULL DEFAULT 0,
    default_limit INT NOT NULL DEFAULT 0,
    default_window_seconds INT NOT NULL DEFAULT 0,
    default_burst INT NOT NULL DEFAULT 0,
    default_key_by VARCHAR(64) NOT NULL DEFAULT '',
    default_action_status INT NOT NULL DEFAULT 0,
    default_action_retry_after_seconds INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_scope_values (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    list_name VARCHAR(64) NOT NULL,
    position INT NOT NULL,
    value_text VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_rules (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    position INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    match_type VARCHAR(32) NOT NULL,
    match_value VARCHAR(1024) NOT NULL,
    policy_enabled INT NOT NULL DEFAULT 0,
    policy_limit INT NOT NULL DEFAULT 0,
    policy_window_seconds INT NOT NULL DEFAULT 0,
    policy_burst INT NOT NULL DEFAULT 0,
    policy_key_by VARCHAR(64) NOT NULL DEFAULT '',
    policy_action_status INT NOT NULL DEFAULT 0,
    policy_action_retry_after_seconds INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_rule_methods (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    rule_position INT NOT NULL,
    position INT NOT NULL,
    method VARCHAR(32) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    enabled INT NOT NULL DEFAULT 0,
    dry_run INT NOT NULL DEFAULT 0,
    mode VARCHAR(64) NOT NULL DEFAULT '',
    challenge_cookie_name VARCHAR(255) NOT NULL DEFAULT '',
    challenge_secret VARCHAR(512) NOT NULL DEFAULT '',
    challenge_ttl_seconds INT NOT NULL DEFAULT 0,
    challenge_status_code INT NOT NULL DEFAULT 0,
    behavioral_enabled INT NOT NULL DEFAULT 0,
    behavioral_window_seconds INT NOT NULL DEFAULT 0,
    behavioral_burst_threshold INT NOT NULL DEFAULT 0,
    behavioral_path_fanout_threshold INT NOT NULL DEFAULT 0,
    behavioral_ua_churn_threshold INT NOT NULL DEFAULT 0,
    behavioral_missing_cookie_threshold INT NOT NULL DEFAULT 0,
    behavioral_score_threshold INT NOT NULL DEFAULT 0,
    behavioral_risk_score_per_signal INT NOT NULL DEFAULT 0,
    browser_enabled INT NOT NULL DEFAULT 0,
    browser_js_cookie_name VARCHAR(255) NOT NULL DEFAULT '',
    browser_score_threshold INT NOT NULL DEFAULT 0,
    browser_risk_score_per_signal INT NOT NULL DEFAULT 0,
    device_enabled INT NOT NULL DEFAULT 0,
    device_require_time_zone INT NOT NULL DEFAULT 0,
    device_require_platform INT NOT NULL DEFAULT 0,
    device_require_hardware_concurrency INT NOT NULL DEFAULT 0,
    device_check_mobile_touch INT NOT NULL DEFAULT 0,
    device_invisible_html_injection INT NOT NULL DEFAULT 0,
    device_invisible_max_body_bytes INT NOT NULL DEFAULT 0,
    device_score_threshold INT NOT NULL DEFAULT 0,
    device_risk_score_per_signal INT NOT NULL DEFAULT 0,
    header_enabled INT NOT NULL DEFAULT 0,
    header_require_accept_language INT NOT NULL DEFAULT 0,
    header_require_fetch_metadata INT NOT NULL DEFAULT 0,
    header_require_client_hints INT NOT NULL DEFAULT 0,
    header_require_upgrade_insecure INT NOT NULL DEFAULT 0,
    header_score_threshold INT NOT NULL DEFAULT 0,
    header_risk_score_per_signal INT NOT NULL DEFAULT 0,
    tls_enabled INT NOT NULL DEFAULT 0,
    tls_require_sni INT NOT NULL DEFAULT 0,
    tls_require_alpn INT NOT NULL DEFAULT 0,
    tls_require_modern_tls INT NOT NULL DEFAULT 0,
    tls_score_threshold INT NOT NULL DEFAULT 0,
    tls_risk_score_per_signal INT NOT NULL DEFAULT 0,
    quarantine_enabled INT NOT NULL DEFAULT 0,
    quarantine_threshold INT NOT NULL DEFAULT 0,
    quarantine_strikes_required INT NOT NULL DEFAULT 0,
    quarantine_strike_window_seconds INT NOT NULL DEFAULT 0,
    quarantine_ttl_seconds INT NOT NULL DEFAULT 0,
    quarantine_status_code INT NOT NULL DEFAULT 0,
    quarantine_reputation_feedback_seconds INT NOT NULL DEFAULT 0,
    challenge_feedback_enabled INT NOT NULL DEFAULT 0,
    challenge_feedback_reputation_seconds INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_scope_values (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    list_name VARCHAR(64) NOT NULL,
    position INT NOT NULL,
    value_text VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_path_policies (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    position INT NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    mode VARCHAR(64) NOT NULL DEFAULT '',
    dry_run_set INT NOT NULL DEFAULT 0,
    dry_run INT NOT NULL DEFAULT 0,
    risk_score_multiplier_percent INT NOT NULL DEFAULT 0,
    risk_score_offset INT NOT NULL DEFAULT 0,
    telemetry_cookie_required INT NOT NULL DEFAULT 0,
    disable_quarantine INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_path_policy_prefixes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    policy_position INT NOT NULL,
    position INT NOT NULL,
    path_prefix VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, policy_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS semantic_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    enabled INT NOT NULL DEFAULT 0,
    mode VARCHAR(64) NOT NULL DEFAULT '',
    log_threshold INT NOT NULL DEFAULT 0,
    challenge_threshold INT NOT NULL DEFAULT 0,
    block_threshold INT NOT NULL DEFAULT 0,
    max_inspect_body INT NOT NULL DEFAULT 0,
    provider_enabled INT NOT NULL DEFAULT 0,
    provider_name VARCHAR(255) NOT NULL DEFAULT '',
    provider_timeout_ms INT NOT NULL DEFAULT 0,
    temporal_window_seconds INT NOT NULL DEFAULT 0,
    temporal_max_entries_per_ip INT NOT NULL DEFAULT 0,
    temporal_burst_threshold INT NOT NULL DEFAULT 0,
    temporal_burst_score INT NOT NULL DEFAULT 0,
    temporal_path_fanout_threshold INT NOT NULL DEFAULT 0,
    temporal_path_fanout_score INT NOT NULL DEFAULT 0,
    temporal_ua_churn_threshold INT NOT NULL DEFAULT 0,
    temporal_ua_churn_score INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS semantic_scope_values (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    list_name VARCHAR(64) NOT NULL,
    position INT NOT NULL,
    value_text VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_settings (
    version_id BIGINT PRIMARY KEY,
    enabled INT NOT NULL DEFAULT 0,
    cooldown_seconds INT NOT NULL DEFAULT 0,
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_triggers (
    version_id BIGINT NOT NULL,
    category VARCHAR(32) NOT NULL,
    enabled INT NOT NULL DEFAULT 0,
    window_seconds INT NOT NULL DEFAULT 0,
    active_threshold INT NOT NULL DEFAULT 0,
    escalated_threshold INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, category),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_security_sources (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    source VARCHAR(128) NOT NULL,
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sinks (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(255) NOT NULL DEFAULT '',
    sink_type VARCHAR(32) NOT NULL,
    enabled INT NOT NULL DEFAULT 0,
    timeout_seconds INT NOT NULL DEFAULT 0,
    webhook_url VARCHAR(2048) NOT NULL DEFAULT '',
    smtp_address VARCHAR(512) NOT NULL DEFAULT '',
    smtp_username VARCHAR(255) NOT NULL DEFAULT '',
    smtp_password VARCHAR(512) NOT NULL DEFAULT '',
    from_address VARCHAR(512) NOT NULL DEFAULT '',
    subject_prefix VARCHAR(512) NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sink_headers (
    version_id BIGINT NOT NULL,
    sink_position INT NOT NULL,
    position INT NOT NULL,
    header_name VARCHAR(255) NOT NULL,
    header_value VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, sink_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sink_recipients (
    version_id BIGINT NOT NULL,
    sink_position INT NOT NULL,
    position INT NOT NULL,
    recipient VARCHAR(512) NOT NULL,
    PRIMARY KEY (version_id, sink_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ip_reputation_scopes (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    enabled INT NOT NULL DEFAULT 0,
    refresh_interval_sec INT NOT NULL DEFAULT 0,
    request_timeout_sec INT NOT NULL DEFAULT 0,
    block_status_code INT NOT NULL DEFAULT 0,
    fail_open INT NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ip_reputation_scope_values (
    version_id BIGINT NOT NULL,
    scope_type VARCHAR(16) NOT NULL,
    host VARCHAR(255) NOT NULL DEFAULT '',
    list_name VARCHAR(64) NOT NULL,
    position INT NOT NULL,
    value_text VARCHAR(1024) NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_cache_config (
    version_id BIGINT PRIMARY KEY,
    enabled INT NOT NULL DEFAULT 0,
    store_dir VARCHAR(1024) NOT NULL,
    max_bytes BIGINT NOT NULL DEFAULT 0,
    memory_enabled INT NOT NULL DEFAULT 0,
    memory_max_bytes BIGINT NOT NULL DEFAULT 0,
    memory_max_entries INT NOT NULL DEFAULT 0,
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crs_disabled_rules (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    rule_name VARCHAR(512) NOT NULL,
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS override_rules (
    version_id BIGINT NOT NULL,
    position INT NOT NULL,
    name VARCHAR(255) NOT NULL,
    content_hash VARCHAR(128) NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS override_rule_versions (
    version_id BIGINT NOT NULL,
    name VARCHAR(255) NOT NULL,
    raw_text MEDIUMTEXT NOT NULL,
    etag VARCHAR(256) NOT NULL,
    PRIMARY KEY (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
