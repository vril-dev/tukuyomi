CREATE TABLE IF NOT EXISTS cache_rule_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rules (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    kind TEXT NOT NULL,
    match_type TEXT NOT NULL,
    match_value TEXT NOT NULL,
    ttl INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rule_methods (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    method TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS cache_rule_vary_headers (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bypass_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bypass_entries (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    path TEXT NOT NULL,
    extra_rule TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS country_block_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS country_block_countries (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    country_code TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    adaptive_enabled INTEGER NOT NULL DEFAULT 0,
    adaptive_score_threshold INTEGER NOT NULL DEFAULT 0,
    adaptive_limit_factor_percent INTEGER NOT NULL DEFAULT 0,
    adaptive_burst_factor_percent INTEGER NOT NULL DEFAULT 0,
    feedback_enabled INTEGER NOT NULL DEFAULT 0,
    feedback_strikes_required INTEGER NOT NULL DEFAULT 0,
    feedback_strike_window_seconds INTEGER NOT NULL DEFAULT 0,
    feedback_adaptive_only INTEGER NOT NULL DEFAULT 0,
    feedback_dry_run INTEGER NOT NULL DEFAULT 0,
    default_enabled INTEGER NOT NULL DEFAULT 0,
    default_limit INTEGER NOT NULL DEFAULT 0,
    default_window_seconds INTEGER NOT NULL DEFAULT 0,
    default_burst INTEGER NOT NULL DEFAULT 0,
    default_key_by TEXT NOT NULL DEFAULT '',
    default_action_status INTEGER NOT NULL DEFAULT 0,
    default_action_retry_after_seconds INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_scope_values (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    list_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_rules (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    match_type TEXT NOT NULL,
    match_value TEXT NOT NULL,
    policy_enabled INTEGER NOT NULL DEFAULT 0,
    policy_limit INTEGER NOT NULL DEFAULT 0,
    policy_window_seconds INTEGER NOT NULL DEFAULT 0,
    policy_burst INTEGER NOT NULL DEFAULT 0,
    policy_key_by TEXT NOT NULL DEFAULT '',
    policy_action_status INTEGER NOT NULL DEFAULT 0,
    policy_action_retry_after_seconds INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limit_rule_methods (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    rule_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    method TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, rule_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT '',
    challenge_cookie_name TEXT NOT NULL DEFAULT '',
    challenge_secret TEXT NOT NULL DEFAULT '',
    challenge_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    challenge_status_code INTEGER NOT NULL DEFAULT 0,
    behavioral_enabled INTEGER NOT NULL DEFAULT 0,
    behavioral_window_seconds INTEGER NOT NULL DEFAULT 0,
    behavioral_burst_threshold INTEGER NOT NULL DEFAULT 0,
    behavioral_path_fanout_threshold INTEGER NOT NULL DEFAULT 0,
    behavioral_ua_churn_threshold INTEGER NOT NULL DEFAULT 0,
    behavioral_missing_cookie_threshold INTEGER NOT NULL DEFAULT 0,
    behavioral_score_threshold INTEGER NOT NULL DEFAULT 0,
    behavioral_risk_score_per_signal INTEGER NOT NULL DEFAULT 0,
    browser_enabled INTEGER NOT NULL DEFAULT 0,
    browser_js_cookie_name TEXT NOT NULL DEFAULT '',
    browser_score_threshold INTEGER NOT NULL DEFAULT 0,
    browser_risk_score_per_signal INTEGER NOT NULL DEFAULT 0,
    device_enabled INTEGER NOT NULL DEFAULT 0,
    device_require_time_zone INTEGER NOT NULL DEFAULT 0,
    device_require_platform INTEGER NOT NULL DEFAULT 0,
    device_require_hardware_concurrency INTEGER NOT NULL DEFAULT 0,
    device_check_mobile_touch INTEGER NOT NULL DEFAULT 0,
    device_invisible_html_injection INTEGER NOT NULL DEFAULT 0,
    device_invisible_max_body_bytes INTEGER NOT NULL DEFAULT 0,
    device_score_threshold INTEGER NOT NULL DEFAULT 0,
    device_risk_score_per_signal INTEGER NOT NULL DEFAULT 0,
    header_enabled INTEGER NOT NULL DEFAULT 0,
    header_require_accept_language INTEGER NOT NULL DEFAULT 0,
    header_require_fetch_metadata INTEGER NOT NULL DEFAULT 0,
    header_require_client_hints INTEGER NOT NULL DEFAULT 0,
    header_require_upgrade_insecure INTEGER NOT NULL DEFAULT 0,
    header_score_threshold INTEGER NOT NULL DEFAULT 0,
    header_risk_score_per_signal INTEGER NOT NULL DEFAULT 0,
    tls_enabled INTEGER NOT NULL DEFAULT 0,
    tls_require_sni INTEGER NOT NULL DEFAULT 0,
    tls_require_alpn INTEGER NOT NULL DEFAULT 0,
    tls_require_modern_tls INTEGER NOT NULL DEFAULT 0,
    tls_score_threshold INTEGER NOT NULL DEFAULT 0,
    tls_risk_score_per_signal INTEGER NOT NULL DEFAULT 0,
    quarantine_enabled INTEGER NOT NULL DEFAULT 0,
    quarantine_threshold INTEGER NOT NULL DEFAULT 0,
    quarantine_strikes_required INTEGER NOT NULL DEFAULT 0,
    quarantine_strike_window_seconds INTEGER NOT NULL DEFAULT 0,
    quarantine_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    quarantine_status_code INTEGER NOT NULL DEFAULT 0,
    quarantine_reputation_feedback_seconds INTEGER NOT NULL DEFAULT 0,
    challenge_feedback_enabled INTEGER NOT NULL DEFAULT 0,
    challenge_feedback_reputation_seconds INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_scope_values (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    list_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_path_policies (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    position INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    mode TEXT NOT NULL DEFAULT '',
    dry_run_set INTEGER NOT NULL DEFAULT 0,
    dry_run INTEGER NOT NULL DEFAULT 0,
    risk_score_multiplier_percent INTEGER NOT NULL DEFAULT 0,
    risk_score_offset INTEGER NOT NULL DEFAULT 0,
    telemetry_cookie_required INTEGER NOT NULL DEFAULT 0,
    disable_quarantine INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bot_defense_path_policy_prefixes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    policy_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    path_prefix TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, policy_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS semantic_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    mode TEXT NOT NULL DEFAULT '',
    log_threshold INTEGER NOT NULL DEFAULT 0,
    challenge_threshold INTEGER NOT NULL DEFAULT 0,
    block_threshold INTEGER NOT NULL DEFAULT 0,
    max_inspect_body INTEGER NOT NULL DEFAULT 0,
    provider_enabled INTEGER NOT NULL DEFAULT 0,
    provider_name TEXT NOT NULL DEFAULT '',
    provider_timeout_ms INTEGER NOT NULL DEFAULT 0,
    temporal_window_seconds INTEGER NOT NULL DEFAULT 0,
    temporal_max_entries_per_ip INTEGER NOT NULL DEFAULT 0,
    temporal_burst_threshold INTEGER NOT NULL DEFAULT 0,
    temporal_burst_score INTEGER NOT NULL DEFAULT 0,
    temporal_path_fanout_threshold INTEGER NOT NULL DEFAULT 0,
    temporal_path_fanout_score INTEGER NOT NULL DEFAULT 0,
    temporal_ua_churn_threshold INTEGER NOT NULL DEFAULT 0,
    temporal_ua_churn_score INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS semantic_scope_values (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    list_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_settings (
    version_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    cooldown_seconds INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_triggers (
    version_id INTEGER NOT NULL,
    category TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    window_seconds INTEGER NOT NULL DEFAULT 0,
    active_threshold INTEGER NOT NULL DEFAULT 0,
    escalated_threshold INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, category),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_security_sources (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    source TEXT NOT NULL,
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sinks (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL DEFAULT '',
    sink_type TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 0,
    timeout_seconds INTEGER NOT NULL DEFAULT 0,
    webhook_url TEXT NOT NULL DEFAULT '',
    smtp_address TEXT NOT NULL DEFAULT '',
    smtp_username TEXT NOT NULL DEFAULT '',
    smtp_password TEXT NOT NULL DEFAULT '',
    from_address TEXT NOT NULL DEFAULT '',
    subject_prefix TEXT NOT NULL DEFAULT '',
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sink_headers (
    version_id INTEGER NOT NULL,
    sink_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    header_name TEXT NOT NULL,
    header_value TEXT NOT NULL,
    PRIMARY KEY (version_id, sink_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS notification_sink_recipients (
    version_id INTEGER NOT NULL,
    sink_position INTEGER NOT NULL,
    position INTEGER NOT NULL,
    recipient TEXT NOT NULL,
    PRIMARY KEY (version_id, sink_position, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ip_reputation_scopes (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    enabled INTEGER NOT NULL DEFAULT 0,
    refresh_interval_sec INTEGER NOT NULL DEFAULT 0,
    request_timeout_sec INTEGER NOT NULL DEFAULT 0,
    block_status_code INTEGER NOT NULL DEFAULT 0,
    fail_open INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (version_id, scope_type, host),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS ip_reputation_scope_values (
    version_id INTEGER NOT NULL,
    scope_type TEXT NOT NULL,
    host TEXT NOT NULL DEFAULT '',
    list_name TEXT NOT NULL,
    position INTEGER NOT NULL,
    value_text TEXT NOT NULL,
    PRIMARY KEY (version_id, scope_type, host, list_name, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS response_cache_config (
    version_id INTEGER PRIMARY KEY,
    enabled INTEGER NOT NULL DEFAULT 0,
    store_dir TEXT NOT NULL,
    max_bytes INTEGER NOT NULL DEFAULT 0,
    memory_enabled INTEGER NOT NULL DEFAULT 0,
    memory_max_bytes INTEGER NOT NULL DEFAULT 0,
    memory_max_entries INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS crs_disabled_rules (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    rule_name TEXT NOT NULL,
    PRIMARY KEY (version_id, position),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS override_rules (
    version_id INTEGER NOT NULL,
    position INTEGER NOT NULL,
    name TEXT NOT NULL,
    content_hash TEXT NOT NULL,
    PRIMARY KEY (version_id, position),
    UNIQUE (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS override_rule_versions (
    version_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    raw_text TEXT NOT NULL,
    etag TEXT NOT NULL,
    PRIMARY KEY (version_id, name),
    FOREIGN KEY (version_id) REFERENCES config_versions(version_id) ON DELETE CASCADE
);
