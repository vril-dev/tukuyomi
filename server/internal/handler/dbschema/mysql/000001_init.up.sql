CREATE TABLE IF NOT EXISTS waf_events (
	id BIGINT NOT NULL AUTO_INCREMENT PRIMARY KEY,
	event VARCHAR(64) NOT NULL,
	ts_unix BIGINT NOT NULL,
	ts VARCHAR(64) NOT NULL,
	rule_id VARCHAR(128) NOT NULL,
	path TEXT NOT NULL,
	country VARCHAR(16) NOT NULL,
	status INT NOT NULL,
	req_id VARCHAR(128) NULL,
	method VARCHAR(16) NULL,
	matched_variable VARCHAR(255) NULL,
	matched_value TEXT NULL,
	raw_json LONGTEXT NOT NULL,
	line_hash CHAR(64) NOT NULL,
	UNIQUE KEY uq_waf_events_line_hash (line_hash),
	KEY idx_waf_events_ts_unix (ts_unix),
	KEY idx_waf_events_event_ts (event, ts_unix),
	KEY idx_waf_events_rule_id (rule_id),
	KEY idx_waf_events_path (path(191)),
	KEY idx_waf_events_country (country)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS ingest_state (
	source VARCHAR(64) NOT NULL PRIMARY KEY,
	`offset` BIGINT NOT NULL,
	size BIGINT NOT NULL,
	mod_time_ns BIGINT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS config_blobs (
	config_key VARCHAR(128) NOT NULL PRIMARY KEY,
	raw_text LONGTEXT NOT NULL,
	etag VARCHAR(128) NOT NULL,
	updated_at_unix BIGINT NOT NULL,
	updated_at VARCHAR(64) NOT NULL,
	KEY idx_config_blobs_updated_at_unix (updated_at_unix)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
