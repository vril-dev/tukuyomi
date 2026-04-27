CREATE TABLE IF NOT EXISTS waf_events (
	id BIGSERIAL PRIMARY KEY,
	event TEXT NOT NULL,
	ts_unix BIGINT NOT NULL,
	ts TEXT NOT NULL,
	rule_id TEXT NOT NULL,
	path TEXT NOT NULL,
	country TEXT NOT NULL,
	status INTEGER NOT NULL,
	req_id TEXT,
	method TEXT,
	matched_variable TEXT,
	matched_value TEXT,
	raw_json TEXT NOT NULL,
	line_hash TEXT NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_waf_events_ts_unix ON waf_events(ts_unix);
CREATE INDEX IF NOT EXISTS idx_waf_events_event_ts ON waf_events(event, ts_unix);
CREATE INDEX IF NOT EXISTS idx_waf_events_rule_id ON waf_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_waf_events_path ON waf_events(path);
CREATE INDEX IF NOT EXISTS idx_waf_events_country ON waf_events(country);
CREATE UNIQUE INDEX IF NOT EXISTS idx_waf_events_line_hash ON waf_events(line_hash);

CREATE TABLE IF NOT EXISTS ingest_state (
	source TEXT PRIMARY KEY,
	"offset" BIGINT NOT NULL,
	size BIGINT NOT NULL,
	mod_time_ns BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS config_blobs (
	config_key TEXT PRIMARY KEY,
	raw_text TEXT NOT NULL,
	etag TEXT NOT NULL,
	updated_at_unix BIGINT NOT NULL,
	updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_config_blobs_updated_at_unix ON config_blobs(updated_at_unix);
