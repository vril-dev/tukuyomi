ALTER TABLE bypass_entries ADD COLUMN request_body TEXT NOT NULL DEFAULT '';
ALTER TABLE bypass_entries ADD COLUMN request_body_inspect_limit_bytes BIGINT NOT NULL DEFAULT 0;
