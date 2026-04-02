[English](db-ops.md) | [日本語](db-ops.ja.md)

# DB Operations (SQLite / MySQL)

This document covers practical operations for `WAF_STORAGE_BACKEND=db` deployments.

## Backend Selection

Use these env vars to enable DB-backed operation:

- `WAF_STORAGE_BACKEND=db`
- `WAF_DB_DRIVER=sqlite|mysql`
- `WAF_DB_PATH` (required for sqlite)
- `WAF_DB_DSN` (required for mysql)
- `WAF_DB_RETENTION_DAYS`
- `WAF_DB_SYNC_INTERVAL_SEC` (optional periodic reconcile loop)

Compatibility flag:

- `WAF_DB_ENABLED` is legacy-only. If `WAF_STORAGE_BACKEND` is unset, `true` maps to `db` and `false` maps to `file`.

Default SQLite path:

- `logs/coraza/tukuyomi.db`

## What Is Stored

### 1. `waf_events`

Ingested WAF log records (`waf-events.ndjson`) used by:

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner latest-event lookup

### 2. `config_blobs`

DB copies of admin-editable config files used for startup sync and multi-instance consistency.

Current blob keys:

- `cache_rules` (`cache.conf`)
- `rate_limit_rules` (`rate-limit.conf`)
- `country_block_rules` (`country-block.conf`)
- `bypass_rules` (`waf.bypass`)
- `bot_defense_rules` (`bot-defense.conf`)
- `semantic_rules` (`semantic.conf`)
- `crs_disabled_rules` (`crs-disabled.conf`)
- `rule_file_sha256:<sha256(path)>` (base rule files listed in `WAF_RULES_FILE`, for example `rules/tukuyomi.conf`)

At startup in DB mode, runtime still loads from files, and each config is synchronized with DB blobs.
If `WAF_DB_SYNC_INTERVAL_SEC >= 1`, each node also runs periodic DB→runtime reconciliation and triggers reload only when content changed.

## Retention / Pruning

`WAF_DB_RETENTION_DAYS` only applies to `waf_events`.

- `30` (default): keep the last 30 days
- `0`: disable pruning

`config_blobs` are not pruned by retention.

## Backup

### SQLite

Before major changes, snapshot DB file:

```bash
cp data/logs/coraza/tukuyomi.db data/logs/coraza/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

If WAL files exist, back them up together:

```bash
cp data/logs/coraza/tukuyomi.db-wal data/logs/coraza/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/logs/coraza/tukuyomi.db-shm data/logs/coraza/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### MySQL

Back up with your normal DB backup flow (for example `mysqldump`).

## Vacuum / Size Maintenance (SQLite)

After heavy tests, run:

```bash
sqlite3 data/logs/coraza/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## Recovery

### SQLite

If DB is missing/corrupted:

1. Stop stack (`docker compose down`).
2. Move broken DB file aside.
3. Start stack (`docker compose up -d coraza nginx`).
4. Call `/tukuyomi-api/logs/stats` once to trigger `waf_events` re-ingest from `waf-events.ndjson`.
5. Re-save important config via admin API if needed to re-seed `config_blobs`.

### MySQL

If DB is reset:

1. Ensure MySQL is reachable with configured DSN.
2. Start/restart coraza so schema bootstrap runs.
3. Trigger logs endpoint once for `waf_events` ingest.
4. Re-save important config via admin API if needed to re-seed `config_blobs`.
