[English](db-ops.md) | [日本語](db-ops.ja.md)

# DB Operations (SQLite / MySQL / PostgreSQL)

Runtime storage is DB-only. tukuyomi starts a database store on boot, bootstraps
the schema, and fails startup if the configured database is unavailable or
invalid. There is no file-storage runtime fallback.

Run schema migrations explicitly before starting a deployed runtime:

```bash
make db-migrate
```

The target builds the local binary, loads the same `config.json` used by normal
startup, applies embedded SQL migrations for the configured driver, records
applied migration file names in `schema_migrations`, and exits without starting
listeners or runtime sync loops.

Import the current bootstrap/export files after migrations when preparing a DB
from file material:

```bash
make db-import
```

`make db-import` runs `db-migrate` first, then imports `config.json` into
`config_blobs.app_config` and `proxy.json` into `config_blobs.proxy_rules`.
After those blobs exist, DB content is authoritative.

## Driver Selection

The DB connection bootstrap is configured in `data/conf/config.json` under
`storage`:

- `db_driver`: `sqlite`, `mysql`, or `pgsql`
- `db_path`: SQLite database path
- `db_dsn`: MySQL or PostgreSQL DSN
- `db_retention_days`: WAF event retention
- `db_sync_interval_sec`: optional periodic DB-to-runtime reconcile loop

`storage.backend` is deprecated. Leave it unset. `storage.backend=file` is
rejected during config validation.

`db_driver`, `db_path`, and `db_dsn` are always read from bootstrap
`config.json` before DB is opened. They are not taken from `app_config`, because
that would let a DB blob move the process to a different DB after the
connection has already been chosen.

Default SQLite path:

- `logs/coraza/tukuyomi.db`

DSN requirements:

- `mysql`: `db_dsn` is required.
- `pgsql`: `db_dsn` is required, for example
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`.

## What Is Stored

### 1. `waf_events`

Ingested WAF log records (`waf-events.ndjson`) used by:

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner latest-event lookup

### 2. `config_blobs`

Authoritative DB copies of admin-editable configuration used for startup sync,
runtime reloads, export/import materialization, and multi-instance consistency.

Current blob keys:

- `app_config` (`config.json` minus bootstrap DB connection fields)
- `proxy_rules` (`proxy.json`)
- `cache_rules` (`cache-rules.json`)
- `cache_store` (`cache-store.json`)
- `rate_limit_rules` (`rate-limit.json`)
- `country_block_rules` (`country-block.json`)
- `bypass_rules` (`waf-bypass.json`)
- `bot_defense_rules` (`bot-defense.json`)
- `semantic_rules` (`semantic.json`)
- `notification_rules` (`notifications.json`)
- `ip_reputation_rules` (`ip-reputation.json`)
- `sites` (`sites.json`)
- `scheduled_tasks` (`scheduled-tasks.json`)
- `upstream_runtime` (`upstream-runtime.json`)
- `crs_disabled_rules` (`crs-disabled.conf`)
- `rule_file_sha256:<sha256(path)>` (base rule files listed in `WAF_RULES_FILE`, for example `rules/tukuyomi.conf`)

Bootstrap/import files that intentionally remain on disk:

- `config.json`: DB connection bootstrap (`storage.db_driver`, `storage.db_path`, `storage.db_dsn`) plus seed/export material for `app_config`
- `proxy.json`: seed/import/export material for `proxy_rules`

Those files are not runtime authority after their DB blobs exist.

### 3. `schema_migrations`

Applied embedded SQL migration file names. This table is operational metadata
for `make db-migrate` and startup's defensive schema check.

Other configured JSON/text files are not a runtime storage backend. They are
initial seed/import/export artifacts:

- if the DB blob is missing, startup seeds DB from the current configured file
- if `app_config` exists, startup applies it after the initial DB open while
  preserving DB connection fields from bootstrap `config.json`
- if `proxy_rules` exists, startup loads proxy routing from DB instead of
  `proxy.json`
- if a DB blob exists for DB-native runtimes such as `sites`,
  `scheduled_tasks`, or `upstream_runtime`, startup loads DB content directly
  without restoring a JSON file first
- file restoration is only a compatibility step for older subsystems that still
  require a file-shaped parser/watcher boundary
- if sync, parsing, or reload fails, startup fails instead of falling back

If `db_sync_interval_sec >= 1`, each node also runs periodic DB-to-runtime
reconciliation and triggers reload only when content changed. For DB-native
runtimes this is DB-to-memory/runtime reload, not DB-to-file restoration.

## Retention / Pruning

`db_retention_days` only applies to `waf_events`.

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

### PostgreSQL

Back up with your normal DB backup flow (for example `pg_dump`).

## Vacuum / Size Maintenance (SQLite)

After heavy tests, run:

```bash
sqlite3 data/logs/coraza/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## Recovery

### SQLite

If DB is missing or corrupted:

1. Stop stack (`docker compose down`).
2. Restore the DB from backup, or move the broken DB file aside only when the
   configured files are a known-good seed/export.
3. Start stack (`docker compose up -d coraza`) so schema bootstrap and initial
   seeding run.
4. Call `/tukuyomi-api/logs/stats` once to trigger `waf_events` re-ingest from
   `waf-events.ndjson`.

### MySQL / PostgreSQL

If DB is reset:

1. Ensure the database is reachable with the configured DSN.
2. Restore from DB backup, or prepare known-good config files for initial seed.
3. Start/restart coraza so schema bootstrap and sync run.
4. Trigger logs endpoint once for `waf_events` ingest.
