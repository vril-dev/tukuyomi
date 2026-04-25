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
startup, applies embedded SQL migrations for the configured driver through
golang-migrate, records the current schema version and dirty flag in
`schema_migrations`, and exits without starting listeners or runtime sync loops.

Install or refresh CRS after migrations so WAF rule assets can be imported into
the DB:

```bash
make crs-install
```

`make crs-install` runs after `db-migrate`, installs CRS seed files under the
configured workdir, and imports base WAF plus CRS `.conf` / `.data` assets into
DB `waf_rule_assets`. To refresh DB rule assets from existing seed files without
downloading CRS again, use:

```bash
make db-import-waf-rule-assets
```

Import the current bootstrap/export files after migrations when preparing a DB
from file material:

```bash
make db-import
```

`make db-import` runs `db-migrate` first, then imports seed/export material into
versioned normalized DB tables. `config.json` is loaded as the `app_config` seed
after built-in defaults are applied; bundled configs intentionally keep only the
`storage` bootstrap block. Configured runtime files such as `conf/proxy.json`
win when present; otherwise `seeds/conf/` supplies the bundled production seed
set before compatibility defaults are used. Runtime files such as `sites`,
`vhosts`, `scheduled_tasks`, `upstream_runtime`, and PHP-FPM runtime inventory
are imported into their own feature tables. After import, those DB rows are
authoritative.

If the import command runs outside the bundle root, set
`WAF_DB_IMPORT_SEED_CONF_DIR` to the directory containing the `seeds/conf` files.

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
that would let a DB-stored value move the process to a different DB after the
connection has already been chosen.

Default SQLite path:

- `db/tukuyomi.db`

DSN requirements:

- `mysql`: `db_dsn` is required.
- `pgsql`: `db_dsn` is required, for example
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`.

## What Is Stored

### 1. `waf_events`

WAF, access, and request-security event records used by:

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner latest-event lookup

Current runtime writes these events directly to DB. `waf-events.ndjson` is a
legacy import source only when an operator intentionally ingests old file logs.

### 2. Versioned runtime config tables

Operator-owned runtime config uses immutable versions:

- `config_domains`
- `config_versions`
- `config_rollbacks`

Feature-owned rows carry `version_id`. Current normalized domains include:

- `app_config_values`, `app_config_lists`, `app_config_list_values`
- `proxy_*`
- `sites`, `site_hosts`, `site_tls`
- `vhosts`, `vhost_*`
- `scheduled_tasks`, `scheduled_task_env`, `scheduled_task_args`
- `upstream_runtime_overrides`
- `cache_rule_scopes`, `cache_rules`, `cache_rule_methods`,
  `cache_rule_vary_headers`
- `bypass_scopes`, `bypass_entries`
- `country_block_scopes`, `country_block_countries`
- `rate_limit_scopes`, `rate_limit_scope_values`, `rate_limit_rules`,
  `rate_limit_rule_methods`
- `bot_defense_scopes`, `bot_defense_scope_values`,
  `bot_defense_path_policies`, `bot_defense_path_policy_prefixes`
- `semantic_scopes`, `semantic_scope_values`
- `notification_settings`, `notification_triggers`,
  `notification_security_sources`, `notification_sinks`,
  `notification_sink_headers`, `notification_sink_recipients`
- `ip_reputation_scopes`, `ip_reputation_scope_values`
- `response_cache_config`
- `crs_disabled_rules`
- `override_rules`, `override_rule_versions`
- `php_runtime_inventory`, `php_runtime_modules`,
  `php_runtime_default_disabled_modules`

### 3. `config_blobs`

`config_blobs` is no longer the authority for normalized runtime or policy
config domains. It remains only for legacy import compatibility and for content
artifacts that are not configuration authority.

Remaining blob examples:

- `waf_rule_assets`, `waf_rule_asset_contents` (base WAF and CRS rule/data assets)

The only file required by production startup after import is:

- `config.json`: DB connection bootstrap (`storage.db_driver`,
  `storage.db_path`, `storage.db_dsn`) plus storage retention/sync bootstrap
  values

That statement is about configuration authority. Runtime byte artifacts are
separate. When site-managed ACME uses the local backend, preserve
`persistent_storage.local.base_dir` (default `data/persistent`). When enabled,
`cache_store.store_dir`, security / FP tuner / proxy-rules audit files,
scheduled-task logs, and PHP-FPM runtime logs/sockets are runtime artifacts, not
DB configuration authority.

Other seed/export files may be kept for operator workflows but are not runtime
authority after their normalized DB rows exist. After `make db-migrate`,
`make crs-install`, and `make db-import`, production runtime can remove
`data/conf/*.json` except `data/conf/config.json` and
PHP-FPM JSON manifests such as `inventory.json`,
`vhosts.json`, `runtime.json`, and `modules.json`. GeoIP managed assets are
also DB-backed after import.

### 4. `schema_migrations`

The golang-migrate schema version table. It stores the current migration
`version` and `dirty` state for `make db-migrate` and startup's defensive schema
check.

Other configured JSON/text files are not a runtime storage backend. They are
initial seed/import/export artifacts:

- if the normalized domain is missing, startup imports DB rows from the current
  configured seed/export file, or from `seeds/conf/` when that file is absent
- if `app_config` exists, startup applies it after the initial DB open while
  preserving DB connection fields from bootstrap `config.json`
- proxy, sites, vhosts, scheduled tasks, upstream runtime, policy domains, WAF
  assets, response cache, and PHP-FPM inventory load DB content directly without
  restoring JSON files first
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
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

If WAL files exist, back them up together:

```bash
cp data/db/tukuyomi.db-wal data/db/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/db/tukuyomi.db-shm data/db/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### MySQL

Back up with your normal DB backup flow (for example `mysqldump`).

### PostgreSQL

Back up with your normal DB backup flow (for example `pg_dump`).

## Vacuum / Size Maintenance (SQLite)

After heavy tests, run:

```bash
sqlite3 data/db/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## Recovery

### SQLite

If DB is missing or corrupted:

1. Stop stack (`docker compose down`).
2. Restore the DB from backup, or move the broken DB file aside only when the
   configured files are a known-good seed/export.
3. Start stack (`docker compose up -d coraza`) so schema bootstrap and initial
   seeding run.
4. Start the service; new WAF/access events are written directly to
   `waf_events`. Only call `/tukuyomi-api/logs/stats` with a configured legacy
   log file if you intentionally need to ingest old `waf-events.ndjson` data.

### MySQL / PostgreSQL

If DB is reset:

1. Ensure the database is reachable with the configured DSN.
2. Restore from DB backup, or prepare known-good config files for initial seed.
3. Start/restart coraza so schema bootstrap and sync run.
4. New WAF/access events are written directly to `waf_events`; trigger the logs
   endpoint only when intentionally ingesting a legacy log file.
