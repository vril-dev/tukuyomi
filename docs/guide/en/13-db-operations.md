# Chapter 13. DB operations (SQLite / MySQL / PostgreSQL)

Part VI — "Operations and troubleshooting" — covers what you need to
keep tukuyomi running in production. The first chapter is the most
fundamental, accident-prone area: **DB operations**.

**Tukuyomi's runtime storage is DB-only.** At startup, tukuyomi opens
the DB store, runs schema bootstrap, and **fails to start if the DB
is unavailable or invalid**. There is no runtime fallback to file
storage. That single sentence frames most of the decisions in this
chapter.

## 13.1 Pre-startup procedure

Before launching a deployed runtime, run schema migration **explicitly**:

```bash
make db-migrate
```

This target:

- Builds the local binary.
- Reads the same `config.json` it would use at normal startup.
- Applies the embedded SQL migrations for the configured driver via
  golang-migrate.

The current schema version and a dirty flag are recorded in
`schema_migrations`. The listener and the runtime sync loop **do not
start** at this point.

After migration, install / refresh CRS and import WAF rule assets into
the DB:

```bash
make crs-install
```

`make crs-install` runs after `db-migrate`. It:

- Places the CRS seed file under the configured workdir.
- **Imports the base WAF and CRS `.conf` / `.data` assets into DB
  `waf_rule_assets`**.

To refresh DB rule assets from existing seed files without
re-downloading CRS:

```bash
make db-import-waf-rule-assets
```

To prepare a DB from existing bootstrap / export files, run import
after migration:

```bash
make db-import
```

`make db-import` behavior:

- Runs `db-migrate` first.
- Then **imports seed / export material into the versioned normalized
  DB tables**.
- Reads `config.json` as `app_config` seed after applying built-in
  defaults (the bundled config intentionally retains only the
  `storage` bootstrap block).
- If configured runtime files such as `conf/proxy.json` exist, they
  take precedence.
- Falls back to the bundled production seed under `seeds/conf/` when
  no configured file exists.
- Falls back to the compatibility default when even that is missing.
- Imports runtime files like `sites`, `vhosts`, `scheduled_tasks`,
  `upstream_runtime`, and PHP-FPM runtime inventory into their
  feature tables.
- After import, **the DB rows are authoritative**.

To run the import command from outside the bundle root, point
`WAF_DB_IMPORT_SEED_CONF_DIR` at the directory that contains the
`seeds/conf` files.

## 13.2 Driver selection

The DB connection bootstrap sits in the `storage` block of
`data/conf/config.json`:

| Key | Purpose |
|---|---|
| `db_driver` | One of `sqlite` / `mysql` / `pgsql`. |
| `db_path` | SQLite database path. |
| `db_dsn` | DSN for MySQL / PostgreSQL. |
| `db_retention_days` | WAF event retention. |
| `db_sync_interval_sec` | Interval of the periodic DB-to-runtime reconciliation loop. |

Notes:

- **`storage.backend` is deprecated.** Do not set it.
  `storage.backend=file` is **rejected** in config validation.
- `db_driver` / `db_path` / `db_dsn` are **always** read from the
  bootstrap `config.json` before opening the DB. This avoids a
  cycle in which an `app_config` value stored in the DB could move
  an already-connected process to a different DB.

The default SQLite path is `db/tukuyomi.db`.

DSN requirements:

- `mysql`: `db_dsn` is mandatory.
- `pgsql`: `db_dsn` is mandatory. Example:
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`

## 13.3 What gets stored

What tukuyomi keeps in the DB falls into four broad categories.

### 13.3.1 `waf_events`

WAF / access / request-security event records. The following endpoints
read this table:

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- The FP Tuner latest-event lookup (Chapter 8)

The current runtime **writes events directly to the DB**.
`waf-events.ndjson` is a **legacy import source** used only when an
operator explicitly ingests an old file log.

### 13.3.2 Versioned runtime config tables

Operator-owned runtime configuration is managed with **immutable
versions**. The central tables are:

- `config_domains`
- `config_versions`
- `config_rollbacks`

Feature-owned rows carry a `version_id`. The currently normalized
domains:

- `app_config_values` / `app_config_lists` / `app_config_list_values`
- `proxy_*`
- `sites` / `site_hosts` / `site_tls`
- `vhosts` / `vhost_*`
- `scheduled_tasks` / `scheduled_task_env` / `scheduled_task_args`
- `upstream_runtime_overrides`
- `cache_rule_scopes` / `cache_rules` / `cache_rule_methods` /
  `cache_rule_vary_headers`
- `bypass_scopes` / `bypass_entries`
- `country_block_scopes` / `country_block_countries`
- `rate_limit_scopes` / `rate_limit_scope_values` /
  `rate_limit_rules` / `rate_limit_rule_methods`
- `bot_defense_scopes` / `bot_defense_scope_values` /
  `bot_defense_path_policies` / `bot_defense_path_policy_prefixes`
- `semantic_scopes` / `semantic_scope_values`
- `notification_settings` / `notification_triggers` /
  `notification_security_sources` / `notification_sinks` /
  `notification_sink_headers` / `notification_sink_recipients`
- `ip_reputation_scopes` / `ip_reputation_scope_values`
- `response_cache_config`
- `crs_disabled_rules`
- `override_rules` / `override_rule_versions`
- `php_runtime_inventory` / `php_runtime_modules` /
  `php_runtime_default_disabled_modules`

Normalized means that **diffs are taken row by row and rollbacks are
versioned**. UI saves on `Settings` and on each policy screen become
row-level operations against these tables.

### 13.3.3 `config_blobs`

`config_blobs` is **not the authority** for normalized runtime / policy
config domains. It only remains for legacy import compatibility and for
content artifacts that are not config authority.

Representative remaining blobs:

- `waf_rule_assets` / `waf_rule_asset_contents` (base WAF and CRS rule
  / data assets)

The **only file required for production startup after import** is:

- `config.json`: DB connection bootstrap (`storage.db_driver` /
  `storage.db_path` / `storage.db_dsn`) plus storage retention / sync
  bootstrap values.

That is just the **config authority** story. Runtime byte artifacts are
handled separately:

- `persistent_storage.local.base_dir` (default `data/persistent`) for
  site-managed ACME with a local backend
- `cache_store.store_dir` when the internal response cache is enabled
- security / FP Tuner / proxy-rules audit
- scheduled-task logs
- PHP-FPM runtime logs / sockets

These are **runtime artifacts, not DB-side configuration**.

The other seed / export files can stay around for operator workflows,
but they are **not the runtime authority** once the corresponding
normalized DB rows exist.

After `make db-migrate` → `make crs-install` → `make db-import`, the
production runtime allows you to delete:

- Any `data/conf/*.json` **except** `data/conf/config.json`.
- PHP-FPM JSON manifests like `inventory.json` / `vhosts.json` /
  `runtime.json` / `modules.json`.

GeoIP managed assets are also DB-backed after import.

### 13.3.4 `schema_migrations`

`schema_migrations` is the schema-version table used by golang-migrate.
For `make db-migrate` and the defensive schema check at startup, it
keeps the current migration **`version`** and **`dirty`** state.

Other configured JSON / text files are **not runtime storage backends**;
they are **initial seed / import / export artifacts**.

- If a normalized domain does not exist, DB rows are imported from the
  current seed / export file. If no configured file is present,
  `seeds/conf/` is used.
- If `app_config` exists, it is applied after the initial DB open —
  except for **DB connection items, which keep the bootstrap
  `config.json` value**.
- proxy / sites / vhosts / scheduled tasks / upstream runtime / policy
  domains / WAF assets / response cache / PHP-FPM inventory are not
  written back to JSON; **the DB content is loaded directly into
  runtime state**.
- If sync / parse / reload fails, the runtime **fails to start
  rather than falling back**.

When `db_sync_interval_sec >= 1`, every node also runs a **periodic
DB-to-runtime reconciliation** and reloads only when content changes.
**The DB-native runtime reloads from DB to memory / runtime, not from
DB to file**.

## 13.4 Retention / pruning

`db_retention_days` applies **only to `waf_events`**:

- `30` (default): retain the last 30 days.
- `0`: disable pruning.

`config_blobs` is **not** pruned by retention.

## 13.5 Backup

For each driver, use the standard backup flow.

### 13.5.1 SQLite

Snapshot the DB file before significant changes:

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

If WAL files exist, back them up too:

```bash
cp data/db/tukuyomi.db-wal data/db/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/db/tukuyomi.db-shm data/db/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### 13.5.2 MySQL

Use the standard DB backup flow (for example, `mysqldump`).

### 13.5.3 PostgreSQL

Use the standard DB backup flow (for example, `pg_dump`).

## 13.6 Vacuum / size maintenance (SQLite)

Run this after heavy testing or when the DB file grows under long-term
operation:

```bash
sqlite3 data/db/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## 13.7 Recovery

### 13.7.1 SQLite

If the DB is missing or corrupted:

1. **Stop the stack** (`docker compose down`).
2. **Restore from a DB backup.** Only set the corrupted file aside and
   re-seed if your config files are **known-good seed / export**.
3. **Start the stack** (`docker compose up -d coraza`). Schema
   bootstrap and initial seed run.
4. Start the service. New WAF / access events go directly to
   `waf_events`. Configure the legacy log file and call
   `/tukuyomi-api/logs/stats` only if you explicitly want to ingest an
   old `waf-events.ndjson`.

### 13.7.2 MySQL / PostgreSQL

If the DB has been reset:

1. Confirm you can **connect to the DB at the configured DSN**.
2. **Restore from a DB backup**, or prepare a **known-good config file
   for initial seed**.
3. Start or restart `coraza` so schema bootstrap and sync run.
4. New WAF / access events go directly to `waf_events`. Call the logs
   endpoint only when you explicitly want to ingest a legacy log file.

## 13.8 Recap

- Runtime storage is **DB-only**. If the DB is broken, fail to start
  rather than fall back to files.
- Run **`make db-migrate` → `make crs-install` → `make db-import`**
  before startup.
- Stored data falls into four families: **WAF events**, **versioned
  normalized config tables**, **legacy `config_blobs` (residual for
  WAF rule assets)**, and **`schema_migrations`**.
- After import, the only file the runtime needs is
  **`data/conf/config.json`**. Other seed JSON can be deleted.
- Retention applies **only to `waf_events`** (30 days by default).

## 13.9 Bridge to the next chapter

With DB operations covered, the next decision is **listener and
reuse-port**. Chapter 14 explains why tukuyomi defaults to a single
listener today, what happens with Docker published-port, and what it
would take to reopen reuse-port.
