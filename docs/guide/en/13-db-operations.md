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

- Downloads CRS (the **default version**) and stages it, together with
  the base rule seed, under `tmp/waf-rule-assets` in the workdir (`data`
  by default).
- **Imports the base WAF and CRS `.conf` / `.data` assets into DB
  `waf_rule_assets`**.

`make crs-ensure` does the same. **Every import replaces all WAF rule
assets in the DB**, including rules edited in the UI and bypass snippets;
read §13.8 before importing into a DB that is already in use.

`make db-import-waf-rule-assets` is **not** a way to refresh from seed
files on its own. It downloads nothing and imports whatever is staged
under `WAF_RULE_ASSET_FS_ROOT` (relative to the workdir); without that
variable it looks in the workdir itself and fails. To import a CRS version other than the
default, stage it with
`scripts/stage_waf_rule_assets.sh <stage-root> <crs-version>` and import
the staged files:

```bash
./scripts/stage_waf_rule_assets.sh data/tmp/waf-rule-assets <crs-version> &&
WAF_RULE_ASSET_FS_ROOT=tmp/waf-rule-assets make db-import-waf-rule-assets &&
rm -rf data/tmp/waf-rule-assets
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
- Falls back to the bundled production seed at `seeds/conf/config-bundle.json` when
  no configured file exists.
- Falls back to the compatibility default when even that is missing.
- Imports runtime files like `sites`, `vhosts`, `scheduled_tasks`,
  `upstream_runtime`, and PHP-FPM runtime inventory into their
  feature tables.
- After import, **the DB rows are authoritative**.

To run the import command from outside the bundle root, point
`WAF_DB_IMPORT_SEED_BUNDLE_FILE` at the config bundle path.

The Gateway Status `Download config` action produces this same
seed/restore bundle format. That export is intentionally separate from
the Center config snapshot sent during signed status polling; the Center
snapshot is a fleet status payload, not an import seed.

## 13.2 Driver selection

The DB connection bootstrap sits in the `storage` block of
`data/conf/config.json`:

| Key | Purpose |
|---|---|
| `db_driver` | One of `sqlite` / `mysql` / `pgsql`. |
| `db_path` | SQLite database path. |
| `db_dsn` | DSN for MySQL / PostgreSQL. |
| `hot_log_retention_days` | Hot WAF event retention in DB. |
| `db_sync_interval_sec` | Interval of the periodic DB-to-runtime reconciliation loop. |

Notes:

- `hot_log_retention_days` replaces the old `db_retention_days` name.
  Host `make install` rewrites a preserved `config.json` before running the
  new binary. For container/cloud manifests and other config-management inputs,
  update the key before deployment; current config validation rejects the old
  key.
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
- `override_rules` / `override_rule_versions` (legacy tables kept as a
  migration source; managed bypass `extra_rule` bodies live in
  `waf_rule_assets` as kind `bypass_extra_rule`)
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
  / data assets, and managed bypass `extra_rule` bodies)

The **only file required for production startup after import** is:

- `config.json`: DB connection bootstrap (`storage.db_driver` /
  `storage.db_path` / `storage.db_dsn`) plus storage retention / sync
  bootstrap values.

That is just the **config authority** story. Runtime byte artifacts are
handled separately:

- `persistent_storage.local.base_dir` (default `data/persistent`) for
  TLS binding ACME with a local backend
- `cache_store.store_dir` when the internal response cache is enabled
- security / FP Tuner / proxy-rules audit
- scheduled-task logs
- PHP-FPM runtime logs / sockets
- WAF log archives under `storage.log_archive.enabled=true`

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
  `seeds/conf/config-bundle.json` is used.
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

`hot_log_retention_days` applies **only to hot `waf_events` rows kept in DB**:

- `30` (default): retain the last 30 days.
- `0`: disable pruning.

With `storage.log_archive.enabled=true` (default), tukuyomi archives
expired complete UTC days before deleting DB rows. The local backend
path is:

```text
data/persistent/log-archives/waf/yyyy=<YYYY>/mm=<MM>/dd=<DD>/part-000001.ndjson.gz
```

For S3, the same key layout is placed below
`persistent_storage.s3.prefix`. The archive job is a Scheduled Task
named `tukuyomi-waf-log-archive`; `make install` adds it once at
`03:17 UTC`. If an operator changes, disables, or deletes that task,
later installs leave that choice alone.

With `storage.log_archive.enabled=false`, retention falls back to
direct DB pruning.

`config_blobs` is **not** pruned by retention.

## 13.5 Backup

For each driver, use the standard backup flow.

### 13.5.1 SQLite

The DB file is the path set in `storage.db_path`. The default
`db/tukuyomi.db` is relative to the runtime working directory:
`data/db/tukuyomi.db` in a development tree, and `db/tukuyomi.db` under
the deployment root (`/opt/tukuyomi` by default) after `make install`.

SQLite runs in **WAL mode**, so recent writes can still be in
`tukuyomi.db-wal`. Copying only `tukuyomi.db` while the service is
running can miss them. Take an online backup with the `sqlite3`
command-line tool, as the runtime user (`umask 077` keeps the copy
private):

```bash
sudo -u tukuyomi sh -c 'umask 077; sqlite3 /opt/tukuyomi/db/tukuyomi.db ".backup /opt/tukuyomi/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)"'
```

Or stop the service and copy the DB file together with its WAL files.
In a development tree:

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
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

## 13.8 Updating the OWASP CRS

tukuyomi does **not carry the OWASP CRS inside the binary**. The CRS is
downloaded when the WAF rule assets are staged, imported into DB
`waf_rule_assets`, and the running service reads it from there. Moving an
existing installation to another CRS version, or re-importing the same
version, therefore means **importing the WAF rule assets into that
installation's DB again**.

`make install` takes the CRS version from `CRS_VERSION=<tag>`, and
`scripts/stage_waf_rule_assets.sh` / `scripts/install_crs.sh` take it as
an argument. `make crs-install` and `make crs-ensure` always stage the
default version.

### 13.8.1 What an import replaces and keeps

The import **does not merge**. It writes a new active set of **all** WAF
rule assets built only from the staged files, even when the CRS version
does not change.

**Replaced** by the staged files:

- Base rules edited on the `Rules` screen, including exclusions written
  by FP Tuner (Chapter 8). `tukuyomi.conf` returns to the seed's content,
  and to enabled even if you had disabled it.
- Base rule files added on the `Rules` screen.
- Bypass snippets (`Rules > Advanced > Bypass snippets`).
- Additions to `crs-setup.conf`. `WAF_RULE_SEED_CRS_SETUP_OVERRIDE=<file>`
  appends the content of that file to the end of `crs-setup.conf` when
  staging, so pass the same file again.

**Kept**:

- The CRS rule-set selection. The list of disabled CRS rule file names
  stays after an import. Files added by the new version start enabled,
  and a name that was removed or renamed no longer has any effect, so
  check the selection on the `Rules` screen after updating.
- Bypass entries, but **not their snippets**. Right after the import, a
  bypass path whose snippet is gone is inspected with the default rules,
  and the log shows `[BYPASS][RULE][WARN] ... (fallback=default-rules)`.
- Proxy, sites, TLS, and admin settings, admin users, and WAF events.

### 13.8.2 Before, during, and after the import

- **Back up the DB first (§13.5).** Older versions of the rule assets
  stay in the DB, but the admin UI and API have no way to list or
  restore them, so they cannot undo an import. To roll back, restore the
  DB backup (when restoring a `.backup` copy, delete `tukuyomi.db-wal`
  and `tukuyomi.db-shm` first) or import the previous CRS version again.
- **`make install` imports every time**, because
  `INSTALL_REFRESH_WAF_ASSETS` defaults to `1`, so re-running it to
  upgrade the binary also replaces local rule edits. On an installed
  environment, `INSTALL_REFRESH_WAF_ASSETS=0` keeps the current assets;
  a first install has none and cannot start without the import. By
  default the installer restarts a running service at the end.
- **The imported rules are in use once the service restarts.**
- **Rules fixed in the UI exist only in the DB.** Before the import, save
  the full response of `GET <admin.api_base_path>/rules`
  (`/tukuyomi-api/rules` by default). After it, put the rules back on the
  `Rules` screen or with `PUT <admin.api_base_path>/rules`, bypass
  snippets first: while the snippet that a bypass entry refers to is
  missing, a bypass configuration that contains that entry cannot be
  saved from the UI or API.
- **Gateways whose WAF rules Center assigns** should not import locally.
  Update the rule bundle in Center and assign it again. If the Gateway's
  rules change after an assignment, that assignment is not applied: it
  stays `blocked` with `local WAF rules changed after assignment`. After
  the Gateway has sent its new rules to Center, assign again.
- **To check the version**, open the `Rules` screen and look at the
  `OWASP CRS ver.` line at the top of `crs-setup.conf`, after the restart.

The commands for staging, importing as the runtime user, containers, and
the development tree are in `docs/build/binary-deployment.md`
("Updating the OWASP CRS").

## 13.9 Recap

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
- Every import of WAF rule assets (`make crs-install`, `make install`)
  **replaces all rule assets in the DB**, including rules edited in the
  UI. Back up the DB first, and follow §13.8 to update the CRS.

## 13.10 Bridge to the next chapter

With DB operations covered, the next decision is **listener and
reuse-port**. Chapter 14 explains why tukuyomi defaults to a single
listener today, what happens with Docker published-port, and what it
would take to reopen reuse-port.
