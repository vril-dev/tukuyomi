[English](db-ops.md) | [日本語](db-ops.ja.md)

# DB Operations (SQLite / MySQL / PostgreSQL)

runtime storage は DB-only です。tukuyomi は起動時に DB store を開き、
schema bootstrap を実行し、DB が利用不能または不正なら起動を失敗させます。
file storage への runtime fallback はありません。

配備済み runtime を起動する前に schema migration を明示実行します。

```bash
make db-migrate
```

この target は local binary を build し、通常起動と同じ `config.json` を読み、
設定 driver 用の embedded SQL migration を golang-migrate で適用します。
現在の schema version と dirty flag は `schema_migrations` に記録され、
listener や runtime sync loop は起動しません。

migration 後に CRS を install / refresh し、WAF rule asset を DB へ import します。

```bash
make crs-install
```

`make crs-install` は `db-migrate` 後に動き、設定 workdir 配下へ CRS seed file を
配置し、base WAF と CRS の `.conf` / `.data` asset を DB `waf_rule_assets` へ
import します。CRS を再ダウンロードせず既存 seed file から DB rule asset だけ
更新する場合は次を使います。

```bash
make db-import-waf-rule-assets
```

既存の bootstrap/export file から DB を準備する場合は、migration 後に import します。

```bash
make db-import
```

`make db-import` は先に `db-migrate` を実行し、その後 seed/export material を
versioned normalized DB table へ import します。`config.json` は DB bootstrap
項目を除いた `app_config`、`proxy.json` は proxy config、`sites`、`vhosts`、
`scheduled_tasks`、`upstream_runtime`、PHP-FPM runtime inventory などの
runtime file は各 feature table へ import されます。import 後はそれらの DB
row が正です。

## Driver Selection

DB 接続 bootstrap は `data/conf/config.json` の `storage` で設定します。

- `db_driver`: `sqlite`, `mysql`, `pgsql`
- `db_path`: SQLite database path
- `db_dsn`: MySQL / PostgreSQL DSN
- `db_retention_days`: WAF event retention
- `db_sync_interval_sec`: periodic DB-to-runtime reconcile loop

`storage.backend` は deprecated です。設定しないでください。
`storage.backend=file` は config validation で拒否されます。

`db_driver`、`db_path`、`db_dsn` は DB を開く前に必ず bootstrap
`config.json` から読みます。`app_config` の DB stored value が
接続済み process を別 DB へ移動させる循環を作らないためです。

default の SQLite path:

- `db/tukuyomi.db`

DSN 要件:

- `mysql`: `db_dsn` が必須
- `pgsql`: `db_dsn` が必須。例:
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`

## What Is Stored

### 1. `waf_events`

以下のエンドポイントで使用する、取り込み済みの WAF log record（`waf-events.ndjson`）です。

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner の latest-event lookup

### 2. Versioned runtime config tables

operator-owned runtime config は immutable version で管理します。

- `config_domains`
- `config_versions`
- `config_rollbacks`

feature-owned row は `version_id` を持ちます。現在 normalized 済みの domain:

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

`config_blobs` は normalized 済み runtime / policy config domain の
authority ではありません。legacy import 互換と、config authority では
ない content artifact のためだけに残っています。

残っている blob 例:

- `waf_rule_assets`, `waf_rule_asset_contents`（base WAF と CRS の rule/data asset）

import 後の本番起動で必要な file は次だけです。

- `config.json`: DB 接続 bootstrap（`storage.db_driver`、`storage.db_path`、
  `storage.db_dsn`）と `app_config` の seed/export material

その他の seed/export file は operator workflow 用に残しても構いませんが、
対応する normalized DB row が存在した後の runtime authority ではありません。
`make db-migrate`、`make crs-install`、`make db-import` 後の本番 runtime では
`data/conf/config.json` 以外の `data/conf/*.json`、
および `inventory.json`、`vhosts.json`、`runtime.json`、
`modules.json` などの PHP-FPM JSON manifest を削除できます。GeoIP managed
asset も import 後は DB-backed です。

### 4. `schema_migrations`

golang-migrate の schema version table です。`make db-migrate` と起動時の
defensive schema check 用に、現在の migration `version` と `dirty` state を
保持します。

その他の設定済み JSON/text file は runtime storage backend ではありません。
initial seed / import / export artifact です。

- normalized domain が存在しない場合、現在の seed/export file から DB row を
  import します
- `app_config` が存在する場合、初期 DB open 後にそれを適用します。ただし DB
  接続項目は bootstrap `config.json` の値を保持します
- proxy、sites、vhosts、scheduled tasks、upstream runtime、policy domain、
  WAF asset、response cache、PHP-FPM inventory は JSON file へ戻さず DB content
  を直接 runtime state に読み込みます
- sync、parse、reload に失敗した場合、fallback せず起動を失敗させます

`db_sync_interval_sec >= 1` の場合、各 node は periodic な DB-to-runtime
reconciliation も実行し、content に変更があった時だけ reload を発火します。
DB-native runtime では DB-to-file restoration ではなく、DB-to-memory/runtime
reload です。

## Retention / Pruning

`db_retention_days` が効くのは `waf_events` だけです。

- `30`（default）: 直近 30 日を保持
- `0`: pruning を無効化

`config_blobs` は retention では prune しません。

## Backup

### SQLite

大きな変更の前には DB file を snapshot します。

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

WAL file がある場合は一緒に backup します。

```bash
cp data/db/tukuyomi.db-wal data/db/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/db/tukuyomi.db-shm data/db/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### MySQL

通常の DB backup flow（例: `mysqldump`）で backup します。

### PostgreSQL

通常の DB backup flow（例: `pg_dump`）で backup します。

## Vacuum / Size Maintenance (SQLite)

heavy test の後は次を実行します。

```bash
sqlite3 data/db/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## Recovery

### SQLite

DB が missing / corrupted の場合:

1. stack を止める（`docker compose down`）。
2. DB backup から復元する。壊れた DB file を退避して再 seed するのは、設定 file が known-good な seed/export の場合だけにする。
3. stack を起動する（`docker compose up -d coraza`）。schema bootstrap と initial seed が走ります。
4. `/tukuyomi-api/logs/stats` を 1 回呼び、`waf-events.ndjson` から `waf_events` を再取り込みさせる。

### MySQL / PostgreSQL

DB が reset された場合:

1. 設定した DSN で DB に接続できることを確認する。
2. DB backup から復元するか、initial seed 用の known-good config file を用意する。
3. schema bootstrap と sync が走るように coraza を起動または再起動する。
4. logs endpoint を 1 回叩いて `waf_events` の取り込みを発火させる。
