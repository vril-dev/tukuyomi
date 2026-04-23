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
設定 driver 用の embedded SQL migration を適用します。適用済み migration file
名は `schema_migrations` に記録され、listener や runtime sync loop は起動しません。

既存の bootstrap/export file から DB を準備する場合は、migration 後に import します。

```bash
make db-import
```

`make db-import` は先に `db-migrate` を実行し、その後 `config.json` を
`config_blobs.app_config`、`proxy.json` を `config_blobs.proxy_rules` へ
import します。これらの blob が作られた後は DB content が正です。

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
`config.json` から読みます。`app_config` からは採用しません。DB blob が
接続済み process を別 DB へ移動させる循環を作らないためです。

default の SQLite path:

- `logs/coraza/tukuyomi.db`

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

### 2. `config_blobs`

startup sync、runtime reload、export/import materialization、multi-instance
consistency に使う、admin から編集可能な config の authoritative DB copy です。

現在の blob key:

- `app_config`（bootstrap DB 接続項目を除いた `config.json`）
- `proxy_rules`（`proxy.json`）
- `cache_rules`（`cache-rules.json`）
- `cache_store`（`cache-store.json`）
- `rate_limit_rules`（`rate-limit.json`）
- `country_block_rules`（`country-block.json`）
- `bypass_rules`（`waf-bypass.json`）
- `bot_defense_rules`（`bot-defense.json`）
- `semantic_rules`（`semantic.json`）
- `notification_rules`（`notifications.json`）
- `ip_reputation_rules`（`ip-reputation.json`）
- `sites`（`sites.json`）
- `scheduled_tasks`（`scheduled-tasks.json`）
- `upstream_runtime`（`upstream-runtime.json`）
- `crs_disabled_rules`（`crs-disabled.conf`）
- `rule_file_sha256:<sha256(path)>`（`WAF_RULES_FILE` に列挙した base rule file。例: `rules/tukuyomi.conf`）

disk に残す bootstrap/import file:

- `config.json`: DB 接続 bootstrap（`storage.db_driver`、`storage.db_path`、`storage.db_dsn`）と `app_config` の seed/export material
- `proxy.json`: `proxy_rules` の seed/import/export material

これらの file は、対応する DB blob が存在した後の runtime authority ではありません。

### 3. `schema_migrations`

適用済み embedded SQL migration file 名です。`make db-migrate` と起動時の
defensive schema check が使う運用 metadata です。

その他の設定済み JSON/text file は runtime storage backend ではありません。
initial seed / import / export artifact です。

- DB blob が存在しない場合、現在の設定 file から DB を seed します
- `app_config` が存在する場合、初期 DB open 後にそれを適用します。ただし DB
  接続項目は bootstrap `config.json` の値を保持します
- `proxy_rules` が存在する場合、startup proxy routing は `proxy.json` ではなく
  DB から読みます
- `sites`、`scheduled_tasks`、`upstream_runtime` のような DB-native runtime
  は、DB blob が存在する場合、JSON file へ戻さず DB content を直接 runtime
  state に読み込みます
- file restoration は、まだ file-shaped parser / watcher boundary を必要とする
  古い subsystem だけの互換処理です
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
cp data/logs/coraza/tukuyomi.db data/logs/coraza/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

WAL file がある場合は一緒に backup します。

```bash
cp data/logs/coraza/tukuyomi.db-wal data/logs/coraza/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/logs/coraza/tukuyomi.db-shm data/logs/coraza/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### MySQL

通常の DB backup flow（例: `mysqldump`）で backup します。

### PostgreSQL

通常の DB backup flow（例: `pg_dump`）で backup します。

## Vacuum / Size Maintenance (SQLite)

heavy test の後は次を実行します。

```bash
sqlite3 data/logs/coraza/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
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
