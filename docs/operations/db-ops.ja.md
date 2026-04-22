[English](db-ops.md) | [日本語](db-ops.ja.md)

# DB Operations (SQLite / MySQL)

この文書は、`WAF_STORAGE_BACKEND=db` で運用する構成の実運用手順をまとめたものです。

## Backend Selection

DB-backed operation を有効にするには、次の env var を使います。

- `WAF_STORAGE_BACKEND=db`
- `WAF_DB_DRIVER=sqlite|mysql`
- `WAF_DB_PATH`（sqlite では必須）
- `WAF_DB_DSN`（mysql では必須）
- `WAF_DB_RETENTION_DAYS`
- `WAF_DB_SYNC_INTERVAL_SEC`（periodic reconcile loop を有効にする場合は任意）

互換フラグ:

- `WAF_DB_ENABLED` は legacy-only です。`WAF_STORAGE_BACKEND` が未設定の場合、`true` は `db`、`false` は `file` に対応します。

default の SQLite path:

- `logs/coraza/tukuyomi.db`

## What Is Stored

### 1. `waf_events`

以下のエンドポイントで使用する、取り込み済みの WAF log record（`waf-events.ndjson`）です。

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner の latest-event lookup

### 2. `config_blobs`

startup sync と multi-instance consistency に使う、admin から編集可能な config file の DB copy です。

現在の blob key:

- `cache_rules`（`cache-rules.json`）
- `rate_limit_rules`（`rate-limit.json`）
- `country_block_rules`（`country-block.json`）
- `bypass_rules`（`waf-bypass.json`）
- `bot_defense_rules`（`bot-defense.json`）
- `semantic_rules`（`semantic.json`）
- `crs_disabled_rules`（`crs-disabled.conf`）
- `rule_file_sha256:<sha256(path)>`（`WAF_RULES_FILE` に列挙した base rule file。例: `rules/tukuyomi.conf`）

DB mode の起動時も、runtime 自体は file から読み込み、各 config は DB blob と同期されます。
`WAF_DB_SYNC_INTERVAL_SEC >= 1` の場合、各 node は periodic な DB→runtime reconciliation も実行し、content に変更があった時だけ reload を発火します。

## Retention / Pruning

`WAF_DB_RETENTION_DAYS` が効くのは `waf_events` だけです。

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

## Vacuum / Size Maintenance (SQLite)

heavy test の後は次を実行します。

```bash
sqlite3 data/logs/coraza/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## Recovery

### SQLite

DB が missing / corrupted の場合:

1. stack を止める（`docker compose down`）。
2. 壊れた DB file を退避する。
3. stack を起動する（`docker compose up -d coraza`）。
4. `/tukuyomi-api/logs/stats` を 1 回呼び、`waf-events.ndjson` から `waf_events` を再取り込みさせる。
5. 必要なら admin API から重要な config を再保存して `config_blobs` を再 seed する。

### MySQL

DB が reset された場合:

1. 設定した DSN で MySQL に接続できることを確認する。
2. schema bootstrap が走るように coraza を起動または再起動する。
3. logs endpoint を 1 回叩いて `waf_events` の取り込みを発火させる。
4. 必要なら admin API から重要な config を再保存して `config_blobs` を再 seed する。
