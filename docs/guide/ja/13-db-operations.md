# 第13章　DB 運用（SQLite / MySQL / PostgreSQL）

第VI部「運用とトラブルシューティング」では、tukuyomi を本番で走らせ続ける
ための足回りを扱います。最初の本章では、もっとも基本的かつ事故が起きやすい
**DB 運用** を整理します。

tukuyomi の **runtime storage は DB-only** です。tukuyomi は起動時に DB
store を開き、schema bootstrap を実行し、**DB が利用不能または不正なら
起動を失敗させます**。file storage への runtime fallback はありません。
この一行に、本章のほとんどの判断が要約されています。

## 13.1　起動前の手順

配備済み runtime を起動する前に、schema migration を **明示的に実行** します。

```bash
make db-migrate
```

この target は、

- local binary を build する
- 通常起動と同じ `config.json` を読む
- 設定 driver 用の embedded SQL migration を **golang-migrate で適用** する

を行います。現在の schema version と dirty flag は `schema_migrations` に
記録され、この時点では listener や runtime sync loop は **起動しません**。

migration 後に、CRS を install / refresh して WAF rule asset を DB に
import します。

```bash
make crs-install
```

`make crs-install` は `db-migrate` 後に動き、

- 設定 workdir 配下に CRS seed file を配置
- base WAF と CRS の `.conf` / `.data` asset を **DB `waf_rule_assets` へ
  import**

を行います。CRS を再ダウンロードせず、既存 seed file から DB rule asset
だけを更新したい場合は次を使います。

```bash
make db-import-waf-rule-assets
```

既存の bootstrap / export file から DB を準備する場合は、migration 後に
`make db-import` を実行します。

```bash
make db-import
```

`make db-import` の挙動は次のとおりです。

- 先に `db-migrate` を実行する
- そのあと、seed / export material を **versioned normalized DB table へ
  import** する
- `config.json` は built-in default 適用後の `app_config` seed として読む
  （ただし bundled config は意図的に **`storage` bootstrap block だけ** を
  保持する）
- `conf/proxy.json` など configured runtime file がある場合はそれが優先
- 無ければ `seeds/conf/` の同梱本番 seed を読む
- それも無ければ互換 default に fallback
- `sites`、`vhosts`、`scheduled_tasks`、`upstream_runtime`、PHP-FPM runtime
  inventory などの runtime file は、各 feature table に import される
- import 後は **DB row が正**

bundle root 以外から import command を実行する場合は、
`WAF_DB_IMPORT_SEED_CONF_DIR` に `seeds/conf` file がある directory を
指定してください。

## 13.2　Driver Selection

DB 接続 bootstrap は `data/conf/config.json` の `storage` block で設定します。

| key | 用途 |
|---|---|
| `db_driver` | `sqlite` / `mysql` / `pgsql` のいずれか |
| `db_path` | SQLite database path |
| `db_dsn` | MySQL / PostgreSQL の DSN |
| `db_retention_days` | WAF event retention |
| `db_sync_interval_sec` | periodic な DB-to-runtime reconcile loop の間隔 |

注意:

- **`storage.backend` は deprecated** です。設定しないでください。
  `storage.backend=file` は config validation で **拒否** されます。
- `db_driver` / `db_path` / `db_dsn` は、DB を開く前に必ず bootstrap
  `config.json` から読みます。`app_config` の DB stored value が、
  接続済み process を別 DB へ移動させる **循環を作らない** ためです。

default の SQLite path は `db/tukuyomi.db` です。

DSN 要件:

- `mysql`: `db_dsn` が必須
- `pgsql`: `db_dsn` が必須。例:
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`

## 13.3　DB に保存されるもの

tukuyomi が DB に保存するのは、大きく **4 種類** に整理できます。

### 13.3.1　`waf_events`

WAF / access / request-security の event record です。次の endpoint が
読み取り対象として使います。

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- FP tuner の latest-event lookup（第8章）

現在の runtime は、これらの event を **DB に直接書き込みます**。
`waf-events.ndjson` は、古い file log を operator が **明示的に取り込む**
場合だけの **legacy import source** です。

### 13.3.2　Versioned runtime config tables

operator-owned な runtime config は、**immutable version** で管理します。
中心となるテーブルは次の 3 つです。

- `config_domains`
- `config_versions`
- `config_rollbacks`

feature-owned な row は `version_id` を持ちます。現在 normalized 済みの
domain は次のとおりです。

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
- `rate_limit_scopes` / `rate_limit_scope_values` / `rate_limit_rules` /
  `rate_limit_rule_methods`
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

normalized されている、ということは **行単位で diff が取れ、versioned で
rollback できる** ということです。`Settings` 画面や各種 policy 画面の保存
操作は、これらのテーブルに対する row 操作として記録されます。

### 13.3.3　`config_blobs`

`config_blobs` は **normalized 済み runtime / policy config domain の
authority ではありません**。legacy import 互換と、config authority では
ない content artifact のためだけに残っています。

残っている代表的な blob は次のとおりです。

- `waf_rule_assets` / `waf_rule_asset_contents`（base WAF と CRS の rule /
  data asset）

import 後の本番起動で **必要な file** は、

- `config.json`: DB 接続 bootstrap（`storage.db_driver` / `storage.db_path`
  / `storage.db_dsn`）と storage retention / sync の bootstrap 値

だけです。

これは **config authority の話** です。runtime byte artifact は別扱いです。
たとえば、

- site-managed ACME を local backend で使う場合の
  `persistent_storage.local.base_dir`（既定 `data/persistent`）
- internal response cache を有効化した場合の `cache_store.store_dir`
- security / FP tuner / proxy rules audit
- scheduled task log
- PHP-FPM runtime log / socket

これらは **DB 設定ではなく runtime artifact** です。

その他の seed / export file は、operator workflow 用に残しても構いませんが、
対応する normalized DB row が存在した後の **runtime authority ではありません**。

`make db-migrate` → `make crs-install` → `make db-import` の後の本番 runtime
では、

- `data/conf/config.json` **以外** の `data/conf/*.json`
- `inventory.json` / `vhosts.json` / `runtime.json` / `modules.json` などの
  PHP-FPM JSON manifest

は **削除しても構いません**。GeoIP managed asset も import 後は DB-backed
です。

### 13.3.4　`schema_migrations`

`schema_migrations` は、golang-migrate の schema version table です。
`make db-migrate` と起動時の defensive schema check 用に、現在の migration
**`version`** と **`dirty` state** を保持します。

その他の設定済み JSON / text file は、runtime storage backend ではなく、
**initial seed / import / export artifact** です。

- normalized domain が存在しない場合、現在の seed / export file から DB
  row を import する。configured file が無い場合は `seeds/conf/` を使う
- `app_config` が存在する場合、初期 DB open 後に適用する。ただし **DB
  接続項目は bootstrap `config.json` の値を保持** する
- proxy / sites / vhosts / scheduled tasks / upstream runtime / policy
  domain / WAF asset / response cache / PHP-FPM inventory は JSON file に
  戻さず、**DB content を直接 runtime state に読み込む**
- sync / parse / reload に失敗した場合、**fallback せず起動を失敗** させる

`db_sync_interval_sec >= 1` の場合は、各 node が **periodic な DB-to-runtime
reconciliation** も実行し、content に変更があったときだけ reload を発火
します。**DB-native runtime では DB-to-file restoration ではなく、DB-to-memory
/ runtime reload** という点を覚えておいてください。

## 13.4　Retention / Pruning

`db_retention_days` が効くのは **`waf_events` だけ** です。

- `30`（default）: 直近 30 日を保持
- `0`: pruning を無効化

`config_blobs` は retention では prune **しません**。

## 13.5　Backup

driver ごとに、通常の DB backup flow をそのまま使います。

### 13.5.1　SQLite

大きな変更の前には DB file を snapshot しておきます。

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

WAL file がある場合は一緒に backup します。

```bash
cp data/db/tukuyomi.db-wal data/db/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/db/tukuyomi.db-shm data/db/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### 13.5.2　MySQL

通常の DB backup フロー（例: `mysqldump`）で backup します。

### 13.5.3　PostgreSQL

通常の DB backup フロー（例: `pg_dump`）で backup します。

## 13.6　Vacuum / Size Maintenance（SQLite）

heavy test のあとや、長期運用で DB file が肥大化したと感じたら、次を実行
します。

```bash
sqlite3 data/db/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## 13.7　Recovery

### 13.7.1　SQLite

DB が missing / corrupted の場合:

1. **stack を止める**（`docker compose down`）。
2. **DB backup から復元** する。壊れた DB file を退避して再 seed するのは、
   設定 file が **known-good な seed / export** の場合だけに限ること。
3. **stack を起動** する（`docker compose up -d coraza`）。schema bootstrap
   と initial seed が走る。
4. service を起動する。新しい WAF / access event は `waf_events` に直接
   書き込まれる。古い `waf-events.ndjson` を明示的に取り込む場合だけ、
   legacy log file を設定して `/tukuyomi-api/logs/stats` を呼ぶ。

### 13.7.2　MySQL / PostgreSQL

DB が reset された場合:

1. 設定した DSN で DB に **接続できることを確認** する。
2. **DB backup から復元** するか、initial seed 用の **known-good config
   file を用意** する。
3. schema bootstrap と sync が走るように、`coraza` を起動または再起動する。
4. 新しい WAF / access event は `waf_events` に直接書き込まれる。legacy
   log file を明示的に取り込む場合だけ、logs endpoint を呼ぶ。

## 13.8　ここまでの整理

- runtime storage は **DB-only**。DB が壊れていれば起動を失敗させ、file
  に fallback しない。
- 起動前に **`make db-migrate` → `make crs-install` → `make db-import`** の
  順で打つ。
- 保存対象は **WAF events**、**versioned normalized config tables**、
  **legacy `config_blobs`（WAF rule asset 用に残存）**、**`schema_migrations`**
  の 4 系統。
- import 後の runtime に必要な file は **`data/conf/config.json` だけ**。
  ほかの seed JSON は削除可。
- retention が効くのは **`waf_events` のみ**（既定 30 日）。

## 13.9　次章への橋渡し

DB 運用で「事故を起こさない」備えができたら、次は **listener と
reuse-port** に関する判断です。第14章では、なぜ tukuyomi が現時点で
single-listener を default にしているか、Docker published-port で何が
起こるか、reuse-port を再開する条件は何か、を扱います。
