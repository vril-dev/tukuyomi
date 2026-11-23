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

- CRS（**既定のバージョン**）をダウンロードし、base rule の seed とともに
  workdir（既定は `data`）配下の `tmp/waf-rule-assets` に stage
- base WAF と CRS の `.conf` / `.data` asset を **DB `waf_rule_assets` へ
  import**

を行います。`make crs-ensure` も同じ動作です。**import のたびに、DB 上のすべての
WAF rule asset が置き換わります**。UI で編集した rule や bypass snippet も
含まれるため、すでに使っている DB へ import する前に第13.8 節を読んでください。

`make db-import-waf-rule-assets` は、それだけで seed file から更新するための
ものでは **ありません**。ダウンロードはせず、`WAF_RULE_ASSET_FS_ROOT`（workdir
からの相対 path）配下に stage されている file を import します。この変数を
指定しないと workdir の直下を探すため、失敗します。既定以外の CRS バージョンを import する場合は、
`scripts/stage_waf_rule_assets.sh <stage-root> <crs-version>` で stage して、
その file を import します。

```bash
./scripts/stage_waf_rule_assets.sh data/tmp/waf-rule-assets <crs-version> &&
WAF_RULE_ASSET_FS_ROOT=tmp/waf-rule-assets make db-import-waf-rule-assets &&
rm -rf data/tmp/waf-rule-assets
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
- 無ければ `seeds/conf/config-bundle.json` の同梱本番 seed を読む
- それも無ければ互換 default に fallback
- `sites`、`vhosts`、`scheduled_tasks`、`upstream_runtime`、PHP-FPM runtime
  inventory などの runtime file は、各 feature table に import される
- import 後は **DB row が正**

bundle root 以外から import command を実行する場合は、
`WAF_DB_IMPORT_SEED_BUNDLE_FILE` に config bundle のパスを指定してください。

Gateway Status の `Download config` は、この seed／restore 用 bundle format
を出力します。この export は、署名付きステータスポーリングで Center へ送る
config snapshot とは意図的に分けています。Center snapshot は fleet status
payload であり、import seed ではありません。

## 13.2　Driver Selection

DB 接続 bootstrap は `data/conf/config.json` の `storage` block で設定します。

| key | 用途 |
|---|---|
| `db_driver` | `sqlite` / `mysql` / `pgsql` のいずれか |
| `db_path` | SQLite database path |
| `db_dsn` | MySQL / PostgreSQL の DSN |
| `hot_log_retention_days` | DB に hot データとして残す WAF event retention |
| `db_sync_interval_sec` | periodic な DB-to-runtime reconcile loop の間隔 |

注意:

- `hot_log_retention_days` は旧 `db_retention_days` から名前を変更した設定です。
  host の `make install` は、保持している `config.json` を新バイナリ実行前に
  書き換えます。container / cloud manifest や構成管理で生成する入力は、
  deployment 前に新キーへ更新してください。現在の config validation は旧キーを
  拒否します。
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
- `override_rules` / `override_rule_versions`（移行元として残る legacy table。
  managed bypass の `extra_rule` body は、`waf_rule_assets` に種別
  `bypass_extra_rule` として保存されます）
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
  data asset、および managed bypass の `extra_rule` body）

import 後の本番起動で **必要な file** は、

- `config.json`: DB 接続 bootstrap（`storage.db_driver` / `storage.db_path`
  / `storage.db_dsn`）と storage retention / sync の bootstrap 値

だけです。

これは **config authority の話** です。runtime byte artifact は別扱いです。
たとえば、

- TLS binding ACME を local backend で使う場合の
  `persistent_storage.local.base_dir`（既定 `data/persistent`）
- internal response cache を有効化した場合の `cache_store.store_dir`
- security / FP tuner / proxy rules audit
- scheduled task log
- PHP-FPM runtime log / socket
- `storage.log_archive.enabled=true` の WAF log archive

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
  row を import する。configured file が無い場合は `seeds/conf/config-bundle.json` を使う
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

`hot_log_retention_days` が効くのは **DB に hot データとして残す `waf_events`
行だけ** です。

- `30`（default）: 直近 30 日を保持
- `0`: pruning を無効化

`storage.log_archive.enabled=true`（default）の場合、期限を過ぎた完了済み
UTC 日は、DB row を削除する前に archive されます。local backend の path は
次の形です。

```text
data/persistent/log-archives/waf/yyyy=<YYYY>/mm=<MM>/dd=<DD>/part-000001.ndjson.gz
```

S3 では、同じ key layout を `persistent_storage.s3.prefix` 配下に置きます。
archive job は `tukuyomi-waf-log-archive` という Scheduled Task です。
`make install` はこの task を `03:17 UTC` で一度だけ追加します。operator が
後で変更、無効化、削除した場合、以後の install はその判断を維持します。

`storage.log_archive.enabled=false` の場合は、従来どおり DB row を直接 prune
します。

`config_blobs` は retention では prune **しません**。

## 13.5　Backup

driver ごとに、通常の DB backup flow をそのまま使います。

### 13.5.1　SQLite

DB file は `storage.db_path` で指定した path です。既定の `db/tukuyomi.db` は
runtime の作業 directory からの相対 path で、開発環境では
`data/db/tukuyomi.db`、`make install` で導入した環境では deployment root（既定は
`/opt/tukuyomi`）配下の `db/tukuyomi.db` です。

SQLite は **WAL mode** で動作するため、直近の書き込みが `tukuyomi.db-wal` に
だけ残っていることがあります。service の稼働中に `tukuyomi.db` だけをコピーする
と、それらを取りこぼすおそれがあります。runtime user として、`sqlite3` の
command-line tool で online backup を取ります（`umask 077` で、コピーを他の
user から読めなくします）。

```bash
sudo -u tukuyomi sh -c 'umask 077; sqlite3 /opt/tukuyomi/db/tukuyomi.db ".backup /opt/tukuyomi/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)"'
```

または、service を止めてから、DB file を WAL file とあわせてコピーします。
開発環境では次のとおりです。

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
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

## 13.8　OWASP CRS の更新

tukuyomi は OWASP CRS を **バイナリに同梱していません**。CRS は WAF rule
asset を stage するときにダウンロードされ、DB `waf_rule_assets` へ import
されて、稼働中の service はそこから読み込みます。したがって、導入済みの環境
で別の CRS バージョンへ移る場合も、同じバージョンを入れ直す場合も、
**その環境の DB へ WAF rule asset をもう一度 import する** ことになります。

`make install` は `CRS_VERSION=<tag>` で CRS のバージョンを指定します。
`scripts/stage_waf_rule_assets.sh` と `scripts/install_crs.sh` は引数で指定
します。`make crs-install` と `make crs-ensure` は、常に既定のバージョンを
stage します。

### 13.8.1　import で置き換わるもの、残るもの

import は既存の内容と **merge しません**。stage した file だけから、
**すべて**の WAF rule asset を新しく作り直して有効にします。CRS のバージョ
ンが同じでも同様です。

stage した file で **置き換わる** もの:

- `Rules` 画面で編集した base rule（FP Tuner が書き込んだ除外を含みます。
  第8章）。`tukuyomi.conf` は seed の内容に戻り、無効にしていた場合も有効に
  戻ります
- `Rules` 画面で追加した base rule file
- bypass snippet（`Rules > Advanced > Bypass snippets`）
- `crs-setup.conf` への追記。stage 時に `WAF_RULE_SEED_CRS_SETUP_OVERRIDE=<file>`
  を指定すると、その file の内容が `crs-setup.conf` の末尾に追記されます。同じ
  file を指定し直してください

**残る** もの:

- CRS rule set の選択。無効にした CRS rule file 名の一覧は、import 後も残り
  ます。新しいバージョンで増えた file は有効で始まり、名前が消えた、または
  変わったものは反映されません。更新後に `Rules` 画面で確かめてください
- bypass の entry。ただし **snippet は消えます**。import の直後から、snippet が
  無くなった path は default の rule で検査され、log に
  `[BYPASS][RULE][WARN] ... (fallback=default-rules)` が出ます
- proxy、sites、TLS、admin の設定、admin user、WAF event

### 13.8.2　import の前、最中、後

- **先に DB を backup します（第13.5 節）。** rule asset の旧版は DB に残り
  ますが、管理 UI と API から参照・復元する手段はなく、import を元に戻せま
  せん。戻すには、backup から DB を復元する（`.backup` で取った file を戻すときは、
  先に `tukuyomi.db-wal` と `tukuyomi.db-shm` を消します）か、前の CRS バージョンをもう一度
  import します。
- **`make install` は毎回 import します。** `INSTALL_REFRESH_WAF_ASSETS` の
  既定値が `1` のため、binary の更新のために再実行すると、ローカルで編集した
  rule も置き換わります。導入済みの環境では、`INSTALL_REFRESH_WAF_ASSETS=0`
  で現在の asset を保持できます。初回の install には asset が無く、import
  しないと起動できません。既定では、installer は最後に稼働中の service を再
  起動します。
- **import した rule は、service を再起動した後に使われます。**
- **UI で直した rule は DB にしかありません。** import の前に、
  `GET <admin.api_base_path>/rules`（既定は `/tukuyomi-api/rules`）のレスポン
  スを内容ごと保存します。import の後で、`Rules` 画面または
  `PUT <admin.api_base_path>/rules` で入れ直します。bypass snippet を先に戻し
  てください。bypass の entry が参照する snippet が無い間は、その entry を含む
  bypass 設定を UI や API から保存できないためです。
- **Center が WAF rule を割り当てる Gateway** では、ローカルで import しない
  でください。Center で rule bundle を更新して、もう一度割り当てます。割り当て
  の後で Gateway の rule が変わると、その割り当ては適用されず、
  `local WAF rules changed after assignment` で `blocked` になります。Gateway
  が新しい rule を Center へ送った後に、割り当て直してください。
- **バージョンの確認** は、再起動の後に `Rules` 画面で、`crs-setup.conf` の
  先頭にある `OWASP CRS ver.` の行を見ます。

stage、runtime user としての import、container、開発環境のコマンドは、
`docs/build/binary-deployment.ja.md` の「OWASP CRS の更新」にあります。

## 13.9　ここまでの整理

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
- WAF rule asset の import（`make crs-install`、`make install`）は、**DB 上の
  すべての rule asset を置き換えます**。UI で編集した rule も含まれます。先に
  DB を backup し、CRS の更新は第13.8 節に従ってください。

## 13.10　次章への橋渡し

DB 運用で「事故を起こさない」備えができたら、次は **listener と
reuse-port** に関する判断です。第14章では、なぜ tukuyomi が現時点で
single-listener を default にしているか、Docker published-port で何が
起こるか、reuse-port を再開する条件は何か、を扱います。
