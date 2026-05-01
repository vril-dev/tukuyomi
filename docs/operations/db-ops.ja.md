[English](db-ops.md) | [日本語](db-ops.ja.md)

# DB 運用（SQLite ／ MySQL ／ PostgreSQL）

ランタイムストレージは DB のみです。tukuyomi は起動時に DB ストアを開き、スキーマブートストラップを実行し、DB が利用不能または不正な状態であれば起動を失敗させます。
ファイルストレージへのランタイムでのフォールバックはありません。

配備済みのランタイムを起動する前に、スキーママイグレーションを明示的に実行します。

```bash
make db-migrate
```

このターゲットはローカルバイナリをビルドし、通常起動と同じ `config.json` を読み込み、設定済みドライバ用の組み込み SQL マイグレーションを golang-migrate で適用します。
現在のスキーマバージョンと dirty フラグは `schema_migrations` に記録され、リスナーやランタイムの同期ループは起動しません。

マイグレーション後に CRS をインストール／更新し、WAF ルールアセットを DB へインポートします。

```bash
make crs-install
```

`make crs-install` は `db-migrate` 後に動作し、設定された作業ディレクトリ配下に CRS シードファイルを配置したうえで、ベース WAF と CRS の `.conf` ／ `.data` アセットを DB `waf_rule_assets` へインポートします。CRS を再ダウンロードせず、既存のシードファイルから DB のルールアセットのみを更新する場合は次を使用します。

```bash
make db-import-waf-rule-assets
```

既存のブートストラップ／エクスポートファイルから DB を準備する場合は、マイグレーション後にインポートします。

```bash
make db-import
```

`make db-import` は先に `db-migrate` を実行し、その後にシード／エクスポート素材をバージョン管理された正規化済み DB テーブルへインポートします。`config.json` は組み込みデフォルト適用後の `app_config` シードとして読み込まれますが、同梱設定は意図的に `storage` のブートストラップブロックのみを保持します。`conf/proxy.json` などの設定済みランタイムファイルがあればそちらが優先され、無い場合は `seeds/conf/` の同梱本番シードを読み込んだうえで、互換デフォルトへフォールバックします。`sites`、`vhosts`、`scheduled_tasks`、`upstream_runtime`、PHP-FPM ランタイムインベントリなどのランタイムファイルは、それぞれの機能テーブルへインポートされます。インポート後は、それらの DB レコードを正として扱います。

バンドルルート以外からインポートコマンドを実行する場合は、`WAF_DB_IMPORT_SEED_CONF_DIR` に `seeds/conf` ファイルが存在するディレクトリを指定してください。

## ドライバの選択

DB 接続のブートストラップは、`data/conf/config.json` の `storage` で設定します。

- `db_driver`: `sqlite`、`mysql`、`pgsql`
- `db_path`: SQLite データベースのパス
- `db_dsn`: MySQL ／ PostgreSQL の DSN
- `db_retention_days`: WAF イベントの保持期間
- `db_sync_interval_sec`: DB からランタイムへの定期的な再同期ループ間隔

`storage.backend` は非推奨です。設定しないでください。
`storage.backend=file` は設定検証で拒否されます。

`db_driver`、`db_path`、`db_dsn` は、DB を開く前に必ずブートストラップ用の `config.json` から読み込みます。`app_config` の DB 上の値が、接続済みプロセスを別の DB へ移動させるような循環を作らないためです。

SQLite のパス既定値:

- `db/tukuyomi.db`

DSN の要件:

- `mysql`: `db_dsn` が必須
- `pgsql`: `db_dsn` が必須。例:
  `postgres://user:pass@postgres:5432/tukuyomi?sslmode=disable`

## 何が保存されるか

### 1. `waf_events`

次のエンドポイントで使用する WAF ／アクセス／リクエストセキュリティのイベントレコードです。

- `/tukuyomi-api/logs/stats`
- `/tukuyomi-api/logs/read?src=waf`
- `/tukuyomi-api/logs/download?src=waf`
- 誤検知チューナーの最新イベントルックアップ

現在のランタイムは、これらのイベントを DB へ直接書き込みます。`waf-events.ndjson` は、古いファイルログをオペレーターが明示的に取り込む場合のみ使用するレガシーなインポート元です。

### 2. バージョン管理されたランタイム設定テーブル

オペレーターが所有するランタイム設定は、イミュータブルなバージョン管理で保持されます。

- `config_domains`
- `config_versions`
- `config_rollbacks`

機能側のレコードは `version_id` を持ちます。現在の正規化済みドメインは次のとおりです。

- `app_config_values`、`app_config_lists`、`app_config_list_values`
- `proxy_*`
- `sites`、`site_hosts`、`site_tls`
- `vhosts`、`vhost_*`
- `scheduled_tasks`、`scheduled_task_env`、`scheduled_task_args`
- `upstream_runtime_overrides`
- `cache_rule_scopes`、`cache_rules`、`cache_rule_methods`、`cache_rule_vary_headers`
- `bypass_scopes`、`bypass_entries`
- `country_block_scopes`、`country_block_countries`
- `rate_limit_scopes`、`rate_limit_scope_values`、`rate_limit_rules`、`rate_limit_rule_methods`
- `bot_defense_scopes`、`bot_defense_scope_values`、`bot_defense_path_policies`、`bot_defense_path_policy_prefixes`
- `semantic_scopes`、`semantic_scope_values`
- `notification_settings`、`notification_triggers`、`notification_security_sources`、`notification_sinks`、`notification_sink_headers`、`notification_sink_recipients`
- `ip_reputation_scopes`、`ip_reputation_scope_values`
- `response_cache_config`
- `crs_disabled_rules`
- `override_rules`、`override_rule_versions`
- `php_runtime_inventory`、`php_runtime_modules`、`php_runtime_default_disabled_modules`

### 3. `config_blobs`

`config_blobs` は、正規化済みのランタイム／ポリシー設定ドメインの正となる保存先ではありません。レガシーインポートとの互換、および設定として正にしないコンテンツアーティファクトのためにのみ残しています。

残っている blob の例:

- `waf_rule_assets`、`waf_rule_asset_contents`（ベース WAF と CRS のルール／データアセット）

インポート後の本番起動で必要なファイルは次のみです。

- `config.json`: DB 接続のブートストラップ（`storage.db_driver`、`storage.db_path`、`storage.db_dsn`）と、ストレージの保持期間／同期間隔のブートストラップ値

これは「設定として何を正とするか」に関する話です。ランタイムのバイトアーティファクトは別扱いです。
サイト管理 ACME をローカルバックエンドで使う場合は、`persistent_storage.local.base_dir`（既定 `data/persistent`）を維持してください。内部レスポンスキャッシュを有効化した場合の `cache_store.store_dir`、セキュリティ ／誤検知チューナー ／プロキシルールの監査、スケジュールタスクのログ、PHP-FPM ランタイムのログ／ソケットは、DB の設定ではなくランタイムのアーティファクトです。

その他のシード／エクスポートファイルはオペレーターのワークフロー用に残しても構いませんが、対応する正規化済みの DB レコードが存在するようになった後は、ランタイムの参照元ではありません。
`make db-migrate`、`make crs-install`、`make db-import` 後の本番ランタイムでは、`data/conf/config.json` 以外の `data/conf/*.json`、および `inventory.json`、`vhosts.json`、`runtime.json`、`modules.json` などの PHP-FPM JSON マニフェストは削除できます。GeoIP のマネージドアセットも、インポート後は DB を正として保持します。

### 4. `schema_migrations`

golang-migrate のスキーマバージョン管理テーブルです。`make db-migrate` および起動時の防御的なスキーマチェック用に、現在のマイグレーション `version` と `dirty` 状態を保持します。

その他の設定済み JSON ／テキストファイルは、ランタイムストレージのバックエンドではありません。あくまで初期シード／インポート／エクスポート用のアーティファクトです。

- 正規化済みドメインが存在しない場合は、現在のシード／エクスポートファイルから DB レコードをインポートします。設定済みファイルが存在しない場合は `seeds/conf/` を使用します
- `app_config` が存在する場合は、初回 DB オープン後にそれを適用します。ただし DB 接続関連の項目は、ブートストラップ `config.json` の値を保持します
- プロキシ、サイト、vhosts、スケジュールタスク、アップストリームランタイム、ポリシードメイン、WAF アセット、レスポンスキャッシュ、PHP-FPM インベントリは、JSON ファイルへ書き戻さず、DB のコンテンツを直接ランタイム状態へ読み込みます
- 同期、パース、リロードに失敗した場合は、フォールバックせず起動を失敗させます

`db_sync_interval_sec >= 1` の場合、各ノードは DB からランタイムへの定期的な再同期も実行し、コンテンツに変更があった時のみリロードを発火します。
DB ネイティブのランタイムでは、DB からファイルへの復元ではなく、DB からメモリ／ランタイムへのリロードを行います。

## 保持期間 ／削除

`db_retention_days` が効くのは `waf_events` のみです。

- `30`（既定）: 直近 30 日を保持
- `0`: 削除を無効化

`config_blobs` は保持期間による削除の対象外です。

## バックアップ

### SQLite

大きな変更を行う前には、DB ファイルをスナップショットしておきます。

```bash
cp data/db/tukuyomi.db data/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)
```

WAL ファイルが存在する場合は、合わせてバックアップしてください。

```bash
cp data/db/tukuyomi.db-wal data/db/tukuyomi.db-wal.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
cp data/db/tukuyomi.db-shm data/db/tukuyomi.db-shm.bak.$(date +%Y%m%d%H%M%S) 2>/dev/null || true
```

### MySQL

通常の DB バックアップ手順（例: `mysqldump`）でバックアップします。

### PostgreSQL

通常の DB バックアップ手順（例: `pg_dump`）でバックアップします。

## バキューム ／サイズメンテナンス（SQLite）

負荷の高いテストの後には、次を実行します。

```bash
sqlite3 data/db/tukuyomi.db "PRAGMA wal_checkpoint(TRUNCATE); VACUUM;"
```

## リカバリ

### SQLite

DB が紛失または破損した場合:

1. スタックを停止します（`docker compose down`）
2. DB バックアップから復元します。壊れた DB ファイルを退避し再シードする方法は、設定ファイルが既知の正常なシード／エクスポートである場合に限ります
3. スタックを起動します（`docker compose up -d coraza`）。スキーマブートストラップと初期シードが実行されます
4. サービスを起動します。新しい WAF ／アクセスイベントは `waf_events` へ直接書き込まれます。古い `waf-events.ndjson` を明示的に取り込む場合のみ、レガシーログファイルを設定したうえで `/tukuyomi-api/logs/stats` を呼び出します

### MySQL / PostgreSQL

DB がリセットされた場合:

1. 設定した DSN で DB へ接続できることを確認します
2. DB バックアップから復元するか、初期シード用の既知の正常な設定ファイルを用意します
3. スキーマブートストラップと同期が実行されるよう、coraza を起動または再起動します
4. 新しい WAF ／アクセスイベントは `waf_events` へ直接書き込まれます。レガシーログファイルを明示的に取り込む場合のみ、logs エンドポイントを呼び出します
