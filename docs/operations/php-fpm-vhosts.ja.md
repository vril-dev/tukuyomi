[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM ランタイム / Vhost 運用

この文書は、`/options`、`/vhosts`、`/proxy-rules` を使う任意の PHP-FPM 運用をまとめたものです。

## 役割分担

- `/options`
  - build 済み runtime の一覧表示
  - materialization 状態 / process 状態の確認
- `/vhosts`
  - 管理対象 `php-fpm` アプリ定義の管理
  - host、port、docroot、rewrite、access rule、basic auth、`.htaccess` subset import、PHP ini override の管理
  - route bind 用 generated target 名の管理
- `/proxy-rules`
  - ルートへの紐付けのみ
  - `/vhosts` が生成した target 名へトラフィックを流す
  - raw の `fcgi://` を通常の運用入口にはしない

## データ配置

PHP-FPM の運用データは `data/php-fpm/` に集約されています。

- `inventory.json`
  - runtime inventory のローカル metadata
- `vhosts.json`
  - 管理対象 PHP-FPM vhost 定義
- `binaries/<runtime_id>/`
  - build 済み runtime bundle、`php-fpm` wrapper、`php` CLI wrapper、`runtime.json`、`modules.json`
- `runtime/<runtime_id>/`
  - 生成された `php-fpm.conf`、pool ファイル、pid/log、listen 用の成果物

汎用のサンプル docroot は `data/vhosts/samples/` に置きます。

既定パスは `data/conf/config.json` の以下で決まります。

- `paths.php_runtime_inventory_file`
- `paths.vhost_config_file`

## Runtime Build と Inventory の流れ

PHP runtime は build されて初めて `/options` に出ます。

runtime bundle の build:

```bash
make php-fpm-build VER=8.3
```

binary 配備レイアウトへ stage する場合:

```bash
sudo make php-fpm-copy RUNTIME=php83
```

binary 配備レイアウトから安全に外す場合:

```bash
sudo make php-fpm-prune RUNTIME=php83
```

対応 version:

- `8.3`
- `8.4`
- `8.5`

build 後の確認手順:

1. `/options` を開く
2. runtime card が出ていることを確認する
3. 次を確認する
   - 表示名 / 検出 version
   - binary path
   - CLI binary path
   - 同梱 module 一覧
   - 実行 user/group
   - materialized target の参照数
   - runtime process 状態
4. `Load` を実行して一覧を更新する

`data/php-fpm/binaries/<runtime_id>/` を削除すると、その runtime は次回 load 時に `/options` から消えます。

補足:

- `php-fpm-copy` の既定配備先は `/opt/tukuyomi` です。別 path は `DEST=/srv/tukuyomi` のように上書きします
- `php-fpm-prune` も既定配備先は `/opt/tukuyomi` です。staged `vhosts.json` の参照と実行中 pid を確認してから削除します
- Docker が必要なのは runtime bundle の build 時だけで、bundle 配置後の実行時には不要です
- PHP / base image library / PECL extension の security update は operator が bundle を rebuild / 再配置して取り込みます
- 同梱 runtime には、SQLite / MySQL(MariaDB) / PostgreSQL の主要 DB 用 extension を標準で含めます
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- 同梱 module 一覧は `/options` または `data/php-fpm/binaries/<runtime_id>/php -m` で確認できます

## Vhost の流れ

管理対象 PHP-FPM アプリ定義は `/vhosts` で管理します。

`/vhosts` は build 済み runtime が 1 つ以上ある時だけ表示されます。

各 vhost の必須項目:

- `name`
- `hostname`
- `listen_port`
- `document_root`
- `generated_target`
- `runtime_id`

任意項目:

- `override_file_name`
  - 既定は `.htaccess`
- `try_files`
- rewrite rules
- access rules
- vhost 全体の basic auth
- access rule 単位の basic auth
- `php_value`
- `php_admin_value`

基本フロー:

1. `/vhosts` を開く
2. vhost を追加する
3. 必須項目を入力する
4. 必要なら rewrite / access / auth / ini を追加する
5. `Validate` を実行する
6. `Apply` を実行する
7. 直前の保存状態へ戻す必要がある時だけ `Rollback` を使う

validate/apply 時には override file の取り込み結果も更新されます。UI では次が確認できます。

- どの override file 名を見に行ったか
- file が見つかったか
- import した rewrite rule 数
- import した access rule 数
- basic auth を import したか
- 解析 / 取り込みメッセージ

## Linked Upstream と Route Binding

vhost を保存しただけではトラフィックは公開されません。

vhost 保存後の流れ:

- `/vhosts` が定義を `data/php-fpm/vhosts.json` へ保存
- runtime layer が `data/php-fpm/runtime/<runtime_id>/` に pool/config を生成
- `linked_upstream_name` で指定した configured upstream が effective proxy runtime では vhost-backed target になります
- `linked_upstream_name` は必須で、`Proxy Rules > Upstreams` に存在する upstream 名を指定する必要があります

実トラフィックの紐付けは `/proxy-rules` で行います。

- `routes[].action.upstream` に vhost の `linked_upstream_name` を指定する
- または `default_route.action.upstream` にその configured upstream 名を指定する

補足:

- `listen_port` は PHP-FPM の FastCGI listen port です
- `http://127.0.0.1:<listen_port>` のような HTTP upstream としては扱いません
- `generated_target` は内部互換 field として残ります。通常運用では route/default route から `linked_upstream_name` を参照してください
- `linked_upstream_name` が既存 configured upstream へ bind している場合、その direct upstream は Vhost を変更するまで `Proxy Rules > Upstreams` から削除できません

`Proxy Rules` はルーティングに集中させ、管理対象 PHP アプリの詳細は `/vhosts` で管理してください。`conf/proxy.json` へ raw の `fcgi://` や generated target を手で書く前提にはしません。

## Process Lifecycle

有効な `php-fpm` vhost があると、tukuyomi は `runtime_id` ごとに 1 つの `php-fpm` master process を supervise します。

- `php-fpm` vhost の追加・変更で runtime の起動または再起動が起こり得る
- 最後の参照 vhost を削除すると、その runtime は停止する
- runtime の状態は `/options` で確認できる

必要なら明示的に制御できます。

```bash
make php-fpm-up RUNTIME=php83
make php-fpm-reload RUNTIME=php83
make php-fpm-down RUNTIME=php83
```

参照が無い runtime bundle を削除する場合:

```bash
make php-fpm-remove RUNTIME=php83
```

runtime は設定に応じて専用の非 root user/group で起動します。

## テスト / Smoke

専用の確認コマンド:

```bash
make php-fpm-test
make php-fpm-smoke VER=8.3
```
