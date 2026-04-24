[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM ランタイム / Vhost 運用

この文書は、`/options`、`/vhosts`、`/proxy-rules` を使う任意の PHP-FPM 運用をまとめたものです。

## 役割分担

- `/options`
  - build 済み runtime の一覧表示
  - materialization 状態 / process 状態の確認
- `/vhosts`
  - 管理対象 `php-fpm` アプリ定義の管理
  - host、FastCGI listen port、docroot、runtime、rewrite、access rule、basic auth、PHP ini override の管理
  - vhost 用の生成 backend / host route の管理
- `/proxy-rules`
  - vhost 以外の direct backend / backend pool / 明示 route 管理
  - PHP-FPM アプリの接続先設定は `/vhosts` 側へ移す
  - configured upstream の URL は `/vhosts` によって書き換えられません
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

既定パスは effective DB `app_config` の default で決まります。

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
- `runtime_id`

任意項目:

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

Vhost の動作は nginx と同じく集中設定です。document root 内の
`.htaccess` のようなファイルは、parse / import / watch / request 時再読込
の対象にしません。古い config に残っている `override_file_name` は移行用
として読み取るだけで、validate/apply 時に保存形から消えます。

## Upstream から Vhost への境界

PHP-FPM アプリを `Proxy Rules > Upstreams` に direct backend として置く運用はやめ、接続先設定は `/vhosts` に移します。

- `Proxy Rules > Upstreams`
  - 外部 HTTP/HTTPS backend など、vhost が所有しない direct backend 用
  - configured upstream URL は表示値どおりに扱われ、vhost によって別 target へ差し替えられません
- `/vhosts`
  - PHP-FPM/static app の host、docroot、runtime、FastCGI listen port を管理
  - 保存時に generated backend と generated host route を effective runtime へ公開

## 生成 Vhost Route

vhost を保存すると、その `hostname` 向けの通信は server-generated proxy state で公開されます。

vhost 保存後の流れ:

- `/vhosts` が定義を `data/php-fpm/vhosts.json` へ保存
- runtime layer が `data/php-fpm/runtime/<runtime_id>/` に pool/config を生成
- effective proxy runtime に `generated_target` 名の generated upstream が追加される
- effective proxy runtime に vhost hostname 用の generated host route `vhost:<name>` が追加される
- `Proxy Rules > Upstreams` の configured upstream URL は変更されない

route の優先順は operator の明示設定を先に見ます。

- explicit `routes[]`
- generated vhost host route
- generated site host fallback route
- `default_route`
- `upstreams[]`

補足:

- `listen_port` は PHP-FPM の FastCGI listen port です
- `http://127.0.0.1:<listen_port>` のような HTTP upstream としては扱いません
- `generated_target` は server-owned の generated backend alias / pool 名です。admin UI では operator input として表示しません
- 通常運用では `generated_target` を `Proxy Rules` に手入力しません。vhost hostname の publish は `/vhosts` の保存で完結します
- `default_route` は一致した vhost hostname を上書きしません
- 例外的に vhost routing を上書きしたい場合は、operator が explicit route を定義します

`Proxy Rules` は vhost 以外の routing / backend pool に集中させ、管理対象 PHP アプリの詳細は `/vhosts` で管理してください。`conf/proxy.json` へ raw の `fcgi://` や generated target を手で書く前提にはしません。

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
