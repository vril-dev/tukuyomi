[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM ランタイム / Runtime App 運用

この文書は、`/options`、`/runtime-apps`、`/proxy-rules` を使う任意の PHP-FPM 運用をまとめたものです。

## 役割分担

- `/options`
  - build 済み runtime の一覧表示
  - materialization 状態 / process 状態の確認
- `/runtime-apps`
  - 管理対象 `php-fpm` アプリ定義の管理
  - runtime listen host、FastCGI listen port、docroot、runtime、rewrite、access rule、basic auth、PHP ini override の管理
  - generated backend の管理
- `/proxy-rules`
  - Runtime Apps が所有しない direct backend / backend pool / 明示 route 管理
  - PHP-FPM アプリの接続先設定は `/runtime-apps` 側へ移す
  - configured upstream の URL は `/runtime-apps` によって書き換えられません
  - raw の `fcgi://` を通常の運用入口にはしない

## データ配置

PHP-FPM の運用データは `data/php-fpm/` に集約されています。

- `inventory.json`
  - runtime inventory のローカル metadata
- `vhosts.json`
  - 管理対象 PHP-FPM Runtime App 定義
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
- `php-fpm-prune` も既定配備先は `/opt/tukuyomi` です。staged `vhosts.json` 内の Runtime App 参照と実行中 pid を確認してから削除します
- Docker が必要なのは runtime bundle の build 時だけで、bundle 配置後の実行時には不要です
- PHP / base image library / PECL extension の security update は operator が bundle を rebuild / 再配置して取り込みます
- 同梱 runtime には、SQLite / MySQL(MariaDB) / PostgreSQL の主要 DB 用 extension を標準で含めます
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- 同梱 module 一覧は `/options` または `data/php-fpm/binaries/<runtime_id>/php -m` で確認できます

## Runtime App の流れ

管理対象 PHP-FPM アプリ定義は `/runtime-apps` で管理します。

`/runtime-apps` は build 済み runtime が 1 つ以上ある時だけ表示されます。

各 Runtime App の必須項目:

- `name`
- `hostname`
- `listen_port`
- `document_root`
- `runtime_id`

任意項目:

- `try_files`
- rewrite rules
- access rules
- Runtime App 全体の basic auth
- access rule 単位の basic auth
- `php_value`
- `php_admin_value`

基本フロー:

1. `/runtime-apps` を開く
2. Runtime App を追加する
3. 必須項目を入力する
4. 必要なら rewrite / access / auth / ini を追加する
5. `Validate` を実行する
6. `Apply` を実行する
7. 直前の保存状態へ戻す必要がある時だけ `Rollback` を使う

Runtime App の動作は nginx と同じく集中設定です。document root 内の
`.htaccess` のようなファイルは、parse / import / watch / request 時再読込
の対象にしません。古い config に残っている `override_file_name` は移行用
として読み取るだけで、validate/apply 時に保存形から消えます。

## Upstream から Runtime App への境界

PHP-FPM アプリを `Proxy Rules > Upstreams` に direct backend として置く運用はやめ、接続先設定は `/runtime-apps` に移します。

- `Proxy Rules > Upstreams`
  - 外部 HTTP/HTTPS backend など、Runtime Apps が所有しない direct backend 用
  - configured upstream URL は表示値どおりに扱われ、Runtime Apps によって別 target へ差し替えられません
- `/runtime-apps`
  - PHP-FPM/static app の runtime listen host、docroot、runtime、FastCGI listen port を管理
  - 保存時に generated backend を effective runtime へ公開

## 生成 Runtime App Backend

Runtime App を保存すると、設定した listener 用の generated backend が公開されます。
JSON の `hostname` は runtime の待ち受け host/address であり、VirtualHost 名や
Host header match ではありません。

Runtime App 保存後の流れ:

- `/runtime-apps` が定義を `data/php-fpm/vhosts.json` へ保存
- runtime layer が `data/php-fpm/runtime/<runtime_id>/` に pool/config を生成
- effective proxy runtime に `generated_target` 名の generated upstream が追加される
- `Proxy Rules > Upstreams` の configured upstream URL は変更されない
- traffic を Runtime App-backed app へ流す時は、operator が `Proxy Rules` の route または default route から generated upstream を選択する

route の優先順は `Proxy Rules` が管理します。

- explicit `routes[]`
- generated site host fallback route
- `default_route`
- `upstreams[]`

補足:

- `hostname` と `listen_port` は PHP-FPM の FastCGI listen target です
- `http://<hostname>:<listen_port>` のような HTTP upstream としては扱いません
- `generated_target` は server-owned の generated backend alias / pool 名です。admin UI では operator input として表示しません
- 通常運用では `Proxy Rules` から generated upstream target へ routing します

PHP runtime の詳細は `/runtime-apps` に置き、公開 traffic の選択は `Proxy Rules` に置きます。
generated upstream target が listener を表すため、raw の `fcgi://` URL を手書きする必要はありません。

## Process Lifecycle

有効な `php-fpm` Runtime App があると、tukuyomi は `runtime_id` ごとに 1 つの `php-fpm` master process を supervise します。

- `php-fpm` Runtime App の追加・変更で runtime の起動または再起動が起こり得る
- 最後の参照 Runtime App を削除すると、その runtime は停止する
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
