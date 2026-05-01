[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM ランタイム / Runtime App 運用

この文書では、`/options`、`/runtime-apps`、`/proxy-rules` を使って PHP-FPM をオプション機能として運用する手順を説明します。

## 管理範囲

- `/options`
  - ビルド済みランタイムの一覧表示
  - 生成状態とプロセス状態の確認
- `/runtime-apps`
  - 管理対象 `php-fpm` アプリケーション定義の管理元
  - ランタイムの待ち受けホスト、FastCGI 待ち受けポート、ドキュメントルート、使用ランタイム、rewrite、アクセスルール、Basic 認証、PHP ini 上書き設定の管理
  - 生成バックエンドの管理
- `/proxy-rules`
  - Runtime Apps が管理しない直接接続バックエンド、バックエンドプール、明示的なルートの管理
  - PHP-FPM アプリケーションの接続先設定は `/runtime-apps` 側で管理する
  - 設定済み upstream URL は `/runtime-apps` によって書き換えられない
  - 生の `fcgi://` 転送指定を通常の運用入口にしない

## データ配置

PHP-FPM の運用データは `data/php-fpm/` 配下に集約されます。

- `inventory.json`
  - ランタイム一覧のローカルメタデータ
- `vhosts.json`
  - 管理対象 PHP-FPM Runtime App 定義
- `binaries/<runtime_id>/`
  - ビルド済みランタイムバンドル、`php-fpm` ラッパー、`php` CLI ラッパー、`runtime.json`、`modules.json`
- `runtime/<runtime_id>/`
  - 生成された `php-fpm.conf`、pool ファイル、pid/log ファイル、待ち受け用の成果物

汎用サンプルのドキュメントルートは `data/vhosts/samples/` 配下に配置します。

既定パスは、有効な DB 設定 `app_config` の既定値で決まります。

- `paths.php_runtime_inventory_file`
- `paths.vhost_config_file`

## ランタイムビルドと一覧更新

PHP ランタイムは、ビルド後に `/options` へ表示されます。

ランタイムバンドルをビルドする場合:

```bash
make php-fpm-build VER=8.3
```

バイナリ配置レイアウトへ配置する場合:

```bash
sudo make php-fpm-copy RUNTIME=php83
```

バイナリ配置レイアウトから安全に削除する場合:

```bash
sudo make php-fpm-prune RUNTIME=php83
```

対応バージョン:

- `8.3`
- `8.4`
- `8.5`

ビルド後は次の順に確認します。

1. `/options` を開く
2. ランタイムカードが表示されていることを確認する
3. 次を確認する
   - 表示名 / 検出バージョン
   - バイナリパス
   - CLI バイナリパス
   - 同梱モジュール一覧
   - 実行ユーザー / グループ
   - 生成済みターゲットの参照数
   - ランタイムプロセス状態
4. `Load` を実行し、一覧を更新する

`data/php-fpm/binaries/<runtime_id>/` を削除すると、そのランタイムは次回の読み込み時に `/options` から消えます。

補足:

- `php-fpm-copy` の既定配置先は `/opt/tukuyomi` です。別の配置先にする場合は、`DEST=/srv/tukuyomi` のように指定します
- `php-fpm-prune` も既定配置先は `/opt/tukuyomi` です。配置済み `vhosts.json` 内の Runtime App 参照と実行中 pid を確認してから削除します
- Docker が必要なのはランタイムバンドルのビルド時だけです。バンドル配置後の実行時には Docker に依存しません
- PHP、ベースイメージのライブラリ、PECL 拡張のセキュリティ更新は運用者が管理します。必要に応じてバンドルを再ビルドし、再配置します
- 同梱ランタイムには、SQLite / MySQL(MariaDB) / PostgreSQL の主要 DB 用拡張を標準で含めます
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- 同梱モジュール一覧は `/options` または `data/php-fpm/binaries/<runtime_id>/php -m` で確認できます

## Runtime App の運用手順

管理対象の PHP-FPM アプリケーション定義は `/runtime-apps` で管理します。

`/runtime-apps` は、ビルド済みランタイムが 1 つ以上検出されている場合にだけ表示されます。

各 Runtime App の必須項目は次のとおりです。

- `name`
- `hostname`
- `listen_port`
- `document_root`
- `runtime_id`

任意項目は次のとおりです。

- `try_files`
- rewrite ルール
- アクセスルール
- Runtime App 全体の Basic 認証
- アクセスルール単位の Basic 認証
- `php_value`
- `php_admin_value`

基本手順:

1. `/runtime-apps` を開く
2. Runtime App を追加する
3. 必須項目を入力する
4. 必要に応じて rewrite / access / auth / ini 設定を追加する
5. `Validate` を実行する
6. `Apply` を実行する
7. 直前の保存状態へ戻す必要がある場合だけ `Rollback` を使う

Runtime App の動作は、nginx と同じく集中管理型の設定で決まります。ドキュメントルート内の `.htaccess` のようなファイルは、解析、取り込み、監視、リクエスト時の再読み込みの対象にしません。古い設定に残っている `override_file_name` は移行用として読み取るだけで、`Validate` / `Apply` 時に保存形式から除去されます。

## Upstreams と Runtime Apps の境界

`tukuyomi` が管理する PHP-FPM アプリケーションは、`Proxy Rules > Upstreams` に直接接続バックエンドとして定義しません。接続先設定は `/runtime-apps` 側へ移します。

- `Proxy Rules > Upstreams`
  - 外部 HTTP/HTTPS サービスなど、Runtime Apps が管理しない直接接続バックエンド用
  - 設定済み upstream URL は表示どおりに扱われ、Runtime Apps によって別ターゲットへ差し替えられません
- `/runtime-apps`
  - PHP-FPM / 静的アプリのランタイム待ち受けホスト、ドキュメントルート、ランタイム、FastCGI 待ち受けポートを管理
  - 保存時に生成バックエンドを有効な実行環境へ公開

## 生成される Runtime App バックエンド

Runtime App を保存すると、設定した待ち受け先に対応する生成バックエンドが公開されます。JSON の `hostname` はランタイムが待ち受けるホスト / アドレスであり、VirtualHost 名や Host ヘッダーの照合条件ではありません。

Runtime App 保存後の処理は次のとおりです。

- `/runtime-apps` が定義を `data/php-fpm/vhosts.json` へ保存
- ランタイム層が `data/php-fpm/runtime/<runtime_id>/` に pool / config ファイルを生成
- 有効なプロキシ実行環境に、`generated_target` 名の生成 upstream が追加される
- `Proxy Rules > Upstreams` の設定済み upstream URL は変更されない
- Runtime App で公開するアプリケーションへトラフィックを流す場合、運用者が `Proxy Rules` のルートまたは default route から生成 upstream を選択する

ルートの優先順は `Proxy Rules` が管理します。

- explicit `routes[]`
- generated site host fallback route
- `default_route`
- `upstreams[]`

補足:

- `hostname` と `listen_port` は PHP-FPM の FastCGI 待ち受けターゲットです
- `http://<hostname>:<listen_port>` のような HTTP upstream としては扱いません
- `generated_target` はサーバー側が所有する生成バックエンドのエイリアス / pool 名です。管理 UI では運用者の入力項目として表示しません
- 通常運用では、`Proxy Rules` から生成 upstream ターゲットへルーティングします

PHP ランタイムの詳細は `/runtime-apps` で管理し、公開トラフィックの振り分けは `Proxy Rules` で管理します。生成 upstream ターゲットが待ち受け先を表すため、生の `fcgi://` URL を手書きする必要はありません。

## プロセスライフサイクル

有効な `php-fpm` Runtime App がある場合、tukuyomi は有効な `runtime_id` ごとに 1 つの `php-fpm` master process を監視します。

- `php-fpm` Runtime App の追加または変更により、対象ランタイムの起動または再起動が発生することがある
- 最後に参照している `php-fpm` Runtime App を削除すると、そのランタイムは停止する
- ランタイムの状態は `/options` で確認できる

必要なら明示的に制御できます。

```bash
make php-fpm-up RUNTIME=php83
make php-fpm-reload RUNTIME=php83
make php-fpm-down RUNTIME=php83
```

参照されていないランタイムバンドルを削除する場合:

```bash
make php-fpm-remove RUNTIME=php83
```

ランタイムは、設定に応じて専用の非 root ユーザー / グループで起動します。

## テスト / スモークテスト

専用の確認コマンド:

```bash
make php-fpm-test
make php-fpm-smoke VER=8.3
```
