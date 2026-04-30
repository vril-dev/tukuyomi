# 第10章　PHP-FPM Runtime と Runtime Apps

第V部に入りました。本章からは、tukuyomi の **edge を通り抜けた先で動く
アプリケーション層** を扱います。最初は PHP-FPM Runtime と、それを束ねる
Runtime Apps の仕組みです。

tukuyomi の Runtime Apps は、

- `/options`: build 済みの **runtime（PHP / PSGI 等）** を管理する画面
- `/runtime-apps`: 各 runtime の **listen / docroot / rewrite / access** を
  管理する画面
- `/proxy-rules`: edge から Runtime App の generated backend に **どう
  routing するか** を管理する画面

の 3 つに役割が分かれています。本章では、PHP-FPM を例にこの 3 画面の関係と、
data の置き場、process lifecycle、Upstream / Runtime App の境界、を整理
します。

![Runtime Apps 画面](images/ui-samples/18-runtime-apps.png)

## 10.1　役割分担

3 画面の責務を一言で並べると次のようになります。

- **`/options`**
  - build 済み runtime の一覧表示
  - materialization 状態 / process 状態の確認
- **`/runtime-apps`**
  - 管理対象の **`php-fpm` アプリ定義** の管理
  - runtime listen host、FastCGI listen port、docroot、runtime、rewrite、
    access rule、basic auth、PHP ini override の管理
  - **generated backend** の管理
- **`/proxy-rules`**
  - Runtime Apps が所有しない **direct backend / backend pool / 明示 route**
    の管理
  - PHP-FPM アプリの接続先設定は `/runtime-apps` 側に移す
  - configured upstream の URL は `/runtime-apps` によって書き換えられない
  - **raw の `fcgi://` を通常の運用入口にしない**

つまり、PHP-FPM の listener と vhost の設定は **Runtime Apps だけ** が持ち、
Proxy Rules はそれを edge にどう露出させるかだけを扱う、という棲み分けです。

## 10.2　データ配置

PHP-FPM の運用データは `data/php-fpm/` に集約されています。

- `inventory.json`
  - runtime inventory のローカル metadata
- `vhosts.json`
  - 管理対象 PHP-FPM Runtime App 定義
- `binaries/<runtime_id>/`
  - build 済み runtime bundle
  - `php-fpm` wrapper、`php` CLI wrapper、`runtime.json`、`modules.json`
- `runtime/<runtime_id>/`
  - 生成された `php-fpm.conf`、pool ファイル、pid / log、listen 用の成果物

汎用のサンプル docroot は `data/vhosts/samples/` に置きます。

既定パスは effective DB `app_config` の default で決まります。

- `paths.php_runtime_inventory_file`
- `paths.vhost_config_file`

第3章で触れたように、これらの JSON は **空 DB 向けの seed / import / export
material** であり、import 後の正は DB です。

## 10.3　Runtime Build と Inventory の流れ

PHP runtime は **build されて初めて `/options` に出る** という前提があります。
runtime bundle を build する標準コマンドは次のとおりです。

```bash
make php-fpm-build VER=8.3
```

binary 配備レイアウトに stage する場合:

```bash
sudo make php-fpm-copy RUNTIME=php83
```

binary 配備レイアウトから安全に外す場合:

```bash
sudo make php-fpm-prune RUNTIME=php83
```

対応 version は次のとおりです。

- `8.3`
- `8.4`
- `8.5`

### 10.3.1　Build 後の確認手順

1. `/options` を開く
2. runtime card が表示されていることを確認する
3. card の中で次を確認する
   - 表示名 / 検出 version
   - binary path
   - CLI binary path
   - 同梱 module 一覧
   - 実行 user / group
   - materialized target の参照数
   - runtime process 状態
4. `Load` を実行して一覧を更新する

`data/php-fpm/binaries/<runtime_id>/` を削除すると、その runtime は **次回
load 時に `/options` から消えます**。

### 10.3.2　補足

- `php-fpm-copy` の既定配備先は `/opt/tukuyomi`。別 path は
  `DEST=/srv/tukuyomi` のように上書きする。
- `php-fpm-prune` も既定配備先は `/opt/tukuyomi`。staged `vhosts.json` 内の
  Runtime App 参照と実行中 pid を確認してから削除すること。
- **Docker が必要なのは runtime bundle の build 時だけ**。bundle 配置後の
  実行時には Docker は不要。
- PHP / base image library / PECL extension の security update は、operator
  が bundle を rebuild / 再配置して取り込む。
- 同梱 runtime には、SQLite / MySQL(MariaDB) / PostgreSQL の主要 DB 用
  extension を標準で含める:
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- 同梱 module 一覧は `/options`、または
  `data/php-fpm/binaries/<runtime_id>/php -m` で確認できる。

## 10.4　Runtime App の流れ

管理対象 PHP-FPM アプリ定義は `/runtime-apps` で管理します。
**`/runtime-apps` は、build 済み runtime が 1 つ以上ある時だけ表示** されます。

### 10.4.1　各 Runtime App の項目

必須項目:

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

### 10.4.2　基本フロー

1. `/runtime-apps` を開く
2. Runtime App を追加する
3. 必須項目を入力する
4. 必要なら rewrite / access / auth / ini を追加する
5. **`Validate`** を実行する
6. **`Apply`** を実行する
7. 直前の保存状態へ戻す必要があるときだけ **`Rollback`** を使う

Runtime App の動作は **nginx と同じく集中設定** です。document root 内の
`.htaccess` のような file は、parse / import / watch / request 時再読込の
対象にしません。古い config に残っている `override_file_name` は移行用と
して **読み取るだけ** で、validate / apply 時に保存形から消えます。

`.htaccess` 文化に慣れた人ほど最初に戸惑うところですが、tukuyomi の
Runtime Apps は **同じ vhost 設定を validate / apply / rollback で扱う** と
いう前提に立ちます。これは UI でレビューできる、誰が変えたかが分かる、
という運用上のメリットを得るための設計です。

## 10.5　Upstream から Runtime App への境界

PHP-FPM アプリを `Proxy Rules > Upstreams` に **direct backend として置く
運用はやめ**、接続先設定は `/runtime-apps` に移します。これが第V部最大の
ポイントです。

| 画面 | 何を持つか |
|---|---|
| `Proxy Rules > Upstreams` | 外部 HTTP/HTTPS backend など、Runtime Apps が **所有しない direct backend**。configured upstream URL は表示値どおり扱われ、Runtime Apps によって別 target に差し替えられない |
| `/runtime-apps` | PHP-FPM / static app の **runtime listen host、docroot、runtime、FastCGI listen port** を管理。保存時に generated backend を effective runtime に公開 |

つまり、

- **PHP-FPM の vhost を Upstreams に手書き** する → やめる
- **Runtime Apps で定義し、generated backend が edge に出てくるのを待つ**
  → こちらが正

という流れになります。

## 10.6　生成 Runtime App Backend

Runtime App を保存すると、設定した listener 用の **generated backend** が
公開されます。**JSON の `hostname` は runtime の待ち受け host / address
であり、VirtualHost 名や Host header match ではない** ので注意してください。

Runtime App 保存後の流れ:

1. `/runtime-apps` が定義を `data/php-fpm/vhosts.json` に保存
2. runtime layer が `data/php-fpm/runtime/<runtime_id>/` に pool / config を
   生成
3. effective proxy runtime に **`generated_target` 名の generated upstream**
   が追加される
4. `Proxy Rules > Upstreams` の configured upstream URL は **変更されない**
5. traffic を Runtime App-backed app へ流すときは、operator が `Proxy Rules`
   の route または default route から generated upstream を選択する

route の優先順は `Proxy Rules` が管理します（第5章を参照）。

- explicit `routes[]`
- generated site host fallback route
- `default_route`
- `upstreams[]`

補足:

- `hostname` と `listen_port` は **PHP-FPM の FastCGI listen target** です。
- `http://<hostname>:<listen_port>` のような HTTP upstream としては扱われ
  ません。
- `generated_target` は server-owned の generated backend alias / pool 名で、
  admin UI では **operator input として表示されません**。
- 通常運用では `Proxy Rules` から generated upstream target に routing します。

PHP runtime の詳細は `/runtime-apps` に置き、公開 traffic の選択は
`Proxy Rules` に置く ── という棲み分けにより、generated upstream target が
listener を表現してくれるため、**raw の `fcgi://` URL を手書きする必要は
ありません**。

## 10.7　Process Lifecycle

有効な `php-fpm` Runtime App があると、tukuyomi は `runtime_id` ごとに 1 つ
の **`php-fpm` master process を supervise** します。

- `php-fpm` Runtime App の **追加・変更** で、runtime の起動または再起動が
  起こり得ます。
- **最後の参照 Runtime App を削除する** と、その runtime は停止します。
- runtime の状態は `/options` で確認できます。

必要なら明示的に制御できます。

```bash
make php-fpm-up     RUNTIME=php83
make php-fpm-reload RUNTIME=php83
make php-fpm-down   RUNTIME=php83
```

参照が無い runtime bundle を削除するときは次を使います。

```bash
make php-fpm-remove RUNTIME=php83
```

runtime は設定に応じて、専用の **非 root user / group** で起動します。

## 10.8　テスト / Smoke

専用の確認コマンドが用意されています。

```bash
make php-fpm-test
make php-fpm-smoke VER=8.3
```

PHP-FPM 周りに変更を入れたあと、最低限これらが通るところまでローカルで
回してから本番反映するのが安全です。

## 10.9　ここまでの整理

- `/options` / `/runtime-apps` / `/proxy-rules` の **3 画面の責務** を
  混ぜない。
- PHP-FPM の vhost を Upstreams に手書きしない。**Runtime Apps が generated
  backend を公開する**。
- runtime bundle は `make php-fpm-build VER=...` で build し、`make
  php-fpm-copy` で deployment 配下へ stage する。
- `php-fpm` master process は **`runtime_id` 単位で supervise** される。
- `.htaccess` ではなく、UI 上で validate / apply / rollback する。

## 10.10　次章への橋渡し

次の第11章では、PHP-FPM と並ぶもう 1 つの runtime である **PSGI（Perl /
Starman 系）の Runtime Apps** を扱います。Movable Type のような既存資産を
持っている読者にとっては、ここが置き換え判断のポイントになります。
