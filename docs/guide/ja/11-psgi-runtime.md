# 第11章　PSGI Runtime（Movable Type など）

第10章の PHP-FPM に続いて、本章では **PSGI（Perl Web Server Gateway
Interface）の Runtime Apps** を扱います。tukuyomi の PSGI support は、
Movable Type などの Perl PSGI app を **別 reverse proxy stack なしで
tukuyomi 管理下に置く** ための機能です。

PHP-FPM 章で見た 3 画面（`/options`、`/runtime-apps`、`/proxy-rules`）の
枠組みは、PSGI でも基本同じです。差分にあたる部分を中心に押さえていきます。

## 11.1　Runtime Model

PSGI runtime のモデルは次のようにシンプルです。

- `make psgi-build VER=5.38` で **`data/psgi/binaries/perl538` に
  Perl / Starman runtime bundle** を作る。
- runtime inventory は `/options` に表示され、DB では
  `psgi_runtime_inventory` として保持される。
- PSGI Runtime App は **runtime を 1 つ選ぶ** 形で構成し、次を定義する。
  - `app_root`
  - `psgi_file`
  - **静的 `document_root`**
  - runtime listen `hostname` / `listen_port`
  - **worker 数**、**max requests**
  - **`extlib` 利用**
  - **環境変数**
- tukuyomi は PSGI Runtime App ごとに **Starman process を 1 つ supervise**
  する。**複数 pool を 1 master にまとめる PHP-FPM とは意図的に分けている**。

PHP-FPM が `runtime_id` 単位で master を持ち、その下に複数 vhost の pool を
持つのに対し、PSGI は **Runtime App = Starman process** の 1:1 対応です。
これは Perl/Starman 系の memory 利用が大きいことと、worker tuning を vhost
ごとに行いたいことを考えての設計差分です。

## 11.2　Movable Type の形

Movable Type を tukuyomi の PSGI Runtime App に乗せるときの典型形は次の
ようになります。

- `app_root`: 展開した Movable Type application directory
- `psgi_file`: `mt.psgi`
- `document_root`: public static directory。通常は `mt-static`
- `try_files`: `$uri`、`$uri/`、`@psgi`
- `include_extlib`: application 側に `extlib/` がある場合は有効

`try_files` は静的 file → `@psgi` sentinel という順で評価します。**静的 file
は `document_root` から直接返し**、dynamic request は `@psgi` sentinel で
**Starman に流す**、という流れです。これにより、画像や CSS のような静的
asset の handling を edge 側で完結させて、Starman の負荷を application 処理
に集中させられます。

ここで踏まえておきたいのは、tukuyomi が Movable Type の **application 設定
までは管理しない**、という点です。

- `mt-config.cgi`
- `CGIPath`
- database DSN
- plugin 設定

これらは Movable Type application 側の責務であり、tukuyomi は生成しません。
tukuyomi の役割は、

- PSGI Runtime App 保存前に **runtime file / path を検査**
- application 固有の config error は **PSGI process 起動時のエラーとして
  表示**

までです。`mt-config.cgi` のミスは Starman の起動時に出るログで追います。

公開 traffic の routing は、PHP-FPM と同じ形になります。すなわち、
**`Proxy Rules` から generated PSGI upstream target へ routing** します。
Runtime App の `hostname` は **Starman の待ち受け host / address** であり、
公開 VirtualHost 名ではない、という点も PHP-FPM 章と共通です。

## 11.3　Process Controls

PSGI Runtime App を保存して materialize したあとは、次のコマンドで
process を制御できます。

```bash
make psgi-up     RUNTIME_APP=mt-site
make psgi-reload RUNTIME_APP=mt-site
make psgi-down   RUNTIME_APP=mt-site
```

同じ操作は `/options` の **PSGI Processes** セクションからも実行できます。

PHP-FPM では `make php-fpm-up RUNTIME=php83` のように **runtime（言語版）
単位** で制御するのに対し、PSGI では **Runtime App 単位** で制御するのが
違いです。Movable Type 1 サイトに対して 1 Starman process が紐づくので、
複数サイトを同居させる場合はそれぞれの `RUNTIME_APP=...` で個別に動かします。

## 11.4　Build

PSGI runtime bundle の build コマンドは次のとおりです。

```bash
make psgi-build VER=5.38
# または
make psgi-build RUNTIME=perl538
```

現在の alias は次のとおりです。

- `perl536`
- `perl538`
- `perl540`

build によって、次の成果物が `data/psgi/binaries/<runtime_id>/` 配下に作られ
ます。

- `perl`
- `starman`
- `runtime.json`
- `modules.json`

### 11.4.1　bundled runtime に含まれる主要モジュール

bundled runtime には、Movable Type 向けの主要 optional module を含めて
います。

- **PSGI / Plack** 関連
- **MySQL / SQLite DB driver**
- **画像 driver**: `GD` / `Imager`
- **archive / XML helper**
- **Plack 経由の XML-RPC**
- **SMTP TLS / SASL**
- **cache helper**
- **OpenID 時代の compatibility module**
- **`IPC::Run`**

ただし、繰り返しになりますが **`mt-config.cgi` は Movable Type application
側の責務** です。画像処理を使う場合は、Movable Type 側で `ImageDriver GD`
または `ImageDriver Imager` を設定してください。

## 11.5　補足

- PSGI listener は **`hostname` と `listen_port` の組で識別** します。
- Starman worker は **Runtime App ごとに memory を使います**。Movable Type
  では traffic が必要とするまで、worker 数を **小さく明示** してください。
- PHP-FPM と同じく、`generated_target` は server-owned であり、`Proxy Rules`
  からは generated upstream として参照する形になります。`fcgi://` のように
  raw な protocol URL を手書きする必要はありません。

## 11.6　ここまでの整理

- PSGI runtime は Movable Type のような Perl PSGI app を **tukuyomi 管理下に
  置く** ための機構。
- runtime bundle は `make psgi-build VER=...`（または `RUNTIME=perl538`）で
  build。
- **Runtime App = Starman process の 1:1**。worker 数 / max requests は
  vhost 単位で tune する。
- 静的は `document_root` から、dynamic は `@psgi` sentinel で Starman へ。
- `mt-config.cgi` などの application 設定は **tukuyomi の管理外**。

## 11.7　次章への橋渡し

次の第12章では、Runtime Apps と並んで重要な役割を担う **Scheduled Tasks**
を扱います。PHP CLI の cron-style task を tukuyomi 上で構造化して持ち、
binary deployment / container deployment それぞれにふさわしい配備パターン
を選ぶ、というのが第12章の主題です。
