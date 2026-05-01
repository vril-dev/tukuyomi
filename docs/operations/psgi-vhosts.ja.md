[English](psgi-vhosts.md) | [日本語](psgi-vhosts.ja.md)

# PSGI ランタイムと Runtime Apps

PSGI 対応は、Movable Type などの Perl PSGI アプリケーションを、別のリバースプロキシ構成を用意せずに `tukuyomi` の管理下へ置くための機能です。

## ランタイムモデル

- `make psgi-build VER=5.38` は、`data/psgi/binaries/perl538` に Perl/Starman ランタイムバンドルを作成します。
- ランタイム一覧は `/options` に表示され、DB では `psgi_runtime_inventory` として保持されます。
- PSGI Runtime App はランタイムを 1 つ選択し、`app_root`、`psgi_file`、静的 `document_root`、ランタイムの待ち受け `hostname` / `listen_port`、worker 数、max requests、`extlib` 利用有無、環境変数を定義します。
- `tukuyomi` は PSGI Runtime App ごとに Starman process を 1 つ監視します。複数 pool を 1 つの master にまとめられる PHP-FPM とは、意図的に別のモデルにしています。

## Movable Type の構成

Movable Type では次の設定を使います。

- `app_root`: 展開した Movable Type アプリケーションディレクトリ
- `psgi_file`: `mt.psgi`
- `document_root`: 公開用の静的ファイルディレクトリ。通常は `mt-static`
- `try_files`: `$uri`, `$uri/`, `@psgi`
- `include_extlib`: アプリケーション側に `extlib/` がある場合に有効化

静的ファイルは `document_root` から直接返し、動的リクエストは `@psgi` を目印に Starman へ流します。
`mt-config.cgi`、`CGIPath`、database DSN、plugin 設定などの Movable Type アプリケーション設定は、`tukuyomi` では生成しません。`tukuyomi` は PSGI Runtime App の保存前にランタイムファイルとパスを検査しますが、アプリケーション固有の設定エラーは PSGI プロセスの起動時エラーとして表示します。

公開トラフィックは、`Proxy Rules` から生成された PSGI upstream ターゲットへルーティングします。
Runtime App の `hostname` は Starman の待ち受けホスト / アドレスであり、公開サイトのホスト名ではありません。

## プロセス制御

PSGI Runtime App を保存し、生成が完了した後は次のコマンドを使えます。

```sh
make psgi-up RUNTIME_APP=mt-site
make psgi-reload RUNTIME_APP=mt-site
make psgi-down RUNTIME_APP=mt-site
```

同じ操作は、`/options` の PSGI Processes からも実行できます。

## ビルド

```sh
make psgi-build VER=5.38
# または
make psgi-build RUNTIME=perl538
```

現在対応している alias は、`perl536`、`perl538`、`perl540` です。

ビルドでは、次のファイルを作成します。

- `data/psgi/binaries/<runtime_id>/perl`
- `data/psgi/binaries/<runtime_id>/starman`
- `data/psgi/binaries/<runtime_id>/runtime.json`
- `data/psgi/binaries/<runtime_id>/modules.json`

同梱ランタイムには、Movable Type 向けの主要な任意モジュールを含めます。
対象は PSGI/Plack、MySQL/SQLite DB ドライバー、画像ドライバーの `GD` / `Imager`、
archive/XML helper、Plack 経由の XML-RPC、SMTP TLS/SASL、cache helper、
OpenID 時代の互換モジュール、`IPC::Run` です。
ただし、`mt-config.cgi` は Movable Type アプリケーション側の責務です。画像処理を使う場合は、`ImageDriver GD` または `ImageDriver Imager` を設定してください。

## 補足

- PSGI リスナーは、`hostname` と `listen_port` の組で識別します。
- Starman worker は Runtime App ごとにメモリを消費します。Movable Type では、トラフィック量が必要とするまでは worker 数を小さく明示してください。
