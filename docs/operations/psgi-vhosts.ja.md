[English](psgi-vhosts.md) | [日本語](psgi-vhosts.ja.md)

# PSGI Runtime と Runtime Apps

PSGI support は Movable Type などの Perl PSGI app を、別 reverse proxy stack なしで tukuyomi 管理下に置くための機能です。

## Runtime Model

- `make psgi-build VER=5.38` で `data/psgi/binaries/perl538` に Perl/Starman runtime bundle を作ります。
- runtime inventory は `/options` に表示され、DB では `psgi_runtime_inventory` として保持されます。
- PSGI Runtime App は runtime を 1 つ選び、`app_root`、`psgi_file`、静的 `document_root`、runtime listen `hostname` / `listen_port`、worker 数、max requests、`extlib` 利用、環境変数を定義します。
- tukuyomi は PSGI Runtime App ごとに Starman process を 1 つ supervise します。複数 pool を 1 master にまとめる PHP-FPM とは意図的に分けています。

## Movable Type の形

Movable Type では以下を使います。

- `app_root`: 展開した Movable Type application directory
- `psgi_file`: `mt.psgi`
- `document_root`: public static directory。通常は `mt-static`
- `try_files`: `$uri`, `$uri/`, `@psgi`
- `include_extlib`: application 側に `extlib/` がある場合は有効

静的 file は `document_root` から直接返し、dynamic request は `@psgi` sentinel で Starman へ流します。
`mt-config.cgi`、`CGIPath`、database DSN、plugin 設定などの Movable Type application config は tukuyomi では生成しません。tukuyomi は PSGI Runtime App 保存前に runtime file/path を検査し、application 固有の config error は PSGI process 起動時のエラーとして表示します。

公開 traffic は `Proxy Rules` から generated PSGI upstream target へ routing します。
Runtime App の `hostname` は Starman の待ち受け host/address であり、公開 VirtualHost 名ではありません。

## Process Controls

PSGI Runtime App を保存して materialize した後は以下を使えます。

```sh
make psgi-up RUNTIME_APP=mt-site
make psgi-reload RUNTIME_APP=mt-site
make psgi-down RUNTIME_APP=mt-site
```

同じ操作は `/options` の PSGI Processes からも実行できます。

## Build

```sh
make psgi-build VER=5.38
# または
make psgi-build RUNTIME=perl538
```

現在の alias は `perl536`、`perl538`、`perl540` です。

build で以下を作ります。

- `data/psgi/binaries/<runtime_id>/perl`
- `data/psgi/binaries/<runtime_id>/starman`
- `data/psgi/binaries/<runtime_id>/runtime.json`
- `data/psgi/binaries/<runtime_id>/modules.json`

bundled runtime には Movable Type 向けの主要 optional module を含めます。
PSGI/Plack、MySQL/SQLite DB driver、画像 driver の `GD` / `Imager`、
archive/XML helper、Plack 経由の XML-RPC、SMTP TLS/SASL、cache helper、
OpenID 時代の compatibility module、`IPC::Run` が対象です。
ただし `mt-config.cgi` は Movable Type application 側の責務です。画像処理を
使う場合は `ImageDriver GD` または `ImageDriver Imager` を設定してください。

## Notes

- PSGI listener は `hostname` と `listen_port` の組で識別します。
- Starman worker は Runtime App ごとに memory を使います。Movable Type では traffic が必要とするまで worker 数は小さく明示してください。
