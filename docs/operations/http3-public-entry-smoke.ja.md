# tukuyomi HTTP/3 Public-Entry Smoke

この文書は、`tukuyomi` の built-in HTTPS + HTTP/3 を確認する専用 runtime smoke を定義したものです。

## コマンド

```bash
make http3-public-entry-smoke
```

## 何を検証するか

この smoke は、一時的なローカル runtime を次の条件で起動します。

- built binary
- built-in TLS を有効化
- built-in HTTP/3 を有効化
- `127.0.0.1` と `localhost` 用の一時 self-signed certificate
- routed traffic 用のローカル echo upstream

これにより、次を保証します。

- HTTPS listener が healthy になる
- HTTPS 応答に `Alt-Svc` が付く
- HTTPS 入口でも routed proxy traffic が通る
- `/tukuyomi-api/status` が `server_http3_enabled=true` と `server_http3_advertised=true` を返す
- live runtime に対して actual HTTP/3 request over UDP が成功する

## なぜ専用コマンドにしているか

この smoke は、次の前提があるため `make smoke`、`make deployment-smoke`、`make ci-local` には混ぜていません。

- TLS runtime の起動
- ローカルホスト上の UDP 利用可否
- 一時 self-signed certificate
- Go 製の HTTP/3 probe

release readiness や operator validation には有用ですが、通常の高速 smoke に入れるには環境依存が強いためです。

## 前提条件

- Go toolchain
- Docker は不要
- `curl`, `jq`, `python3`, `rsync`, `install`
- ローカル UDP loopback が使えること

## 推奨タイミング

次を変更した後に回します。

- `server.http3.*`
- built-in TLS listener の挙動
- `Alt-Svc` の扱い
- HTTPS/HTTP/3 listener pair に影響しうる startup 変更

また、`tukuyomi` を direct HTTPS/HTTP/3 entrypoint として案内する前の専用確認にも向いています。

## 関連ドキュメント

- 回帰マトリクス: [regression-matrix.ja.md](regression-matrix.ja.md)
- ベンチマークベースライン: [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
