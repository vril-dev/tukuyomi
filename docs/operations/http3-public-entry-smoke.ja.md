# tukuyomi HTTP/3 公開エントリポイント スモークテスト

この文書では、`tukuyomi` の内蔵 HTTPS / HTTP/3 を確認するためのスモークテストを説明します。
公開エントリポイントとして `tukuyomi` 自身で TLS と HTTP/3 を終端する構成が、実行時に正しく動くかを確認するための専用コマンドです。

## コマンド

```bash
make http3-public-entry-smoke
```

## 確認内容

このスモークテストは、一時的なローカル環境で `tukuyomi` を次の条件で起動します。

- ビルド済みのバイナリを使用する
- 内蔵 TLS を有効にする
- 内蔵 HTTP/3 を有効にする
- `127.0.0.1` と `localhost` 用の一時自己署名証明書を使う
- ルーティング先として応答確認用のローカル upstream を立てる

この状態で、次を確認します。

- HTTPS listener が正常に起動する
- HTTPS 応答で `Alt-Svc` が広告される
- HTTPS 入口からのプロキシ通信が upstream まで到達する
- `/tukuyomi-api/status` が `server_http3_enabled=true` と `server_http3_advertised=true` を返す
- 稼働中のプロセスに対して、UDP 上の実際の HTTP/3 リクエストが成功する

## 専用コマンドにしている理由

このスモークテストは、`make smoke`、`make deployment-smoke`、`make ci-local` には含めていません。
通常の高速 smoke に混ぜるには、次のような環境依存が強いためです。

- TLS を有効にしたプロセスの起動が必要
- ローカルホスト上で UDP が使える必要がある
- 一時自己署名証明書を生成して使う
- Go 製の HTTP/3 probe を使う

そのため、このコマンドはリリース前確認や運用者による検証には有用ですが、通常の高速スモークテストからは分離しています。

## 前提条件

- Go ツールチェーン
- Docker は不要
- `curl`, `jq`, `python3`, `rsync`, `install`
- ローカル UDP loopback が使えること

## 実行するタイミング

次を変更した後に実行します。

- `server.http3.*`
- 内蔵 TLS listener の挙動
- `Alt-Svc` の扱い
- HTTPS / HTTP/3 listener に影響する起動処理

また、`tukuyomi` を HTTPS / HTTP/3 の直接公開エントリポイントとして案内する前の確認にも向いています。

## 関連ドキュメント

- 回帰マトリクス: [regression-matrix.ja.md](regression-matrix.ja.md)
- ベンチマークベースライン: [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
