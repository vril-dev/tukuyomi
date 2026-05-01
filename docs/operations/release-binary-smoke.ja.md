# tukuyomi 公開バイナリのスモークテスト

この文書では、公開用のリリース tarball を対象にしたスモークテストを説明します。
配布物そのものを展開し、同梱された確認環境で起動できるかを確認するための手順です。

## コマンド

```bash
make release-binary-smoke VERSION=v0.8.1
```

必要に応じて指定する変数:

- `RELEASE_BINARY_SMOKE_ARCH=amd64|arm64`
- `RELEASE_BINARY_SMOKE_SKIP_BUILD=1`
- `RELEASE_BINARY_SMOKE_KEEP_EXTRACTED=1`
- `RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1`

## 実行内容

`make release-binary-smoke` は、`make deployment-smoke` とは確認する対象が異なります。

- `deployment-smoke`
  - `docs/build/` 配下の運用手順を検証する
  - リポジトリ内で一時配置したランタイムやサンプルコンテナを使う
- `release-binary-smoke`
  - 公開用 tarball を作成する
  - 作成した tarball を展開する
  - 展開した配布物内の `testenv/release-binary/setup.sh` を実行する
  - 展開した配布物に含まれる Docker smoke 環境を起動する
  - 展開した配布物内の `./smoke.sh` を実行する

つまり、利用者が公開配布物を入手した時に、その配布物だけで起動確認できるかを見るためのコマンドです。

## 確認内容

展開した公開配布物から次を確認します。

- リリース tarball に必要なランタイムファイルが含まれている
- 同梱のセットアップスクリプトが、書き込み可能な実行時ディレクトリを用意できる
- 同梱の Docker smoke 環境を build / 起動できる
- 展開した配布物から、管理ログイン、セッション状態確認、ログアウトによるセッション無効化が通る
- protected-host を経由する routed proxy の通信が通る
- 公開成果物からクライアント向け gzip 圧縮が動く
- 公開成果物から、固定 fixture に対する WAF block が再現する

## 推奨の使い方

リリース前確認では、次の順に実行することを推奨します。

```bash
make ci-local-extended
make gotestwaf
make release-binary-smoke VERSION=v0.8.1
```

## マルチアーキテクチャ方針

ローカルの release-binary smoke は、既定では実行ホストと同じアーキテクチャの成果物を対象にします。

- `amd64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=amd64`
- `arm64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=arm64`
- 非 native 成果物の検証は、対応 hardware、release host、またはその arch を担当する専用 CI で行う前提です

ローカルで別アーキテクチャの成果物をあえて試す場合だけ、次を指定してください。

```bash
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1
```

この指定は best-effort です。Docker、展開した binary、ローカル host が、追加の emulation 設定なしでその成果物を扱えることまでは保証しません。

## 関連ドキュメント

- 回帰テストマトリクス: [regression-matrix.ja.md](regression-matrix.ja.md)
- binary/systemd deployment: [binary-deployment.ja.md](../build/binary-deployment.ja.md)
