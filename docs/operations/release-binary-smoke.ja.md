# tukuyomi Release-Binary Smoke

この文書は、公開 release tarball 向けの top-level smoke を定義したものです。

## コマンド

```bash
make release-binary-smoke VERSION=v0.8.1
```

任意の変数:

- `RELEASE_BINARY_SMOKE_ARCH=amd64|arm64`
- `RELEASE_BINARY_SMOKE_SKIP_BUILD=1`
- `RELEASE_BINARY_SMOKE_KEEP_EXTRACTED=1`
- `RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1`

## 何をするか

`make release-binary-smoke` は `make deployment-smoke` とは役割が違います。

- `deployment-smoke`
  - `docs/build/` の operator guide を検証する
  - repo local の staged runtime や sample container を使う
- `release-binary-smoke`
  - 公開 tarball を build する
  - その tarball を展開する
  - bundle 内の `testenv/release-binary/setup.sh` を実行する
  - bundle local の Docker smoke 環境を起動する
  - bundle local の `./smoke.sh` を実行する

つまり「公開配布物そのものをダウンロードした時に動くか」を確認するための top-level command です。

## 何を検証するか

展開した public bundle から次を確認します。

- release tarball に必要な runtime file が入っている
- bundle local の setup script が writable runtime directory を用意できる
- bundle local の Docker smoke 環境が build / 起動できる
- 展開 artifact から admin login / session status / logout invalidation が通る
- protected-host traffic が通る
- public artifact から client-facing gzip が動く
- public artifact から deterministic な WAF block が発火する

## 推奨の使い方

release readiness としては次の順を推奨します。

```bash
make ci-local-extended
make gotestwaf
make release-binary-smoke VERSION=v0.8.1
```

## Multi-arch policy

ローカルの release-binary smoke は、既定では host-native artifact を対象にします。

- `amd64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=amd64`
- `arm64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=arm64`
- 非 native artifact の検証は、対応 hardware、release host、またはその arch を担当する専用 CI で行う前提です

cross-arch のローカル実行をあえて試したい場合だけ、次を付けてください。

```bash
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1
```

この override は best-effort です。Docker、展開した binary、ローカル host が追加 emulation なしでその artifact を扱えることまでは保証しません。

## 関連ドキュメント

- 回帰マトリクス: [regression-matrix.ja.md](regression-matrix.ja.md)
- binary/systemd deployment: [binary-deployment.ja.md](../build/binary-deployment.ja.md)
