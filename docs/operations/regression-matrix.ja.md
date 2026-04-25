# tukuyomi 回帰マトリクス

この文書は、既存のローカル検証コマンドが実際にどの運用観点を保証しているかを整理したものです。  
「どのコマンドを回せば十分か」を shell script を読まずに判断するために使います。

## コマンドの役割

| コマンド | 主目的 | 使いどころ |
| --- | --- | --- |
| `make smoke` | 通常 compose stack に対する高速な admin / routed-proxy 回帰 | 日常的な commit や config 変更前 |
| `make deployment-smoke` | `docs/build` に書いた binary/systemd と sample container 導線の再現 | `docs/build`、packaging、runtime layout を触った後 |
| `make release-binary-smoke` | 公開 tarball を build/extract し bundle local の Docker smoke を実行 | binary artifact を公開する前 |
| `make http3-public-entry-smoke` | built-in HTTPS + HTTP/3 listener を live runtime で確認 | TLS/HTTP/3 listener を変えた後、または direct H3 ingress 案内前 |
| `make smoke-extended` | `smoke` + `deployment-smoke` | runtime と deployment docs の両方を触った時、または release 前 |
| `make ci-local` | `check` + `smoke` | PR を出す前のローカル基準 |
| `make ci-local-extended` | `check` + `smoke-extended` | release / packaging 前の強めのローカル確認 |
| `make gotestwaf` | WAF 効き具合と false positive 回帰 | release 前、または CRS / request-inspection 変更後 |
| `make bench` / `make bench-proxy` | proxy transport の throughput / latency baseline | proxy transport tuning 変更後 |
| `make bench-waf` | WAF allow/block の throughput / latency baseline | WAF inspection、CRS、bypass、logging 変更後 |
| `make bench-full` | proxy と WAF の performance baseline | performance 影響があり得る release 前 |

## 保証マトリクス

benchmark target は、この決定的な保証マトリクスからは意図的に外しています。
人が読む performance artifact を生成し、任意の threshold で fail できますが、通常 CI gate ではありません。

凡例:

- `yes`: そのコマンドが直接見ている
- `partial`: 間接的には通るが、主目的ではない
- `no`: 通常自動化には入っていない

| 観点 | `make smoke` | `make deployment-smoke` | `make release-binary-smoke` | `make http3-public-entry-smoke` | `make smoke-extended` | `make ci-local` | `make ci-local-extended` | `make gotestwaf` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Admin login で signed session cookie が発行される | yes | yes | yes | no | yes | yes | yes | no |
| login 後の session status が取れる | yes | yes | yes | no | yes | yes | yes | no |
| logout で browser auth が無効化される | yes | yes | yes | no | yes | yes | yes | no |
| session ベースの変更系 admin API に CSRF token が付く | yes | yes | yes | no | yes | yes | yes | no |
| 埋め込み Admin UI に到達できる | yes | yes | no | no | yes | yes | yes | no |
| routed proxy の host/path/query/header rewrite | yes | yes | yes | yes | yes | yes | yes | no |
| client-facing gzip response compression | yes | yes | yes | no | yes | yes | yes | no |
| built-in HTTPS listener が manual certificate で起動する | no | no | no | yes | no | no | no | no |
| HTTPS 応答に `Alt-Svc` が付く | no | no | no | yes | no | no | no | no |
| actual HTTP/3 request over UDP が成功する | no | no | no | yes | no | no | no | no |
| release fixture に対する deterministic な WAF block | no | no | yes | no | no | no | no | yes |
| binary / systemd deployment guide の妥当性 | no | yes | no | no | yes | no | yes | no |
| container deployment guide の妥当性 | no | yes | no | no | yes | no | yes | no |
| release-binary runtime layout と writable path | no | no | yes | no | no | no | no | no |
| より広い attack suite に対する WAF 効き具合 | no | no | no | no | no | no | no | yes |

## 各コマンドが実際に見ているもの

### `make smoke`

通常 compose stack 向けの最速回帰です。以下を保証します。

- 埋め込み Admin UI が配信される
- login 後、browser が API key bootstrap から signed session cookie に切り替わる
- `/auth/session` と `/auth/logout` が正しく動く
- session ベースの admin mutation に `X-CSRF-Token` が付く
- routed proxy rule が validate / dry-run / apply でき、実トラフィックに反映される
- `Accept-Encoding: gzip` で client-facing gzip が返る

deployment guide、release-binary layout、GoTestWAF、HTTP/3 public entry は見ません。

### `make deployment-smoke`

`docs/build/` の手順を実際に踏みます。以下を保証します。

- staged binary/systemd 風 runtime tree で `tukuyomi` が起動できる
- staged binary で split public/admin listener mode も動く
- `docs/build/Dockerfile.example` の sample container image が起動できる
- packaging 後でも `make smoke` 相当の admin session / CSRF / routed proxy / gzip が通る
- split mode でも public listener に admin path が出ず、admin listener も arbitrary proxy traffic を受けない
- 想定している writable runtime path と audit log が作られる

deployment docs、startup layout、sample Dockerfile、package asset を触った後に使うコマンドです。

### `make smoke-extended`

release 寄りの組み合わせです。

- 通常 compose stack の smoke
- その上で deployment guide の binary / container 再現

runtime と operator docs の整合をまとめて見たい時に使います。

### `make release-binary-smoke`

公開 tarball 自体を確認する専用 top-level smoke です。以下を保証します。

- release tarball を build / extract できる
- 展開 bundle に runnable な `testenv/release-binary/` が入っている
- bundle local の setup / smoke script が動く
- 公開 artifact から admin session、routed proxy、gzip、deterministic WAF block が通る

binary asset を upload する前、または `[release]` に公開する前に使います。

### `make http3-public-entry-smoke`

built-in HTTPS + HTTP/3 listener を live runtime で確認する専用 smoke です。以下を保証します。

- `tukuyomi` が built-in TLS を有効にして起動できる
- HTTPS 応答に `Alt-Svc` が付く
- `/tukuyomi-api/status` が HTTP/3 listener を enabled / advertised として返す
- live runtime に対して actual HTTP/3 request over UDP が成功する
- HTTPS listener 入口でも routed proxy traffic が通る

TLS、UDP、一時 self-signed certificate 前提のため、通常の smoke ladder とは分けています。

### `make ci-local`

PR 前の最小ローカル基準です。

- `make check`
  - Go tests
  - UI tests
  - compose config validation
- その上で `make smoke`

「この状態で PR を出してよいか」の最小ラインです。

### `make ci-local-extended`

release / packaging 前の強めのローカル基準です。

- `make ci-local` の内容全部
- さらに `make smoke-extended` による deployment guide 再現

tag 打ちや packaging、deployment docs 変更前に使います。

### `make gotestwaf`

Admin UI や deployment guide は見ません。以下を保証します。

- 現行 WAF 設定が true-positive 攻撃をしきい値以上 block できる
- 必要なら false-positive / bypass のしきい値も維持できる
- `data/tmp/gotestwaf/` にレポートが出る

CRS、request-inspection、bypass、semantic、rate-limit の変更で enforcement に影響が出る時に使います。

### `make bench` / `make bench-proxy`

proxy transport benchmark です。
既存の proxy tuning preset を、設定した request 数と concurrency で測定し、`data/tmp/reports/proxy/` に Markdown / JSON artifact を出します。

upstream transport、buffering、compression、timeout、retry、response handling を触った後に使います。

### `make bench-waf`

WAF inspection benchmark です。
allow / block scenario が期待 status を返すことを probe してから、concurrency ごとの throughput / latency を測定します。

CRS selection、request inspection、WAF logging、bypass、WAF path に overhead を足し得る policy code を触った後に使います。
検知品質を見たい場合は別途 `make gotestwaf` を使います。

### `make bench-full`

proxy と WAF の benchmark target を順に実行します。
performance に敏感な release 前、または proxy transport と WAF inspection の両方をまたぐ変更で使います。

## 推奨 confidence ladder

| confidence level | コマンド |
| --- | --- |
| まず runtime sanity | `make smoke` |
| ローカル CI 基準 | `make ci-local` |
| deployment docs の妥当性確認 | `make deployment-smoke` |
| 公開 binary artifact の妥当性確認 | `make release-binary-smoke VERSION=vX.Y.Z` |
| WAF corpus を除く release readiness | `make ci-local-extended` |
| WAF corpus を含む release readiness | `make ci-local-extended && make gotestwaf` |
| proxy performance 比較 | `make bench-proxy` |
| WAF performance 比較 | `make bench-waf` |
| combined performance 比較 | `make bench-full` |
| direct HTTPS/HTTP/3 entry readiness | `make http3-public-entry-smoke` |
| 公開バイナリ release readiness | `make ci-local-extended && make gotestwaf && make release-binary-smoke VERSION=vX.Y.Z` |

## 通常検証でまだ埋まっていない gap

現時点で routine validation から漏れているもの:

- 任意の workstation 1 台からの完全な multi-arch public tarball smoke
  - `release-binary-smoke` は host-native を既定にしたが、非 native artifact は対応 hardware、release host、または emulation 方針が別途必要

## 関連ドキュメント

- binary/systemd deployment: [binary-deployment.ja.md](../build/binary-deployment.ja.md)
- container deployment: [container-deployment.ja.md](../build/container-deployment.ja.md)
- release-binary smoke: [release-binary-smoke.ja.md](release-binary-smoke.ja.md)
- HTTP/3 public-entry smoke: [http3-public-entry-smoke.ja.md](http3-public-entry-smoke.ja.md)
