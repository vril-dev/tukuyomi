# 第18章　ベンチマークと回帰マトリクス

第VII部に入りました。本章では、tukuyomi が標準で持っている **ベンチマーク
と回帰確認の枠組み** を整理します。

具体的には、

- `make bench-proxy` / `make bench-waf` / `make bench-full` の役割と入力
- `make smoke` 系の **回帰マトリクス**（何を保証しているか）
- どの順番で叩けば「どこまで安心できるか」が決まる **confidence ladder**
- 公開 release tarball を確認する `make release-binary-smoke`

までを扱います。本書の前章までに何度も「`make bench` で測ってください」と
書いてきた、その本体です。

## 18.1　ベンチマーク ── 何のためのコマンドか

tukuyomi のベンチマークは、**ローカル環境で proxy / WAF の挙動を比較する
ための baseline** を作るために用意されています。

| コマンド | 目的 | 出力 |
|---|---|---|
| `make bench` | `make bench-proxy` の後方互換 alias | proxy tuning artifact |
| `make bench-proxy` | proxy transport preset の比較 | `proxy-benchmark-summary.*` |
| `make bench-waf` | WAF allow / block inspection scenario の比較 | `waf-benchmark-summary.*` |
| `make bench-full` | proxy と WAF benchmark を順に実行 | 両方の artifact |

これは「本番 capacity の厳密な再現」ではありません。あくまでローカルの
**制御された baseline** です。それでも、

- 同じマシンで preset 同士を比較する
- branch 間で同じ条件の artifact を並べて比較する
- release 前に大きな regression がないか確認する

という用途には十分機能します。

### 18.1.1　`make bench-proxy` がやること

`make bench` と `make bench-proxy` は `./scripts/benchmark_proxy_tuning.sh`
の wrapper で、次を自動実行します。

- 既定では benchmark 専用の **一時 config / SQLite DB** を準備する
- ローカルの `tukuyomi` compose stack を起動する
- `scripts/benchmark_upstream.go` の **並行処理対応 Go upstream mock** を
  一時起動する
- `/tukuyomi-api/proxy-rules` 経由で proxy preset を適用する
- `BENCH_PROXY_MODE=proxy-only` を明示しない限り、**WAF inspection を含む
  通常の proxy listener path** を計測する
- warm-up 実行
- 対象 path に対して **ApacheBench（`ab`）** で負荷
- `BENCH_PROFILE=1` のときだけ **CPU / heap / allocation profile を取得**
- 終了時に proxy rules、rate-limit rules、benchmark 中に無効化した
  request-security guard、proxy-only WAF bypass を **元へ戻す**

upstream mock を Python `http.server` ではなく Go server にしているのは、
**高 concurrency で直列化上限に引っ張られないため** です。

### 18.1.2　`make bench-waf` がやること

`make bench-waf` は `./scripts/benchmark_waf.sh` の wrapper で、proxy 側と
似た準備を行ったあと、WAF scenario を計測します。既定の scenario は次の
2 つです。

| Scenario | 期待 status | 目的 |
|---|---:|---|
| `allow` | `200` | WAF inspection を通過すべき benign request |
| `block-xss` | `403` | CRS で block されるべき encoded XSS query |

各 scenario を **計測前に probe** して期待 status が出ることを確認してから、
ApacheBench で負荷をかけます。

`make gotestwaf` の代替ではありません。**広い攻撃 corpus と false-positive
回帰は、引き続き GoTestWAF を正にします**。本コマンドは「WAF inspection を
含めた path で throughput / latency が劣化していないか」を見るためのもの
です。

### 18.1.3　いつ回すか

推奨タイミング:

- proxy transport 周りを変更した後（`force_http2` / buffering / timeout /
  response compression）
- runtime path の変更で throughput / latency に影響がありそうな release 前
- 同一マシン上で preset 同士を比較したい時

### 18.1.4　標準コマンド

シンプルな確認:

```bash
make bench
```

proxy transport と WAF inspection の両方に影響しうる変更での標準例:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench-full
```

`BENCH_PROXY_MODE=current`（既定）は **production に近い proxy + WAF
inspection path** です。proxy hot path 単独の profile を見たい時だけ
`BENCH_PROXY_MODE=proxy-only` を使います。

### 18.1.5　前提条件

- Docker と Docker Compose が利用可能
- ローカルに `ab` が入っている
- `curl`、`jq`、Go が使える
- 比較可能な程度に **マシン負荷が落ち着いている**

branch 間比較をする場合は、**同じホスト・同じ concurrency・同じ request 数**
で回してください。

### 18.1.6　主な入力パラメータ

| 変数 | 既定値 | 意味 |
|---|---|---|
| `BENCH_REQUESTS` | Makefile 経由は `120`、script 直接実行は `600` | preset / concurrency ごとの計測 request 数。判断用 run は `>=600` |
| `WARMUP_REQUESTS` | Makefile 経由は `20`、script 直接実行は `100` | 計測前の warm-up request 数 |
| `BENCH_CONCURRENCY` | `1,10,50` | カンマ区切りの concurrency 一覧 |
| `BENCH_PATH` | `/bench` | `tukuyomi` 越しに叩く path |
| `BENCH_TIMEOUT_SEC` | `30` | ApacheBench timeout |
| `BENCH_DISABLE_RATE_LIMIT` | `1` | 計測中だけ rate-limit rules を一時無効化するか |
| `BENCH_DISABLE_REQUEST_GUARDS` | `1` | 計測中だけ bot-defense / semantic / IP-reputation を一時無効化するか |
| `BENCH_ACCESS_LOG_MODE` | `full` | proxy rules の `access_log_mode` |
| `BENCH_CLIENT_KEEPALIVE` | `1` | `1` なら ApacheBench に `-k` を渡す |
| `BENCH_PROXY_MODE` | `current` | `current` は WAF inspection を含む。`proxy-only` は `BENCH_PATH` だけ一時的に WAF inspection を bypass |
| `BENCH_PROXY_ENGINE` | `tukuyomi_proxy` | benchmark config の `proxy.engine.mode` を一時的に書き換える（対応値は `tukuyomi_proxy` のみ） |
| `BENCH_ISOLATED_RUNTIME` | `1` | `data/tmp/bench` 配下の一時 config / DB を使う |
| `BENCH_PROFILE` | `0` | `1` で pprof CPU / heap / allocation artifact を取得 |
| `BENCH_MAX_FAIL_RATE_PCT` | 未設定 | 行単位 fail gate |
| `BENCH_MIN_RPS` | 未設定 | 行単位の最低 RPS gate |
| `WAF_BENCH_SCENARIOS` | `allow,block-xss` | `make bench-waf` で実行する WAF scenario |

### 18.1.7　出力の正本

proxy benchmark の正本は次の 2 ファイル（+ optional な profile）です。

- Markdown summary: `data/tmp/reports/proxy/proxy-benchmark-summary.md`
- Machine-readable JSON: `data/tmp/reports/proxy/proxy-benchmark-summary.json`
- 任意の raw profile: `data/tmp/reports/proxy/proxy-benchmark-*.pprof`

WAF benchmark の正本:

- Markdown summary: `data/tmp/reports/proxy/waf-benchmark-summary.md`
- Machine-readable JSON: `data/tmp/reports/proxy/waf-benchmark-summary.json`

これらを **branch 間比較**、**release note 用の要約**、**tuning 議論**、
**Markdown を parse したくない自動化** などの正本として使います。

### 18.1.8　Hot Path Logging と Profile Capture

framework の request log は、proxy の product access log と重複するため
**既定で無効** です。一時調査で Gin の raw request log が必要なときだけ
`observability.request_log.enabled=true` にします。performance benchmark
では、通常この値を `false` のままにしてください。

profile capture は既定で無効です。取りたいときは `BENCH_PROFILE=1` を
指定します。pprof server は **opt-in で、container 内 loopback にだけ
bind** し、public proxy port には公開しません。**raw `.pprof` はローカル
調査用 artifact なので commit しない**、というルールです。

### 18.1.9　閾値ポリシー

閾値は **必須ではなく、意図して付けるもの** です。

```bash
BENCH_MAX_FAIL_RATE_PCT=0.5 \
BENCH_MIN_RPS=300 \
BENCH_CONCURRENCY=10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

ルール:

- instability を fail にしたいときは `BENCH_MAX_FAIL_RATE_PCT` を使う
- `make bench-waf` では、計測前の exact status probe に加えて、unexpected
  response-family rate を `BENCH_MAX_FAIL_RATE_PCT` で gate する
- 既知のローカル基準を守りたいときだけ `BENCH_MIN_RPS` を使う
- **別マシンへ同じ `BENCH_MIN_RPS` をそのまま流用しない**
- rate limit / request guard を含めたい場合は、`BENCH_DISABLE_RATE_LIMIT=0`
  / `BENCH_DISABLE_REQUEST_GUARDS=0` を明示し、その条件を review に明記する
- `BENCH_REQUESTS<600` の単発結果は **smoke data** として扱う。採用判断には
  `BENCH_REQUESTS>=600` または **同条件 3 回以上の median** が必要

### 18.1.10　なぜ通常 CI に入れないのか

`make bench` は `ci-local` や通常 GitHub CI に **入れていません**。理由:

- ホストノイズの影響が大きい
- container 起動やローカルツール差でぶれやすい
- `ab` が全 developer / runner に常備されている前提ではない
- script が runtime proxy rules を変更し、既定では rate-limit と request-
  security guard も一時無効化する

これは **人が読む performance baseline** であって、決定的な unit test では
ありません。

### 18.1.11　現在の preset

| Preset | 主な設定 | 用途 |
|---|---|---|
| `balanced` | `force_http2=false`, `disable_compression=false`, `buffer_request_body=false`, `flush_interval_ms=0` | 汎用の標準設定 |
| `low-latency` | `force_http2=false`, `disable_compression=true`, `buffer_request_body=false`, `flush_interval_ms=0` | API / SSE の低遅延重視 |
| `buffered-guard` | `force_http2=false`, `buffer_request_body=true`, `max_response_buffer_bytes=1048576`, `flush_interval_ms=0` | バッファ制御と応答サイズ上限を重視 |

## 18.2　回帰マトリクス ── どのコマンドが何を保証するか

ベンチマークが性能の話であるのに対し、`make smoke` 系は **挙動の妥当性**
を確認するための回帰検証です。次のようなコマンドが揃っています。

| コマンド | 主目的 | 使いどころ |
|---|---|---|
| `make smoke` | 通常 compose stack に対する高速な admin / routed-proxy 回帰 | 日常的な commit や config 変更前 |
| `make deployment-smoke` | `docs/build` に書いた binary / systemd と sample container 導線の再現 | `docs/build`、packaging、runtime layout を触った後 |
| `make release-binary-smoke` | 公開 tarball を build / extract し、bundle local の Docker smoke を実行 | binary artifact を公開する前 |
| `make http3-public-entry-smoke` | built-in HTTPS + HTTP/3 listener を live runtime で確認 | TLS / HTTP/3 listener を変えた後、または direct H3 ingress 案内前 |
| `make smoke-extended` | `smoke` + `deployment-smoke` | runtime と deployment docs の両方を触ったとき / release 前 |
| `make ci-local` | `check` + `smoke` | PR を出す前のローカル基準 |
| `make ci-local-extended` | `check` + `smoke-extended` | release / packaging 前の強めのローカル確認 |
| `make gotestwaf` | WAF 効き具合と false positive 回帰 | release 前、または CRS / request-inspection 変更後 |
| `make bench` / `make bench-proxy` | proxy transport の throughput / latency baseline | proxy transport tuning 後 |
| `make bench-waf` | WAF allow/block の throughput / latency baseline | WAF inspection / CRS / bypass / logging 後 |
| `make bench-full` | proxy と WAF の performance baseline | performance 影響があり得る release 前 |

### 18.2.1　保証マトリクス

これらのコマンドが「何を直接保証しているか」を 1 つの表にまとめたのが、
保証マトリクスです。`yes` は直接見ている、`partial` は間接的に通る、`no`
は通常自動化に入っていない、という意味です。

| 観点 | `make smoke` | `deployment-smoke` | `release-binary-smoke` | `http3-public-entry-smoke` | `smoke-extended` | `ci-local` | `ci-local-extended` | `gotestwaf` |
|---|---|---|---|---|---|---|---|---|
| Admin login で signed session cookie 発行 | yes | yes | yes | no | yes | yes | yes | no |
| login 後の session status 取得 | yes | yes | yes | no | yes | yes | yes | no |
| logout で browser auth 無効化 | yes | yes | yes | no | yes | yes | yes | no |
| session ベース admin API に CSRF token | yes | yes | yes | no | yes | yes | yes | no |
| 埋め込み Admin UI への到達 | yes | yes | no | no | yes | yes | yes | no |
| routed proxy の host/path/query/header rewrite | yes | yes | yes | yes | yes | yes | yes | no |
| client-facing gzip response compression | yes | yes | yes | no | yes | yes | yes | no |
| built-in HTTPS listener が manual cert で起動 | no | no | no | yes | no | no | no | no |
| HTTPS 応答に `Alt-Svc` 付与 | no | no | no | yes | no | no | no | no |
| 実 HTTP/3 over UDP request 成功 | no | no | no | yes | no | no | no | no |
| release fixture に対する deterministic な WAF block | no | no | yes | no | no | no | no | yes |
| binary / systemd deployment guide の妥当性 | no | yes | no | no | yes | no | yes | no |
| container deployment guide の妥当性 | no | yes | no | no | yes | no | yes | no |
| release-binary runtime layout / writable path | no | no | yes | no | no | no | no | no |
| 広い attack suite に対する WAF 効き具合 | no | no | no | no | no | no | no | yes |

> benchmark target は、この決定的な保証マトリクスからは **意図的に外して**
> います。人が読む performance artifact を生成し、任意の threshold で fail
> できますが、通常 CI gate ではありません。

### 18.2.2　各コマンドの中身

主要コマンドの中身を簡単に補足します。

- **`make smoke`**: 通常 compose stack 向けの最速回帰。Admin UI、login →
  session cookie、`/auth/session` / `/auth/logout`、CSRF token、proxy
  validate / dry-run / apply、gzip。deployment guide / release-binary /
  GoTestWAF / HTTP/3 は **見ない**。
- **`make deployment-smoke`**: `docs/build/` の手順を実際に踏み、staged
  binary / systemd / sample container 起動を確認。split mode の listener
  分離も確認。`make smoke` 相当の admin / proxy / gzip も通る。
- **`make smoke-extended`**: `smoke` + `deployment-smoke`。runtime と
  operator docs の整合をまとめて見る。
- **`make release-binary-smoke`**: 公開 tarball を build → extract → bundle
  local の `setup.sh` / `smoke.sh` を実行。**「公開配布物そのものをダウン
  ロードしたときに動くか」を確認** する top-level command。
- **`make http3-public-entry-smoke`**: built-in HTTPS + HTTP/3 listener を
  live runtime で確認（第15章で詳述）。
- **`make ci-local`**: `make check`（Go tests / UI tests / compose config
  validation）+ `make smoke`。PR 前の最小ライン。
- **`make ci-local-extended`**: `ci-local` 全部 + `smoke-extended`。tag
  打ちや packaging、deployment docs 変更前。
- **`make gotestwaf`**: 現行 WAF 設定が **true-positive 攻撃をしきい値以上
  block** できるか、necessary なら **false-positive / bypass** のしきい値
  も維持されるか。`data/tmp/gotestwaf/` にレポート。
- **`make bench` / `make bench-proxy` / `make bench-waf` / `make bench-full`**:
  17.1 節を参照。

## 18.3　Release-binary smoke ── 公開配布物そのものを確認する

公開配布する tarball については、専用の top-level smoke が用意されています。

```bash
make release-binary-smoke VERSION=v0.8.1
```

任意の変数:

- `RELEASE_BINARY_SMOKE_ARCH=amd64|arm64`
- `RELEASE_BINARY_SMOKE_SKIP_BUILD=1`
- `RELEASE_BINARY_SMOKE_KEEP_EXTRACTED=1`
- `RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1`

### 18.3.1　`make deployment-smoke` との違い

両者は役割が違います。

- **`deployment-smoke`**: `docs/build/` の operator guide を検証する。
  repo local の staged runtime や sample container を使う。
- **`release-binary-smoke`**: **公開 tarball** を build → 展開 → bundle 内
  の `testenv/release-binary/setup.sh` を実行 → bundle local の Docker
  smoke 環境を起動 → bundle local の `./smoke.sh` を実行。

つまり、`release-binary-smoke` は「**公開配布物そのものをダウンロード
したときに動くか**」を確認する top-level command です。

### 18.3.2　何を検証するか

展開した public bundle から次を確認します。

- release tarball に必要な runtime file が入っている
- bundle local の setup script が writable runtime directory を用意できる
- bundle local の Docker smoke 環境が build / 起動できる
- 展開 artifact から **admin login / session status / logout invalidation**
  が通る
- **protected-host traffic** が通る
- public artifact から **client-facing gzip** が動く
- public artifact から **deterministic な WAF block** が発火する

### 18.3.3　Multi-arch policy

ローカルの release-binary smoke は、既定で **host-native artifact** を
対象にします。

- `amd64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=amd64`
- `arm64` host では通常 `RELEASE_BINARY_SMOKE_ARCH=arm64`
- 非 native artifact の検証は、対応 hardware / release host / 専用 CI で
  行う前提

cross-arch のローカル実行をあえて試したい場合は次を付けます。

```bash
RELEASE_BINARY_SMOKE_ALLOW_CROSS_ARCH=1
```

ただしこの override は **best-effort** です。Docker、展開した binary、
ローカル host が追加 emulation なしでその artifact を扱えることまでは保証
しません。

## 18.4　推奨 confidence ladder

何をしたいかに応じて、どこまで叩くかを決める指針です。

| confidence level | コマンド |
|---|---|
| まず runtime sanity | `make smoke` |
| ローカル CI 基準 | `make ci-local` |
| deployment docs の妥当性確認 | `make deployment-smoke` |
| 公開 binary artifact の妥当性確認 | `make release-binary-smoke VERSION=vX.Y.Z` |
| WAF corpus を除く release readiness | `make ci-local-extended` |
| WAF corpus を含む release readiness | `make ci-local-extended && make gotestwaf` |
| proxy performance 比較 | `make bench-proxy` |
| WAF performance 比較 | `make bench-waf` |
| combined performance 比較 | `make bench-full` |
| direct HTTPS / HTTP/3 entry readiness | `make http3-public-entry-smoke` |
| 公開バイナリ release readiness | `make ci-local-extended && make gotestwaf && make release-binary-smoke VERSION=vX.Y.Z` |

## 18.5　通常検証で埋まっていない gap

現時点で routine validation から漏れているのは次です。

- 任意の workstation 1 台からの **完全な multi-arch public tarball smoke**
  - `release-binary-smoke` は host-native を既定にしたが、非 native artifact
    は **対応 hardware / release host / その arch を担当する専用 CI** が
    別途必要

これは将来の improvement target で、現状は割り切り（本番 release は対応
hardware で確認する）として明文化しておく、という整理になっています。

## 18.6　ここまでの整理

- 性能比較は **`make bench-proxy` / `make bench-waf` / `make bench-full`**。
  本番再現ではなく、**同条件で並べて見る** ためのもの。
- 機能の妥当性は **`make smoke` 系の保証マトリクス** を辞書として使う。
  「何を確認したいか」で叩くコマンドを選ぶ。
- 公開 tarball 自体は **`make release-binary-smoke`** で確認する。
- どこまで叩けば安心かは、**confidence ladder** に従って積み上げる。

## 18.7　次章への橋渡し

第VII部もあと 1 章です。次の第19章では、**static fast-path 評価** ── 静的
content に対する zero-copy / cache replay を一般戦略にしない理由、すでに
ある bounded fast-path、再検討する条件 ── を扱います。
