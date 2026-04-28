# tukuyomi ベンチマークベースライン

この文書は、ローカル benchmark target を `tukuyomi` の tuning 比較や release 前確認に使うための運用ルールを定義したものです。
shell script を読まなくても、同じ条件で比較できるようにすることを目的にしています。

## benchmark コマンド

| コマンド | 目的 | 出力 |
| --- | --- | --- |
| `make bench` | `make bench-proxy` の後方互換 alias | proxy tuning artifact |
| `make bench-proxy` | proxy transport preset の比較 | `proxy-benchmark-summary.*` |
| `make bench-waf` | WAF allow/block inspection scenario の比較 | `waf-benchmark-summary.*` |
| `make bench-full` | proxy と WAF benchmark を順に実行 | 両方の artifact |

## `make bench-proxy` がやること

`make bench` と `make bench-proxy` は `./scripts/benchmark_proxy_tuning.sh` の wrapper です。
このスクリプトは次を自動実行します。

- 既定では benchmark 専用の一時 config / SQLite DB を準備
- ローカルの `tukuyomi` compose stack を起動
- `scripts/benchmark_upstream.go` の並行処理対応 Go upstream mock を一時起動
- `/tukuyomi-api/proxy-rules` 経由で proxy preset を適用
- `BENCH_PROXY_MODE=proxy-only` を明示しない限り、WAF inspection を含む通常の proxy listener path を計測
- warm-up 実行
- 対象 path に対して ApacheBench（`ab`）で負荷
- `BENCH_PROFILE=1` の場合だけ CPU / heap / allocation profile を取得
- 終了時に proxy rules、rate-limit rules、benchmark 中に無効化した request-security guard files、一時的な proxy-only WAF bypass 設定を元へ戻す

用途は、proxy preset の比較や、大きな性能劣化がないかの release 前確認です。

## `make bench-waf` がやること

`make bench-waf` は `./scripts/benchmark_waf.sh` の wrapper です。
このスクリプトは次を自動実行します。

- 既定では benchmark 専用の一時 config / SQLite DB を準備
- ローカルの `tukuyomi` compose stack を起動
- `scripts/benchmark_upstream.go` の並行処理対応 Go upstream mock を一時起動
- `/tukuyomi-api/proxy-rules` 経由で benchmark 用の安定した proxy route を適用
- 必要に応じて計測中だけ rate-limit rules を一時無効化
- WAF / proxy の計測に challenge / block の副作用が混ざらないよう、必要に応じて bot-defense、semantic、IP-reputation guard files を一時無効化
- 各 WAF scenario を計測前に probe し、期待 status を確認
- scenario / concurrency ごとに ApacheBench（`ab`）で負荷
- 終了時に proxy rules と rate-limit rules を元へ戻す

既定の WAF scenario:

| Scenario | 期待 status | 目的 |
| --- | ---: | --- |
| `allow` | `200` | WAF inspection を通過すべき benign request |
| `block-xss` | `403` | CRS で block されるべき encoded XSS query |

request-inspection、CRS、bypass、logging 周りを触った後に、WAF inspection の throughput / latency を比較する用途です。
`make gotestwaf` の代替ではありません。広い攻撃 corpus と false-positive 回帰は引き続き GoTestWAF を正にします。

## いつ回すか

推奨タイミング:

- proxy transport 周りを変更した後
  - `force_http2`
  - buffering
  - timeout
  - response compression
- runtime path の変更で throughput / latency 影響がありそうな release 前
- 同一マシン上で preset 同士を比較したい時

これは本番 capacity の厳密な再現ではありません。  
あくまでローカルの制御された baseline です。
同梱 upstream mock は小さな Go HTTP server なので、高 concurrency で Python `http.server` の直列化上限に引っ張られないようにしています。

## 標準コマンド

```bash
make bench
```

proxy transport と WAF inspection の両方に影響し得る変更での標準例:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench-full
```

内部的には、現在の `BENCH_*` 環境変数で `./scripts/benchmark_proxy_tuning.sh` を呼びます。

人が比較する標準例:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

`BENCH_PROXY_MODE=current` は現行の production に近い proxy + WAF inspection path です。
proxy hot path 単独の profile を見たい時だけ `BENCH_PROXY_MODE=proxy-only` を使います。

## 前提条件

- Docker と Docker Compose が利用可能
- ローカルに `ab` が入っている
- `curl`, `jq`, Go が使える
- 比較可能な程度にマシン負荷が落ち着いている

branch 間比較をする場合は、同じホスト、同じ concurrency、同じ request 数で回してください。

## 入力パラメータ

| 変数 | 既定値 | 意味 |
| --- | --- | --- |
| `BENCH_REQUESTS` | Makefile 経由は `120`、script 直接実行は `600` | preset / concurrency ごとの計測 request 数。判断用 run は `>=600` |
| `WARMUP_REQUESTS` | Makefile 経由は `20`、script 直接実行は `100` | 計測前の warm-up request 数 |
| `BENCH_CONCURRENCY` | `1,10,50` | カンマ区切りの concurrency 一覧 |
| `BENCH_PATH` | `/bench` | `tukuyomi` 越しに叩く path |
| `BENCH_TIMEOUT_SEC` | `30` | ApacheBench timeout |
| `BENCH_DISABLE_RATE_LIMIT` | `1` | 計測中だけ rate-limit rules を一時無効化するか |
| `BENCH_DISABLE_REQUEST_GUARDS` | `1` | 計測中だけ bot-defense、semantic、IP-reputation guards を一時無効化するか |
| `BENCH_ACCESS_LOG_MODE` | `full` | proxy rules の `access_log_mode`。throughput 調査では `off` / `minimal` も使用可能 |
| `BENCH_CLIENT_KEEPALIVE` | `1` | `1` なら ApacheBench に `-k` を渡す。旧 connection-churn baseline は `0` |
| `BENCH_PROXY_MODE` | `current` | `current` は WAF inspection を含む。`proxy-only` は `BENCH_PATH` だけ一時的に WAF inspection を bypass |
| `BENCH_PROXY_ENGINE` | `tukuyomi_proxy` | benchmark config の `proxy.engine.mode` を一時的に書き換える。対応値は `tukuyomi_proxy` のみ |
| `BENCH_ISOLATED_RUNTIME` | `1` | `data/tmp/bench` 配下の一時 config / DB を使う。現在のローカル runtime 状態を意図的に測る時だけ `0` |
| `BENCH_PROFILE` | `0` | `1` で pprof CPU / heap / allocation artifact を取得 |
| `BENCH_PROFILE_ADDR` | `127.0.0.1:6060` | container 内の loopback 専用 pprof listener address |
| `BENCH_PROFILE_SECONDS` | `10` | CPU profile の取得秒数 |
| `BENCH_MAX_FAIL_RATE_PCT` | 未設定 | 行単位 fail gate |
| `BENCH_MIN_RPS` | 未設定 | 行単位の最低 RPS gate |
| `WAF_BENCH_SCENARIOS` | `allow,block-xss` | `make bench-waf` で実行する WAF scenario 一覧 |
| `UPSTREAM_PORT` | auto | 一時 upstream port。未指定ならローカル衝突を避けるため自動選択 |
| `OUTPUT_FILE` | `data/tmp/reports/proxy/proxy-benchmark-summary.md` | 人間向け Markdown summary の出力先 |
| `OUTPUT_JSON_FILE` | `data/tmp/reports/proxy/proxy-benchmark-summary.json` | 機械可読 JSON の出力先 |

## 出力の正本

proxy benchmark の正本:

- Markdown summary: `data/tmp/reports/proxy/proxy-benchmark-summary.md`
- Machine-readable JSON: `data/tmp/reports/proxy/proxy-benchmark-summary.json`
- optional raw profiles: `data/tmp/reports/proxy/proxy-benchmark-*.pprof`

WAF benchmark の正本:

- Markdown summary: `data/tmp/reports/proxy/waf-benchmark-summary.md`
- Machine-readable JSON: `data/tmp/reports/proxy/waf-benchmark-summary.json`

これらを次の用途の正本として扱います。

- branch 間比較
- release note 用の要約
- tuning 議論
- Markdown を parse したくない automation

summary に含まれる主な項目:

- preset
- WAF benchmark 行では scenario
- WAF benchmark 行では期待 status と probe status
- concurrency
- requests
- failures / non-2xx 数
- fail rate または unexpected response-family rate
- average / p95 / p99 latency
- 実測 RPS
- rate limit を無効化したかどうか
- request-security guards を無効化したかどうか
- proxy access log mode
- client keep-alive mode
- 一時 upstream port
- benchmark mode（`current` / `proxy-only`）
- profile capture の状態と artifact path

JSON artifact には同じ run metadata と、preset / concurrency または scenario / concurrency ごとに比較しやすい `rows[]` が入ります。

## Hot Path Logging

framework の request log は、proxy の product access log と重複するため既定で無効です。
一時調査で Gin の raw request log が必要な場合だけ `observability.request_log.enabled=true` にします。
performance benchmark では、通常この値を `false` のままにしてください。

proxy benchmark は既定で client keep-alive を有効化します。旧来の `ab` connection-churn baseline を再現したい場合は `BENCH_CLIENT_KEEPALIVE=0` を明示してください。

## Profile Capture

profile capture は既定で無効です。通常の proxy + WAF inspection path で profile を取る場合:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
make bench-proxy
```

WAF inspection と切り離して proxy hot path の cost を見る場合は、同じ条件で benchmark path だけ一時的に WAF bypass します。

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
BENCH_PROXY_MODE=proxy-only \
make bench-proxy
```

pprof server は opt-in で、container 内 loopback にだけ bind し、public proxy port には公開しません。
raw `.pprof` はローカル調査用 artifact なので commit しません。review には解釈した summary だけを残します。

## 閾値ポリシー

閾値は必須ではなく、意図して付けるものです。

例:

```bash
BENCH_MAX_FAIL_RATE_PCT=0.5 \
BENCH_MIN_RPS=300 \
BENCH_CONCURRENCY=10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

ルール:

- instability を fail にしたい時は `BENCH_MAX_FAIL_RATE_PCT` を使う
- `make bench-waf` では、計測前の exact status probe に加えて unexpected response-family rate を `BENCH_MAX_FAIL_RATE_PCT` で gate する
- 既知のローカル基準を守りたい時だけ `BENCH_MIN_RPS` を使う
- 別マシンへ同じ `BENCH_MIN_RPS` をそのまま流用しない
- rate limit を含めたい場合は `BENCH_DISABLE_RATE_LIMIT=0` にし、その条件を review に明記する
- bot-defense、semantic、IP-reputation を含めたい場合は `BENCH_DISABLE_REQUEST_GUARDS=0` にし、その条件を review に明記する
- `BENCH_REQUESTS<600` の単発結果は smoke data として扱う。採用判断には `BENCH_REQUESTS>=600` または同条件 3 回以上の median が必要

## なぜ通常 CI に入れないのか

`make bench` を `ci-local` や通常 GitHub CI に入れていない理由:

- ホストノイズの影響が大きい
- container 起動やローカルツール差でぶれやすい
- `ab` が全 developer / runner に常備されている前提ではない
- script が runtime proxy rules を変更し、既定では rate-limit と request-security guard files も一時無効化する

これは人が読む performance baseline であって、決定的な unit test ではありません。

JSON artifact を追加しても、この task では benchmark を通常 CI に移しません。

## 比較時の見方

release / tuning baseline として使う時は次を守ります。

1. `BENCH_REQUESTS`、`WARMUP_REQUESTS`、`BENCH_CONCURRENCY` を揃える
2. `BENCH_DISABLE_RATE_LIMIT` を揃える
3. RPS / latency を比較する時は `BENCH_PROXY_MODE` を揃える
4. `BENCH_PROXY_ENGINE=tukuyomi_proxy` を明示し、benchmark output に native engine を記録する
5. 生成された Markdown summary を横に並べて比較する
6. 1 回のぶれより、傾向の変化を見る

見るべき問い:

- fail rate が `0` から非 `0` になっていないか
- 同じ preset / concurrency で p95 / p99 latency が大きく悪化していないか
- ある preset の優位性が消えていないか
- WAF 行では、計測前の allow path が `200`、block path が `403` を維持しているか
- 同じ scenario / concurrency で WAF block latency や RPS が大きく変化していないか

## 現在の presets

| Preset | 主な設定 | 用途 |
| --- | --- | --- |
| `balanced` | `force_http2=false`, `disable_compression=false`, `buffer_request_body=false`, `flush_interval_ms=0` | 汎用の標準設定 |
| `low-latency` | `force_http2=false`, `disable_compression=true`, `buffer_request_body=false`, `flush_interval_ms=0` | API / SSE の低遅延重視 |
| `buffered-guard` | `force_http2=false`, `buffer_request_body=true`, `max_response_buffer_bytes=1048576`, `flush_interval_ms=0` | バッファ制御と応答サイズ上限を重視 |

## 関連ドキュメント

- 回帰コマンド整理: [regression-matrix.ja.md](regression-matrix.ja.md)
- WAF 回帰: [README.ja.md#WAF回帰テストGoTestWAF](../../README.ja.md#WAF回帰テストGoTestWAF)
