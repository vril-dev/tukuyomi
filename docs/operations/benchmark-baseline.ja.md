# tukuyomi ベンチマークベースライン

この文書は、ローカルのベンチマーク用ターゲットを `tukuyomi` のチューニング比較やリリース前確認に使うための運用ルールを定義したものです。
シェルスクリプトを読まなくても、同じ条件で比較できるようにすることを目的としています。

## ベンチマークコマンド

| コマンド | 目的 | 出力 |
| --- | --- | --- |
| `make bench` | `make bench-proxy` の後方互換エイリアス | プロキシチューニングのアーティファクト |
| `make bench-proxy` | プロキシトランスポートのプリセット比較 | `proxy-benchmark-summary.*` |
| `make bench-waf` | WAF の allow ／ block 検査シナリオの比較 | `waf-benchmark-summary.*` |
| `make bench-full` | プロキシと WAF のベンチマークを順に実行 | 両方のアーティファクト |

## `make bench-proxy` の処理内容

`make bench` と `make bench-proxy` は `./scripts/benchmark_proxy_tuning.sh` のラッパーです。
このスクリプトは次を自動実行します。

- 既定では、ベンチマーク専用の一時設定 ／ SQLite DB を準備
- ローカルの `tukuyomi` compose スタックを起動
- `scripts/benchmark_upstream.go` の並行処理対応 Go アップストリームモックを一時起動
- `/tukuyomi-api/proxy-rules` 経由でプロキシプリセットを適用
- `BENCH_PROXY_MODE=proxy-only` を明示しない限り、WAF 検査を含む通常のプロキシリスナー経路を計測
- ウォームアップ実行
- 対象パスに対して ApacheBench（`ab`）で負荷をかける
- `BENCH_PROFILE=1` の場合のみ、CPU ／ヒープ ／アロケーションの profile を取得
- 終了時に、プロキシルール、レート制限ルール、ベンチマーク中に無効化したリクエストセキュリティのガード設定、一時的に設定した proxy-only WAF バイパスを元の状態に戻す

用途は、プロキシプリセットの比較や、リリース前に大きな性能劣化が発生していないかの確認です。

## `make bench-waf` の処理内容

`make bench-waf` は `./scripts/benchmark_waf.sh` のラッパーです。
このスクリプトは次を自動実行します。

- 既定では、ベンチマーク専用の一時設定 ／ SQLite DB を準備
- ローカルの `tukuyomi` compose スタックを起動
- `scripts/benchmark_upstream.go` の並行処理対応 Go アップストリームモックを一時起動
- `/tukuyomi-api/proxy-rules` 経由で、ベンチマーク用の安定したプロキシルートを適用
- 必要に応じて、計測中だけレート制限ルールを一時的に無効化
- WAF ／プロキシの計測にチャレンジ／ブロックの副作用が混じらないよう、必要に応じて bot-defense、semantic、IP レピュテーションのガード設定を一時的に無効化
- 各 WAF シナリオを計測前にプローブし、期待されるステータスを確認
- シナリオ／並行度ごとに ApacheBench（`ab`）で負荷をかける
- 終了時に、プロキシルールとレート制限ルールを元の状態に戻す

既定の WAF シナリオ:

| シナリオ | 期待ステータス | 目的 |
| --- | ---: | --- |
| `allow` | `200` | WAF 検査を通過するべき正常リクエスト |
| `block-xss` | `403` | CRS でブロックされるべきエンコード済み XSS クエリ |

リクエスト検査、CRS、バイパス、ロギング周りに変更を入れた後で、WAF 検査のスループット ／レイテンシを比較するための用途です。
`make gotestwaf` の代替ではありません。広い攻撃コーパスや誤検知の回帰テストは、引き続き GoTestWAF を正とします。

## いつ実行するか

推奨タイミング:

- プロキシトランスポート周りを変更した後
  - `force_http2`
  - バッファリング
  - タイムアウト
  - レスポンス圧縮
- ランタイム経路の変更により、スループット ／レイテンシへの影響が想定されるリリース前
- 同一マシン上でプリセット同士を比較したい時

これは本番容量を厳密に再現するものではありません。
あくまでローカルで条件を揃えたベースラインです。
同梱のアップストリームモックは小さな Go HTTP サーバーであり、高並行時に Python `http.server` のようなシリアル化の上限に引きずられないようにしています。

## 標準コマンド

```bash
make bench
```

プロキシトランスポートと WAF 検査の両方に影響し得る変更を入れた場合の標準例:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench-full
```

内部的には、現在の `BENCH_*` 環境変数を引き継いで `./scripts/benchmark_proxy_tuning.sh` を呼び出します。

人が比較する際の標準例:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

`BENCH_PROXY_MODE=current` は、現行の本番に近いプロキシ＋ WAF 検査経路です。
プロキシのホットパスのみで profile を取りたい場合のみ、`BENCH_PROXY_MODE=proxy-only` を使用します。

## 前提条件

- Docker と Docker Compose が利用可能
- ローカルに `ab` がインストール済み
- `curl`、`jq`、Go が利用可能
- 比較が成立する程度に、マシン側の負荷が落ち着いている

ブランチ間で比較する場合は、同じホスト、同じ並行度、同じリクエスト数で実行してください。

## 入力パラメータ

| 変数 | 既定値 | 意味 |
| --- | --- | --- |
| `BENCH_REQUESTS` | Makefile 経由は `120`、スクリプト直接実行は `600` | プリセット／並行度ごとの計測リクエスト数。判断に使う実行は `>=600` |
| `WARMUP_REQUESTS` | Makefile 経由は `20`、スクリプト直接実行は `100` | 計測前のウォームアップリクエスト数 |
| `BENCH_CONCURRENCY` | `1,10,50` | カンマ区切りの並行度一覧 |
| `BENCH_PATH` | `/bench` | `tukuyomi` 越しに叩くパス |
| `BENCH_TIMEOUT_SEC` | `30` | ApacheBench のタイムアウト |
| `BENCH_DISABLE_RATE_LIMIT` | `1` | 計測中だけレート制限ルールを一時無効化するか |
| `BENCH_DISABLE_REQUEST_GUARDS` | `1` | 計測中だけ bot-defense、semantic、IP レピュテーションの各ガードを一時無効化するか |
| `BENCH_ACCESS_LOG_MODE` | `full` | プロキシルールの `access_log_mode`。スループット調査では `off` ／ `minimal` も使用可 |
| `BENCH_CLIENT_KEEPALIVE` | `1` | `1` の場合、ApacheBench に `-k` を渡す。旧来のコネクションチャーンベースラインは `0` |
| `BENCH_PROXY_MODE` | `current` | `current` は WAF 検査を含む。`proxy-only` は `BENCH_PATH` のみ一時的に WAF 検査をバイパス |
| `BENCH_PROXY_ENGINE` | `tukuyomi_proxy` | ベンチマーク設定の `proxy.engine.mode` を一時的に書き換える。対応値は `tukuyomi_proxy` のみ |
| `BENCH_ISOLATED_RUNTIME` | `1` | `data/tmp/bench` 配下の一時設定／DB を使用する。現状のローカルランタイム状態を意図的に計測する場合のみ `0` |
| `BENCH_PROFILE` | `0` | `1` の場合、pprof の CPU ／ヒープ ／アロケーションのアーティファクトを取得 |
| `BENCH_PROFILE_ADDR` | `127.0.0.1:6060` | コンテナ内のループバック専用 pprof リスナーアドレス |
| `BENCH_PROFILE_SECONDS` | `10` | CPU profile の取得秒数 |
| `BENCH_MAX_FAIL_RATE_PCT` | 未設定 | 行単位の失敗率ゲート |
| `BENCH_MIN_RPS` | 未設定 | 行単位の最低 RPS ゲート |
| `WAF_BENCH_SCENARIOS` | `allow,block-xss` | `make bench-waf` で実行する WAF シナリオ一覧 |
| `UPSTREAM_PORT` | auto | 一時アップストリームのポート。未指定の場合はローカル衝突を避けるため自動選択 |
| `OUTPUT_FILE` | `data/tmp/reports/proxy/proxy-benchmark-summary.md` | 人間向け Markdown サマリーの出力先 |
| `OUTPUT_JSON_FILE` | `data/tmp/reports/proxy/proxy-benchmark-summary.json` | 機械可読な JSON の出力先 |

## 正となる出力

プロキシベンチマークで正となる出力:

- Markdown サマリー: `data/tmp/reports/proxy/proxy-benchmark-summary.md`
- 機械可読な JSON: `data/tmp/reports/proxy/proxy-benchmark-summary.json`
- 任意で生成される raw profile: `data/tmp/reports/proxy/proxy-benchmark-*.pprof`

WAF ベンチマークで正となる出力:

- Markdown サマリー: `data/tmp/reports/proxy/waf-benchmark-summary.md`
- 機械可読な JSON: `data/tmp/reports/proxy/waf-benchmark-summary.json`

これらを次の用途で正として扱います。

- ブランチ間比較
- リリースノート用の要約
- チューニング議論
- Markdown をパースしたくない自動化処理

サマリーに含まれる主な項目:

- プリセット
- WAF ベンチマーク行ではシナリオ
- WAF ベンチマーク行では期待ステータスとプローブステータス
- 並行度
- リクエスト数
- 失敗数 ／ non-2xx 数
- 失敗率、または期待外のレスポンスファミリーの発生率
- 平均 ／ p95 ／ p99 のレイテンシ
- 実測 RPS
- レート制限を無効化したかどうか
- リクエストセキュリティの各ガードを無効化したかどうか
- プロキシのアクセスログモード
- クライアント keep-alive モード
- 一時アップストリームのポート
- ベンチマークモード（`current` ／ `proxy-only`）
- profile 取得の状態とアーティファクトのパス

JSON アーティファクトには、同じ実行メタデータと、プリセット ／並行度、またはシナリオ ／並行度ごとに比較しやすい `rows[]` が格納されます。

## ホットパスのロギング

フレームワーク側のリクエストログは、プロキシのプロダクトアクセスログと重複するため、既定で無効です。
一時的な調査で Gin の生のリクエストログが必要な場合のみ、`observability.request_log.enabled=true` に設定します。
パフォーマンスベンチマークでは、通常この値を `false` のままにしてください。

プロキシベンチマークは、既定でクライアント keep-alive を有効にします。旧来の `ab` のコネクションチャーンベースラインを再現したい場合は、`BENCH_CLIENT_KEEPALIVE=0` を明示してください。

## profile の取得

profile の取得は既定で無効です。通常のプロキシ＋ WAF 検査経路で profile を取る場合:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
make bench-proxy
```

WAF 検査と切り離して、プロキシのホットパスのコストだけを見たい場合は、同じ条件でベンチマーク対象パスのみ一時的に WAF をバイパスします。

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
BENCH_PROXY_MODE=proxy-only \
make bench-proxy
```

pprof サーバーはオプトインで、コンテナ内のループバックにのみバインドし、公開プロキシポートには露出しません。
raw の `.pprof` はローカル調査用のアーティファクトであるためコミットしません。レビューには、解釈済みのサマリーのみを残します。

## 閾値ポリシー

閾値は必須ではなく、意図して設定するものです。

例:

```bash
BENCH_MAX_FAIL_RATE_PCT=0.5 \
BENCH_MIN_RPS=300 \
BENCH_CONCURRENCY=10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

ルール:

- 不安定さを失敗扱いしたい場合は `BENCH_MAX_FAIL_RATE_PCT` を使う
- `make bench-waf` では、計測前のステータス完全一致プローブに加えて、期待外のレスポンスファミリーの発生率を `BENCH_MAX_FAIL_RATE_PCT` でゲートする
- 既知のローカル基準を担保したい場合のみ `BENCH_MIN_RPS` を使う
- 別マシンへ同じ `BENCH_MIN_RPS` をそのまま流用しない
- レート制限を含めて計測したい場合は `BENCH_DISABLE_RATE_LIMIT=0` とし、その条件をレビューに明記する
- bot-defense、semantic、IP レピュテーションを含めて計測したい場合は `BENCH_DISABLE_REQUEST_GUARDS=0` とし、その条件をレビューに明記する
- `BENCH_REQUESTS<600` の単発結果はスモークデータとして扱う。採用判断には `BENCH_REQUESTS>=600`、または同条件で 3 回以上実行した中央値が必要

## 通常 CI に組み込まない理由

`make bench` を `ci-local` や通常の GitHub CI に組み込んでいない理由は次のとおりです。

- ホスト側のノイズの影響が大きい
- コンテナ起動やローカルツールの差異により結果がぶれやすい
- `ab` がすべての開発者／ランナーにインストールされている前提を置けない
- スクリプトがランタイムのプロキシルールを変更し、既定ではレート制限とリクエストセキュリティの各ガードも一時的に無効化する

これは人が読むためのパフォーマンスベースラインであって、決定論的な単体テストではありません。

JSON アーティファクトを追加しても、このタスクではベンチマークを通常の CI に移しません。

## 比較時の見方

リリース ／チューニングのベースラインとして使う場合は、次を守ってください。

1. `BENCH_REQUESTS`、`WARMUP_REQUESTS`、`BENCH_CONCURRENCY` を揃える
2. `BENCH_DISABLE_RATE_LIMIT` を揃える
3. RPS ／レイテンシを比較する場合は `BENCH_PROXY_MODE` を揃える
4. `BENCH_PROXY_ENGINE=tukuyomi_proxy` を明示し、ベンチマーク出力にネイティブエンジンを記録する
5. 生成された Markdown サマリーを横並びで比較する
6. 1 回のぶれよりも、傾向の変化を見る

確認すべき観点:

- 失敗率が `0` から非 `0` になっていないか
- 同じプリセット／並行度で、p95 ／ p99 のレイテンシが大きく悪化していないか
- あるプリセットの優位性が消えていないか
- WAF 行では、計測前の allow パスが `200`、block パスが `403` を維持しているか
- 同じシナリオ／並行度で、WAF ブロックのレイテンシ／RPS が大きく変化していないか

## 現在のプリセット

| プリセット | 主な設定 | 用途 |
| --- | --- | --- |
| `balanced` | `force_http2=false`、`disable_compression=false`、`buffer_request_body=false`、`flush_interval_ms=0` | 汎用の標準設定 |
| `low-latency` | `force_http2=false`、`disable_compression=true`、`buffer_request_body=false`、`flush_interval_ms=0` | API ／ SSE の低遅延重視 |
| `buffered-guard` | `force_http2=false`、`buffer_request_body=true`、`max_response_buffer_bytes=1048576`、`flush_interval_ms=0` | バッファ制御と応答サイズ上限を重視 |

## 関連ドキュメント

- 回帰テストコマンド整理: [regression-matrix.ja.md](regression-matrix.ja.md)
- WAF 回帰: [README.ja.md#WAF回帰テストGoTestWAF](../../README.ja.md#WAF回帰テストGoTestWAF)
