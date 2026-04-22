# tukuyomi Reuse-Port Evaluation

この文書は、実験的な `SO_REUSEPORT` / multi-listener fan-out の評価結果を記録したものです。

`tukuyomi` は現時点で listener fan-out を shipped feature として持ちません。この文書は、no-go 判断を記憶ではなく exact command と計測結果で残すためにあります。

## 結論

- 実験的 listener fan-out について、Docker の published-port 挙動は support しない扱いとする
- 評価した local host では、安定した benchmark 改善は確認できなかった
- この 2 点が同時に解けるまでは、listener fan-out を supported runtime に戻さない

## Docker published-port の症状

評価中、実験的 listener fan-out を有効にした Docker port-published runtime は、単純な health probe でも失敗することがありました。

確認に使った probe:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

観測した失敗:

```text
curl: (56) Recv failure: Connection reset by peer
```

これだけで feature を ship しない理由として十分です。direct public listener を目指す機能が、一般的な local Docker publish 経路で不安定なのは許容できません。

## review で使った benchmark recipe

review では、同じ host 上で既存の local benchmark harness を使い、listener topology だけを切り替えて比較しました。

実行コマンド:

```bash
HOST_CORAZA_PORT=19090 \
WAF_LISTEN_PORT=9090 \
WAF_API_KEY_PRIMARY=dev-only-change-this-key-please \
BENCH_REQUESTS=120 \
WARMUP_REQUESTS=20 \
BENCH_CONCURRENCY=1,20 \
BENCH_DISABLE_RATE_LIMIT=1 \
./scripts/benchmark_proxy_tuning.sh
```

比較したもの:

- single-listener baseline
- `reuse_port=true` と `listener_count=2` を使う実験的 fan-out

## 計測結果

### Single-listener baseline

記録した run では次の結果でした。

- `balanced@20`: `fail_rate=0.00%`, `p95=1019ms`, `rps=58.15`
- `low-latency@20`: `fail_rate=0.00%`, `p95=1017ms`, `rps=57.88`
- `buffered-guard@20`: `fail_rate=0.00%`, `p95=1173ms`, `rps=99.23`

### 実験的 fan-out (`reuse_port=true`, `listener_count=2`)

記録した run では次の結果でした。

- `balanced@20`: `fail_rate=28.33%`, `p95=5002ms`, `rps=19.81`
- `low-latency@1`: `fail_rate=100.00%` で全応答が non-2xx
- `low-latency@20`: `fail_rate=100.00%` で全応答が non-2xx
- `buffered-guard@1`: `fail_rate=6.67%`, `p95=3083ms`, `rps=4.34`
- `buffered-guard@20`: single-listener baseline に対して明確な改善なし

これは「小さい regression」や「host noise」ではなく、明確な no-go 判定です。

## 解釈

評価した host では、TCP accept fan-out が本当の bottleneck だという根拠は得られませんでした。

むしろ見えたのは次です。

- Docker published-port 挙動の不安定さ
- workload 依存で大きく崩れる benchmark
- listener 複雑化を正当化できる一貫した throughput / latency 改善がないこと

そのため、優先順位は今のままです。

1. upstream transport tuning
2. metrics / observability
3. backpressure / queueing
4. cache / compression / runtime tuning
5. listener fan-out は host/runtime の根拠が十分に揃った時だけ再検討

## 再開条件

listener fan-out を再開するなら、少なくとも次を満たす必要があります。

- 対象 host class で benchmark 改善が再現できる
- Docker published-port の smoke が clean である
  - もしくは Docker-published local runtime を support 範囲外にすることを明示する
- 想定 deployment topology を先に文書化する
- bottleneck が upstream/WAF ではなく listener accept 分散にあると説明できる

## 関連文書

- 現在の判断文書:
  - [listener-topology.ja.md](listener-topology.ja.md)
- 再開 policy:
  - [reuseport-policy.ja.md](reuseport-policy.ja.md)
- benchmark baseline:
  - [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
