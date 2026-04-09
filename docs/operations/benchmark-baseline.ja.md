[English](benchmark-baseline.md) | [日本語](benchmark-baseline.ja.md)

# Benchmark Baseline

このドキュメントは、front proxy 依存を段階的に減らしていく中で、
tukuyomi の runtime profile を比較するための軽量 benchmark harness を説明します。

## 何を測るか

benchmark runner は次を記録します。

- requests/sec
- error rate
- p50 / p95 / p99 latency
- 実行前後の Docker CPU / memory のスナップショット

目的は production sizing ではなく、commit 間の比較です。

## Baseline Scenarios

現時点の baseline matrix は次です。

- `api-gateway front pass`
- `api-gateway direct pass`
- `api-gateway front block`
- `api-gateway direct block`
- `nextjs front cache`
- `nextjs direct cache`
- 低頻度の admin side traffic を入れた `nextjs front cache`

これらは今ある example stack に対応しています。

- `front`: `client -> nginx -> tukuyomi -> app`
- `direct`: `client -> tukuyomi -> app`

将来 thin-front fixture ができた場合も、`BENCH_BASE_URL=... BENCH_SKIP_STACK_UP=1`
で同じ runner を使えます。

## Commands

1 シナリオだけ回す場合:

```bash
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
```

標準 baseline matrix を回す場合:

```bash
make benchmark-baseline
```

admin side traffic を載せる場合:

```bash
BENCH_ADMIN_SIDE_TRAFFIC=1 \
make benchmark-scenario EXAMPLE=nextjs TOPOLOGY=front SCENARIO=cache
```

direct の in-memory cache を計測したい場合:

```bash
make benchmark-scenario EXAMPLE=nextjs TOPOLOGY=direct SCENARIO=cache
```

rate-limit を有効のまま benchmark したい場合:

```bash
BENCH_DISABLE_RATE_LIMIT=0 \
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
```

## Output

結果は `artifacts/benchmarks/<timestamp>/` に出力されます。

各 report には次が入ります。

- benchmark summary JSON
- 実行前の Docker stats snapshot
- 実行後の Docker stats snapshot

例:

```bash
artifacts/benchmarks/20260406-160000/api-gateway-front-pass.json
```

## Notes

- cache 系の測定は default では `front` topology で使います。
  direct の `client -> tukuyomi -> app` を測りたい場合は、
  `TOPOLOGY=direct SCENARIO=cache` で harness が
  `WAF_RESPONSE_CACHE_MODE=memory` を自動で有効にします。
- harness は repo 内で閉じています。`go run ./cmd/httpbench` と
  `examples/` の Docker Compose を使います。
- runner が example stack を自分で起動する場合は、baseline を
  policy throttling のノイズで汚さないために、example の rate-limit を
  default で無効化します。
- matrix は直列実行前提です。各 scenario の開始前に対象 Compose project を
  一度 reset します。
- 数値は、同じ machine・同じ concurrency 条件で比較して使ってください。
