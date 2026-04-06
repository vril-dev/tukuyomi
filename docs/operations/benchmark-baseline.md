[English](benchmark-baseline.md) | [日本語](benchmark-baseline.ja.md)

# Benchmark Baseline

This document describes the lightweight benchmark harness used to compare `[web]`
runtime profiles while the front-proxy dependency shifts over time.

## What It Measures

The benchmark runner records:

- requests/sec
- error rate
- p50 / p95 / p99 latency
- one-shot Docker CPU and memory snapshots before and after the run

It is intended for commit-to-commit comparison, not production sizing.

## Baseline Scenarios

Current baseline matrix:

- `api-gateway front pass`
- `api-gateway direct pass`
- `api-gateway front block`
- `api-gateway direct block`
- `nextjs front cache`
- `nextjs front cache` with low-rate admin side traffic

Those scenarios map to the currently available example stacks:

- `front`: `client -> nginx -> tukuyomi -> app`
- `direct`: `client -> tukuyomi -> app`

When a future thin-front fixture exists, the same runner can target it with
`BENCH_BASE_URL=... BENCH_SKIP_STACK_UP=1`.

## Commands

Run one scenario:

```bash
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
```

Run the standard baseline matrix:

```bash
make benchmark-baseline
```

Add admin side traffic:

```bash
BENCH_ADMIN_SIDE_TRAFFIC=1 \
make benchmark-scenario EXAMPLE=nextjs TOPOLOGY=front SCENARIO=cache
```

Keep rate-limit enabled while benchmarking:

```bash
BENCH_DISABLE_RATE_LIMIT=0 \
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
```

## Output

Results are written under `artifacts/benchmarks/<timestamp>/`.

Each report contains:

- benchmark summary JSON
- Docker stats snapshot before the run
- Docker stats snapshot after the run

Example:

```bash
artifacts/benchmarks/20260406-160000/api-gateway-front-pass.json
```

## Notes

- Cache-focused measurements are meaningful on the `front` topology by default.
  For direct `client -> tukuyomi -> app` measurements, enable
  `WAF_RESPONSE_CACHE_MODE=memory` in the target stack first.
- The harness intentionally uses repo-local tooling: `go run ./cmd/httpbench`
  plus Docker Compose stacks from `examples/`.
- When the runner starts an example stack itself, it disables example
  rate-limit rules by default so the baseline reflects proxy/WAF/app throughput
  rather than policy throttling noise.
- The matrix is intended to run sequentially. Each scenario resets its target
  Compose project before startup.
- Numbers are useful when compared on the same machine and same concurrency
  settings.
