# tukuyomi Benchmark Baseline

This document defines how to use the local benchmark targets as repeatable tuning and release-readiness benchmarks for `tukuyomi`.
It is intentionally operator-facing: the goal is to make benchmark runs comparable without reading the shell script first.

## Benchmark commands

| Command | Purpose | Output |
| --- | --- | --- |
| `make bench` | Backward-compatible alias for `make bench-proxy` | proxy tuning artifacts |
| `make bench-proxy` | Compare proxy transport presets | `proxy-benchmark-summary.*` |
| `make bench-waf` | Compare WAF allow/block inspection scenarios | `waf-benchmark-summary.*` |
| `make bench-full` | Run proxy and WAF benchmarks in order | both artifact sets |

## What `make bench-proxy` does

`make bench` and `make bench-proxy` are wrappers around `./scripts/benchmark_proxy_tuning.sh`.
The script:

- starts the local `tukuyomi` compose stack
- launches a temporary concurrent Go upstream mock from `scripts/benchmark_upstream.go`
- applies proxy presets through `/tukuyomi-api/proxy-rules`
- measures the normal proxy listener path, including WAF inspection, unless `BENCH_PROXY_MODE=proxy-only` is explicitly set
- warms the route
- runs ApacheBench (`ab`) against the target path
- optionally captures CPU / heap / allocation profiles when `BENCH_PROFILE=1`
- restores proxy rules, rate-limit rules, benchmark-disabled request-security guard files, and temporary proxy-only WAF bypass settings at the end

Use it to compare proxy tuning presets and to catch large regressions before release work.

## What `make bench-waf` does

`make bench-waf` is a wrapper around `./scripts/benchmark_waf.sh`.
The script:

- starts the local `tukuyomi` compose stack
- launches a temporary concurrent Go upstream mock from `scripts/benchmark_upstream.go`
- applies a stable benchmark proxy route through `/tukuyomi-api/proxy-rules`
- optionally disables rate-limit rules during the run
- optionally disables bot-defense, semantic, and IP-reputation guard files during the run so WAF/proxy measurements are not mixed with challenge/block side effects
- probes each WAF scenario for the expected status before measuring
- runs ApacheBench (`ab`) for each scenario and concurrency level
- restores proxy rules and rate-limit rules at the end

Default WAF scenarios:

| Scenario | Expected status | Purpose |
| --- | ---: | --- |
| `allow` | `200` | Benign request that should pass WAF inspection |
| `block-xss` | `403` | Encoded XSS query that should be blocked by CRS |

Use it to compare WAF inspection throughput and latency after request-inspection, CRS, bypass, or logging changes.
Do not use it as a replacement for `make gotestwaf`; GoTestWAF remains the broader WAF effectiveness and false-positive regression.

## When to run it

Recommended use cases:

- after changing proxy transport behavior
  - `force_http2`
  - buffering
  - timeouts
  - response compression
- before release if the runtime path changed in a way that could affect throughput or latency
- when comparing one proxy preset against another on the same machine

Do not treat this as an exact production-capacity model. It is a controlled local baseline, not a load lab.
The bundled upstream mock is a small Go HTTP server, so the allow/proxy path is not capped by Python `http.server` serialization under higher concurrency.

## Standard command

```bash
make bench
```

This expands to `./scripts/benchmark_proxy_tuning.sh` with the current `BENCH_*` environment variables.

Recommended explicit run for human review:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

Use the default `BENCH_PROXY_MODE=current` result when you need the current production-shaped proxy path, which includes WAF inspection.
Use `BENCH_PROXY_MODE=proxy-only` only when profiling proxy hot-path overhead separately from WAF inspection.

Recommended combined run when both proxy transport and WAF inspection could be affected:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench-full
```

## Prerequisites

- Docker and Docker Compose are available
- `ab` is installed locally
- `curl`, `jq`, and Go are available
- the machine is quiet enough that repeated runs are comparable

If you want to compare two branches, use the same host, concurrency levels, and request count for both runs.

## Benchmark inputs

| Variable | Default | Meaning |
| --- | --- | --- |
| `BENCH_REQUESTS` | `120` via Makefile, `600` script fallback | Measured requests per preset/concurrency row; use `>=600` for decision runs |
| `WARMUP_REQUESTS` | `20` via Makefile, `100` script fallback | Warm-up requests sent before measurement |
| `BENCH_CONCURRENCY` | `1,10,50` | Comma-separated concurrency levels |
| `BENCH_PATH` | `/bench` | Path requested through `tukuyomi` |
| `BENCH_TIMEOUT_SEC` | `30` | ApacheBench timeout |
| `BENCH_DISABLE_RATE_LIMIT` | `1` | Temporarily disable rate-limit rules during the run |
| `BENCH_DISABLE_REQUEST_GUARDS` | `1` | Temporarily disable bot-defense, semantic, and IP-reputation guards during the run |
| `BENCH_ACCESS_LOG_MODE` | `full` | Proxy rules `access_log_mode`; use `off` or `minimal` for throughput investigations |
| `BENCH_CLIENT_KEEPALIVE` | `1` | Pass `-k` to ApacheBench when `1`; set `0` for the older connection-churn baseline |
| `BENCH_PROXY_MODE` | `current` | `current` includes WAF inspection; `proxy-only` temporarily bypasses WAF inspection for `BENCH_PATH` |
| `BENCH_PROXY_ENGINE` | `tukuyomi_proxy` | Temporarily writes `proxy.engine.mode` in `conf/config.json`; set `net_http` only for compatibility comparisons |
| `BENCH_PROFILE` | `0` | Set to `1` to capture pprof CPU, heap, and allocation artifacts |
| `BENCH_PROFILE_ADDR` | `127.0.0.1:6060` | Loopback-only pprof listener address inside the container |
| `BENCH_PROFILE_SECONDS` | `10` | CPU profile capture duration |
| `BENCH_MAX_FAIL_RATE_PCT` | unset | Optional fail gate per row |
| `BENCH_MIN_RPS` | unset | Optional minimum RPS gate per row |
| `WAF_BENCH_SCENARIOS` | `allow,block-xss` | Comma-separated WAF scenarios for `make bench-waf` |
| `UPSTREAM_PORT` | auto | Temporary upstream port; leave unset to avoid local port collisions |
| `OUTPUT_FILE` | `data/logs/proxy/proxy-benchmark-summary.md` | Human-facing Markdown summary output |
| `OUTPUT_JSON_FILE` | `data/logs/proxy/proxy-benchmark-summary.json` | Machine-readable JSON output |

## Source of truth output

Proxy benchmark source of truth:

- Markdown summary: `data/logs/proxy/proxy-benchmark-summary.md`
- Machine-readable JSON: `data/logs/proxy/proxy-benchmark-summary.json`
- Optional raw profiles: `data/logs/proxy/proxy-benchmark-*.pprof`

WAF benchmark source of truth:

- Markdown summary: `data/logs/proxy/waf-benchmark-summary.md`
- Machine-readable JSON: `data/logs/proxy/waf-benchmark-summary.json`

These files are the source of truth for:

- branch-to-branch comparisons
- release notes
- tuning discussions
- automation that should not parse Markdown

The summary records:

- preset
- scenario, for WAF benchmark rows
- expected status and probe status, for WAF benchmark rows
- concurrency
- requests
- failures / non-2xx count
- fail rate or unexpected response-family rate
- average / p95 / p99 latency
- measured RPS
- whether rate limiting was disabled
- whether request-security guards were disabled
- proxy access log mode
- client keep-alive mode
- temporary upstream port
- benchmark mode (`current` or `proxy-only`)
- profile capture status and artifact paths

The JSON artifact keeps the same run metadata plus a stable `rows[]` array for preset/concurrency or scenario/concurrency comparisons.

## Hot Path Logging

Framework request logging is disabled by default because it duplicates the product proxy access log.
Enable `observability.request_log.enabled=true` only for temporary troubleshooting when raw Gin request logs are needed.
Keep it `false` for performance benchmarks.

Proxy benchmarks enable client keep-alive by default. Set `BENCH_CLIENT_KEEPALIVE=0` only when you need to reproduce the older ApacheBench connection-churn baseline.

## Profile Capture

Profile capture is disabled by default. To capture profiles for the normal proxy + WAF inspection path:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
make bench-proxy
```

To isolate proxy hot-path cost from WAF inspection, run the same conditions with a temporary WAF bypass for the benchmark path:

```bash
BENCH_REQUESTS=600 \
WARMUP_REQUESTS=100 \
BENCH_CONCURRENCY=1,10,50 \
BENCH_PROFILE=1 \
BENCH_PROXY_MODE=proxy-only \
make bench-proxy
```

The pprof server is opt-in, binds only to loopback inside the container, and is not published through the public proxy port.
Raw `.pprof` files are local investigation artifacts; do not commit them. Commit or paste only the interpreted summary needed for review.

## Threshold policy

Thresholds are optional and should be used intentionally.

Example:

```bash
BENCH_MAX_FAIL_RATE_PCT=0.5 \
BENCH_MIN_RPS=300 \
BENCH_CONCURRENCY=10,50 \
BENCH_DISABLE_RATE_LIMIT=1 \
make bench
```

Rules:

- use `BENCH_MAX_FAIL_RATE_PCT` when the run must fail on instability
- for `make bench-waf`, `BENCH_MAX_FAIL_RATE_PCT` gates the unexpected response-family rate after an exact preflight status probe
- use `BENCH_MIN_RPS` when you have a known machine-local baseline to defend
- do not reuse one machine's `BENCH_MIN_RPS` on a different runner without recalibration
- if you intentionally want rate-limit behavior included, set `BENCH_DISABLE_RATE_LIMIT=0` and record that explicitly in the review
- if you intentionally want bot-defense, semantic, or IP-reputation behavior included, set `BENCH_DISABLE_REQUEST_GUARDS=0` and record that explicitly in the review
- treat single-run `BENCH_REQUESTS<600` output as smoke data only; decision baselines need `BENCH_REQUESTS>=600` or three same-condition runs with median reporting

## Why this is not a normal CI gate

`make bench` is not part of `ci-local` or normal GitHub CI because:

- results are too sensitive to host noise
- container startup and local tool differences add variance
- `ab` is not guaranteed on every developer machine or CI runner
- the script intentionally mutates runtime proxy rules and, by default, temporarily disables rate-limit and request-security guard files

This command is a human-reviewed performance baseline, not a deterministic unit test.

The JSON artifact makes later automation possible, but this task does not move benchmark execution into normal CI.

## How to compare runs

When using the benchmark as a release/tuning baseline:

1. keep `BENCH_REQUESTS`, `WARMUP_REQUESTS`, and `BENCH_CONCURRENCY` identical across runs
2. keep `BENCH_DISABLE_RATE_LIMIT` identical across runs
3. keep `BENCH_PROXY_MODE` identical when comparing RPS or latency
4. keep `BENCH_PROXY_ENGINE` explicit; compare `net_http` and `tukuyomi_proxy` as separate runs
5. compare the generated Markdown summaries side by side
6. focus on trend shifts, not single-run noise

Good comparison questions:

- Did fail rate change from zero to non-zero?
- Did p95/p99 latency regress materially for the same preset and concurrency?
- Did one preset stop being meaningfully better than another?
- For WAF rows, did the allow path stay 200 and the block path stay 403 before load was measured?
- Did WAF block latency or RPS shift materially for the same scenario and concurrency?

## Current presets

| Preset | Main knobs | Suggested use |
| --- | --- | --- |
| `balanced` | `force_http2=false`, `disable_compression=false`, `buffer_request_body=false`, `flush_interval_ms=0` | General default |
| `low-latency` | `force_http2=false`, `disable_compression=true`, `buffer_request_body=false`, `flush_interval_ms=0` | API / SSE style lower-latency workloads |
| `buffered-guard` | `force_http2=false`, `buffer_request_body=true`, `max_response_buffer_bytes=1048576`, `flush_interval_ms=0` | Stronger buffering and response-size control |

## Related docs

- regression command map: [regression-matrix.md](regression-matrix.md)
- WAF regression: [README.md#WAF-Regression-Test-GoTestWAF](../../README.md#WAF-Regression-Test-GoTestWAF)
