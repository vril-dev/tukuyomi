# tukuyomi Reuse-Port Evaluation

This document captures the evaluation result for experimental `SO_REUSEPORT` / multi-listener fan-out work.

`tukuyomi` does not currently ship listener fan-out. This document exists so the no-go decision is backed by exact smoke and benchmark inputs instead of memory.

## Decision

- Docker published-port behavior is not considered supported for the experimental listener fan-out path
- no stable benchmark win was shown on the evaluated local host
- listener fan-out should stay out of the supported runtime until those two points change together

## Docker published-port symptom

During evaluation, a Docker port-published runtime with the experimental listener fan-out could fail even on a simple health probe.

Observed probe:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

Observed failure:

```text
curl: (56) Recv failure: Connection reset by peer
```

This was sufficient to block shipping the feature. A direct public listener cannot be treated as production-ready if the common local Docker publish path is unstable.

## Benchmark recipe used during review

Review used the existing local benchmark harness on the same host, with only the listener topology changed between runs.

Command:

```bash
HOST_CORAZA_PORT=19090 \
WAF_LISTEN_PORT=9090 \
WAF_ADMIN_USERNAME=admin \
WAF_ADMIN_PASSWORD=dev-only-change-this-password-please \
BENCH_REQUESTS=120 \
WARMUP_REQUESTS=20 \
BENCH_CONCURRENCY=1,20 \
BENCH_DISABLE_RATE_LIMIT=1 \
./scripts/benchmark_proxy_tuning.sh
```

The benchmark compared:

- single-listener baseline
- experimental fan-out with `reuse_port=true` and `listener_count=2`

## Measured results

### Single-listener baseline

From the recorded run:

- `balanced@20`: `fail_rate=0.00%`, `p95=1019ms`, `rps=58.15`
- `low-latency@20`: `fail_rate=0.00%`, `p95=1017ms`, `rps=57.88`
- `buffered-guard@20`: `fail_rate=0.00%`, `p95=1173ms`, `rps=99.23`

### Experimental fan-out (`reuse_port=true`, `listener_count=2`)

From the recorded run:

- `balanced@20`: `fail_rate=28.33%`, `p95=5002ms`, `rps=19.81`
- `low-latency@1`: `fail_rate=100.00%` with all responses non-2xx
- `low-latency@20`: `fail_rate=100.00%` with all responses non-2xx
- `buffered-guard@1`: `fail_rate=6.67%`, `p95=3083ms`, `rps=4.34`
- `buffered-guard@20`: no clear win over the single-listener baseline

These numbers are not a "small or noisy regression". They are a no-go result.

## Interpretation

The evaluated host did not show evidence that TCP accept fan-out was the real bottleneck.

Instead, the experiment showed:

- unstable Docker published-port behavior
- large workload-dependent regressions
- no consistent throughput or latency improvement that would justify extra listener complexity

That keeps the current priority order intact:

1. upstream transport tuning
2. metrics and observability
3. backpressure and queueing behavior
4. cache/compression/runtime tuning
5. listener fan-out only if the host/runtime evidence becomes much stronger

## Reopen criteria

Do not reopen listener fan-out unless all of the following are true:

- the target host class shows a repeatable benchmark improvement
- Docker published-port smoke is clean, or the feature is explicitly scoped away from Docker-published local runtime
- the expected deployment topology is documented up front
- the measured bottleneck is clearly in listener accept distribution rather than upstream/WAF work

## Related docs

- current decision note:
  - [listener-topology.md](listener-topology.md)
- reopen policy:
  - [reuseport-policy.md](reuseport-policy.md)
- benchmark baseline:
  - [benchmark-baseline.md](benchmark-baseline.md)
