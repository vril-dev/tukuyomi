# tukuyomi Reuse-Port Host Matrix and Policy

This document defines the policy for any future re-evaluation of experimental listener fan-out in `tukuyomi`.

It does not reopen the feature. It defines where evaluation is allowed to matter, what topologies are in scope, and what benchmark/smoke gates must pass before runtime work is reconsidered.

## Policy summary

- listener fan-out remains out of the supported runtime
- any future re-evaluation must start from host/runtime policy, not from implementation enthusiasm
- Docker bridge published-port behavior is not a hard requirement for reopening the feature
- if someone wants Docker published-port support specifically, that must be scoped as a separate deliverable

## Host/runtime matrix

| Tier | Host/runtime class | Example topology | Policy status | Why |
| --- | --- | --- | --- | --- |
| A | Linux VM or bare metal, direct host bind | direct public entrypoint on `:443` | Required | This is the most credible case for listener accept fan-out |
| A | Linux container with host networking or equivalent direct socket ownership | host-network container, no bridge publish path in front | Required when containerized direct entrypoint is a target | Still close to direct socket ownership |
| B | Linux behind an external LB/CDN, but `tukuyomi` still owns the local listener directly | LB -> VM/container host network -> `tukuyomi` | Optional | Worth checking if it matches an intended deployment shape |
| C | Docker bridge + published host port | `docker compose` `19090:9090` style local runtime | Out of scope for support gating | Good local DX path, but not a reliable performance gate for listener fan-out |
| C | Desktop VM forwarding layers or other non-Linux host-network abstractions | Docker Desktop / nested forwarding | Out of scope | Too many moving parts between client and listener |

## What "required" means

A reopen discussion should not advance unless Tier A evidence exists.

That means:

- at least one Tier A host/runtime class must show a repeatable benchmark win
- the same class must pass simple listener smoke without resets or non-2xx anomalies
- the measured benefit must remain after enabling the real runtime shape used by `tukuyomi`
  - WAF
  - routing
  - retry/health logic
  - compression
  - cache

## Docker published-port policy

Docker bridge published-port behavior is treated as a separate concern.

Current policy:

- do not block a future re-evaluation solely because Docker published-port is unstable
- do not treat Docker published-port success as sufficient evidence for adoption either
- if bridge-published local/container runtime is a product requirement, schedule it as a separate task with its own smoke contract

This keeps local developer ergonomics from dictating a low-level listener decision for production-grade deployments.

## Benchmark gate shape

Any future re-evaluation should use the existing benchmark harness with a fixed side-by-side comparison.

Base command:

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

Compare:

- single-listener baseline
- candidate fan-out topology

Minimum expectations for adoption:

- no new connection-reset symptom in the target topology
- no preset/concurrency row with fail-rate above `0%`
- no row that flips to fully non-2xx under the candidate topology
- at least one meaningful improvement at target concurrency
  - either clearly better RPS
  - or clearly lower p95/p99
- no large regression in the non-improving rows

This is intentionally conservative. Listener fan-out adds platform complexity, so marginal wins are not enough.

## Smoke gate shape

At minimum, the target topology should pass:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

If TLS is part of the evaluated topology, also include an HTTPS smoke on the real listener port and any admin/API path needed for control-plane sanity.

The smoke goal is not feature coverage. It is proving that the listener topology itself is stable before spending time on deeper throughput claims.

## Reopen checklist

Do not reopen listener fan-out work unless all of the following are true:

1. the intended deployment topology is written down first
2. the evaluated host/runtime class is Tier A, or there is an explicit reason to include a Tier B class
3. benchmark comparison uses a fixed recipe
4. smoke is clean in the same topology
5. the bottleneck is argued to be listener accept distribution rather than upstream/WAF work

## Related docs

- current decision note:
  - [listener-topology.md](listener-topology.md)
- concrete evaluation evidence:
  - [reuseport-evaluation.md](reuseport-evaluation.md)
- benchmark baseline:
  - [benchmark-baseline.md](benchmark-baseline.md)
