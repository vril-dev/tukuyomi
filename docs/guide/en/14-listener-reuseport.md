# Chapter 14. Listener topology and reuse-port

This chapter covers why tukuyomi keeps a **single-listener topology**
as the supported runtime today, the rationale for not adopting
`SO_REUSEPORT` / multi-listener fan-out, and the conditions that
would justify reopening fan-out in the future.

This is not a tuning chapter for "use the latest feature today".
It is **a chapter that records, in a reproducible form, the decision
not to add complexity**. Whenever you feel the urge to tune
listener-related behavior, this is the policy to come back to.

## 14.1 The current decision

State the conclusions up front:

- **The supported runtime keeps a single TCP listener.**
- The optional HTTP redirect listener stays a single socket.
- The built-in HTTP/3 listener stays a single UDP socket.
- **`SO_REUSEPORT` / multi-listener fan-out is not adopted today.**
- The public HTTP/1.1 data-plane listener is handled by the Tukuyomi
  native HTTP/1.1 server, and the admin listener stays on a separate
  control-plane server path.

In short, **lower-level listener fan-out knobs are not added** to
`tukuyomi`.

## 14.2 Why we parked it at evaluation

The `SO_REUSEPORT` / multi-listener prototype was actually **brought to
review**; the conclusion was that **a safe, consistent improvement
could not be confirmed**.

Notable observations:

- **`connection reset by peer` was observed in smoke tests with
  Docker port-published runtimes.**
- **Local benchmarks showed strong workload-dependent variance**, with
  meaningful regressions in places rather than stable improvements.
- `tukuyomi` spends time on WAF inspection, routing, retry / health,
  compression, and cache, so **TCP accept fan-out is not necessarily
  the first bottleneck**.

That is why **tukuyomi treats the single-listener topology as the
supported runtime** today.

### 14.2.1 The Docker published-port symptom

While the experimental listener fan-out was enabled, simple health
probes against a Docker port-published runtime **failed**:

The probe used:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

The observed failure:

```text
curl: (56) Recv failure: Connection reset by peer
```

That alone is reason enough not to ship the feature. **A feature aimed
at being a direct public listener cannot be unstable on the common
local Docker publish path.**

### 14.2.2 Benchmark results

Reviews used the existing local benchmark harness on the same host
and switched only the listener topology. The command:

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

What we compared:

- Single-listener baseline.
- Experimental fan-out with `reuse_port=true` and `listener_count=2`.

#### Single-listener baseline

In the recorded run:

- `balanced@20`: `fail_rate=0.00%`, `p95=1019ms`, `rps=58.15`
- `low-latency@20`: `fail_rate=0.00%`, `p95=1017ms`, `rps=57.88`
- `buffered-guard@20`: `fail_rate=0.00%`, `p95=1173ms`, `rps=99.23`

#### Experimental fan-out (`reuse_port=true`, `listener_count=2`)

Under the same conditions, the fan-out side recorded:

- `balanced@20`: `fail_rate=28.33%`, `p95=5002ms`, `rps=19.81`
- `low-latency@1`: `fail_rate=100.00%`; all responses non-2xx
- `low-latency@20`: `fail_rate=100.00%`; all responses non-2xx
- `buffered-guard@1`: `fail_rate=6.67%`, `p95=3083ms`, `rps=4.34`
- `buffered-guard@20`: no clear improvement over the single-listener
  baseline

This is **a clear no-go**, not "a small regression" or "host noise".

## 14.3 Where to focus instead

Given the evaluation, the current direction is:

- **Keep the default single-listener topology.**
- For throughput tuning, start with **`make bench` and transport
  metrics**.
- Before reconsidering listener fan-out, **prioritize**:
  - Upstream transport tuning (Chapter 6)
  - Cache
  - Compression
  - Backpressure (Chapter 3 §3.9)

The stance is "do not act on a hunch that fan-out makes things
faster"; instead, **collect evidence that the bottleneck really is
listener accept**.

## 14.4 Host / runtime matrix

If we were to revisit listener fan-out, here is the policy for
**which host / runtime to treat as the meaningful evaluation
target**:

| Tier | Host / runtime class | Example | Policy status | Rationale |
|---|---|---|---|---|
| A | Direct host bind on Linux VM or bare metal | An entrypoint that publishes `:443` directly | **Required** | The most reliable case for evaluating accept fan-out |
| A | Linux container with host networking or equivalent direct socket ownership | A host-network container that does not use bridge publish | **Required** if a containerized direct entrypoint is the target | Behaves like direct socket ownership |
| B | Behind an external LB / CDN, with `tukuyomi` itself holding a local listener | LB → VM / host-network container → `tukuyomi` | **Optional** | Worth confirming when it matches the intended deployment shape |
| C | Docker bridge + published host port | `19090:9090` style `docker compose` | **Out of scope** as a reopen gate | Good for local DX, but not trustworthy as a performance gate for listener fan-out |
| C | Non-Linux host-network abstractions (Desktop VM forwarding, etc.) | Docker Desktop, nested forwarding | **Out of scope** | Too many variables between client and listener |

### 14.4.1 What "Required" means

Reopening **does not move forward without Tier A evidence**.
Specifically:

- A **Tier A host / runtime class** in which benchmark improvements
  reproduce.
- **A clean listener smoke** in the same class.
- **The improvement persists after enabling tukuyomi's actual runtime
  shape**:
  - WAF
  - Routing
  - Retry / health logic
  - Compression
  - Cache

## 14.5 Docker published-port policy

Treat Docker published-port as a **separate question**.

Current policy:

- **Instability under Docker published-port does not by itself
  permanently rule out future reopening.**
- **Conversely, "Docker published-port works" does not make a reopen
  case.**
- If you want to make bridge-published local / container runtime a
  product requirement, that is a **separate task with its own smoke
  contract**.

In other words, **the local-DX needs of Docker should not pull
production-grade listener decisions**.

## 14.6 Benchmark gate shape (for reopening)

A future reopen requires **a comparison against the existing benchmark
harness with a fixed recipe**.

The base command is the one from §14.2.2. The comparison is
**single-listener baseline** vs. **fan-out candidate topology**.

Minimum bar for reopening:

- **No connection-reset symptoms** on the target topology.
- **`fail_rate` does not exceed 0%** on any preset / concurrency
  row.
- **No row collapses to all non-2xx** on the candidate topology.
- **At least one meaningful improvement at the target concurrency**:
  - Clearly better RPS, **or**
  - Clearly better p95 / p99.
- **No large regression** on rows that do not improve.

This bar is intentionally strict. **Listener fan-out adds platform
complexity, so a marginal win is not a reason to ship it.**

## 14.7 Smoke gate shape

At minimum, the target topology must pass:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

If TLS is in scope, add:

- HTTPS smoke against the actual listener port.
- Sanity checks for admin / API paths if needed.

The goal of smoke is **not feature coverage**; it is to **demonstrate
that the listener topology itself is stable**.

## 14.8 Reopen checklist

Listener fan-out can be reopened **only when all of these are
satisfied**:

1. **The intended deployment topology is documented first.**
2. The evaluation target is **Tier A** (or, with explicit
   justification, Tier B).
3. The benchmark comparison uses **a fixed recipe**.
4. **Smoke is clean** on the same topology.
5. There is an explanation that the bottleneck **is in listener accept
   distribution**, not in upstream / WAF.

## 14.9 Recap

- `SO_REUSEPORT` / multi-listener fan-out is **not adopted** today.
  Single-listener is the supported runtime.
- The evaluation found Docker published-port `connection reset` and
  large fail-rate increases in benchmarks.
- Bottleneck evidence sits with WAF / routing / cache, so we
  prioritize upstream transport tuning, metrics, backpressure, cache,
  and compression first.
- Reopening is gated on **Tier A benchmark improvements + clean smoke
  + a bottleneck explanation**.

## 14.10 Bridge to the next chapter

We have framed the listener topology. Chapter 15 covers what runs on
that single listener — **HTTPS and HTTP/3** — including built-in TLS
termination, ACME automatic refresh, the dedicated UDP listener for
HTTP/3, and HTTP/3 public-entry smoke.
