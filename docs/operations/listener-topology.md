# tukuyomi Listener Topology

This document records the current listener-topology decision for `tukuyomi`.

## Current decision

- keep the supported runtime as a single TCP listener
- keep the optional HTTP redirect listener single-socket
- keep the built-in HTTP/3 listener as a single UDP socket
- do not ship `SO_REUSEPORT` / multi-listener fan-out in the current runtime
- serve the public HTTP/1.1 data-plane listener with Tukuyomi's native
  HTTP/1.1 server; keep the admin listener on the separate control-plane
  server path

The current answer is no: `tukuyomi` does not expose a lower-level listener fan-out knob.

## Why this stays evaluation-only

An experimental `SO_REUSEPORT` / multi-listener implementation was exercised, but it did not show safe or consistent wins.

Observed during review:

- Docker port-published smoke could hit `connection reset by peer`
- local benchmark runs showed strong workload skew and, in some cases, severe regressions rather than stable gains
- `tukuyomi` already spends meaningful time in WAF inspection, routing, retry/health logic, compression, and cache behavior, so TCP accept fan-out is not assumed to be the first bottleneck

Because of that, `tukuyomi` keeps the simpler single-listener topology as the supported runtime.

## What to do instead

- keep the default single-listener topology
- use `make bench` and transport metrics first when chasing throughput issues
- prioritize upstream transport tuning, cache behavior, compression, and backpressure before revisiting listener fan-out

## Follow-up

If listener fan-out is reconsidered later, it should be reintroduced only after:

- a repeatable benchmark win on the target host class
- a clean Docker/published-port smoke story
- clear evidence that listener accept distribution, not upstream/WAF work, is the dominant bottleneck

## Related docs

- benchmark baseline: [benchmark-baseline.md](benchmark-baseline.md)
- reuse-port evaluation: [reuseport-evaluation.md](reuseport-evaluation.md)
- reuse-port host matrix and policy: [reuseport-policy.md](reuseport-policy.md)
- HTTP/3 public-entry smoke: [http3-public-entry-smoke.md](http3-public-entry-smoke.md)
