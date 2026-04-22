# Static Fast-Path Evaluation

`tukuyomi` is not a file-serving proxy in the `nginx` / `sendfile` sense. This document records whether a static fast-path or zero-copy strategy is worth pursuing after the current runtime responsibilities were re-checked.

## Decision

Do not pursue a general static fast-path or zero-copy implementation right now.

## Why

`tukuyomi` still spends meaningful work in layers that naturally keep response handling in user space:

- request-side WAF inspection still runs before the upstream request is allowed through
- route selection, retry, health state, and circuit logic still decide which upstream is used
- response header sanitation still runs on live responses and cached replays
- client-facing compression still requires buffered bodies for transformable responses
- cache replay still reinjects request-scoped headers such as `X-Request-ID` and WAF hit metadata

This means a generic "sendfile like nginx" path would only help a narrow subset of responses while adding complexity to the normal runtime.

## Where zero-copy does not fit well

### Live upstream responses

- The body usually arrives from an upstream socket, not from a local file
- `tukuyomi` may still buffer, compress, sanitize, or retry around that response
- Go's reverse-proxy path does not expose a clean zero-copy handoff once those layers are in play

### Cached responses as a general strategy

- Cached replays already avoid upstream latency
- The current cache design now has:
  - bounded L1 memory replay
  - file-backed L2 replay
- Once L1 is enabled, the remaining disk-hit population is narrower than before

## Existing bounded fast-paths

`tukuyomi` already has smaller optimizations that match its workload better than a generic static-file fast-path:

- cache hits can now replay from the in-memory front cache without re-reading the body from disk
- file-backed cache hits avoid upstream calls entirely
- upgrade / websocket style traffic bypasses buffering and response compression
- runtime knobs already allow low-latency vs buffered/control-heavy presets

## What would justify reopening this

Only reopen this work if profiling shows a real bottleneck in cached body replay after the current cache stack and compression choices are applied.

Concrete evidence should show at least one of these:

- cache-hit body transfer dominates request latency for large immutable assets
- CPU time clusters around cache replay copy paths rather than WAF / routing / compression
- the target workload is mostly cache-hit static delivery where security and rewrite layers are effectively no-ops

## Narrow future slice if reopened

If this is reopened later, keep it extremely small:

- evaluate only the file-backed cache replay body path
- do not change live upstream proxying
- do not bypass request WAF inspection
- do not bypass response header sanitation
- do not weaken cache safety rules around auth, cookies, API paths, or `Set-Cookie`

That slice should be treated as a benchmarked experiment, not as an architectural promise.
