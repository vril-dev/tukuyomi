# Chapter 18. Static fast-path evaluation

Closing Part VII, this chapter records tukuyomi's stance on **static
fast-paths and zero-copy**. As with Chapter 14 (listener fan-out /
reuse-port), the goal is to **document the decision *not to do
something* in a reproducible form**.

## 18.1 The decision — not pursuing it

`tukuyomi` is **not a pure file-serving proxy** like `nginx`. Given
the current runtime responsibilities, the conclusion is:

> **A general-purpose static fast-path / zero-copy implementation is
> not on the roadmap today.**

## 18.2 Why not

`tukuyomi`'s response handling still has multiple layers that are
**naturally handled in user space**:

- **WAF inspection** on the request side always runs before going
  upstream.
- **Route selection / retry / health / circuit** decisions go into
  upstream selection.
- **Response-header sanitation** applies to both live responses and
  cached replays.
- **Client-facing compression** requires body buffering for
  transformable responses.
- **Cache replay** still injects request-scoped headers like
  `X-Request-ID` and WAF hit metadata.

So an `nginx`-style **`sendfile` generic fast-path** would help only
a small fraction of responses while raising the complexity of the
ordinary runtime.

## 18.3 Where zero-copy fits poorly

To make the abstract claim concrete, two specific places:

### 18.3.1 Live upstream responses

- The body usually arrives over an **upstream socket, not a local
  file**.
- `tukuyomi` may run **buffering / compression / sanitize / retry**
  around it.
- **Cleanly handing off** to zero-copy after that layer is hard.

### 18.3.2 Cache replay as a general strategy

- **Cached replay already avoids upstream latency.**
- The current cache design has two stages:
  - **A bounded L1 memory replay.**
  - **A file-backed L2 replay.**
- Once L1 is enabled, **the surface area where "optimizing only the
  disk hit" still wins is narrow**.

In short, the typical scenarios where one feels "static fast-path
would speed this up" are largely already absorbed by the cache. The
question is whether further reduction to zero-copy actually pays in
real workloads.

## 18.4 Bounded fast-paths already in place

`tukuyomi` already includes **smaller, workload-fit optimizations**
rather than a generic static-file fast-path:

- **Cache hits replay from the in-memory front cache**, avoiding disk
  reads.
- **Even file-backed cache hits avoid the upstream call.**
- **Upgrade / WebSocket traffic** does not go through buffering or
  response compression.
- Runtime presets (Chapter 17) let you switch among **low-latency**
  and **buffered-control** modes.

The design is "**add bounded fast-paths matched to specific use
cases**", not "make every response zero-copy".

## 18.5 Conditions for reopening

The policy may reopen **only when, with the current cache and
compression stance applied, cached body replay is empirically the
bottleneck**.

At minimum, one of the following needs to hold:

- **Cache-hit body transfer for large immutable assets** dominates
  request latency.
- **CPU time concentrates in the cache replay copy path**, not in
  WAF / routing / compression.
- **The majority of the target workload is cache-hit static
  delivery**, with the security / rewrite layer effectively a no-op.

In other words, **without that evidence, the policy is not to steer
toward "introduce a sendfile-style fast-path"**.

## 18.6 The narrow slice if reopened

Even when reopened in the future, the **slice is kept extremely
narrow**:

- Targeting only **the file-backed cache replay body path**.
- **No change to live upstream proxying.**
- **Request WAF inspection is not bypassed.**
- **Response-header sanitation is not bypassed.**
- Cache-safety rules around **auth / cookie / API path / `Set-Cookie`**
  are not weakened.

The slice is **not an architectural promise; it is an experiment with
benchmarks attached**. The hard commitment is that **tukuyomi's
safety boundaries — security / sanitize / cache-safety rules — do
not slip** through any optimization.

## 18.7 Recap

- A generic static fast-path / zero-copy is **not adopted**.
- The reason is that `tukuyomi`'s response processing has multiple
  **user-space-bound layers** (WAF / routing / sanitize / compression
  / header injection on cache replay).
- **Bounded fast-paths already exist** (in-memory L1 cache, the
  file-backed L2, upgrade tunneling, runtime presets).
- Reopening is justified **only with empirical evidence that the
  cache replay copy path is the bottleneck**, and even then WAF /
  sanitize / cache-safety rules do not bend.

## 18.8 Bridge to the next chapter

The main body ends here. The appendices that follow gather the
**operator reference** (every block of `data/conf/config.json` and
DB `app_config_*`, the admin API, the Make target index) — which
many earlier chapters reference — into a dictionary you can read
alongside the prose.

Finally, **Appendix B** collects the v1.2.0 release notes for the
feature set behind this edition.
