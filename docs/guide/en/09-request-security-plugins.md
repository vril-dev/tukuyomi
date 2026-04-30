# Chapter 9. Request-time security plugins

Chapters 7 and 8 covered post-processing of the Coraza WAF result.
This chapter covers tukuyomi's separate axis — the **request-time
security extension plugin model**.

`tukuyomi` accepts request-time security extensions as
**compile-time plugins** under `server/internal/handler`. This is
deliberately static — **Go runtime `.so` plugins are not used**. The
extension point is meant for "internal extension" at source level,
not for crossing an ABI.

## 9.1 The boundary — metadata resolver vs. request-security plugin

Start with **where `request_security_plugins` sits**. It is no longer
the first request-extension layer.

Before request-security plugins run, `[proxy]` runs
**`request_metadata_resolvers`**. This is an enrichment-only phase
responsible for normalizing typed request metadata such as:

- Client IP
- Country
- Country source (`header` or `mmdb`)

The current ordering is:

1. Proxy request entry
2. **Request metadata resolvers**
3. Country block
4. Rate limit
5. **Request-security plugins**
6. WAF / CRS

The rules are clean:

- **Metadata resolvers do enrichment only — they do not block /
  challenge.**
- **Request-security plugins are the decision layer** (block or not).
- **CRS plugins are a separate rule-bundle surface** (handled inside
  Coraza).

Said differently, country resolution via a MaxMind-compatible `.mmdb`
**belongs to the metadata resolver layer, not to
`request_security_plugins`**.

## 9.2 Plugin interface

A plugin implements:

```go
type requestSecurityPlugin interface {
    Name() string
    Phase() requestSecurityPluginPhase
    Enabled() bool
    Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool
}
```

- `Phase()` returns one of:
  - `requestSecurityPluginPhasePreWAF`
  - `requestSecurityPluginPhasePostWAF`
- The return of `Handle(...)`:
  - `true`: continue to the next plugin.
  - `false`: the request is considered handled or blocked; stop the
    chain.

`requestSecurityPluginContext` provides normalized request metadata to
plugins — request ID, client IP, country, current time, semantic
evaluation state, and so on.

## 9.3 The canonical `SecurityEvent` contract

Plugins do not just run alone; they can **publish a canonical
in-process security event** for cooperation with built-ins and other
plugins. Built-in and internal extensions can publish this canonical
event through `requestSecurityPluginContext`.

Stable fields on the event model:

- `event_id`
- `ts`
- `req_id`
- `trace_id`
- `client_ip`
- `country`
- `path`
- `phase`
- `source_plugin`
- `family`
- `event_type`
- `action`
- `enforced`
- `dry_run`
- `risk_score`
- `status`
- `attributes`

This is an **internal contract for cross-plugin behavior**. **It does
not replace JSON logs or the security audit trail; it complements
them.** Three surfaces exist independently — keep that distinction
clear.

### 9.3.1 Context helpers

`requestSecurityPluginContext` exposes the helpers needed to manage
events:

- `ctx.publishSecurityEvent(...)`
- `ctx.SecurityEvents()`
- `ctx.SubscribeSecurityEvents(...)`
- `ctx.newSecurityEvent(...)`
- `ctx.deriveSecurityEvent(...)`

Basic flow:

1. Construct a canonical event at the actual decision point.
2. Publish it as soon as the decision is final.
3. Downstream subscribers **within the same request** react
   **synchronously**.
4. Operator-facing JSON logs / audit records are kept as a **separate
   surface**.

### 9.3.2 Ordering and visibility

- **Ordering is deterministic** and follows the actual request path.
- **Subscribers see only events that have already happened** (no
  peeking into the future).
- **The bus is per-request and in-process only.** It does not cross
  process / request boundaries.
- **Derived events from feedback are appended in runtime order**, so a
  subscriber may observe both the original event and the synchronous
  feedback event.

### 9.3.3 Dry-run semantics

- `dry_run=true` represents a **would-enforce** outcome: nothing was
  actually blocked.
- `enforced=true` means the **runtime actually applied** the action.
- **Feedback consumers should check both fields before mutating shared
  state.** (Do not, for example, build a penalty out of `enforced=true`
  alone.)

Built-in examples:

- `bot_challenge_dry_run` publishes `dry_run=true` and **does not**
  produce live challenge-failure penalty state.
- `rate_limited` publishes `enforced=true` **only when the request was
  actually throttled**.

### 9.3.4 Bounded shared feedback

When you build a feedback loop across plugins, restrict it to
**bounded in-memory state**:

- Do not build unbounded per-request / per-identity maps.
- Prefer TTL- or window-based accumulators.
- Make feedback **idempotent** when possible.
- Restrict `attributes` to **structured metadata for known
  consumers**. Do not abuse it as a dumping ground for large log
  objects.

## 9.4 Registration

A plugin registers itself through a registration helper called from
`init()`:

```go
func init() {
    registerRequestSecurityPlugin(newMyPlugin)
}
```

The factory signature:

```go
type requestSecurityPluginFactory func() requestSecurityPlugin
```

Current built-in registration lives in
`request_security_plugins.go`. The three built-ins are:

- `ip_reputation`
- `bot_defense`
- `semantic`

These correspond to the Gateway UI's `IP Reputation` /
`Bot Defense` / `Semantic Security` screens.

## 9.5 File placement

New plugin files go under:

```
server/internal/handler/
```

Recommended naming:

```
my_feature_request_security_plugin.go
```

## 9.6 Minimal example

A minimal plugin that aborts with `451` whenever it sees
`X-Tukuyomi-Sample-Block: 1`:

```go
package handler

import "github.com/gin-gonic/gin"

type sampleRequestSecurityPlugin struct{}

func init() {
    registerRequestSecurityPlugin(newSampleRequestSecurityPlugin)
}

func newSampleRequestSecurityPlugin() requestSecurityPlugin {
    return &sampleRequestSecurityPlugin{}
}

func (p *sampleRequestSecurityPlugin) Name() string {
    return "sample"
}

func (p *sampleRequestSecurityPlugin) Phase() requestSecurityPluginPhase {
    return requestSecurityPluginPhasePreWAF
}

func (p *sampleRequestSecurityPlugin) Enabled() bool {
    return true
}

func (p *sampleRequestSecurityPlugin) Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool {
    if c.GetHeader("X-Tukuyomi-Sample-Block") == "1" {
        c.AbortWithStatus(451)
        return false
    }
    return true
}
```

That alone adds the sample plugin to the built-in chain in the pre-WAF
phase.

## 9.7 Build and test

Because this is a compile-time extension, source files placed under
`server/internal/handler/` are **picked up automatically** by the
regular build. There is no `.so` loading or registry file to edit.

Useful verification commands:

```bash
cd server
go test ./internal/handler ./...
```

At minimum, confirm that the new plugin builds and existing tests pass
before opening a PR.

## 9.8 Design rules

To close, the rules to keep in mind when writing a plugin:

- **Make plugin behavior deterministic and fail-safe.** The same input
  yields the same decision; on failure, fall safely.
- **Prefer the runtime store and helpers over direct file I/O.** A
  plugin that reads or writes files directly tends to break in
  containerized / replicated deployments.
- When you **block / challenge** a request or **hand it off to
  downstream security logic**, publish a canonical `SecurityEvent`.
- **Keep admin / config compatibility intact even when replacing
  built-in behavior.**
- **Treat this as an internal extension point, not a stable
  third-party plugin ABI.** Breaking changes can happen across
  internal commits, so plan to build / distribute internally.

## 9.9 Recap

- `request_security_plugins` is the decision layer. Enrichment is the
  metadata resolver's responsibility.
- The plugin interface has four methods — `Name / Phase / Enabled /
  Handle`. `Phase` is preWAF or postWAF.
- Plugins cooperate within a single request by publishing
  `SecurityEvent` on the bus.
- Distinguish dry_run from enforced; keep feedback bounded.
- Registration is `registerRequestSecurityPlugin(...)` in `init()`,
  files go under `server/internal/handler/`.

## 9.10 Bridge to the next chapter

Part IV covered the **edge-security side** of tukuyomi — Coraza false
positives, FP Tuner, and the request-time security plugin model.
Part V switches to **Runtime Apps** — PHP-FPM and PSGI runtimes, plus
scheduled tasks — that run after the edge.
