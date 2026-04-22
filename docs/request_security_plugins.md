[English](request_security_plugins.md) | [日本語](request_security_plugins.ja.md)

# Request-Time Security Plugins

`tukuyomi` supports request-time security extensions as compile-time plugins inside `coraza/src/internal/handler`.

This is intentionally static and does not use Go runtime `.so` plugins.

## Boundary: metadata resolvers vs request-security plugins

`request_security_plugins` are not the first request-extensibility layer
anymore.

Before request-security plugins run, `[proxy]` now executes
`request_metadata_resolvers`.

That enrichment-only phase is responsible for normalizing typed request
metadata such as:

- client IP
- country
- country source (`header` or `mmdb`)

Current order is:

1. proxy request entry
2. request metadata resolvers
3. country block
4. rate limit
5. request-security plugins
6. WAF / CRS

Rules:

- metadata resolvers enrich context only
- metadata resolvers do not block/challenge requests
- request-security plugins are still the decision layer
- CRS plugins remain a separate rule-bundle surface

This means MaxMind-compatible `.mmdb` country resolution belongs to the
metadata resolver layer, not to `request_security_plugins`.

## Plugin Interface

Plugins use this interface:

```go
type requestSecurityPlugin interface {
    Name() string
    Phase() requestSecurityPluginPhase
    Enabled() bool
    Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool
}
```

- `Phase()`:
  - `requestSecurityPluginPhasePreWAF`
  - `requestSecurityPluginPhasePostWAF`
- `Handle(...)` return value:
  - `true`: continue to the next plugin
  - `false`: request handled or blocked, stop the chain

`requestSecurityPluginContext` provides normalized request metadata such as request ID, client IP, country, current time, and semantic evaluation state.

## Canonical `SecurityEvent` Contract

Built-ins and internal extensions can publish canonical in-process security events through `requestSecurityPluginContext`.

The event model is intentionally explicit:

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

This is an internal contract for cross-plugin behavior. It complements JSON logs and the security-audit trail; it does not replace them.

### Context helpers

`requestSecurityPluginContext` exposes:

- `ctx.publishSecurityEvent(...)`
- `ctx.SecurityEvents()`
- `ctx.SubscribeSecurityEvents(...)`
- `ctx.newSecurityEvent(...)`
- `ctx.deriveSecurityEvent(...)`

Typical flow:

1. Create a canonical event near the actual decision point.
2. Publish it immediately after the decision is known.
3. Let downstream subscribers react synchronously within the same request.
4. Keep operator-facing JSON logs and audit records as separate surfaces.

### Ordering and visibility

- Ordering is deterministic and follows the actual request path.
- Subscribers only see events that have already happened.
- The bus is per-request and in-process only.
- Derived feedback events are appended in runtime order, so a subscriber may observe both the original event and any synchronous feedback event emitted from it.

### Dry-run semantics

- `dry_run=true` means the event describes a would-enforce outcome.
- `enforced=true` means the runtime actually applied the action.
- Feedback consumers must check both fields before mutating shared state.

Built-in examples:

- `bot_challenge_dry_run` publishes `dry_run=true` and does not create live challenge-failure penalty state.
- `rate_limited` publishes `enforced=true` only when the request was actually throttled.

### Bounded shared feedback

Use bounded in-memory state only for feedback loops.

- Do not create unbounded per-request or per-identity maps.
- Prefer TTL/window-based accumulators.
- Keep feedback idempotent where possible.
- Treat `attributes` as structured metadata for known consumers, not a dumping ground for whole log objects.

## Registration

Register plugins with:

```go
func init() {
    registerRequestSecurityPlugin(newMyPlugin)
}
```

Factory signature:

```go
type requestSecurityPluginFactory func() requestSecurityPlugin
```

Current built-ins are registered in `request_security_plugins.go`:

- `ip_reputation`
- `bot_defense`
- `semantic`

## File Placement

Add new plugin files under:

- `coraza/src/internal/handler/`

Recommended naming:

- `my_feature_request_security_plugin.go`

## Minimal Example

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

## Build And Test

Because this is a compile-time extension, normal builds automatically include the plugin once the source file is present.

Useful checks:

```bash
cd coraza/src
go test ./internal/handler ./...
```

## Design Rules

- Keep plugins deterministic and fail-safe.
- Prefer runtime stores and helpers over direct file I/O.
- Emit canonical `SecurityEvent` objects when blocking, challenging, or feeding downstream security logic.
- Avoid breaking admin/config compatibility when replacing built-in behavior.
- Treat this as an internal extension point, not a stable third-party plugin ABI.
