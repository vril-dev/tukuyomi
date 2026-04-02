[English](request_security_plugins.md) | [日本語](request_security_plugins.ja.md)

# Request-Time Security Plugins

`tukuyomi` supports request-time security extensions as compile-time plugins inside `coraza/src/internal/handler`.

This is intentionally static and does not use Go runtime `.so` plugins.

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
- Emit structured events when blocking or challenging requests.
- Avoid breaking admin/config compatibility when replacing built-in behavior.
- Treat this as an internal extension point, not a stable third-party plugin ABI.
