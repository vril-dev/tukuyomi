[English](request_security_plugins.md) | [日本語](request_security_plugins.ja.md)

# Request-Time Security Plugins

`tukuyomi` は `coraza/src/internal/handler` 内の compile-time plugin として request-time security extension をサポートします。

これは意図的に static で、Go runtime の `.so` plugin は使いません。

## Plugin Interface

plugin は次の interface を使います。

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
- `Handle(...)` の戻り値:
  - `true`: 次の plugin へ進む
  - `false`: request は処理済みまたは blocked とみなし、chain を止める

`requestSecurityPluginContext` は request ID、client IP、country、current time、semantic evaluation state などの normalized request metadata を提供します。

## Registration

plugin の登録:

```go
func init() {
    registerRequestSecurityPlugin(newMyPlugin)
}
```

factory signature:

```go
type requestSecurityPluginFactory func() requestSecurityPlugin
```

現在の built-in registration は `request_security_plugins.go` にあります。

- `ip_reputation`
- `bot_defense`
- `semantic`

## File Placement

新しい plugin file は次の配下に追加します。

- `coraza/src/internal/handler/`

推奨 naming:

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

これは compile-time extension なので、source file があれば通常 build に自動で含まれます。

便利な確認コマンド:

```bash
cd coraza/src
go test ./internal/handler ./...
```

## Design Rules

- plugin の挙動は deterministic かつ fail-safe に保つ。
- direct file I/O ではなく runtime store と helper を優先する。
- request を block / challenge した時は structured event を出力する。
- built-in behavior を置き換える場合も admin/config の互換性を壊さない。
- これは stable な third-party plugin ABI ではなく、internal extension point として扱う。
