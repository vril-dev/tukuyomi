[English](request_security_plugins.md) | [日本語](request_security_plugins.ja.md)

# Request-Time Security Plugins

`tukuyomi` は `server/internal/handler` 内の compile-time plugin として request-time security extension をサポートします。

これは意図的に static で、Go runtime の `.so` plugin は使いません。

## 境界: metadata resolver と request-security plugin

`request_security_plugins` は、いまや最初の request 拡張層ではありません。

request-security plugin が動く前に、`[proxy]` は
`request_metadata_resolvers` を実行します。

この enrichment-only phase は、次のような typed request metadata を正規化する責務を持ちます。

- client IP
- country
- country source（`header` または `mmdb`）

現在の順序はこうです。

1. proxy request entry
2. request metadata resolvers
3. country block
4. rate limit
5. request-security plugins
6. WAF / CRS

ルール:

- metadata resolver は context enrichment のみ
- metadata resolver は block/challenge しない
- request-security plugin は引き続き decision layer
- CRS plugin は別の rule-bundle surface

つまり MaxMind 互換 `.mmdb` による country 解決は、
`request_security_plugins` ではなく metadata resolver 層に属します。

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

## Canonical `SecurityEvent` 契約

built-in と internal extension は `requestSecurityPluginContext` を通して canonical な in-process security event を publish できます。

event model は次の stable field を持ちます。

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

これは cross-plugin 挙動のための internal contract です。JSON log や security-audit trail を置き換えるものではなく、それらを補完します。

### Context helper

`requestSecurityPluginContext` は次を提供します。

- `ctx.publishSecurityEvent(...)`
- `ctx.SecurityEvents()`
- `ctx.SubscribeSecurityEvents(...)`
- `ctx.newSecurityEvent(...)`
- `ctx.deriveSecurityEvent(...)`

基本フロー:

1. 実際の decision point で canonical event を組み立てる
2. decision が確定した直後に publish する
3. 同一 request 内の downstream subscriber が同期的に反応する
4. operator 向け JSON log / audit record は別 surface として維持する

### Ordering と可視性

- ordering は deterministic で、実際の request path に従います
- subscriber が見えるのは、すでに発生した event だけです
- bus は per-request / in-process のみです
- feedback による derived event も runtime 順に追加されるため、subscriber は元 event と同期 feedback event の両方を観測することがあります

### Dry-run semantics

- `dry_run=true` は would-enforce の結果を表します
- `enforced=true` は runtime が実際に action を適用したことを表します
- feedback consumer は shared state を更新する前に両方を確認してください

built-in の例:

- `bot_challenge_dry_run` は `dry_run=true` を publish し、live challenge-failure penalty state は作りません
- `rate_limited` は実際に throttle された request のときだけ `enforced=true` を publish します

### Bounded shared feedback

feedback loop では bounded な in-memory state だけを使ってください。

- unbounded な per-request / per-identity map を作らない
- TTL / window ベースの accumulator を優先する
- 可能なら feedback は idempotent に保つ
- `attributes` は既知 consumer 向けの structured metadata とし、巨大な log object の置き場にしない

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

- `server/internal/handler/`

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
cd server
go test ./internal/handler ./...
```

## Design Rules

- plugin の挙動は deterministic かつ fail-safe に保つ。
- direct file I/O ではなく runtime store と helper を優先する。
- request を block / challenge したり downstream security logic に渡す時は canonical `SecurityEvent` を publish する。
- built-in behavior を置き換える場合も admin/config の互換性を壊さない。
- これは stable な third-party plugin ABI ではなく、internal extension point として扱う。
