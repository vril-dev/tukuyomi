# 第9章　Request-Time Security Plugins

第7・8章では Coraza WAF の **検査結果に対する誤検知対処** を扱いました。
本章では、tukuyomi が WAF とは別軸で持っている **request-time security
extension の plugin model** を扱います。

`tukuyomi` の `server/internal/handler` 内には、**compile-time の plugin**
として request-time security extension が組み込めるようになっています。
これは意図的に static で、**Go runtime の `.so` plugin は使いません**。
ABI を超えた拡張ではなく、source レベルでの「internal extension point」と
いう設計です。

## 9.1　位置関係 ── metadata resolver と request-security plugin

最初に、`request_security_plugins` が **どこに座っているか** を確認しておき
ます。これはもはや「最初の request 拡張層」ではありません。

request-security plugin が動く前に、`[proxy]` は **`request_metadata_resolvers`**
を実行します。これは enrichment-only な phase で、次のような typed request
metadata を正規化する責務を持ちます。

- client IP
- country
- country source（`header` または `mmdb`）

現在の処理順序は次のとおりです。

1. proxy request entry
2. **request metadata resolvers**
3. country block
4. rate limit
5. **request-security plugins**
6. WAF / CRS

ルールはきれいに整理されています。

- **metadata resolver は context enrichment のみ。block / challenge しない。**
- **request-security plugin は decision layer**（block する／しない を決める）。
- **CRS plugin は別の rule-bundle surface**（Coraza 側で扱う）。

つまり、MaxMind 互換 `.mmdb` による country 解決は、`request_security_plugins`
ではなく **metadata resolver 層に属する** のが今の設計です。

## 9.2　Plugin Interface

plugin は次の interface を満たす実装を提供します。

```go
type requestSecurityPlugin interface {
    Name() string
    Phase() requestSecurityPluginPhase
    Enabled() bool
    Handle(c *gin.Context, ctx *requestSecurityPluginContext) bool
}
```

- `Phase()` の戻り値は次のいずれか:
  - `requestSecurityPluginPhasePreWAF`
  - `requestSecurityPluginPhasePostWAF`
- `Handle(...)` の戻り値:
  - `true`: 次の plugin へ進む
  - `false`: request は処理済みまたは blocked とみなし、chain を止める

`requestSecurityPluginContext` は、normalized な request metadata（request
ID、client IP、country、current time、semantic evaluation state など）を
plugin に提供します。

## 9.3　Canonical `SecurityEvent` 契約

plugin は単独で動くだけでなく、**canonical な in-process security event** を
publish して他の plugin / built-in と協調できます。built-in と internal
extension は、`requestSecurityPluginContext` を通してこの canonical event を
publish できます。

event model の stable field は次のとおりです。

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

これは **cross-plugin 挙動のための internal contract** です。**JSON log や
security-audit trail を置き換えるものではなく、それらを補完する** 位置
づけです。3 つの surface が独立して存在する、という認識が大事です。

### 9.3.1　Context helper

`requestSecurityPluginContext` は、event を扱うために次の helper を提供
します。

- `ctx.publishSecurityEvent(...)`
- `ctx.SecurityEvents()`
- `ctx.SubscribeSecurityEvents(...)`
- `ctx.newSecurityEvent(...)`
- `ctx.deriveSecurityEvent(...)`

基本フローは次のとおりです。

1. 実際の decision point で canonical event を組み立てる
2. decision が確定した直後に publish する
3. **同一 request 内** の downstream subscriber が **同期的に** 反応する
4. operator 向けの JSON log / audit record は **別 surface** として維持する

### 9.3.2　Ordering と可視性

- **ordering は deterministic** で、実際の request path に従います。
- **subscriber が見えるのは、すでに発生した event だけ** です（未来は
  見えない）。
- **bus は per-request / in-process のみ** です。process / request の境界を
  越えません。
- feedback による **derived event も runtime 順に追加** されるため、
  subscriber は元 event と同期 feedback event の両方を観測することがあります。

### 9.3.3　Dry-run semantics

- `dry_run=true` は **would-enforce の結果** を表します。実際には何も
  block していません。
- `enforced=true` は **runtime が実際に action を適用したこと** を表します。
- **feedback consumer は shared state を更新する前に、両方を確認してください**。
  （`enforced=true` だけ見て penalty を作るような実装にしないこと）

built-in の例:

- `bot_challenge_dry_run` は `dry_run=true` を publish し、live challenge
  failure の penalty state は **作らない**。
- `rate_limited` は **実際に throttle された request** のときだけ
  `enforced=true` を publish する。

### 9.3.4　Bounded shared feedback

複数 plugin 間で feedback loop を作るときは、**bounded な in-memory state**
だけを使ってください。

- unbounded な per-request / per-identity の map を作らない
- TTL / window ベースの accumulator を優先する
- 可能なら feedback は **idempotent** に保つ
- `attributes` は **既知 consumer 向けの structured metadata** に限定する。
  巨大な log object の置き場として濫用しない

## 9.4　Registration

plugin は `init()` から registration helper を呼んで登録します。

```go
func init() {
    registerRequestSecurityPlugin(newMyPlugin)
}
```

factory signature は次のとおりです。

```go
type requestSecurityPluginFactory func() requestSecurityPlugin
```

現在の built-in registration は `request_security_plugins.go` にあります。
組み込みで動いているのは次の 3 つです。

- `ip_reputation`
- `bot_defense`
- `semantic`

それぞれは Gateway UI の `IP Reputation` / `Bot Defense` / `Semantic Security`
画面と対応します。

## 9.5　File Placement

新しい plugin file は次の配下に追加します。

```
server/internal/handler/
```

推奨 naming は次のとおりです。

```
my_feature_request_security_plugin.go
```

## 9.6　Minimal Example

最小の実装例です。`X-Tukuyomi-Sample-Block: 1` を見たら `451` で abort する
だけの plugin です。

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

これだけで、built-in plugin の chain に sample plugin が pre-WAF phase で
追加されます。

## 9.7　Build And Test

compile-time extension なので、source file が `server/internal/handler/` 配下に
あれば、通常 build に **自動で含まれます**。`.so` の load 設定や registry
への登録 file の編集は不要です。

便利な確認コマンドは次のとおりです。

```bash
cd server
go test ./internal/handler ./...
```

最低限、新しい plugin が build 通る・既存テストが回る、までは確認してから
PR にします。

## 9.8　Design Rules

最後に、plugin を書くときに守りたい設計ルールをまとめておきます。

- plugin の挙動は **deterministic かつ fail-safe** に保つ。同じ input には
  同じ decision が返る。失敗時は安全側に倒す。
- **direct file I/O ではなく、runtime store と helper を優先** する。
  plugin から file を直接読み書きすると、container / replicated 配備で
  破綻しやすい。
- request を **block / challenge** したり、**downstream security logic に
  渡す** ときは、canonical `SecurityEvent` を publish する。
- **built-in behavior を置き換える plugin** であっても、admin / config の
  互換性を壊さない。
- **stable な third-party plugin ABI ではなく、internal extension point
  として扱う**。breaking change は内部の commit で起こり得るので、社内で
  build / 配布する前提で扱う。

## 9.9　ここまでの整理

- `request_security_plugins` は decision layer。enrichment は metadata
  resolver の責務。
- plugin interface は `Name / Phase / Enabled / Handle` の 4 メソッド。
  `Phase` は preWAF / postWAF。
- 同一 request 内で `SecurityEvent` を bus に流して plugin 同士が協調できる。
- dry_run / enforced を区別し、feedback は bounded に。
- 登録は `init()` で `registerRequestSecurityPlugin(...)`、配置は
  `server/internal/handler/`。

## 9.10　次章への橋渡し

第IV部では、tukuyomi の **edge security 側** ── Coraza WAF 誤検知対処、
FP Tuner、request-time security plugin ── を扱いました。次の第V部では、
edge を抜けたあとに動く **Runtime Apps** ── PHP-FPM Runtime と PSGI
Runtime、そして Scheduled Tasks ── を扱います。
