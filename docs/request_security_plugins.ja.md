[English](request_security_plugins.md) | [日本語](request_security_plugins.ja.md)

# Request-Time Security Plugins

`tukuyomi` は `server/internal/handler` 配下のコンパイル時プラグインとして、リクエスト時のセキュリティ拡張をサポートします。

これは意図的に静的な仕組みであり、Go ランタイムの `.so` プラグインは使用しません。

## 境界: メタデータリゾルバとリクエストセキュリティプラグイン

`request_security_plugins` は、最初のリクエスト拡張層ではなくなりました。

リクエストセキュリティプラグインが動作する前に、`request_metadata_resolvers` を実行します。

このエンリッチメント専用フェーズは、次のような型付きリクエストメタデータの正規化を担います。

- クライアント IP
- 接続元国
- 接続元国の取得ソース（`header` または `mmdb`）

現在の処理順序は次のとおりです。

1. プロキシのリクエスト受け付け
2. リクエストメタデータリゾルバ
3. 国別ブロック
4. レート制限
5. リクエストセキュリティプラグイン
6. WAF ／ CRS

ルール:

- メタデータリゾルバはコンテキストのエンリッチメントのみを行う
- メタデータリゾルバはブロック／チャレンジを行わない
- リクエストセキュリティプラグインは引き続き判定層
- CRS プラグインは別系統のルールバンドル

したがって、MaxMind 互換 `.mmdb` による接続元国の解決は、`request_security_plugins` ではなくメタデータリゾルバ層に属します。

## プラグインインターフェース

プラグインは次のインターフェースを実装します。

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
  - `true`: 次のプラグインへ処理を進める
  - `false`: リクエストは処理済みまたはブロック済みとみなし、チェーンを停止する

`requestSecurityPluginContext` は、リクエスト ID、クライアント IP、接続元国、現在時刻、セマンティック評価状態など、正規化済みのリクエストメタデータを提供します。

## 正規 `SecurityEvent` 契約

組み込みプラグインおよび内部拡張は、`requestSecurityPluginContext` を経由して、プロセス内で正規化されたセキュリティイベントを発行できます。

イベントモデルが持つ安定フィールドは次のとおりです。

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

これはプラグイン横断の挙動を担保するための内部契約です。JSON ログやセキュリティ監査ログを置き換えるものではなく、それらを補完する位置付けです。

### コンテキストヘルパー

`requestSecurityPluginContext` は次を提供します。

- `ctx.publishSecurityEvent(...)`
- `ctx.SecurityEvents()`
- `ctx.SubscribeSecurityEvents(...)`
- `ctx.newSecurityEvent(...)`
- `ctx.deriveSecurityEvent(...)`

基本フロー:

1. 実際の判定ポイントで正規イベントを組み立てる
2. 判定が確定した直後にイベントを発行する
3. 同一リクエスト内の下流のサブスクライバが同期的に反応する
4. オペレーター向けの JSON ログや監査レコードは別系統で維持する

### 順序と可視性

- 順序は決定的で、実際のリクエストパスに従います
- サブスクライバが観測できるのは、すでに発生したイベントのみです
- イベントバスはリクエスト単位かつプロセス内のみで動作します
- フィードバックによって派生したイベントも実行順に追加されるため、サブスクライバは元のイベントと同期的なフィードバックイベントの両方を観測することがあります

### ドライラン挙動

- `dry_run=true` は「適用していたら起きていた結果」を表します
- `enforced=true` はランタイムが実際にアクションを適用したことを表します
- フィードバックの受信側は、共有状態を更新する前に両方を確認してください

組み込みの例:

- `bot_challenge_dry_run` は `dry_run=true` を発行し、実際のチャレンジ失敗ペナルティ状態は作りません
- `rate_limited` は、実際にスロットルされたリクエストの場合のみ `enforced=true` を発行します

### 上限付きの共有フィードバック

フィードバックループでは、上限付きのインメモリ状態のみを使用してください。

- 上限のないリクエスト単位／アイデンティティ単位のマップを作らない
- TTL ／ウィンドウ方式のアキュムレータを優先する
- 可能ならフィードバックは冪等に保つ
- `attributes` は既知のコンシューマ向けの構造化メタデータとし、巨大なログオブジェクトの置き場にしない

## 登録

プラグインの登録:

```go
func init() {
    registerRequestSecurityPlugin(newMyPlugin)
}
```

ファクトリのシグネチャ:

```go
type requestSecurityPluginFactory func() requestSecurityPlugin
```

現在の組み込み登録は `request_security_plugins.go` にあります。

- `ip_reputation`
- `bot_defense`
- `semantic`

## ファイル配置

新しいプラグインファイルは次の配下に追加します。

- `server/internal/handler/`

推奨される命名:

- `my_feature_request_security_plugin.go`

## 最小例

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

## ビルドとテスト

これはコンパイル時の拡張機構であるため、ソースファイルが存在すれば通常のビルドに自動的に含まれます。

確認用のコマンド例:

```bash
cd server
go test ./internal/handler ./...
```

## 設計ルール

- プラグインの挙動は決定的かつフェイルセーフに保つこと。
- 直接のファイル I/O ではなく、ランタイムのストアとヘルパーを優先すること。
- リクエストをブロック／チャレンジする場合や、下流のセキュリティロジックに引き渡す場合は、正規 `SecurityEvent` を発行すること。
- 組み込みの挙動を置き換える場合も、管理 API ／設定の互換性を壊さないこと。
- これは安定したサードパーティ向けプラグイン ABI ではなく、内部の拡張ポイントとして扱うこと。
