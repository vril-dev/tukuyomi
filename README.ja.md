# tukuyomi

Coraza + CRS WAF 搭載のリバースプロキシ／API Gateway

[English](README.md) | [日本語](README.ja.md)

![管理画面トップ](docs/images/ui-samples/01-status.png)

## 概要

`tukuyomi` は、シングルバイナリで動作するアプリケーションエッジ向けのコントロールプレーンです。Coraza WAF と OWASP CRS、リバースプロキシのルーティング、リクエストセキュリティ制御、オプションの Runtime Apps、スケジュールジョブ、Center モード、IoT／Edge デバイス登録までを 1 つの製品として統合しています。

主な用途は次のとおりです。

- リバースプロキシとルート管理
- WAF と誤検知チューニング
- レート／国別／ボット／セマンティック／IP レピュテーション制御
- 組み込みの管理 UI／API
- オプションの静的ホスティング／PHP-FPM／スケジュールジョブ
- Center 承認付きのオプションの IoT／Edge デバイス識別子登録
- シングルバイナリまたは Docker 配備

## IoT／Edge デバイス登録

Gateway には、Tukuyomi Center で承認されたローカルのデバイス識別子を必須とする IoT／Edge 配備向けのオプションモードがあります。Center が登録トークンを発行し、Gateway が Ed25519 のデバイス識別子を生成して署名付きの登録申請を送信し、Center 側でオペレーターが承認します。IoT／Edge モードでは、Gateway が Center から `approved` のデバイスステータスを取得するまで、公開プロキシのトラフィックはロックされたままです。承認後は、ステータス更新時にリビジョンが変化したタイミングで、Gateway がマスク済みの設定スナップショットに署名して Center へ送信します。

Web／VPS 配備では IoT／Edge モードは無効のままにしてください。運用フロー、プレビュー URL の注意点、公開鍵フィンガープリントの形式は [docs/operations/device-auth-enrollment.ja.md](docs/operations/device-auth-enrollment.ja.md) を参照してください。

## ルールファイルと初期セットアップ

本リポジトリには、ライセンス順守の都合上、OWASP CRS 本体は同梱していません。代わりに、最小の起動用ベースルールのシードを `seeds/waf/rules/` に同梱しています。

通常のランタイム用には、まず DB スキーマを作成し、続けて CRS シードファイルを配置したうえで、WAF ルールアセットを DB へインポートしてください。

```bash
make db-migrate
make crs-install
```

組み込み管理 UI と既定のアップストリームを含む最小構成で始める場合は、プリセットを適用します。

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

同梱の `minimal` プリセットが配置するのは `.env` と `data/conf/config.json` のみです。`conf/proxy.json` ／ `conf/sites.json` が無い場合、`make db-import` は `seeds/conf/` を読み込んだうえで、互換性のあるデフォルトへフォールバックします。

初回の DB インポート前に、ブートストラップしたいシードファイルを実値へ差し替えてください。

- `data/conf/config.json`: DB 接続のブートストラップ
- `seeds/conf/*.json`: 空 DB 向けに同梱される本番用シード一式
- `data/conf/proxy.json`: プロキシルールの初期シード／インポートファイル
- `data/conf/sites.json`: サイトオーナーシップ／TLS を使う場合の初期シード／インポートファイル
- `data/conf/scheduled-tasks.json`: スケジュールタスクを使う場合の初期シード／インポートファイル

その後、本番起動前に `make db-import` を実行し、残りの設定シードを DB に取り込みます。`make crs-install` は `make db-migrate` 後に動作し、WAF／CRS のルールアセットを DB へインポートします。インポート後の本番起動で必要なのは、DB 接続のブートストラップ用 `data/conf/config.json` と DB 上のレコードのみです。ランタイムの設定として正となるのは DB であり、その他のシード JSON やルールファイルはランタイムの参照元ではありません。

## クイックスタート

### インストール

Linux ホストへ直接導入する場合は、まずインストールターゲットから実行します。

```bash
make install TARGET=linux-systemd
```

これが Gateway のインストール経路です。Gateway／Center UI を埋め込んだ Go バイナリをビルドし、ランタイムツリーを作成したうえで、DB マイグレーション、WAF／CRS アセットのインポート、初回 DB 設定のシード投入、ローカルホスト向け systemd ユニットのインストールまでを一括で実行します。
スケジュールタスク用タイマーは既定で有効になります。このホストでスケジュールタスクを実行しない場合は、`INSTALL_ENABLE_SCHEDULED_TASKS=0` を指定してください。

Center をコントロールプレーンホストへ導入する場合は、同じ `TARGET` にロールを指定します。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

Gateway のインストールでは、内部的にスーパーバイザー／ワーカーランタイムを使用します。スーパーバイザーが TCP リスナーを所有し、レディネス確認後に初期ワーカーをアクティブ化します。Center は別のコントロールプレーンロールとして導入され、Gateway のリクエストパス向けスーパーバイザーは使用しません。HTTP/3 は UDP ハンドオフ実装が完了するまで、Gateway のスーパーバイザーでは拒否されます。

`PREFIX`、`INSTALL_USER`、スケジュールタスク用ユニットの詳細、およびホストへ直接インストールするのではなくコンテナ／プラットフォームへ配備する場合の詳細は、以下を参照してください。

- [docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md)
- [docs/build/container-deployment.ja.md](docs/build/container-deployment.ja.md)

### ローカルテストプレビュー

Gateway UI とローカルランタイムの一連のフローだけを試したい場合は、`preview` ターゲットを使用してください。

```bash
make preset-apply PRESET=minimal
make gateway-preview-up
```

`make gateway-preview-up` は CRS の ensure フローを自動的に実行します。
このフローでは、`make db-migrate` の実行、CRS シードファイルが存在しない場合の配置、および WAF ルールアセットの DB へのインポートまでをまとめて行います。

その後、既定では以下にアクセスします。

- Gateway UI: `http://localhost:9090/tukuyomi-ui`
- Gateway API: `http://localhost:9090/tukuyomi-api`

既定では、`make gateway-preview-up` はプレビュー専用の SQLite DB を使用し、起動のたびにその DB とプレビュー専用の設定ファイルを初期化します。
`GATEWAY_PREVIEW_PERSIST=1` を指定すると、プレビュー用の設定と DB の状態を `gateway-preview-down` と `gateway-preview-up` の間で保持できます。

### ランタイム設定モデル

`tukuyomi` は責務ごとに設定を分離しています。

- `.env`: Docker 実行時の差分のみ
- `data/conf/config.json`: DB 接続のブートストラップ。同梱設定は `storage` ブロックのみを保持
- DB `app_config_*`: グローバルランタイム／リスナー／管理／ストレージポリシー／パス設定
- DB `proxy_*`: 稼働中のプロキシトランスポート／ルーティング設定
- `seeds/conf/*`: 設定済みシードファイルが無いときに使う、空 DB 向けの同梱本番シード
- `data/conf/proxy.json`: プロキシルールのシード／インポート／エクスポート用素材
- DB `proxy_backend_pools` ／ `proxy_backend_pool_members`: 名前付きアップストリームメンバーから構成する、ルート単位のバランシンググループ
- `data/conf/upstream-runtime.json`: `Proxy Rules > Upstreams` で定義したオプトイン方式のランタイムオーバーライド用、シード／インポート／エクスポート素材
- `data/conf/sites.json`: サイトオーナーシップと TLS バインディングのシード／インポート／エクスポート素材
- DB `vhosts` ／ `vhost_*`: 稼働中の Runtime Apps 設定。ストレージ名は互換性のため `vhost` のままです
- DB `waf_rule_assets`: ベース WAF と CRS のルール／データアセット
- DB `override_rules`: 管理されたバイパスである `extra_rule` のルール本体
- DB `php_runtime_inventory` ／ `php_runtime_modules`: PHP-FPM ランタイムインベントリとモジュールメタデータ
- DB `psgi_runtime_inventory` ／ `psgi_runtime_modules`: Perl／Starman ランタイムインベントリとモジュールメタデータ
- `data/php-fpm/inventory.json` ／ `data/php-fpm/vhosts.json`: PHP-FPM と Runtime Apps のシード／インポート／エクスポート素材
- `data/psgi/inventory.json`: PSGI ランタイムのシード／インポート／エクスポート素材
- `data/conf/scheduled-tasks.json`: スケジュールタスクのシード／インポート／エクスポート素材

ベース WAF／CRS アセットと管理されたバイパスのオーバーライドは、DB を正として保持します。
`make crs-install` はルールのインポート素材を `data/tmp` 配下に一時ステージングし、DB へのインポート後にステージを削除します。設定上のパスは論理的なアセット名および互換参照として残りますが、ランタイムは `data/rules`、`data/conf/rules`、`data/geoip` のフォールバックディレクトリを使用しません。同様に、起動時設定、ポリシー、サイト、Runtime Apps、スケジュールタスク、アップストリームランタイム、レスポンスキャッシュ、PHP-FPM インベントリ各ドメインも、`make db-import` 実行後は DB から直接読み込みます。

運用面の詳細は以下を参照してください。

- [docs/reference/operator-reference.ja.md](docs/reference/operator-reference.ja.md)
- [docs/operations/listener-topology.ja.md](docs/operations/listener-topology.ja.md)

`Proxy Rules > Upstreams` は直接指定のバックエンドノードカタログ、`Proxy Rules > Backend Pools` はルートから参照可能なアップストリーム名をまとめる、ルート単位のバランシンググループです。ルートは通常 `action.backend_pool` にバインドし、`Backends` はルーティングで使用される直接指定のアップストリームバックエンドオブジェクトを一覧化したうえで、ランタイム操作は直接指定された名前付きアップストリームノード自体に対して行います。

構造化された `Proxy Rules` エディタでは、運用フローを次の順序で表示します。

1. `Upstreams`
2. `Backend Pools`
3. `Routes` ／ `Default route`

`Upstreams` の各行には専用の `Probe` があり、パネル全体に対する曖昧なターゲットではなく、指定した設定済みアップストリームに対して疎通確認を行います。

`Proxy Rules > Upstreams` で定義した直接指定の名前付きアップストリームは、`Backends` からドレイン／無効化／ランタイムでの重みオーバーライドが可能で、`proxy.json` を編集せずに運用変更できます。プロキシルールの編集内容は DB `proxy_rules` に保存し、ランタイム専用のオーバーライドは DB `upstream_runtime` に保存します。
`data/conf/upstream-runtime.json` はそのシード／インポート／エクスポート素材です。

ルート単位の Web 負荷分散を使用する場合は、`upstreams[]` でバックエンドノードを定義し、`backend_pools[]` でグループを構成したうえで、ルートを `action.backend_pool` にバインドします。

Runtime Apps の管理アプリケーションでは、ランタイムの待ち受けホストとポートを `Runtime Apps` に定義します。ランタイムはその待ち受けターゲットから生成バックエンドを作成し、トラフィックのルーティングは `Proxy Rules` からその生成アップストリームターゲットへ向けます。
`Proxy Rules > Upstreams` の設定済みアップストリーム URL が、Runtime Apps によって差し替えられることはありません。
ランタイムの有効化／ドレイン／無効化、およびランタイムでの重みオーバーライドは、`Backends` に表示される直接指定の名前付きアップストリームに限定されます。

通常の `http://` ／ `https://` アップストリームへのプロキシでは、自動的に以下を付与します。

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

さらに `emit_upstream_name_request_header=true` を有効にすると、次のヘッダーも付与できます。

- `X-Tukuyomi-Upstream-Name`

この内部オブザーバビリティ向けヘッダーは、最終ターゲットが `Proxy Rules > Upstreams` の設定済みの名前付きアップストリームであった場合にのみ付与されます。直接指定したルートの URL や、Runtime Apps が生成するターゲットには付与されません。また、ルートレベルの `request_headers` から上書きすることもできません。

### ルート単位のバックエンドプール最小例

```json
{
  "upstreams": [
    { "name": "localhost1", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true },
    { "name": "localhost2", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true },
    { "name": "localhost3", "url": "http://127.0.0.1:9081", "weight": 1, "enabled": true },
    { "name": "localhost4", "url": "http://127.0.0.1:9082", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-localhost", "strategy": "round_robin", "members": ["localhost1", "localhost2"] },
    { "name": "site-app", "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ],
  "routes": [
    { "name": "site-localhost", "priority": 10, "match": { "hosts": ["localhost"] }, "action": { "backend_pool": "site-localhost" } },
    { "name": "site-app", "priority": 20, "match": { "hosts": ["app"] }, "action": { "backend_pool": "site-app" } }
  ]
}
```

## 配備ガイド

配備形態に応じて以下を参照してください。

- シングルバイナリ／systemd:
  - [docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md)
- Docker ／コンテナプラットフォーム:
  - [docs/build/container-deployment.ja.md](docs/build/container-deployment.ja.md)
- 公開／管理リスナー分離の例:
  - [docs/build/config.split-listener.example.json](docs/build/config.split-listener.example.json)

コンテナプラットフォーム向けサンプル:

- ECS シングルインスタンス:
  - [docs/build/ecs-single-instance.task-definition.example.json](docs/build/ecs-single-instance.task-definition.example.json)
  - [docs/build/ecs-single-instance.service.example.json](docs/build/ecs-single-instance.service.example.json)
- Kubernetes シングルインスタンス:
  - [docs/build/kubernetes-single-instance.example.yaml](docs/build/kubernetes-single-instance.example.yaml)
- Azure Container Apps シングルインスタンス:
  - [docs/build/azure-container-apps-single-instance.example.yaml](docs/build/azure-container-apps-single-instance.example.yaml)

## ドキュメント索引

### コアオペレーターリファレンス

- オペレーターリファレンス:
  - [docs/reference/operator-reference.ja.md](docs/reference/operator-reference.ja.md)
- Admin API OpenAPI:
  - [docs/api/admin-openapi.yaml](docs/api/admin-openapi.yaml)
- リクエストセキュリティプラグインモデル:
  - [docs/request_security_plugins.ja.md](docs/request_security_plugins.ja.md)

### セキュリティとチューニング

- WAF チューニング:
  - [docs/operations/waf-tuning.ja.md](docs/operations/waf-tuning.ja.md)
- 誤検知チューナー API 仕様:
  - [docs/operations/fp-tuner-api.ja.md](docs/operations/fp-tuner-api.ja.md)
- アップストリーム HTTP/2 と h2c:
  - [docs/operations/upstream-http2.ja.md](docs/operations/upstream-http2.ja.md)
- 静的ファイルファストパス評価:
  - [docs/operations/static-fastpath-evaluation.ja.md](docs/operations/static-fastpath-evaluation.ja.md)

### PHP とスケジュールタスク

- PHP-FPM ランタイムと Runtime Apps:
  - [docs/operations/php-fpm-vhosts.ja.md](docs/operations/php-fpm-vhosts.ja.md)
- PSGI Runtime Apps と Movable Type:
  - [docs/operations/psgi-vhosts.ja.md](docs/operations/psgi-vhosts.ja.md)
- スケジュールタスクとスケジューラ配備:
  - [docs/operations/php-scheduled-tasks.ja.md](docs/operations/php-scheduled-tasks.ja.md)

### DB ／メトリクス／回帰テスト

- DB 運用:
  - [docs/operations/db-ops.ja.md](docs/operations/db-ops.ja.md)
- ベンチマークベースライン:
  - [docs/operations/benchmark-baseline.ja.md](docs/operations/benchmark-baseline.ja.md)
- 回帰テストマトリクス:
  - [docs/operations/regression-matrix.ja.md](docs/operations/regression-matrix.ja.md)
- リリースバイナリスモークテスト:
  - [docs/operations/release-binary-smoke.ja.md](docs/operations/release-binary-smoke.ja.md)

## 品質ゲート

ローカルでの確認:

```bash
make ci-local
```

配備ガイドの再生成まで含む拡張ローカル回帰テスト:

```bash
make ci-local-extended
```

代表的な CI 必須チェックは次のとおりです。

- `ci / go-test`
- `ci / mysql-logstore-test`
- `ci / ui-test`
- `ci / compose-validate`
- `ci / waf-test (sqlite)`

## ライセンス

tukuyomi は、nginx と同じパーミッシブライセンス系列である BSD 2-Clause License で公開しています。詳細は [LICENSE](LICENSE) を参照してください。

サードパーティ依存ライブラリの著作権表示は [NOTICE](NOTICE) を参照してください。
依存ライセンスのメタデータは、`server/go.mod` ／ `server/go.sum` および `web/tukuyomi-admin` ／ `web/tukuyomi-center` のパッケージロックファイルから確認できます。

## tukuyomi とは？

**tukuyomi** は、nginx + Coraza WAF をベースとした OSS WAF **mamotama** を前身として発展したプロダクトです。

名前は **「護りたまえ」** に由来します。
mamotama が「保護」を核心に据えていたのに対し、tukuyomi はより構造化され、運用しやすい Web Protection を目指しています。
