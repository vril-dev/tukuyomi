# tukuyomi

Coraza + CRS WAF reverse proxy / API gateway

[English](README.md) | [日本語](README.ja.md)

![管理画面トップ](docs/images/ui-samples/01-status.png)

## 概要

`tukuyomi` は single-binary の application-edge control plane です。Coraza WAF +
OWASP CRS、reverse proxy routing、request security controls、optional Runtime Apps、
scheduled jobs、Center mode、IoT / Edge device enrollment を 1 つの製品として統合しています。

主な用途は次のとおりです。

- reverse proxy と route 管理
- WAF と誤検知チューニング
- rate / country / bot / semantic / IP reputation 制御
- built-in の管理 UI/API
- optional な static hosting / PHP-FPM / scheduled jobs
- Center 承認付きの optional IoT / Edge device identity 登録
- single binary または Docker 配備

## IoT / Edge デバイス登録

Gateway には、Tukuyomi Center で承認されたローカル device identity が必要な
IoT / Edge deployment 向けの optional mode が入っています。現時点の実装範囲は
登録フローです。Center が enrollment token を発行し、Gateway が Ed25519 の
device identity を生成して署名付き登録申請を送り、Center 側で operator が承認します。
IoT / Edge mode では、Gateway が Center の `approved` device status を refresh するまで
public proxy traffic はロックされます。

Web/VPS deployment では IoT / Edge mode は OFF のままにしてください。運用フロー、
preview URL の注意点、public key fingerprint の形式は
[docs/operations/device-auth-enrollment.ja.md](docs/operations/device-auth-enrollment.ja.md)
を参照してください。

## ルールファイルと初期セットアップ

本リポジトリには、ライセンス順守のため OWASP CRS 本体は同梱していません。
代わりに、最小の起動用ベースルール seed を `seeds/waf/rules/` に同梱しています。

通常 runtime 用には、先に DB schema を作り、その後 CRS seed file を配置して
WAF rule asset を DB へ import してください。

```bash
make db-migrate
make crs-install
```

埋め込み管理 UI と既定 upstream を含む最小構成で始める場合は、preset を適用します。

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

bundled の `minimal` preset が配置するのは `.env` と
`data/conf/config.json` だけです。`conf/proxy.json` / `conf/sites.json`
が無ければ、`make db-import` は `seeds/conf/` を読んでから互換 default に
fallback します。

初回 DB import 前には、bootstrap したい seed file を実値へ差し替えてください。

- `data/conf/config.json`: DB 接続 bootstrap
- `seeds/conf/*.json`: 空 DB 向けに同梱される本番 seed set
- `data/conf/proxy.json`: proxy rules の初期 seed/import file
- `data/conf/sites.json`: site ownership / TLS を使う場合の初期 seed/import file
- `data/conf/scheduled-tasks.json`: scheduled tasks を使う場合の初期 seed/import file

その後、本番起動前に `make db-import` を実行し、残りの設定 seed を DB へ
取り込みます。`make crs-install` は `make db-migrate` 後に動き、WAF/CRS
rule asset を DB へ import します。import 後の本番起動で必要なのは DB
接続 bootstrap 用の `data/conf/config.json` と DB row であり、その他の seed
JSON/rule file は runtime authority ではありません。

## クイックスタート

### インストール

Linux host へ直接入れる場合は、まず install target から始めます。

```bash
make install TARGET=linux-systemd
```

これは Gateway のインストール経路です。Gateway / Center UI を埋め込んだ Go バイナリをビルドし、ランタイムツリーを作成したうえで、DBマイグレーション、WAF/CRSアセットのインポート、初回DB設定のシード投入、ローカルホスト向けsystemdユニットのインストールまでを一括で実行します。
スケジュールタスク用タイマーはデフォルトで有効になります。このホストでスケジュールタスクを実行しない場合は、`INSTALL_ENABLE_SCHEDULED_TASKS=0` を指定してください。

Center を control plane ホストに入れる場合は、同じ `TARGET` に role を指定します。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

Gateway install は内部的に supervisor / worker runtime を使います。supervisor が
TCP listener を所有し、readiness 後に初期 worker を activate します。Center は
別の control-plane role として入り、Gateway の request-path supervisor は使いません。
HTTP/3 は UDP handoff 実装まで Gateway supervisor では拒否されます。

`PREFIX`、`INSTALL_USER`、スケジュールタスク用ユニットの詳細、およびホストへのインストールではなくコンテナ／プラットフォームへのデプロイを利用する場合の詳細については、以下を参照してください。

- [docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md)
- [docs/build/container-deployment.ja.md](docs/build/container-deployment.ja.md)

### ローカルテスト preview

Gateway UI とローカルランタイムのフローだけを試したい場合は、`preview` ターゲットを使用してください。

```bash
make preset-apply PRESET=minimal
make gateway-preview-up
```

`make gateway-preview-up` は CRS の ensure フローを自動的に実行します。
このフローでは、`make db-migrate` の実行、CRS シードファイルが存在しない場合の配置、および WAFルールアセットのDBへのインポートまでをまとめて行います。

その後、既定では以下へアクセスします。

- Gateway UI: `http://localhost:9090/tukuyomi-ui`
- Gateway API: `http://localhost:9090/tukuyomi-api`

デフォルトでは、`make gateway-preview-up` はプレビュー専用の SQLite DB を使用し、起動のたびにその DB とプレビュー専用の設定ファイルを初期化します。
`GATEWAY_PREVIEW_PERSIST=1` を指定すると、プレビュー用の設定と DB の状態を gateway-preview-down と gateway-preview-up の間で保持できます。

### Runtime 設定モデル

`tukuyomi` は責務ごとに設定を分けています。

- `.env`: Docker 実行差分のみ
- `data/conf/config.json`: DB 接続 bootstrap。bundled config は `storage` block だけを保持
- DB `app_config_*`: global runtime / listener / admin / storage policy / path 設定
- DB `proxy_*`: live の proxy transport / routing 設定
- `seeds/conf/*`: configured seed file が無い時に使う同梱の空 DB 向け本番 seed
- `data/conf/proxy.json`: proxy rules の seed/import/export material
- DB `proxy_backend_pools` / `proxy_backend_pool_members`: named upstream member から作る route 単位の balancing group
- `data/conf/upstream-runtime.json`: `Proxy Rules > Upstreams` で定義した opt-in runtime override の seed/import/export material
- `data/conf/sites.json`: site ownership と TLS binding の seed/import/export material
- DB `vhosts` / `vhost_*`: live Runtime Apps config。storage 名は互換性のため `vhost` のままです
- DB `waf_rule_assets`: base WAF と CRS の rule/data asset
- DB `override_rules`: managed bypass `extra_rule` の rule body
- DB `php_runtime_inventory` / `php_runtime_modules`: PHP-FPM runtime inventory と module metadata
- DB `psgi_runtime_inventory` / `psgi_runtime_modules`: Perl/Starman runtime inventory と module metadata
- `data/php-fpm/inventory.json` / `data/php-fpm/vhosts.json`: PHP-FPM と Runtime Apps の seed/import/export material
- `data/psgi/inventory.json`: PSGI runtime の seed/import/export material
- `data/conf/scheduled-tasks.json`: scheduled task の seed/import/export material

base WAF/CRS asset と managed bypass override は DB-backed です。
`make crs-install` は rule import material を `data/tmp` 配下へ一時 stage し、
DB へ import してから stage を削除します。設定された path は logical asset 名および
互換参照として残りますが、runtime は `data/rules`、`data/conf/rules`、
`data/geoip` fallback directory を使いません。同じく startup、policy、site、
Runtime Apps、scheduled task、upstream runtime、response cache、PHP-FPM inventory domain
も `make db-import` 後は DB から直接読みます。

運用面の詳細は以下を参照してください。

- [docs/reference/operator-reference.ja.md](docs/reference/operator-reference.ja.md)
- [docs/operations/listener-topology.ja.md](docs/operations/listener-topology.ja.md)

`Proxy Rules > Upstreams` は direct backend node catalog、`Proxy Rules >
Backend Pools` は route から参照できる upstream 名をまとめる route 単位の
balancing group です。route は通常 `action.backend_pool` に bind し、
`Backends` は routing で使われる direct upstream backend object を一覧化しつつ、
runtime 操作は direct named upstream node 自体に対して行います。

structured な `Proxy Rules` editor では、運用フローを次の順で表示します。

1. `Upstreams`
2. `Backend Pools`
3. `Routes` / `Default route`

`Upstreams` の各行には専用の `Probe` があり、panel 全体の曖昧な target ではなく、
指定した configured upstream に対して疎通確認を行います。

`Proxy Rules > Upstreams` で定義した direct named upstream は
`Backends` から drain / disable / runtime weight override ができ、
`proxy.json` を編集せずに運用変更できます。Proxy rule 編集は DB
`proxy_rules` に保存し、runtime 専用 override は DB `upstream_runtime` に保存します。
`data/conf/upstream-runtime.json` は seed/import/export material です。

route 単位の web balancing を使う時は、`upstreams[]` で backend node を定義し、
`backend_pools[]` で group を作り、route を `action.backend_pool` に bind します。

Runtime Apps 管理 application は、runtime の待ち受け host と port を `Runtime Apps` に定義します。
runtime はその listen target から generated backend を作り、traffic の routing は
`Proxy Rules` からその generated upstream target へ向けます。
`Proxy Rules > Upstreams` の configured upstream URL は Runtime Apps によって差し替えられません。
runtime enable / drain / disable と runtime weight override は、
`Backends` に表示される direct named upstream に限定します。

通常の `http://` / `https://` upstream proxy では自動的に:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

を付与します。

さらに `emit_upstream_name_request_header=true` を有効にすると、次も付与できます。

- `X-Tukuyomi-Upstream-Name`

この内部 observability header は、最終 target が `Proxy Rules > Upstreams`
の configured named upstream だった時だけ付与されます。direct route URL と
generated Runtime Apps target には付きません。また、route-level の
`request_headers` から override することもできません。

### 最小 route-scoped backend pool 例

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

配備形態に応じて次を参照してください。

- single binary / systemd:
  - [docs/build/binary-deployment.ja.md](docs/build/binary-deployment.ja.md)
- Docker / container platform:
  - [docs/build/container-deployment.ja.md](docs/build/container-deployment.ja.md)
- split public/admin listener 例:
  - [docs/build/config.split-listener.example.json](docs/build/config.split-listener.example.json)

container platform 向けサンプル:

- ECS single-instance:
  - [docs/build/ecs-single-instance.task-definition.example.json](docs/build/ecs-single-instance.task-definition.example.json)
  - [docs/build/ecs-single-instance.service.example.json](docs/build/ecs-single-instance.service.example.json)
- Kubernetes single-instance:
  - [docs/build/kubernetes-single-instance.example.yaml](docs/build/kubernetes-single-instance.example.yaml)
- Azure Container Apps single-instance:
  - [docs/build/azure-container-apps-single-instance.example.yaml](docs/build/azure-container-apps-single-instance.example.yaml)

## ドキュメント索引

### Core Operator Reference

- operator reference:
  - [docs/reference/operator-reference.ja.md](docs/reference/operator-reference.ja.md)
- Admin API OpenAPI:
  - [docs/api/admin-openapi.yaml](docs/api/admin-openapi.yaml)
- Request security plugin model:
  - [docs/request_security_plugins.ja.md](docs/request_security_plugins.ja.md)

### Security と Tuning

- WAF tuning:
  - [docs/operations/waf-tuning.ja.md](docs/operations/waf-tuning.ja.md)
- FP Tuner API contract:
  - [docs/operations/fp-tuner-api.ja.md](docs/operations/fp-tuner-api.ja.md)
- upstream HTTP/2 と h2c:
  - [docs/operations/upstream-http2.ja.md](docs/operations/upstream-http2.ja.md)
- static fastpath evaluation:
  - [docs/operations/static-fastpath-evaluation.ja.md](docs/operations/static-fastpath-evaluation.ja.md)

### PHP と Scheduled Tasks

- PHP-FPM runtime と Runtime Apps:
  - [docs/operations/php-fpm-vhosts.ja.md](docs/operations/php-fpm-vhosts.ja.md)
- PSGI Runtime Apps と Movable Type:
  - [docs/operations/psgi-vhosts.ja.md](docs/operations/psgi-vhosts.ja.md)
- Scheduled Tasks と scheduler 配備:
  - [docs/operations/php-scheduled-tasks.ja.md](docs/operations/php-scheduled-tasks.ja.md)

### DB / Metrics / Regression

- DB 運用:
  - [docs/operations/db-ops.ja.md](docs/operations/db-ops.ja.md)
- benchmark baseline:
  - [docs/operations/benchmark-baseline.ja.md](docs/operations/benchmark-baseline.ja.md)
- regression matrix:
  - [docs/operations/regression-matrix.ja.md](docs/operations/regression-matrix.ja.md)
- release binary smoke:
  - [docs/operations/release-binary-smoke.ja.md](docs/operations/release-binary-smoke.ja.md)

## 品質ゲート

ローカル確認:

```bash
make ci-local
```

deployment guide 再生まで含めた拡張ローカル回帰:

```bash
make ci-local-extended
```

典型的な CI required checks は次です。

- `ci / go-test`
- `ci / mysql-logstore-test`
- `ci / ui-test`
- `ci / compose-validate`
- `ci / waf-test (sqlite)`

## ライセンス

tukuyomi は、nginx と同じ permissive license 系列である BSD 2-Clause License
で公開します。詳細は [LICENSE](LICENSE) を参照してください。

サードパーティ依存ライブラリの著作権表示は [NOTICE](NOTICE) を参照してください。
依存ライセンスの metadata は `server/go.mod` / `server/go.sum` と
`web/tukuyomi-admin` / `web/tukuyomi-center` の package lock files から確認できます。

## tukuyomi とは？

**tukuyomi** は、nginx + Coraza WAF をベースとした OSS WAF **mamotama** を前身として発展したプロダクトです。

名前は **「護りたまえ」** に由来します。
mamotama が「保護」を核心に据えていたのに対し、tukuyomi はより構造化され、運用しやすい Web Protection を目指しています。
