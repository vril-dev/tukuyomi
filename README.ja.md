# tukuyomi

Coraza + CRS WAF reverse proxy / API gateway

[English](README.md) | [日本語](README.ja.md)

![管理画面トップ](docs/images/ui-samples/01-status.png)

## 概要

`tukuyomi` は Tukuyomi ファミリーの汎用 reverse proxy / API gateway 製品です。
Coraza WAF + OWASP CRS に、built-in の route 管理、埋め込み管理 UI/API、
optional な static / PHP-FPM hosting、cache、app-edge policy control を統合しています。

主な用途は次のとおりです。

- reverse proxy と route 管理
- WAF と誤検知チューニング
- rate / country / bot / semantic / IP reputation 制御
- built-in の管理 UI/API
- optional な static hosting / PHP-FPM / scheduled jobs
- single binary または Docker 配備

## 製品ポジショニング

`tukuyomi` は、アプリケーション境界を担当する WAF / reverse proxy 製品の canonical repository です。
旧 `tukuyomi-proxy` 系列はこのリポジトリへ統合し、今後は `tukuyomi` プロダクト名で継続します。

`tukuyomi-releases` にある旧 `tukuyomi-proxy` バイナリは archive として残しますが、
同リポジトリは今後の proxy/WAF 更新チャネルではありません。proxy、routing、cache、
WAF tuning、PHP-FPM、scheduled tasks の開発は `tukuyomi` に集約します。

詳細な比較は [docs/product-comparison.ja.md](docs/product-comparison.ja.md) を参照してください。

## ルールファイルと初期セットアップ

本リポジトリには、ライセンス順守のため OWASP CRS 本体は同梱していません。
代わりに、最小の起動用ベースルール seed `data/rules/tukuyomi.conf` を同梱しています。

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

初回 DB import 前には、bootstrap したい seed file を実値へ差し替えてください。

- `data/conf/config.json`: DB 接続 bootstrap
- `data/conf/proxy.json`: proxy rules の初期 seed/import file
- `data/conf/sites.json`: site ownership / TLS を使う場合の初期 seed/import file
- `data/conf/scheduled-tasks.json`: scheduled tasks を使う場合の初期 seed/import file

その後、本番起動前に `make db-import` を実行し、残りの設定 seed を DB へ
取り込みます。`make crs-install` は `make db-migrate` 後に動き、WAF/CRS
rule asset を DB へ import します。import 後の本番起動で必要なのは DB
接続 bootstrap 用の `data/conf/config.json` と DB row であり、その他の seed
JSON/rule file は runtime authority ではありません。

## クイックスタート

### ローカル preview

単純なローカル preview 手順は次です。

```bash
make preset-apply PRESET=minimal
make ui-preview-up
```

`make ui-preview-up` は CRS ensure flow を自動実行します。この flow は
`make db-migrate` を実行し、CRS seed file が無ければ配置し、WAF rule asset を
DB へ import します。

その後、既定では以下へアクセスします。

- 管理 UI: `http://localhost:9090/tukuyomi-ui`
- 管理 API: `http://localhost:9090/tukuyomi-api`

既定では `make ui-preview-up` は preview 専用 SQLite DB を使い、起動のたびに
その DB と preview 専用設定 file を初期化します。`UI_PREVIEW_PERSIST=1` を付けると、
preview 専用設定と DB state を `ui-preview-down` / `ui-preview-up` の間で保持できます。

### Runtime 設定モデル

`tukuyomi` は責務ごとに設定を分けています。

- `.env`: Docker 実行差分のみ
- `data/conf/config.json`: DB 接続 bootstrap と app config seed/export material
- DB `app_config_*`: global runtime / listener / admin / storage policy / path 設定
- DB `proxy_*`: live の proxy transport / routing 設定
- `data/conf/proxy.json`: proxy rules の seed/import/export material
- DB `proxy_backend_pools` / `proxy_backend_pool_members`: named upstream member から作る route 単位の balancing group
- `data/conf/upstream-runtime.json`: `Proxy Rules > Upstreams` で定義した opt-in runtime override の seed/import/export material
- `data/conf/sites.json`: site ownership と TLS binding の seed/import/export material
- DB `vhosts` / `vhost_*`: live vhost と PHP-FPM vhost config
- DB `waf_rule_assets`: base WAF と CRS の rule/data asset
- DB `override_rules`: managed bypass `extra_rule` の rule body
- `data/conf/rules/*.conf`: managed bypass override の任意 seed file
- DB `php_runtime_inventory` / `php_runtime_modules`: PHP-FPM runtime inventory と module metadata
- `data/php-fpm/inventory.json` / `data/php-fpm/vhosts.json`: PHP-FPM の seed/import/export material
- `data/conf/scheduled-tasks.json`: scheduled task の seed/import/export material

base WAF/CRS asset と managed bypass override は import 後 DB-backed です。
設定された path は logical asset 名および互換参照として残りますが、DB に active
generation があれば runtime は seed file の存在を要求しません。同じく startup、
policy、site、vhost、scheduled task、upstream runtime、response cache、
PHP-FPM inventory domain も `make db-import` 後は DB から直接読みます。

運用面の詳細は以下を参照してください。

- [docs/reference/operator-reference.ja.md](docs/reference/operator-reference.ja.md)
- [docs/operations/listener-topology.ja.md](docs/operations/listener-topology.ja.md)

`Proxy Rules > Upstreams` は direct backend node catalog、`Proxy Rules >
Backend Pools` は route から参照できる upstream 名をまとめる route 単位の
balancing group です。route は通常 `action.backend_pool` に bind し、
`Backends` は routing で使われる canonical backend object を一覧化しつつ、
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

Vhost を同じ routing namespace に載せたい時は、Vhost に
`linked_upstream_name` が必須で、`Proxy Rules > Upstreams` に既に存在している
upstream 名でなければなりません。Vhost はその configured upstream に bind し、
effective runtime ではその upstream 自体が vhost-backed target として解決されます。
従来の `generated_target` は vhost materialization の内部互換 field として残ります。
Vhost に bind されている configured upstream は、Vhost 側を relink するまで
`Proxy Rules > Upstreams`
から削除できません。

通常の `http://` / `https://` upstream proxy では自動的に:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

を付与します。

さらに `emit_upstream_name_request_header=true` を有効にすると、次も付与できます。

- `X-Tukuyomi-Upstream-Name`

この内部 observability header は、最終 target が `Proxy Rules > Upstreams`
の configured named upstream だった時だけ付与されます。direct route URL と
generated vhost target には付きません。また、route-level の
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

- PHP-FPM runtime と VHosts:
  - [docs/operations/php-fpm-vhosts.ja.md](docs/operations/php-fpm-vhosts.ja.md)
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
- `ci / compose-validate`
- `ci / waf-test (file)`
- `ci / waf-test (sqlite)`

## ライセンス

tukuyomi は、nginx と同じ permissive license 系列である BSD 2-Clause License
で公開します。詳細は [LICENSE](LICENSE) を参照してください。

サードパーティ依存ライブラリの著作権表示は [NOTICE](NOTICE) を参照してください。
依存ライセンスの metadata は `coraza/src/go.mod` / `coraza/src/go.sum` と
`web/tukuyomi-admin/package-lock.json` から確認できます。

## tukuyomi とは？

**tukuyomi** は、nginx + Coraza WAF をベースとした OSS WAF **mamotama** を前身として発展したプロダクトです。

名前は **「護りたまえ」(mamoritamae)** に由来し、*「守護を与えよ」* という意味を持ちます。
mamotama が「保護」を核心に据えていたのに対し、tukuyomi はより構造化され、
運用しやすい web protection を目指しています。
