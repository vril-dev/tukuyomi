# 運用リファレンス

このドキュメントは、以前 `README.ja.md` に直接書いていた運用向け詳細をまとめたものです。

## 実行時設定

`.env` は Docker / 実行差分だけに使います。`data/conf/config.json` は DB
接続 bootstrap であり、DB open 後の app/proxy/runtime/policy 挙動は
normalized DB table から読みます。

### Docker / ローカル MySQL（任意）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `MYSQL_PORT` | `13306` | `mysql` profile 利用時に、ローカル MySQL コンテナ `3306` へ割り当てるホスト側ポート。 |
| `MYSQL_DATABASE` | `tukuyomi` | ローカル MySQL コンテナで初期作成する DB 名。 |
| `MYSQL_USER` | `tukuyomi` | ローカル MySQL コンテナで作成するアプリ用ユーザー。 |
| `MYSQL_PASSWORD` | `tukuyomi` | `MYSQL_USER` のパスワード。 |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | root パスワード。 |
| `MYSQL_TZ` | `UTC` | コンテナのタイムゾーン。 |

### `data/conf/config.json` / DB `app_config`

`data/conf/config.json` は DB を開く前に必要な `storage.db_driver`、
`storage.db_path`、`storage.db_dsn` を提供します。その他の product-wide
config は bootstrap/import 後、DB `app_config` に保存します。

主な block:

| Block | 役割 |
| --- | --- |
| `server` | listener, timeout, backpressure, TLS, HTTP/3, public/admin 分離 |
| `runtime` | `gomaxprocs`, `memory_limit_mb` など Go runtime 制御 |
| `admin` | UI/API path, session, 外部公開方針, trusted CIDR, admin rate limit |
| `paths` | rules, bypass, country, rate, bot, semantic, CRS, sites, tasks, artifact の配置 |
| `proxy` | rollback 履歴と process-wide proxy engine 制御 |
| `crs` | CRS enable flag |
| `storage` | DB-only runtime store (`sqlite`, `mysql`, `pgsql`), retention, sync interval, log file rotation limit |
| `fp_tuner` | 外部 provider endpoint, approval, timeout, audit |
| `request_metadata` | `header` / `mmdb` など country 解決方法 |
| `observability` | OTLP tracing 設定 |

container 起動で通常必要なのは:

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `WAF_CONFIG_FILE` | `conf/config.json` | 起動時 config path。 |
| `WAF_LISTEN_PORT` | `9090` | compose helper / healthcheck 用 port。`server.listen_addr` と合わせます。 |

### Inbound Timeout Boundary

- public HTTP/1.1 data-plane listener は Tukuyomi native HTTP/1.1 server が処理します。admin listener、HTTP redirect listener、HTTP/3 helper は分離した control / edge helper のままです
- `server.read_header_timeout_sec` は request line と header のみ
- `server.read_timeout_sec` は request line + header + body 全体の inbound read budget
- `server.write_timeout_sec` は response write の上限です。slow client は data-plane goroutine を保持し続けず close します
- `server.idle_timeout_sec` は keep-alive の request 間 idle 時間の上限です
- `server.graceful_shutdown_timeout_sec` は deploy / reload 時に live connection を drain する上限時間です。超過後は force close します
- TLS public listener はこの native server path では HTTP/1.1 を advertise します。HTTP/3 は有効時も専用 HTTP/3 listener で処理します

### Overload Backpressure

```json
"server": {
  "max_concurrent_requests": 96,
  "max_queued_requests": 0,
  "queued_request_timeout_ms": 0,
  "max_concurrent_proxy_requests": 80,
  "max_queued_proxy_requests": 32,
  "queued_proxy_request_timeout_ms": 100
}
```

- `max_concurrent_requests` は process-wide cap
- `max_concurrent_proxy_requests` は data-plane cap
- queue は対応する `max_concurrent_* > 0` の時だけ有効
- queue に入った成功応答には:
  - `X-Tukuyomi-Overload-Queued: true`
  - `X-Tukuyomi-Overload-Queue-Wait-Ms`
- 拒否時は queue 系理由を含む `503`

### Built-in TLS Termination（任意）

```json
"server": {
  "listen_addr": ":9443",
  "http3": {
    "enabled": true,
    "alt_svc_max_age_sec": 86400
  },
  "tls": {
    "enabled": true,
    "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
    "key_file": "/etc/tukuyomi/tls/privkey.pem",
    "min_version": "tls1.2",
    "redirect_http": true,
    "http_redirect_addr": ":9080"
  }
}
```

要点:

- `server.tls.enabled=false` が既定
- `server.http3.enabled=true` には built-in TLS が必要
- HTTP/3 は `server.listen_addr` と同じ numeric port を UDP で使う
- `server.tls.redirect_http=true` で plain HTTP listener を追加
- ACME auto TLS は site ごとの `tls.mode=acme` で選択します。ACME account key・challenge token・証明書 cache は `persistent_storage` の `acme/` namespace に保存します。
- ACME HTTP-01 を使うため、port 80 を `server.tls.http_redirect_addr` へ到達させてください。Let's Encrypt `staging` / `production` は site ごとの ACME environment で選びます。
- `paths.site_config_file` の既定は `conf/sites.json` です。DB-backed runtime では、これは空 DB の seed/export path であり live source of truth ではありません。

### Persistent File Storage

`persistent_storage` は ACME cache など、DB ではなく byte として永続化する runtime artifact の配置先です。

```json
{
  "persistent_storage": {
    "backend": "local",
    "local": {
      "base_dir": "data/persistent"
    }
  }
}
```

- `local` は単一 node または operator が用意した共有 mount 向けです。
- S3 は provider 名、bucket、region、endpoint、prefix などの非秘密情報のみを設定対象にします。MinIO 等の S3-compatible endpoint では `force_path_style=true` を使います。
- API key、secret key、client secret、token、connection string は JSON/DB に保存しません。AWS/Azure/GCP の認証は env、managed identity、Workload Identity、ADC など platform 側で供給します。
- S3 backend は `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、任意の `AWS_SESSION_TOKEN`、`AWS_REGION` / `AWS_DEFAULT_REGION` を runtime env から読みます。
- Azure Blob Storage / Google Cloud Storage は provider adapter が入るまで fail-closed です。local へ暗黙 fallback しません。

S3-compatible backend 例:

```json
{
  "persistent_storage": {
    "backend": "s3",
    "s3": {
      "bucket": "tukuyomi-runtime",
      "region": "us-east-1",
      "endpoint": "http://minio:9000",
      "prefix": "prod",
      "force_path_style": true
    }
  }
}
```

MinIO integration test は通常回帰では skip されます。実行する場合は、既存 bucket を用意し、`TUKUYOMI_MINIO_S3_ENDPOINT`、`TUKUYOMI_MINIO_S3_BUCKET`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` を設定します。

TLS 証明書選択は TLS handshake 時点で終わるため、route host/path より前に決まります。

### 管理面の基本

- `admin.session_secret` は server-side 専用で保持
- CLI/automation は `admin.api_key_primary` / `admin.api_key_secondary`
- 管理UIは API key を session cookie へ交換して使う
- `Settings` は `Save config only` で、listener/runtime/storage 系は restart が必要

### Host Network Hardening（L3/L4 基本）

`tukuyomi` は L7 gateway です。上流 DDoS 防御の代替ではありません。

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`

```conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 対称ルーティング前提。非対称ルーティングや複数 NIC / トンネル環境では 2 を検討
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

適用:

```bash
sudo sysctl --system
```

## 管理ダッシュボード

管理UIは Go binary から `/tukuyomi-ui` として配信されます。

主な画面:

| Path | 役割 |
| --- | --- |
| `/status` | runtime status, config snapshot, listener topology |
| `/logs` | WAF / security log 閲覧 |
| `/rules` / `/rule-sets` | base rule 編集と CRS toggle |
| `/bypass` / `/country-block` / `/rate-limit` | DB-synced policy 編集 |
| `/ip-reputation` / `/bot-defense` / `/semantic` | request-time security 制御 |
| `/notifications` | aggregate alerting 設定 |
| `/cache` | cache rules と internal cache store |
| `/proxy-rules` | route/upstream/default-route 編集と validate/probe/dry-run/apply/rollback |
| `/backends` | canonical backend object の一覧。direct named upstream は runtime enable / drain / disable / weight override に対応し、vhost に bind された configured upstream はこの slice では status-only |
| `/sites` | site ownership と TLS binding |
| `/options` | runtime inventory, optional artifact, GeoIP/Country DB 管理 |
| `/vhosts` | static / `php-fpm` vhost と必須の configured upstream bind |
| `/scheduled-tasks` | cron-style command task と last-run status |
| `/settings` | DB `app_config` 編集（restart-required 設定） |

UI sample は `docs/images/ui-samples/` にあります。

### 起動

```bash
make env-init
make db-migrate
make crs-install
make compose-up
```

管理UIは `http://localhost:${CORAZA_PORT:-9090}/tukuyomi-ui` を開きます。

### よく使う Make ターゲット

```bash
make help
make build
make check
make smoke
make smoke-extended
make ci-local
make ci-local-extended
make deployment-smoke
make release-binary-smoke VERSION=v0.8.1
make http3-public-entry-smoke
make compose-down
```

### 関連ガイド

- binary deployment: [../build/binary-deployment.ja.md](../build/binary-deployment.ja.md)
- container deployment: [../build/container-deployment.ja.md](../build/container-deployment.ja.md)
- request-time security plugins: [../request_security_plugins.ja.md](../request_security_plugins.ja.md)
- regression matrix: [../operations/regression-matrix.ja.md](../operations/regression-matrix.ja.md)
- benchmark baseline: [../operations/benchmark-baseline.ja.md](../operations/benchmark-baseline.ja.md)
- upstream HTTP/2: [../operations/upstream-http2.ja.md](../operations/upstream-http2.ja.md)
- HTTP/3 public-entry smoke: [../operations/http3-public-entry-smoke.ja.md](../operations/http3-public-entry-smoke.ja.md)
- WAF tuning: [../operations/waf-tuning.ja.md](../operations/waf-tuning.ja.md)
- FP Tuner API contract: [../operations/fp-tuner-api.ja.md](../operations/fp-tuner-api.ja.md)
- PHP runtime / vhosts: [../operations/php-fpm-vhosts.ja.md](../operations/php-fpm-vhosts.ja.md)
- scheduled tasks: [../operations/php-scheduled-tasks.ja.md](../operations/php-scheduled-tasks.ja.md)
- DB operations: [../operations/db-ops.ja.md](../operations/db-ops.ja.md)

## Proxy Routing と Transport

upstream failure 時の応答:

- `error_html_file` と `error_redirect_url` の両方が未設定なら既定の `502 Bad Gateway`
- `error_html_file` 設定時は HTML client へ maintenance page、その他へ plain text `503`
- `error_redirect_url` 設定時は `GET` / `HEAD` を redirect、その他は plain text `503`

routing model:

- `routes[]` は `priority` 昇順で first-match
- 選択順:
  1. explicit `routes[]`
  2. DB `sites` domain 由来の generated host fallback route
  3. `default_route`
  4. `upstreams[]`
- host match は exact と `*.example.com`
- path match は `exact`, `prefix`, `regex`
- `upstreams[]` は named backend node catalog です。各行は static `url` か `discovery` のどちらか一方を使います
- `backend_pools[]` は named upstream member から route 単位の balancing set を作る
- `action.backend_pool` は balancing の標準 route binding
- `action.upstream` は設定済み upstream 名のみ
- `action.canary_upstream` と `action.canary_weight_percent` で route-level canary
- `action.host_rewrite`, `action.path_rewrite.prefix`, `action.query_rewrite` で outbound rewrite
- `action.request_headers`, `action.response_headers` で bounded header 制御
- `response_header_sanitize` は最終 response-header safety gate
- structured editor は次の順で operator workflow を見せます
  1. `Upstreams`
  2. `Backend Pools`
  3. `Routes` / `Default route`
- `Upstreams` の各行には専用の `Probe` があり、configured upstream を1件ずつ疎通確認します。
- `Vhosts` は `linked_upstream_name` を必須で持ちます。これにより route binding や backend-pool member から、同じ upstream 名 namespace で Vhost を参照できます。
- `linked_upstream_name` は `Proxy Rules > Upstreams` に既に存在している configured upstream でなければなりません。Vhost 側で managed alias は作りません。
- `generated_target` は vhost materialization 用の server-owned 内部互換 state です。operator の route/pool 紐付けは `linked_upstream_name` を使います。
- Vhost が bind している direct upstream は、Vhost 側を relink するまで `Proxy Rules > Upstreams` から削除できません。

### Proxy Engine

DB `app_config` の `proxy.engine.mode` で process-wide proxy engine を表します。
対応する engine は Tukuyomi native proxy のみです。この変更には process restart が必要です。

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は built-in engine で、WAF/routing selection 後に Tukuyomi の response bridge を使います。同じ HTTP parser、upstream transport、health、retry、TLS、HTTP/2、cache、route response headers、1xx informational responses、trailers、streaming flush behavior、native Upgrade/WebSocket tunnel、response-sanitize path を維持します。
- legacy `net_http` bridge は削除済みです。`proxy.engine.mode` に `tukuyomi_proxy` 以外を指定すると config validation で拒否します。
- HTTP/1.1 と明示的な upstream HTTP/2 mode は Tukuyomi native upstream transport を使います。HTTPS `force_attempt` は ALPN で `h2` が選ばれない場合だけ native HTTP/1.1 へ fallback します。
- Upgrade/WebSocket handshake request は `tukuyomi_proxy` 内で処理します。`101 Switching Protocols` 後の WebSocket frame payload は tunnel data であり、HTTP WAF inspection の入力ではありません。
- runtime visibility は `/tukuyomi-api/status` の `proxy_engine_mode` と `Settings -> Runtime Inventory` で確認できます。

### Runtime Backend Operations

- normalized `upstream_runtime` DB domain が `Proxy Rules > Upstreams` から materialize された backend key ごとの opt-in runtime override を保持します。`data/conf/upstream-runtime.json` は空 DB の seed/export path です
- `Backends` は canonical backend object を一覧しつつ、次の runtime 操作盤です
  - `enabled`
  - `draining`
  - `disabled`
  - 正の `weight_override`
- override が無い backend は DB `proxy_rules` の設定どおりに動きます。`data/conf/proxy.json` は seed/import/export material です
- runtime 操作対象は static direct upstream と DNS discovery で materialize された target です
- vhost に bind された configured upstream は route / pool から参照でき、`Backends` に status-only の canonical object として表示されます
- route 直書き URL、generated `static`、generated `php-fpm` target は runtime 操作対象外です
- `draining` / `disabled` / `unhealthy` backend は新規 target selection から外れます
- `proxy_access` log には selected backend の runtime state として以下が出ます
  - `selected_upstream_admin_state`
  - `selected_upstream_health_state`
  - `selected_upstream_effective_selectable`
  - `selected_upstream_effective_weight`
  - `selected_upstream_inflight`
- block された request には selected-backend field を出しません

通常の `http://` / `https://` upstream proxy では自動的に:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

を付与します。

さらに `emit_upstream_name_request_header=true` を有効にすると、次も付与できます。

- `X-Tukuyomi-Upstream-Name`

これは内部 observability 用 header です。`[proxy]` は inbound の同名 header を
一度除去し、最終 target が `Proxy Rules > Upstreams` の configured named
upstream だった時だけ付け直します。

これらの runtime 管理 header は route-level `request_headers` では上書きできません。

### 最小 upstream 例

```json
{
  "upstreams": [
    { "name": "primary", "url": "http://app.internal:8080", "weight": 1, "enabled": true }
  ],
  "load_balancing_strategy": "round_robin",
  "hash_policy": "cookie",
  "hash_key": "session",
  "expose_waf_debug_headers": false
}
```

### Dynamic DNS Backend Discovery

backend address を DNS が管理する container / Kubernetes 環境では
`upstreams[].discovery` を使います。Routes / Backend Pools は従来通り
canonical upstream name を参照します。runtime は bounded interval で DNS を解決し、
解決結果を backend target として materialize します。後続 lookup が失敗した場合は
last-good target set を保持します。

```json
{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "record_types": ["A", "AAAA"],
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    },
    {
      "name": "api-srv",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns_srv",
        "service": "http",
        "proto": "tcp",
        "name": "api.default.svc.cluster.local",
        "scheme": "https",
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ]
}
```

- `type=dns` は A/AAAA record を解決し、`hostname`, `scheme`, `port` が必須です
- `type=dns_srv` は `_service._proto.name` を解決し、SRV の port を使います
- `scheme` は `http` / `https` のみです。`fcgi` / `static` は discovery 対象外です
- DNS は request ごとに解決しません。更新間隔は `refresh_interval_sec` で制御します
- 初回 lookup が失敗し last-good が無い場合、その upstream は selectable target 0 になります
- `Backends` と health status で materialized target と discovery error を確認できます

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

### Backend Pool Sticky Sessions

`backend_pools[].sticky_session` は proxy が署名付き affinity Cookie を発行する機能です。
`hash_policy=cookie` は既存のアプリ Cookie を hash 入力にするだけですが、
`sticky_session` は load-balancer Cookie を proxy 自身が発行・更新します。

```json
{
  "backend_pools": [
    {
      "name": "site-api",
      "strategy": "round_robin",
      "members": ["api-a", "api-b"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 86400,
        "path": "/",
        "secure": true,
        "http_only": true,
        "same_site": "lax"
      }
    }
  ]
}
```

- 有効な sticky Cookie は round-robin、least-conn、hash selection より優先されます。
- invalid、expired、tampered、unknown、disabled、draining、unhealthy な sticky target は無視されます。
- Cookie 値は署名され、selected target identifier と expiry だけを保持します。backend URL は含めません。
- 署名 key は process-local で起動時に生成されます。restart 後の古い Cookie は安全に拒否され、次の応答で更新されます。
- `same_site=none` では `secure=true` が必須です。

```json
{
  "routes": [
    {
      "name": "service-a-prefix",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "service-a",
        "host_rewrite": "service-a.internal",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}
```

### dry-run 例

```bash
curl -sS \
  -H "X-API-Key: ${WAF_API_KEY}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

route 関連 log:

- `proxy_route`
- `original_host`, `original_path`, `original_query`
- `rewritten_host`, `rewritten_path`, `rewritten_query`
- `selected_route`
- `proxy_route` は route classification 後、WAF / final target selection 前に emit されるため、`selected_upstream` / `selected_upstream_url` は出しません
- `proxy_access` と post-selection transport log は、final target が確定した後だけ `selected_upstream` / `selected_upstream_url` を出します

request flow:

- request metadata resolution
- route classification と rewrite planning
- country block / request-security plugins / rate limit / WAF
- final target selection
- proxy transport または direct static / php-fpm serving

## 管理 API

schema 詳細は [../api/admin-openapi.yaml](../api/admin-openapi.yaml) を参照してください。

主な endpoint 群:

| Group | 例 |
| --- | --- |
| runtime status / metrics | `/status`, `/metrics` |
| logs / evidence | `/logs/read`, `/logs/stats`, `/logs/security-audit*`, `/logs/download` |
| rules / CRS | `/rules*`, `/crs-rule-sets*` |
| policy files | `/bypass-rules*`, `/country-block-rules*`, `/rate-limit-rules*`, `/ip-reputation*`, `/notifications*`, `/bot-defense-rules*`, `/semantic-rules*` |
| FP Tuner | `/fp-tuner/propose`, `/fp-tuner/apply` |
| cache | `/cache-rules*`, `/cache-store*` |
| PHP / vhosts / tasks | `/php-runtimes*`, `/vhosts*`, `/scheduled-tasks*` |
| sites / proxy routing | `/sites*`, `/proxy-rules*` |
| GeoIP country update | `/request-country-mode`, `/request-country-db*`, `/request-country-update*` |

`GET /tukuyomi-api/status` では:

- listener/runtime disclosure
- TLS/HTTP3 state
- site runtime state
- upstream HA/runtime state
- request-security counters と config snapshot

を確認できます。

## Policy Files と Security Controls

### WAF Bypass / Special Rule

`paths.bypass_file` の既定は `conf/waf-bypass.json` です。

```json
{
  "default": {
    "entries": [
      { "path": "/assets/" },
      { "path": "/about/user.php" }
    ]
  },
  "hosts": {
    "example.com": {
      "entries": [
        { "path": "/search", "extra_rule": "orders-preview.conf" }
      ]
    }
  }
}
```

managed な `extra_rule` body は DB `override_rules` に保存し、`Rules` 画面で用途を `Bypass Rules extra_rule` にして編集します。`conf/rules` filesystem fallback はありません。起動時の base WAF rule set には混ぜず、bypass entry から logical `extra_rule` name で参照された時だけ load します。
host scope の優先順は exact `host:port`、次に bare `host`、最後に `default` です。host-specific scope は default を merge せず置き換えます。

### Country Block

`paths.country_block_file` の既定は `conf/country-block.json` です。

- JSON field は `default.blocked_countries` と optional `hosts.<host>.blocked_countries`
- 値は ISO-3166 alpha-2 country code と `UNKNOWN`
- match すると WAF 前に `403`
- country 解決は `request_metadata_resolvers` が担当
- `header` mode は `X-Country-Code`
- `mmdb` mode は DB-managed な country MMDB asset を runtime へ load して解決します
- host scope の優先順は exact `host:port`、次に bare `host`、最後に `default`

### Rate Limit

`paths.rate_limit_file` の既定は `conf/rate-limit.json` です。

要点:

- JSON 形式で `default_policy` と `rules`
- `key_by` は `ip`, `country`, `ip_country`, `session`, `ip_session`, `jwt_sub`, `ip_jwt_sub`
- adaptive throttling で bot / semantic risk を利用可能
- feedback で sustained abuse を bot-defense quarantine へ昇格可能

### IP Reputation

`paths.ip_reputation_file` の既定は `conf/ip-reputation.json` です。

- local file と HTTP/HTTPS feed をサポート
- inline allowlist が feed 由来 block より優先
- request-time security の順序は `ip_reputation -> bot_defense -> semantic`

### WebSocket Scope

- HTTP upgrade handshake は通常 request と同様に検査
- upgraded frame は pass-through で WAF/body inspect しません

### Admin Surface Hardening

- `admin.external_mode`: `deny_external`, `api_only_external`, `full_external`
- `admin.trusted_cidrs` で trusted peer を定義
- `admin.trust_forwarded_for=true` は direct peer が trusted の時だけ有効
- `admin.rate_limit` で管理面専用 throttle を追加

### Observability

- `/metrics` は TLS, upstream HA, rate limit, semantic, request-security counter を expose
- WAF/access event は DB-backed です。security audit は別の file/evidence stream として残り、file rotation 設定は file-backed audit / legacy log stream に適用されます。
- optional OTLP tracing は `observability.tracing`

### Notifications

`paths.notification_file` の既定は `conf/notifications.json` です。

- per-request ではなく aggregate state transition を通知
- `webhook`, `email` をサポート
- `/notifications/test` で test 通知
- `/notifications/status` で sink/runtime 状態確認

### Bot Defense

`paths.bot_defense_file` の既定は `conf/bot-defense.json` です。

主な機能:

- suspicious UA challenge
- behavioral detection
- browser/device telemetry cookie
- first-request header signals
- direct HTTPS 向け TLS fingerprint heuristic
- repeated-strike quarantine
- path-aware override
- global / per-flow `dry_run`

### Semantic Security

`paths.semantic_file` の既定は `conf/semantic.json` です。

- enforcement stage は `off | log_only | challenge | block`
- temporal signal を含む request scoring
- `semantic_anomaly` log には `reason_list` と `score_breakdown`

### Security Audit Trail

`security_audit` は request-level の署名付き audit trail を追加します。

- decision-chain JSON は `paths.security_audit_file`
- encrypted evidence blob は `paths.security_audit_blob_dir`
- body retention は opt-in かつ bounded
- integrity verify は `/logs/security-audit/verify`

### Rules / CRS Editing

- `/rules` は active な DB-backed base rule asset を編集
- `/rule-sets` は logical `rules/crs/rules/*.conf` name の DB-backed CRS asset を toggle
- save 成功時は WAF hot reload
- reload failure 時は auto rollback

## Logs と Cache

### Log Retrieval

```bash
curl -s -H "X-API-Key: <your-api-key>" \
     "http://<host>/tukuyomi-api/logs/read?tail=100&country=JP" | jq .
```

### Cache Feature

cache rules と internal cache store 設定は DB table で version 管理されます。
`data/conf/cache-rules.json` は空 DB 向けの seed/import material のままです。
internal cache store 設定は normalized row が無い時に DB default から seed され、
`data/conf/cache-store.json` は明示的な no-DB fallback 実行時だけ意味を持ちます。

例:

```json
{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": { "type": "prefix", "value": "/_next/static/chunks/" },
        "methods": ["GET", "HEAD"],
        "ttl": 600,
        "vary": ["Accept-Encoding"]
      },
      {
        "kind": "DENY",
        "match": { "type": "prefix", "value": "/tukuyomi-api/" }
      }
    ]
  },
  "hosts": {
    "admin.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": { "type": "prefix", "value": "/" },
          "methods": ["GET", "HEAD"],
          "ttl": 600
        }
      ]
    }
  }
}
```

動作概要:

- host ごとの cache scope は default scope に merge されず、match 時は置き換わります
- match した response は internal file-backed cache に保存可能
- optional の bounded L1 memory cache を有効化可能
- `POST /tukuyomi-api/cache-store/clear` で即時全削除
- authenticated traffic や upstream response に `Set-Cookie` があるものは保存しません

確認用 header:

- `X-Tukuyomi-Cacheable: 1`
- `X-Accel-Expires: <seconds>`
- `X-Tukuyomi-Cache: MISS|HIT`
