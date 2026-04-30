# 付録A　運用リファレンス

本付録は、`data/conf/config.json` と DB `app_config_*` の主要 block、
管理 UI / API、Make ターゲット、Policy file と Security control、Logs と
Cache を **辞書代わりに引ける形** でまとめたものです。本文で「設定 key
を直接引きたい」と感じたとき、ここに戻ってきてください。

各セクションは、上流の `docs/reference/operator-reference.ja.md` を
日本語書籍向けに整文しつつ、構造はそのまま保つようにしています。

## A.1　実行時設定

`.env` は **Docker / 実行差分だけ** に使います。`data/conf/config.json` は
**DB 接続 bootstrap** であり、DB open 後の app / proxy / runtime / policy
挙動は normalized DB table から読みます。

### A.1.1　Docker / ローカル MySQL（任意）

| 変数名 | 例 | 説明 |
|---|---|---|
| `MYSQL_PORT` | `13306` | `mysql` profile 利用時、ローカル MySQL コンテナ `3306` へ割り当てるホスト側ポート |
| `MYSQL_DATABASE` | `tukuyomi` | ローカル MySQL コンテナで初期作成する DB 名 |
| `MYSQL_USER` | `tukuyomi` | ローカル MySQL コンテナで作成するアプリ用ユーザー |
| `MYSQL_PASSWORD` | `tukuyomi` | `MYSQL_USER` のパスワード |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | root パスワード |
| `MYSQL_TZ` | `UTC` | コンテナのタイムゾーン |

### A.1.2　`data/conf/config.json` / DB `app_config`

`data/conf/config.json` は DB を開く前に必要な `storage.db_driver`、
`storage.db_path`、`storage.db_dsn` を提供します。その他の product-wide
config は bootstrap / import 後、DB `app_config` に保存します。

主要 block:

| Block | 役割 |
|---|---|
| `server` | listener、timeout、backpressure、TLS、HTTP/3、public/admin 分離 |
| `runtime` | `gomaxprocs`、`memory_limit_mb` などの Go runtime 制御 |
| `admin` | UI / API path、session、外部公開方針、trusted CIDR、admin rate limit |
| `paths` | rules、bypass、country、rate、bot、semantic、CRS、sites、tasks、artifact の配置 |
| `proxy` | rollback 履歴と process-wide proxy engine 制御 |
| `crs` | CRS enable flag |
| `storage` | DB-only runtime store（`sqlite` / `mysql` / `pgsql`）、retention、sync interval、log file rotation limit |
| `fp_tuner` | 外部 provider endpoint、approval、timeout、audit |
| `request_metadata` | `header` / `mmdb` などの country 解決方法 |
| `observability` | OTLP tracing 設定 |

container 起動で通常必要になる env:

| 変数名 | 例 | 説明 |
|---|---|---|
| `WAF_CONFIG_FILE` | `conf/config.json` | 起動時 config path |
| `WAF_LISTEN_PORT` | `9090` | compose helper / healthcheck 用 port。`server.listen_addr` と合わせる |

### A.1.3　Inbound Timeout Boundary

- public HTTP/1.1 data-plane listener は Tukuyomi native HTTP/1.1 server が
  処理する。admin listener、HTTP redirect listener、HTTP/3 helper は分離した
  control / edge helper のまま。
- `server.read_header_timeout_sec`: request line と header のみ
- `server.read_timeout_sec`: request line + header + body 全体の inbound
  read budget
- `server.write_timeout_sec`: response write の上限
- `server.idle_timeout_sec`: keep-alive の request 間 idle 時間の上限
- `server.graceful_shutdown_timeout_sec`: deploy / reload 時に live
  connection を drain する上限。**超過後は force close**
- TLS public listener は HTTP/1.1 を advertise。HTTP/3 は **専用 listener**

### A.1.4　Overload Backpressure

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

- `max_concurrent_requests`: process-wide cap
- `max_concurrent_proxy_requests`: data-plane cap
- queue は対応する `max_concurrent_* > 0` のときだけ有効
- queue に入った成功応答には次の header が付く
  - `X-Tukuyomi-Overload-Queued: true`
  - `X-Tukuyomi-Overload-Queue-Wait-Ms`
- 拒否時は queue 系理由を含む `503`

### A.1.5　Built-in TLS Termination（任意）

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
    "key_file":  "/etc/tukuyomi/tls/privkey.pem",
    "min_version": "tls1.2",
    "redirect_http": true,
    "http_redirect_addr": ":9080"
  }
}
```

要点:

- `server.tls.enabled=false` が既定
- `server.http3.enabled=true` には built-in TLS が必須
- HTTP/3 は `server.listen_addr` と同じ numeric port を **UDP** で使う
- `server.tls.redirect_http=true` で plain HTTP listener を追加
- ACME auto TLS は site ごとの `tls.mode=acme` で選択。ACME account key /
  challenge token / 証明書 cache は `persistent_storage` の `acme/`
  namespace に保存
- ACME HTTP-01 のため、port 80 を `server.tls.http_redirect_addr` に
  到達させる
- Let's Encrypt の `staging` / `production` は site ごとの ACME environment
  で選ぶ
- `paths.site_config_file` の既定は `conf/sites.json`。DB-backed runtime
  では空 DB の seed / export path

### A.1.6　Persistent File Storage

`persistent_storage` は **ACME cache など、DB ではなく byte として永続化
する runtime artifact** の配置先です。

```json
{
  "persistent_storage": {
    "backend": "local",
    "local": { "base_dir": "data/persistent" }
  }
}
```

- `local` は単一 node または operator が用意した共有 mount 向け
- S3 は provider 名 / bucket / region / endpoint / prefix などの **非秘密
  情報のみ** を設定対象にする。MinIO 等の S3-compatible では
  `force_path_style=true`
- API key / secret key / client secret / token / connection string は
  JSON / DB に保存しない
- AWS / Azure / GCP の認証は env / managed identity / Workload Identity /
  ADC など platform 側で供給
- S3 backend は `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / 任意の
  `AWS_SESSION_TOKEN` / `AWS_REGION` / `AWS_DEFAULT_REGION` を runtime env
  から読む
- Azure Blob / GCS は provider adapter が入るまで fail-closed。local への
  暗黙 fallback はしない

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

MinIO integration test は通常回帰では skip されます。実行する場合は、
既存 bucket を用意し、`TUKUYOMI_MINIO_S3_ENDPOINT` /
`TUKUYOMI_MINIO_S3_BUCKET` / `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY` を設定します。

### A.1.7　管理面の基本

- `admin.session_secret` は **server-side 専用** で保持
- CLI / automation は user ごとの **personal access token** を使う
- 管理 UI は username / password login と DB-backed session cookie を使う
- `Settings` は `Save config only`。listener / runtime / storage 系は
  **restart が必要**

### A.1.8　Host Network Hardening（L3/L4 基本）

`tukuyomi` は L7 gateway であり、**上流 DDoS 防御の代替ではありません**。
最低限の host hardening として、次の sysctl を当てておきます。

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`:

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

## A.2　管理ダッシュボード

管理 UI は Go binary から **`/tukuyomi-ui`** として配信されます。主な画面は
次のとおりです。

| Path | 役割 |
|---|---|
| `/status` | runtime status / config snapshot / listener topology |
| `/logs` | WAF / security log 閲覧 |
| `/rules` | runtime WAF rule 順序 / base rule 編集 / CRS toggle |
| `/bypass` / `/country-block` / `/rate-limit` | DB-synced policy 編集 |
| `/ip-reputation` / `/bot-defense` / `/semantic` | request-time security 制御 |
| `/notifications` | aggregate alerting 設定 |
| `/cache` | cache rules と internal cache store |
| `/proxy-rules` | Runtime Apps が所有しない direct upstream / backend pool / route 編集と validate / probe / dry-run / apply / rollback |
| `/backends` | direct upstream backend object の一覧。direct named upstream は runtime enable / drain / disable / weight override に対応。Runtime App generated target は Runtime Apps 側 |
| `/sites` | site ownership と TLS binding |
| `/options` | runtime inventory / optional artifact / GeoIP / Country DB 管理 |
| `/runtime-apps` | static / `php-fpm` / `psgi` の runtime listener / docroot / runtime / generated backend 管理 |
| `/scheduled-tasks` | cron-style command task と last-run status |
| `/settings` | DB `app_config` 編集（restart-required 設定） |

UI sample は `docs/images/ui-samples/` にあります（本書では `images/ui-samples/`
に複製済み）。

### A.2.1　起動

```bash
make env-init
make db-migrate
make crs-install
make compose-up
```

管理 UI は `http://localhost:${CORAZA_PORT:-9090}/tukuyomi-ui` で開きます。

### A.2.2　よく使う Make ターゲット

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

## A.3　Proxy Routing と Transport（リファレンス）

upstream failure 時の応答は次の 3 通りです。

- `error_html_file` と `error_redirect_url` の両方が未設定: 既定の
  `502 Bad Gateway`
- `error_html_file` 設定時: HTML client にメンテナンスページ、その他は
  plain text `503`
- `error_redirect_url` 設定時: `GET` / `HEAD` を redirect、その他は
  plain text `503`

routing model:

- `routes[]` は `priority` 昇順で **first-match**
- 選択順:
  1. explicit `routes[]`
  2. DB `sites` domain 由来の generated host fallback route
  3. `default_route`
  4. `upstreams[]`
- host match: exact と `*.example.com`
- path match: `exact` / `prefix` / `regex`
- `upstreams[]`: Runtime Apps が所有しない direct backend node catalog。
  各行は static `url` か `discovery` のどちらか
- `backend_pools[]`: named upstream member から route 単位の balancing set
- `action.backend_pool`: balancing 標準の route binding
- `action.upstream`: direct upstream 名 または server-generated Runtime App
  upstream 名
- `action.canary_upstream` と `action.canary_weight_percent`: route-level
  canary
- `action.host_rewrite` / `action.path_rewrite.prefix` /
  `action.query_rewrite`: outbound rewrite
- `action.request_headers` / `action.response_headers`: bounded header 制御
- `response_header_sanitize`: 最終 response-header safety gate
- structured editor は次の順で workflow を見せる
  1. `Upstreams`
  2. `Backend Pools`
  3. `Routes` / `Default route`
- `Upstreams` の各行に専用の `Probe`
- `Runtime Apps` は generated backend を effective runtime に公開
- `Runtime Apps` は configured upstream URL を書き換えない

### A.3.1　Proxy Engine

```json
{ "proxy": { "engine": { "mode": "tukuyomi_proxy" } } }
```

- 対応 engine は **`tukuyomi_proxy` のみ**。restart-required
- `tukuyomi_proxy` は WAF / routing 後に Tukuyomi の response bridge を使う
- legacy `net_http` bridge は削除済み。`tukuyomi_proxy` 以外は config
  validation で拒否
- HTTP/1.1 と明示的な upstream HTTP/2 mode は Tukuyomi native upstream
  transport を使う。HTTPS `force_attempt` は ALPN で `h2` が選ばれない
  場合だけ native HTTP/1.1 へ fallback
- Upgrade / WebSocket handshake は `tukuyomi_proxy` 内で処理
- runtime visibility: `/tukuyomi-api/status` の `proxy_engine_mode` と
  `Settings → Runtime Inventory`

### A.3.2　WAF Engine

```json
{ "waf": { "engine": { "mode": "coraza" } } }
```

- 現 build で稼働可能なのは **`coraza` のみ**
- `mod_security` は将来用の既知 mode。adapter 未 compile では fail-closed
- 未知 mode は config validation で拒否
- runtime visibility: `/tukuyomi-api/status` の `waf_engine_mode` /
  `waf_engine_modes` と `Settings → Runtime Inventory`
- 左 navigation の `Security > Coraza` は engine-specific として、active WAF
  engine が Coraza でなければ隠す。`Security > Request Controls` は
  Tukuyomi request policy なので表示維持

### A.3.3　Runtime Backend Operations

- normalized `upstream_runtime` DB domain が direct upstream / DNS discovery
  から materialize された backend key ごとの **opt-in runtime override** を
  保持する。`data/conf/upstream-runtime.json` は空 DB の seed / export
- `Backends` は direct upstream backend object 一覧と次の runtime 操作:
  - `enabled`
  - `draining`
  - `disabled`
  - 正の `weight_override`
- override が無い backend は DB `proxy_rules` の設定どおりに動く
- runtime 操作対象は static direct upstream と DNS discovery で materialize
  された target
- Runtime App generated target は `Runtime Apps` 側で扱い、`Backends` には
  表示しない
- route 直書き URL と Runtime App generated target は runtime 操作対象外
- `draining` / `disabled` / `unhealthy` backend は新規 target selection
  から外れる
- `proxy_access` log の selected backend 系 field（5.3.1 節を参照）

通常 `http://` / `https://` upstream proxy では次の header を自動付与:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

`emit_upstream_name_request_header=true` を有効にすると:

- `X-Tukuyomi-Upstream-Name`

これは internal observability 用 header。`[proxy]` は inbound の同名 header
を一度除去し、最終 target が `Proxy Rules > Upstreams` の configured named
upstream のときだけ付け直す。これらの runtime 管理 header は route-level
`request_headers` から override 不可。

### A.3.4　最小 upstream / backend pool 例

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

route-scoped backend pool 最小例（第5章 5.1.4 節と同じ）:

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
    { "name": "site-app",       "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ],
  "routes": [
    { "name": "site-localhost", "priority": 10, "match": { "hosts": ["localhost"] }, "action": { "backend_pool": "site-localhost" } },
    { "name": "site-app",       "priority": 20, "match": { "hosts": ["app"] },       "action": { "backend_pool": "site-app" } }
  ]
}
```

### A.3.5　Dynamic DNS Backend Discovery

第5章 5.5 節を参照。`type=dns` は A / AAAA、`type=dns_srv` は SRV。
`refresh_interval_sec` で更新間隔を制御。初回失敗 + last-good なしなら
selectable target が 0、後続失敗時は last-good を保持。

### A.3.6　Backend Pool Sticky Sessions

第5章 5.6 節を参照。`backend_pools[].sticky_session.enabled=true` で
proxy が署名付き Cookie を発行。tampered / expired / unknown / disabled /
draining / unhealthy な sticky target は無視。`same_site=none` には
`secure=true` 必須。

### A.3.7　Dry-run

```bash
curl -sS \
  -H "Authorization: Bearer ${WAF_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

route 関連 log:

- `proxy_route`
- `original_host` / `original_path` / `original_query`
- `rewritten_host` / `rewritten_path` / `rewritten_query`
- `selected_route`

`proxy_route` は route classification 後・WAF / final target selection 前に
emit。`selected_upstream` / `selected_upstream_url` は post-selection log
だけに出る。

request flow:

- request metadata resolution
- route classification と rewrite planning
- country block / request-security plugins / rate limit / WAF
- final target selection
- proxy transport または direct static / php-fpm serving

## A.4　管理 API

schema 詳細は `docs/api/admin-openapi.yaml` を参照してください。主な
endpoint 群:

| Group | 例 |
|---|---|
| runtime status / metrics | `/status`, `/metrics` |
| logs / evidence | `/logs/read`, `/logs/stats`, `/logs/security-audit*`, `/logs/download` |
| rules / CRS | `/rules*`, `/crs-rule-sets*` |
| policy files | `/bypass-rules*`, `/country-block-rules*`, `/rate-limit-rules*`, `/ip-reputation*`, `/notifications*`, `/bot-defense-rules*`, `/semantic-rules*` |
| FP Tuner | `/fp-tuner/propose`, `/fp-tuner/apply` |
| cache | `/cache-rules*`, `/cache-store*` |
| PHP / Runtime Apps / tasks | `/php-runtimes*`, `/runtime-apps*`, `/scheduled-tasks*` |
| sites / proxy routing | `/sites*`, `/proxy-rules*` |
| GeoIP country update | `/request-country-mode`, `/request-country-db*`, `/request-country-update*` |

`GET /tukuyomi-api/status` で確認できるもの:

- listener / runtime disclosure
- TLS / HTTP/3 state
- site runtime state
- upstream HA / runtime state
- request-security counters と config snapshot

## A.5　Policy Files と Security Controls

### A.5.1　WAF Bypass / Special Rule

`paths.bypass_file` の既定は `conf/waf-bypass.json`。

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

- managed な `extra_rule` body は **DB `override_rules`** に保存し、
  `Rules > Advanced > Bypass snippets` で編集
- `conf/rules` filesystem fallback は **無し**
- 起動時の base WAF rule set には混ぜず、bypass entry から logical
  `extra_rule` 名で参照されたときだけ load
- host scope の優先順は exact `host:port` → bare `host` → `default`。
  host-specific scope は default を merge **せず置き換え**

### A.5.2　Country Block

`paths.country_block_file` の既定は `conf/country-block.json`。

- JSON field は `default.blocked_countries` と optional
  `hosts.<host>.blocked_countries`
- 値は ISO-3166 alpha-2 country code と `UNKNOWN`
- match すると WAF 前に `403`
- country 解決は `request_metadata_resolvers` 担当
- `header` mode: `X-Country-Code`
- `mmdb` mode: DB-managed な country MMDB asset を runtime に load して解決
- host scope 優先順は exact `host:port` → bare `host` → `default`

### A.5.3　Rate Limit

`paths.rate_limit_file` の既定は `conf/rate-limit.json`。

- JSON 形式で `default_policy` と `rules`
- `key_by`: `ip` / `country` / `ip_country` / `session` / `ip_session` /
  `jwt_sub` / `ip_jwt_sub`
- adaptive throttling で bot / semantic risk を利用可能
- feedback で sustained abuse を bot-defense quarantine へ昇格可能

### A.5.4　IP Reputation

`paths.ip_reputation_file` の既定は `conf/ip-reputation.json`。

- local file と HTTP / HTTPS feed をサポート
- inline allowlist が feed 由来 block より優先
- request-time security の順序: **`ip_reputation → bot_defense → semantic`**

### A.5.5　WebSocket Scope

- HTTP upgrade handshake は通常 request と同様に検査
- upgraded frame は **pass-through**。WAF / body inspect は **しない**

### A.5.6　Admin Surface Hardening

- `admin.external_mode`: `deny_external` / `api_only_external` /
  `full_external`
- `admin.trusted_cidrs` で trusted peer を定義
- `admin.trust_forwarded_for=true` は direct peer が trusted のときだけ有効
- `admin.rate_limit` で管理面専用 throttle を追加

### A.5.7　Observability

- `/metrics` は TLS / upstream HA / rate limit / semantic / request-security
  counter を expose
- WAF / access event は **DB-backed**。security audit は別の file /
  evidence stream として残り、file rotation 設定は file-backed audit /
  legacy log stream に適用される
- optional OTLP tracing は `observability.tracing`

### A.5.8　Notifications

`paths.notification_file` の既定は `conf/notifications.json`。

- per-request ではなく **aggregate state transition** を通知
- `webhook`、`email` をサポート
- `/notifications/test` で test 通知
- `/notifications/status` で sink / runtime 状態確認

### A.5.9　Bot Defense

`paths.bot_defense_file` の既定は `conf/bot-defense.json`。

主な機能:

- suspicious UA challenge
- behavioral detection
- browser / device telemetry cookie
- first-request header signals
- direct HTTPS 向け TLS fingerprint heuristic
- repeated-strike quarantine
- path-aware override
- global / per-flow `dry_run`

### A.5.10　Semantic Security

`paths.semantic_file` の既定は `conf/semantic.json`。

- enforcement stage: `off` / `log_only` / `challenge` / `block`
- temporal signal を含む request scoring
- `semantic_anomaly` log には `reason_list` と `score_breakdown`

### A.5.11　Security Audit Trail

`security_audit` は **request-level の署名付き audit trail** を追加します。

- decision-chain JSON: `paths.security_audit_file`
- encrypted evidence blob: `paths.security_audit_blob_dir`
- body retention は **opt-in かつ bounded**
- integrity verify: `/logs/security-audit/verify`

### A.5.12　Rules / CRS Editing

- `/rules` は Coraza CRS asset と base WAF rule asset を runtime 順に表示
- active な DB-backed base rule asset を編集
- base WAF rule asset は disable できる。disable された asset は編集可能
  なまま、live WAF load set から外れる
- logical `rules/crs/rules/*.conf` 名の DB-backed CRS asset を toggle
- save 成功時は WAF hot reload。reload failure 時は **auto rollback**

## A.6　Logs と Cache

### A.6.1　Log Retrieval

```bash
curl -s -H "Authorization: Bearer <your-personal-access-token>" \
     "http://<host>/tukuyomi-api/logs/read?tail=100&country=JP" | jq .
```

### A.6.2　Cache Feature

cache rules と internal cache store 設定は **DB table で version 管理**
されます。`data/conf/cache-rules.json` は空 DB 向けの seed / import
material のままです。internal cache store 設定は normalized row が無い
時に DB default から seed され、`data/conf/cache-store.json` は明示的な
no-DB fallback 実行時だけ意味を持ちます。

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

- host ごとの cache scope は default scope に **merge されず、match 時は
  置き換わる**
- match した response は internal file-backed cache に保存可能
- optional の bounded **L1 memory cache** を有効化可能
- `POST /tukuyomi-api/cache-store/clear` で即時全削除
- authenticated traffic や upstream response に `Set-Cookie` があるものは
  保存しない

確認用 header:

- `X-Tukuyomi-Cacheable: 1`
- `X-Accel-Expires: <seconds>`
- `X-Tukuyomi-Cache: MISS|HIT`
