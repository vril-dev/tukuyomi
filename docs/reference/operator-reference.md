# Operator Reference

This document holds the detailed operator-facing reference that previously
lived inline in `README.md`.

## Runtime Configuration

Use `.env` only for Docker/runtime wiring. `data/conf/config.json` is the DB
connection bootstrap; after DB opens, application and proxy behavior are loaded
from DB `config_blobs`.

### Docker / Local MySQL (Optional)

| Variable | Example | Description |
| --- | --- | --- |
| `MYSQL_PORT` | `13306` | Host port mapped to the local MySQL container `3306` when profile `mysql` is enabled. |
| `MYSQL_DATABASE` | `tukuyomi` | Initial database name created in the local MySQL container. |
| `MYSQL_USER` | `tukuyomi` | Application user created in the local MySQL container. |
| `MYSQL_PASSWORD` | `tukuyomi` | Password for `MYSQL_USER`. |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | Root password for the local MySQL container. |
| `MYSQL_TZ` | `UTC` | Container timezone. |

### `data/conf/config.json` / DB `app_config`

`data/conf/config.json` must provide `storage.db_driver`, `storage.db_path`, and
`storage.db_dsn` before DB can be opened. The rest of the product-wide config is
stored in DB `app_config` after bootstrap/import.

Main blocks:

| Block | Purpose |
| --- | --- |
| `server` | Listener address, timeouts, backpressure, TLS, HTTP/3, public/admin split listener behavior |
| `runtime` | Go runtime caps such as `gomaxprocs` and `memory_limit_mb` |
| `admin` | UI/API paths, session behavior, external exposure policy, trusted CIDRs, admin rate limit |
| `paths` | File locations for rules, bypass, country, rate, bot, semantic, CRS, sites, scheduled tasks, and artifacts |
| `proxy` | Rollback history limits and process-wide proxy engine behavior |
| `crs` | CRS enable flag |
| `storage` | DB-only runtime store (`sqlite`, `mysql`, `pgsql`), retention, sync interval, log file rotation limits |
| `fp_tuner` | External provider endpoint, approval, timeout, and audit controls |
| `request_metadata` | Metadata resolution source such as `header` or `mmdb` for country resolution |
| `observability` | OTLP tracing configuration |

Container startup usually needs only:

| Variable | Example | Description |
| --- | --- | --- |
| `WAF_CONFIG_FILE` | `conf/config.json` | Startup config path. |
| `WAF_LISTEN_PORT` | `9090` | Compose helper/healthcheck port. Keep aligned with `server.listen_addr`. |

### Inbound Timeout Boundary

- The public HTTP/1.1 data-plane listener is served by Tukuyomi's native
  HTTP/1.1 server. The admin listener, HTTP redirect listener, and HTTP/3
  helper remain separate control/edge helpers.
- `server.read_header_timeout_sec` applies only to the request line and headers.
- `server.read_timeout_sec` is the total inbound read budget for request line, headers, and body.
- `server.write_timeout_sec` bounds response writes. A slow client is closed
  rather than allowed to hold a data-plane goroutine indefinitely.
- `server.idle_timeout_sec` bounds keep-alive idle time between requests.
- `server.graceful_shutdown_timeout_sec` bounds deploy/reload drain time before force-closing live connections.
- TLS public listeners advertise HTTP/1.1 for this native server path. HTTP/3
  is still handled by the dedicated HTTP/3 listener when enabled.

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

- `max_concurrent_requests` is the process-wide cap.
- `max_concurrent_proxy_requests` is the data-plane cap.
- Queueing is active only when the matching `max_concurrent_*` value is greater than `0`.
- Successful queued responses add:
  - `X-Tukuyomi-Overload-Queued: true`
  - `X-Tukuyomi-Overload-Queue-Wait-Ms`
- Rejected overload responses return `503` with queue-related reason fields.

### Optional Built-in TLS Termination

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

Notes:

- `server.tls.enabled=false` is the default.
- `server.http3.enabled=true` requires built-in TLS termination.
- HTTP/3 uses the same numeric port as `server.listen_addr`, but over UDP.
- `server.tls.redirect_http=true` starts a second plain HTTP listener that redirects to HTTPS.
- ACME can be enabled with `server.tls.acme.*`.
- `paths.site_config_file` defaults to `conf/sites.json`; in DB-backed runtime this is the empty-DB seed/export path, not the live source of truth.

TLS certificate selection happens during the TLS handshake, before host/path
routing runs.

### Admin Surface Basics

- Keep a dedicated `admin.session_secret` server-side.
- CLI and automation use `admin.api_key_primary` / `admin.api_key_secondary`.
- The embedded admin UI exchanges API key access for a signed session cookie.
- `Settings` is `Save config only`: listener/runtime/storage changes need restart.

### Host Network Hardening (L3/L4 Basics)

`tukuyomi` is an L7 gateway. It does not replace upstream DDoS
protection.

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`

```conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Assumes symmetric routing. Consider 2 for asymmetric routing, multi-NIC, or tunnel setups.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

Apply with:

```bash
sudo sysctl --system
```

## Admin Dashboard

Admin UI is served by the Go binary at `/tukuyomi-ui`.

Main screens:

| Path | Purpose |
| --- | --- |
| `/status` | Runtime status, config snapshot, listener topology, health/runtime disclosure |
| `/logs` | WAF/security logs and detail lookups |
| `/rules` / `/rule-sets` | Base rule editing and CRS toggles |
| `/bypass` / `/country-block` / `/rate-limit` | DB-synced policy editing |
| `/ip-reputation` / `/bot-defense` / `/semantic` | Request-time security controls |
| `/notifications` | Aggregate alerting config and runtime status |
| `/cache` | Cache rules and internal cache store controls |
| `/proxy-rules` | Structured route/upstream/default-route editor with validate/probe/dry-run/apply/rollback |
| `/backends` | Canonical backend object inventory. Direct named upstreams support runtime enable/drain/disable and weight override; vhost-bound configured upstreams are status-only in this slice |
| `/sites` | Site ownership and TLS binding |
| `/options` | Runtime inventory, optional artifacts, GeoIP/Country DB management |
| `/vhosts` | Static / `php-fpm` vhost definitions and required configured-upstream bindings |
| `/scheduled-tasks` | Command-based cron task definitions and run status |
| `/settings` | Product-wide DB `app_config` editor for restart-required settings |

UI samples live under `docs/images/ui-samples/`.

### Startup

```bash
make setup
make compose-up
```

Open the embedded admin UI at `http://localhost:${CORAZA_PORT:-9090}/tukuyomi-ui`.

### Common Make Targets

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

### Related Guides

- binary deployment: [../build/binary-deployment.md](../build/binary-deployment.md)
- container deployment: [../build/container-deployment.md](../build/container-deployment.md)
- request-time security plugins: [../request_security_plugins.md](../request_security_plugins.md)
- regression matrix: [../operations/regression-matrix.md](../operations/regression-matrix.md)
- benchmark baseline: [../operations/benchmark-baseline.md](../operations/benchmark-baseline.md)
- upstream HTTP/2: [../operations/upstream-http2.md](../operations/upstream-http2.md)
- HTTP/3 public-entry smoke: [../operations/http3-public-entry-smoke.md](../operations/http3-public-entry-smoke.md)
- WAF tuning: [../operations/waf-tuning.md](../operations/waf-tuning.md)
- FP Tuner API contract: [../operations/fp-tuner-api.md](../operations/fp-tuner-api.md)
- PHP runtime / vhosts: [../operations/php-fpm-vhosts.md](../operations/php-fpm-vhosts.md)
- scheduled tasks: [../operations/php-scheduled-tasks.md](../operations/php-scheduled-tasks.md)
- DB operations: [../operations/db-ops.md](../operations/db-ops.md)

## Proxy Routing and Transport

Upstream failure response behavior:

- If `error_html_file` and `error_redirect_url` are both unset, the proxy returns the default `502 Bad Gateway`.
- If `error_html_file` is set, HTML-capable clients receive that page and other clients receive plain text `503`.
- If `error_redirect_url` is set, `GET` / `HEAD` requests are redirected there and other methods receive plain text `503`.

Routing model:

- `routes[]` are evaluated in ascending `priority` order with first-match semantics.
- Selection order is:
  1. explicit `routes[]`
  2. generated host fallback routes from the DB `sites` config blob
  3. `default_route`
  4. `upstreams[]`
- Host matching supports exact host and `*.example.com` wildcard host.
- Path matching supports `exact`, `prefix`, and `regex`.
- `upstreams[]` is the named backend node catalog. A row can use either a static `url` or `discovery`, never both.
- `backend_pools[]` groups named upstream members into route-scoped balancing sets.
- `action.backend_pool` is the standard route binding for balancing.
- `action.upstream` accepts configured upstream names only.
- `action.canary_upstream` and `action.canary_weight_percent` provide route-level canary.
- `action.host_rewrite`, `action.path_rewrite.prefix`, and `action.query_rewrite` rewrite outbound traffic.
- `action.request_headers` and `action.response_headers` allow bounded header manipulation.
- `response_header_sanitize` is the final proxy-side response-header safety gate.
- The structured editor shows operator workflow in this order:
  1. `Upstreams`
  2. `Backend Pools`
  3. `Routes` / `Default route`
- Each `Upstreams` row has its own `Probe` action so connectivity checks target one configured upstream at a time.
- `Vhosts` must define `linked_upstream_name` so route bindings and backend-pool members can reference a Vhost through the same upstream-name namespace.
- `linked_upstream_name` must already exist in `Proxy Rules > Upstreams`; Vhosts do not create managed aliases here.
- `generated_target` is server-owned internal compatibility state for vhost materialization. Operator route/pool binding should use `linked_upstream_name`.
- A direct upstream currently bound by a Vhost cannot be removed from `Proxy Rules > Upstreams` until the Vhost is relinked.

### Proxy Engine

DB `app_config` exposes the process-wide proxy engine under `proxy.engine.mode`.
Only Tukuyomi's native proxy engine is supported. Changing it requires a process restart.

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` is the built-in engine and uses Tukuyomi's response bridge after WAF/routing selection while preserving the same HTTP parser, upstream transport, health, retry, TLS, HTTP/2, cache, route response headers, 1xx informational responses, trailers, streaming flush behavior, native Upgrade/WebSocket tunnel, and response-sanitize path.
- The legacy `net_http` bridge has been removed; setting `proxy.engine.mode` to any value other than `tukuyomi_proxy` is rejected during config validation.
- HTTP/1.1 and explicit upstream HTTP/2 modes use Tukuyomi native upstream transports; HTTPS `force_attempt` falls back to native HTTP/1.1 only when ALPN does not select `h2`.
- Upgrade/WebSocket handshake requests stay inside `tukuyomi_proxy`; WebSocket frame payloads after `101 Switching Protocols` are tunnel data and are not HTTP WAF inspection input.
- Runtime visibility is exposed through `/tukuyomi-api/status` as `proxy_engine_mode` and through `Settings -> Runtime Inventory`.

### Runtime Backend Operations

- DB blob `upstream_runtime` stores opt-in runtime overrides for materialized backend keys from `Proxy Rules > Upstreams`; `data/conf/upstream-runtime.json` is only an empty-DB seed/export path.
- `Backends` lists canonical backend objects, not backend pools.
- `Backends` is the runtime operations panel for:
  - `enabled`
  - `draining`
  - `disabled`
  - positive `weight_override`
- No override means configured behavior from DB `proxy_rules`; `data/conf/proxy.json` is only seed/import/export material.
- Runtime operations apply to static direct upstreams and DNS-discovered materialized targets.
- Configured upstreams bound by Vhosts are routable and pool-addressable, and `Backends` exposes them as status-only canonical objects.
- Direct route URLs, generated `static`, and generated `php-fpm` targets are not included.
- `draining`, `disabled`, and `unhealthy` backends are excluded from new target selection.
- `proxy_access` logs now expose the selected backend runtime state via:
  - `selected_upstream_admin_state`
  - `selected_upstream_health_state`
  - `selected_upstream_effective_selectable`
  - `selected_upstream_effective_weight`
  - `selected_upstream_inflight`
- Blocked requests do not emit selected-backend fields.

Standard `http://` and `https://` upstream proxying automatically adds:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

Optional `emit_upstream_name_request_header=true` also adds:

- `X-Tukuyomi-Upstream-Name`

This is an internal observability header. `[proxy]` strips any inbound value and
re-emits it only when the final selected target is a configured named upstream
from `Proxy Rules > Upstreams`.

Those runtime-managed headers cannot be overridden by route-level
`request_headers`.

### Minimal Upstream Example

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

Use `upstreams[].discovery` when backend addresses are owned by DNS, such as
container or Kubernetes service discovery. Routes and backend pools still refer
to the canonical upstream name. The runtime resolves DNS on a bounded interval,
materializes the resolved targets, and keeps the last-good target set when a
later lookup fails.

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

- `type=dns` resolves A/AAAA records and requires `hostname`, `scheme`, and `port`.
- `type=dns_srv` resolves `_service._proto.name` records and uses the SRV port.
- `scheme` is limited to `http` or `https`; `fcgi` and `static` are not discovery targets.
- DNS is not resolved per request. Runtime refresh is controlled by `refresh_interval_sec`.
- On initial lookup failure with no last-good targets, that upstream has no selectable targets.
- `Backends` and health status expose each materialized target and discovery errors.

### Minimal Route-Scoped Backend Pool Example

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

`backend_pools[].sticky_session` enables proxy-issued signed affinity cookies.
This is different from `hash_policy=cookie`: `hash_policy=cookie` only hashes an
application cookie that already exists, while `sticky_session` issues and
refreshes the load-balancer cookie itself.

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

- A valid sticky cookie is preferred before round-robin, least-conn, or hash selection.
- Invalid, expired, tampered, unknown, disabled, draining, or unhealthy sticky targets are ignored.
- The cookie value is signed and stores only a selected target identifier and expiry, not the backend URL.
- The signing key is process-local and generated on startup. After restart, old sticky cookies are safely rejected and refreshed.
- `same_site=none` requires `secure=true`.

### Route Example

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

### Dry-Run Example

```bash
curl -sS \
  -H "X-API-Key: ${WAF_API_KEY}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

Route-related logs include:

- `proxy_route`
- `original_host`, `original_path`, `original_query`
- `rewritten_host`, `rewritten_path`, `rewritten_query`
- `selected_route`
- `proxy_route` is emitted after route classification but before WAF / final target selection, so it does not disclose `selected_upstream` or `selected_upstream_url`
- `proxy_access` and post-selection transport logs disclose `selected_upstream` and `selected_upstream_url` only after a final target has been chosen

Request flow is:

- request metadata resolution
- route classification and rewrite planning
- country block / request-security plugins / rate limit / WAF
- final target selection
- proxy transport or direct static / php-fpm serving

## Admin API

Detailed schemas live in [../api/admin-openapi.yaml](../api/admin-openapi.yaml).

Main endpoint groups:

| Group | Examples |
| --- | --- |
| Runtime status / metrics | `/status`, `/metrics` |
| Logs / evidence | `/logs/read`, `/logs/stats`, `/logs/security-audit*`, `/logs/download` |
| Rules / CRS | `/rules*`, `/crs-rule-sets*` |
| Policy files | `/bypass-rules*`, `/country-block-rules*`, `/rate-limit-rules*`, `/ip-reputation*`, `/notifications*`, `/bot-defense-rules*`, `/semantic-rules*` |
| FP Tuner | `/fp-tuner/propose`, `/fp-tuner/apply` |
| Cache | `/cache-rules*`, `/cache-store*` |
| PHP / vhosts / tasks | `/php-runtimes*`, `/vhosts*`, `/scheduled-tasks*` |
| Sites / proxy routing | `/sites*`, `/proxy-rules*` |
| GeoIP country update | `/request-country-mode`, `/request-country-db*`, `/request-country-update*` |

`GET /tukuyomi-api/status` also exposes:

- listener/runtime disclosure
- TLS/HTTP3 state
- site runtime state
- upstream HA/runtime state
- request-security counters and configuration snapshots

## Policy Files and Security Controls

### WAF Bypass / Special Rule Application

`paths.bypass_file` defaults to `conf/waf-bypass.json`.

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
        { "path": "/search", "extra_rule": "conf/rules/search-endpoint.conf" }
      ]
    }
  }
}
```

Managed `extra_rule` files belong under `conf/rules/*.conf` and are edited from the `Override Rules` page. They are not added to the base WAF rule set at startup; they are loaded only when a bypass entry references them.
See `conf/waf-bypass.sample.json` for the bundled sample that references `conf/rules/search-endpoint.conf`.
Host scope precedence is exact `host:port`, then bare `host`, then `default`. Host-specific entries replace the default scope; they do not merge with it.

### Country Block

`paths.country_block_file` defaults to `conf/country-block.json`.

- JSON fields: `default.blocked_countries`, optional `hosts.<host>.blocked_countries`
- allowed values remain ISO-3166 alpha-2 country codes plus `UNKNOWN`
- matched countries are blocked with `403` before WAF inspection
- country resolution is now handled by `request_metadata_resolvers`
- `header` mode trusts `X-Country-Code`
- `mmdb` mode resolves from installed `country.mmdb`
- host scope precedence is exact `host:port`, then bare `host`, then `default`

### Rate Limit

`paths.rate_limit_file` defaults to `conf/rate-limit.json`.

Key ideas:

- file format is JSON with `default_policy` and `rules`
- `key_by` supports `ip`, `country`, `ip_country`, `session`, `ip_session`, `jwt_sub`, `ip_jwt_sub`
- adaptive throttling can combine bot/semantic risk
- feedback can promote sustained rate-limit abuse into bot-defense quarantine

### IP Reputation

`paths.ip_reputation_file` defaults to `conf/ip-reputation.json`.

- supports local files and HTTP/HTTPS feeds
- inline allowlist always wins over feed-sourced block entries
- request-time security order is `ip_reputation -> bot_defense -> semantic`

### WebSocket Scope

- HTTP upgrade handshake is inspected like normal request traffic
- upgraded frames are pass-through and are not WAF/body-inspected

### Admin Surface Hardening

- `admin.external_mode`: `deny_external`, `api_only_external`, `full_external`
- `admin.trusted_cidrs` controls trusted peers
- `admin.trust_forwarded_for=true` is honored only when the direct peer is already trusted
- `admin.rate_limit` adds a dedicated admin throttle

### Observability

- `/metrics` exposes TLS, upstream HA, rate limit, semantic, and request-security counters
- WAF/access/audit log file rotation is controlled by `storage.file_rotate_bytes`, `storage.file_max_bytes`, `storage.file_retention_days`
- optional OTLP tracing is configured under `observability.tracing`

### Notifications

`paths.notification_file` defaults to `conf/notifications.json`.

- aggregate state transitions instead of per-request alerts
- supports `webhook` and `email`
- `/notifications/test` sends a test notification
- `/notifications/status` shows sink/runtime state

### Bot Defense

`paths.bot_defense_file` defaults to `conf/bot-defense.json`.

Capabilities include:

- classic suspicious UA challenge
- behavioral detection
- browser/device telemetry cookie
- first-request header signals
- TLS fingerprint heuristics for direct HTTPS traffic
- repeated-strike quarantine
- path-aware bot policy overrides
- global or per-flow `dry_run`

### Semantic Security

`paths.semantic_file` defaults to `conf/semantic.json`.

- staged enforcement: `off | log_only | challenge | block`
- request scoring with temporal signals
- `semantic_anomaly` logs include `reason_list` and `score_breakdown`

### Security Audit Trail

`security_audit` adds a signed request-level audit trail.

- decision-chain JSON is written to `paths.security_audit_file`
- encrypted evidence blobs are written to `paths.security_audit_blob_dir`
- body retention is opt-in and bounded
- integrity verification is available from `/logs/security-audit/verify`

### Rules / CRS Editing

- `/rules` edits active base rule files
- `/rule-sets` toggles CRS files under `rules/crs/rules/*.conf`
- successful saves hot-reload WAF
- failed reloads auto-rollback

## Logs and Cache

### Log Retrieval

```bash
curl -s -H "X-API-Key: <your-api-key>" \
     "http://<host>/tukuyomi-api/logs/read?tail=100&country=JP" | jq .
```

### Cache Feature

Cache config is stored in `data/conf/cache-rules.json`. Internal cache store settings
live in `data/conf/cache-store.json`.

Example:

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

Behavior summary:

- host-specific cache scopes replace, rather than merge with, the default scope
- matching responses can be stored in the internal file-backed cache
- optional bounded L1 memory cache can be enabled
- `POST /tukuyomi-api/cache-store/clear` clears the cache immediately
- authenticated traffic and upstream responses with `Set-Cookie` are not stored

Verify with response headers:

- `X-Tukuyomi-Cacheable: 1`
- `X-Accel-Expires: <seconds>`
- `X-Tukuyomi-Cache: MISS|HIT`
