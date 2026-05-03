# Appendix A. Operator reference

This appendix is a dictionary-style reference to the major blocks of
`data/conf/config.json` and DB `app_config_*`, plus the admin UI / API,
Make targets, policy files, security controls, and logs / cache. Use
it as the place to look up a configuration key directly when reading
the main text.

Each section keeps the structure of the upstream
`docs/reference/operator-reference.md` while polishing the prose for a
book-length read.

## A.1 Runtime configuration

`.env` is **only for container / runtime deltas**.
`data/conf/config.json` is the **DB connection bootstrap**, and the
behavior of app / proxy / runtime / policy after the DB is opened is
read from normalized DB tables.

### A.1.1 Docker / local MySQL (optional)

| Variable | Example | Description |
|---|---|---|
| `MYSQL_PORT` | `13306` | Host-side port mapped to `3306` of the local MySQL container under the `mysql` profile. |
| `MYSQL_DATABASE` | `tukuyomi` | Initial DB name created on the local MySQL container. |
| `MYSQL_USER` | `tukuyomi` | Application user created on the local MySQL container. |
| `MYSQL_PASSWORD` | `tukuyomi` | Password for `MYSQL_USER`. |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | The root password. |
| `MYSQL_TZ` | `UTC` | Container time zone. |

### A.1.2 `data/conf/config.json` / DB `app_config`

`data/conf/config.json` carries `storage.db_driver`, `storage.db_path`,
and `storage.db_dsn` that are needed before opening the DB. Other
product-wide configuration is stored under DB `app_config` after
bootstrap / import.

Major blocks:

| Block | Purpose |
|---|---|
| `server` | Listeners, timeouts, backpressure, TLS, HTTP/3, public/admin split |
| `runtime` | Go runtime controls — `gomaxprocs`, `memory_limit_mb`, etc. |
| `admin` | UI / API path, sessions, external-exposure policy, trusted CIDRs, admin rate limit |
| `paths` | Locations of rules, bypass, country, rate, bot, semantic, CRS, sites, tasks, artifacts |
| `proxy` | Rollback history and process-wide proxy engine controls |
| `crs` | CRS enable flag |
| `storage` | DB-only runtime store (`sqlite` / `mysql` / `pgsql`), retention, sync interval, log file rotation limit |
| `fp_tuner` | External provider endpoint, approval, timeout, audit |
| `request_metadata` | Country resolution method (`header` / `mmdb`, etc.) |
| `observability` | OTLP tracing settings |

Env typically required for container startup:

| Variable | Example | Description |
|---|---|---|
| `WAF_CONFIG_FILE` | `conf/config.json` | Startup config path. |
| `WAF_LISTEN_PORT` | `9090` | Compose helper / healthcheck port. Match `server.listen_addr`. |

### A.1.3 Inbound timeout boundary

- The public HTTP/1.1 data-plane listener is handled by the Tukuyomi
  native HTTP/1.1 server. The admin listener, the HTTP redirect
  listener, and the HTTP/3 helper remain separate control / edge
  helpers.
- `server.read_header_timeout_sec`: request line and headers only.
- `server.read_timeout_sec`: inbound read budget for request line +
  headers + body in total.
- `server.write_timeout_sec`: upper bound for response write.
- `server.idle_timeout_sec`: upper bound for keep-alive idle between
  requests.
- `server.graceful_shutdown_timeout_sec`: upper bound for draining
  live connections on deploy / reload. **Force-close after the
  budget.**
- The TLS public listener advertises HTTP/1.1. **HTTP/3 lives on a
  dedicated listener.**

### A.1.4 Overload backpressure

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

- `max_concurrent_requests`: process-wide cap.
- `max_concurrent_proxy_requests`: data-plane cap.
- Queues only apply when the corresponding `max_concurrent_*` is
  greater than `0`.
- Successful queued responses include:
  - `X-Tukuyomi-Overload-Queued: true`
  - `X-Tukuyomi-Overload-Queue-Wait-Ms`
- Rejections return `503` with a queue-related reason.

### A.1.5 Built-in TLS termination (optional)

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

Key points:

- `server.tls.enabled=false` is the default.
- `server.http3.enabled=true` requires built-in TLS.
- HTTP/3 uses the same numeric port as `server.listen_addr` over **UDP**.
- `server.tls.redirect_http=true` adds a plain HTTP listener.
- ACME auto TLS is per-site via `tls.mode=acme`. The ACME account
  key, challenge tokens, and certificate cache live under the `acme/`
  namespace of `persistent_storage`.
- For ACME HTTP-01, port 80 must reach
  `server.tls.http_redirect_addr`.
- Let's Encrypt `staging` / `production` is selected per site under
  the ACME environment.
- `paths.site_config_file` defaults to `conf/sites.json`. In the
  DB-backed runtime this is a seed / export path for an empty DB.

### A.1.6 Persistent file storage

`persistent_storage` holds **runtime artifacts that persist as bytes,
not in the DB**, such as the ACME cache.

```json
{
  "persistent_storage": {
    "backend": "local",
    "local": { "base_dir": "data/persistent" }
  }
}
```

- `local` is for a single node or an operator-prepared shared mount.
- S3 stores **only non-secret information** in DB `app_config`:
  provider name, bucket, region, endpoint, prefix, etc. Use
  `force_path_style=true` for MinIO and other S3-compatible
  endpoints.
- API keys / secret keys / client secrets / tokens / connection
  strings are **not** stored in JSON or DB.
- AWS / Azure / GCP authentication is delivered via env, managed
  identity, Workload Identity, ADC, and similar platform mechanisms.
- The S3 backend reads `AWS_ACCESS_KEY_ID` /
  `AWS_SECRET_ACCESS_KEY` / optional `AWS_SESSION_TOKEN` /
  `AWS_REGION` / `AWS_DEFAULT_REGION` from the runtime env.
- Azure Blob / GCS are fail-closed until provider adapters ship; no
  implicit fallback to local.

S3-compatible backend example:

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

The MinIO integration test is skipped under regular regression. To
run it, prepare an existing bucket and set
`TUKUYOMI_MINIO_S3_ENDPOINT` / `TUKUYOMI_MINIO_S3_BUCKET` /
`AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`.

### A.1.7 Admin basics

- `admin.session_secret` is **server-side only**.
- CLI / automation use **per-user personal access tokens**.
- The admin UI uses username / password login plus a DB-backed session
  cookie.
- `Settings` is `Save config only`. **Listener / runtime / storage
  changes require a restart.**

### A.1.8 Host network hardening (L3/L4 basics)

`tukuyomi` is an **L7 gateway**. **It is not a substitute for upstream
DDoS protection.** The bare minimum host hardening is the following
sysctls:

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`:

```conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# Symmetric routing assumed. For asymmetric routing or environments with
# multiple NICs / tunnels, consider 2.
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

Apply:

```bash
sudo sysctl --system
```

## A.2 Admin dashboard

The admin UI is served from the Go binary at **`/tukuyomi-ui`**. The
main screens:

| Path | Role |
|---|---|
| `/status` | Runtime status / config snapshot / listener topology |
| `/logs` | WAF / security log browsing |
| `/rules` | Runtime WAF rule order / base rule editor / CRS toggle |
| `/bypass` / `/country-block` / `/rate-limit` | DB-synced policy editing |
| `/ip-reputation` / `/bot-defense` / `/semantic` | Request-time security controls |
| `/notifications` | Aggregate alerting settings |
| `/cache` | Cache rules and the internal cache store |
| `/proxy-rules` | Direct upstream / backend pool / route editing for what Runtime Apps does not own; validate / probe / dry-run / apply / rollback |
| `/backends` | List of direct upstream backend objects. Direct named upstreams support runtime enable / drain / disable / weight override; Runtime App generated targets live under Runtime Apps |
| `/sites` | Site ownership and TLS binding |
| `/options` | Runtime inventory / optional artifacts / GeoIP / Country DB management |
| `/runtime-apps` | Runtime listener / docroot / runtime / generated backend management for static / `php-fpm` / `psgi` apps |
| `/scheduled-tasks` | Cron-style command tasks and last-run status |
| `/settings` | Edit DB `app_config` (restart-required settings) |

The UI samples live under the shared `docs/images/ui-samples/` directory. This
book references them with `../../images/ui-samples/`.

### A.2.1 Bringing it up

```bash
make env-init
make db-migrate
make crs-install
make compose-up
```

Open the admin UI at
`http://localhost:${CORAZA_PORT:-9090}/tukuyomi-ui`.

### A.2.2 Common Make targets

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

## A.3 Proxy routing and transport (reference)

Three patterns for the response on upstream failure:

- Both `error_html_file` and `error_redirect_url` unset: the default
  `502 Bad Gateway`.
- `error_html_file` set: a maintenance page for HTML clients,
  plain-text `503` for everything else.
- `error_redirect_url` set: redirect `GET` / `HEAD`, plain-text `503`
  for everything else.

Routing model:

- `routes[]` is **first-match in ascending `priority` order**.
- Selection order:
  1. Explicit `routes[]`.
  2. The generated host fallback route derived from the DB `sites`
     domain.
  3. `default_route`.
  4. `upstreams[]`.
- Host match: exact and `*.example.com`.
- Path match: `exact` / `prefix` / `regex`.
- `upstreams[]`: catalog of direct backend nodes not owned by
  Runtime Apps. Each row uses either a static `url` or a
  `discovery`.
- `backend_pools[]`: per-route balancing sets composed of named
  upstream members.
- `action.backend_pool`: the standard balancing route binding.
- `action.upstream`: a direct upstream name or a server-generated
  Runtime App upstream name.
- `action.canary_upstream` and `action.canary_weight_percent`:
  route-level canary.
- `action.host_rewrite` / `action.path_rewrite.prefix` /
  `action.query_rewrite`: outbound rewriting.
- `action.request_headers` / `action.response_headers`: bounded
  header control.
- `response_header_sanitize`: the final response-header safety gate.
- The structured editor surfaces the workflow in this order:
  1. `Upstreams`
  2. `Backend Pools`
  3. `Routes` / `Default route`
- Each row in `Upstreams` has a dedicated `Probe`.
- `Runtime Apps` exposes generated backends to the effective runtime.
- `Runtime Apps` does not rewrite the configured upstream URL.

### A.3.1 Proxy engine

```json
{ "proxy": { "engine": { "mode": "tukuyomi_proxy" } } }
```

- The supported engine is **only `tukuyomi_proxy`**. Restart-required.
- `tukuyomi_proxy` runs Tukuyomi's response bridge after WAF / routing
  selection.
- The legacy `net_http` bridge has been removed. Anything other than
  `tukuyomi_proxy` is rejected at config validation.
- HTTP/1.1 and explicit upstream HTTP/2 modes use the Tukuyomi native
  upstream transport. HTTPS `force_attempt` falls back to native
  HTTP/1.1 only when ALPN does not select `h2`.
- Upgrade / WebSocket handshakes are handled inside `tukuyomi_proxy`.
- Runtime visibility: `proxy_engine_mode` from `/tukuyomi-api/status`.

### A.3.2 WAF engine

```json
{ "waf": { "engine": { "mode": "coraza" } } }
```

- The only available engine in this build is **`coraza`**.
- `mod_security` is a known mode reserved for a future adapter; it
  fails closed when the adapter is not compiled in.
- Unknown modes are rejected at config validation.
- Runtime visibility: `waf_engine_mode` / `waf_engine_modes` from
  `/tukuyomi-api/status` and `Settings → Runtime Inventory`.
- The left navigation treats `Security > Coraza` as engine-specific
  and hides it when the active WAF engine is not Coraza.
  `Security > Request Controls` is Tukuyomi request policy and stays
  visible.

### A.3.3 Runtime backend operations

- The normalized `upstream_runtime` DB domain holds **opt-in runtime
  overrides per backend key** materialized from direct upstreams /
  DNS discovery. `data/conf/upstream-runtime.json` is seed / export
  for an empty DB.
- `Backends` lists direct upstream backend objects and offers the
  following runtime operations:
  - `enabled`
  - `draining`
  - `disabled`
  - Positive `weight_override`
- A backend without overrides behaves as configured in DB
  `proxy_rules`.
- Operable runtime targets are static direct upstreams and DNS
  discovery materialized targets.
- Runtime App generated targets are handled in `Runtime Apps`, not
  in `Backends`.
- URLs written directly into routes and Runtime App generated
  targets are **not operable** at runtime.
- Backends in `draining` / `disabled` / `unhealthy` are excluded
  from new target selection.
- `proxy_access` log fields about the selected backend (see Chapter
  5 §5.3.1).

For ordinary `http://` / `https://` upstream proxying, the following
headers are added automatically:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

With `emit_upstream_name_request_header=true`:

- `X-Tukuyomi-Upstream-Name`

This is an internal observability header. `[proxy]` strips any inbound
header of the same name first and re-emits only when the final target
is a configured named upstream from `Proxy Rules > Upstreams`. These
runtime-managed headers cannot be overridden from a route-level
`request_headers`.

### A.3.4 Minimal upstream / backend pool examples

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

A minimal route-scoped backend pool (same as Chapter 5 §5.1.4):

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

### A.3.5 Dynamic DNS backend discovery

See Chapter 5 §5.5. `type=dns` resolves A / AAAA;
`type=dns_srv` resolves SRV. Refresh cadence is governed by
`refresh_interval_sec`. With a first-failure and no last-good, there
are zero selectable targets; on subsequent failure, the last-good set
is retained.

### A.3.6 Backend pool sticky sessions

See Chapter 5 §5.6.
`backend_pools[].sticky_session.enabled=true` makes the proxy issue a
signed cookie. Sticky targets that are tampered / expired / unknown /
disabled / draining / unhealthy are ignored. `same_site=none`
requires `secure=true`.

### A.3.7 Dry-run

```bash
curl -sS \
  -H "Authorization: Bearer ${WAF_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

Route-related logs:

- `proxy_route`
- `original_host` / `original_path` / `original_query`
- `rewritten_host` / `rewritten_path` / `rewritten_query`
- `selected_route`

`proxy_route` is emitted **after** route classification but
**before** WAF / final target selection, so it carries no
`selected_upstream` / `selected_upstream_url`. Post-selection logs do.

Request flow:

- Request metadata resolution
- Route classification and rewrite planning
- Country block / request-security plugins / rate limit / WAF
- Final target selection
- Proxy transport, or direct static / php-fpm serving

## A.4 Admin API

For schema details, see `docs/api/admin-openapi.yaml`. Major endpoint
groups:

| Group | Examples |
|---|---|
| Runtime status / metrics | `/status`, `/metrics` |
| Logs / evidence | `/logs/read`, `/logs/stats`, `/logs/security-audit*`, `/logs/download` |
| Rules / CRS | `/rules*`, `/crs-rule-sets*` |
| Policy files | `/bypass-rules*`, `/country-block-rules*`, `/rate-limit-rules*`, `/ip-reputation*`, `/notifications*`, `/bot-defense-rules*`, `/semantic-rules*` |
| FP Tuner | `/fp-tuner/propose`, `/fp-tuner/apply` |
| Cache | `/cache-rules*`, `/cache-store*` |
| PHP / Runtime Apps / tasks | `/php-runtimes*`, `/runtime-apps*`, `/scheduled-tasks*` |
| Sites / proxy routing | `/sites*`, `/proxy-rules*` |
| GeoIP country update | `/request-country-mode`, `/request-country-db*`, `/request-country-update*` |

`GET /tukuyomi-api/status` shows:

- Listener / runtime disclosure
- TLS / HTTP/3 state
- Site runtime state
- Upstream HA / runtime state
- Request-security counters and a config snapshot

## A.5 Policy files and security controls

### A.5.1 WAF Bypass / special rule

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
        { "path": "/search", "extra_rule": "orders-preview.conf" }
      ]
    }
  }
}
```

- Managed `extra_rule` bodies are stored in **DB `override_rules`**
  and edited from `Rules > Advanced > Bypass snippets`.
- There is **no** filesystem fallback at `conf/rules`.
- `extra_rule` is **not** mixed into the base WAF rule set at
  startup; it is loaded only when a bypass entry references its
  logical `extra_rule` name.
- Host scope precedence: exact `host:port` → bare `host` →
  `default`. **A host-specific scope replaces `default` rather than
  merging with it.**

### A.5.2 Country block

`paths.country_block_file` defaults to `conf/country-block.json`.

- JSON fields are `default.blocked_countries` and optional
  `hosts.<host>.blocked_countries`.
- Values are ISO-3166 alpha-2 country codes plus `UNKNOWN`.
- A match returns `403` **before WAF**.
- Country resolution is the responsibility of
  `request_metadata_resolvers`.
- `header` mode: `X-Country-Code`.
- `mmdb` mode: load a DB-managed country MMDB asset into the runtime.
- Host scope precedence: exact `host:port` → bare `host` →
  `default`.

### A.5.3 Rate limit

`paths.rate_limit_file` defaults to `conf/rate-limit.json`.

- JSON has `default_policy` and `rules`.
- `key_by`: `ip` / `country` / `ip_country` / `session` /
  `ip_session` / `jwt_sub` / `ip_jwt_sub`.
- Adaptive throttling can use bot / semantic risk.
- Feedback can promote sustained abuse to **bot-defense quarantine**.

### A.5.4 IP reputation

`paths.ip_reputation_file` defaults to `conf/ip-reputation.json`.

- Supports local files and HTTP / HTTPS feeds.
- Inline allowlist takes precedence over feed-based blocks.
- Request-time security order: **`ip_reputation → bot_defense →
  semantic`**.

### A.5.5 WebSocket scope

- The HTTP upgrade handshake is inspected like a normal request.
- Frames after upgrade **pass through** — no WAF / body inspection.

### A.5.6 Admin surface hardening

- `admin.external_mode`: `deny_external` / `api_only_external` /
  `full_external`.
- Define trusted peers via `admin.trusted_cidrs`.
- `admin.trust_forwarded_for=true` only applies when the direct
  peer is trusted.
- `admin.rate_limit` adds throttling specifically for the admin
  surface.

### A.5.7 Observability

- `/metrics` exposes counters for TLS / upstream HA / rate limit /
  semantic / request-security.
- WAF / access events are **DB-backed**. The security audit remains
  on a separate file / evidence stream; file rotation settings apply
  to file-backed audit / legacy log streams.
- Optional OTLP tracing under `observability.tracing`.

### A.5.8 Notifications

`paths.notification_file` defaults to `conf/notifications.json`.

- Notifications are about **aggregate state transitions**, not
  per-request events.
- `webhook` and `email` are supported.
- Test notifications via `/notifications/test`.
- Sink / runtime status via `/notifications/status`.

### A.5.9 Bot defense

`paths.bot_defense_file` defaults to `conf/bot-defense.json`.

Major features:

- Suspicious-UA challenge
- Behavioral detection
- Browser / device telemetry cookies
- First-request header signals
- TLS fingerprint heuristic for direct HTTPS
- Repeated-strike quarantine
- Path-aware overrides
- Global / per-flow `dry_run`

### A.5.10 Semantic security

`paths.semantic_file` defaults to `conf/semantic.json`.

- Enforcement stages: `off` / `log_only` / `challenge` / `block`.
- Request scoring with temporal signals.
- The `semantic_anomaly` log includes `reason_list` and
  `score_breakdown`.

### A.5.11 Security audit trail

`security_audit` adds a **request-level signed audit trail**.

- Decision-chain JSON: `paths.security_audit_file`.
- Encrypted evidence blob: `paths.security_audit_blob_dir`.
- Body retention is **opt-in and bounded**.
- Verify integrity via `/logs/security-audit/verify`.

### A.5.12 Rules / CRS editing

- `/rules` shows Coraza CRS assets and base WAF rule assets in
  runtime order.
- The active DB-backed base rule asset is editable.
- Base WAF rule assets are disable-able. A disabled asset stays
  editable but drops out of the live WAF load set.
- Toggle DB-backed CRS assets named like
  `rules/crs/rules/*.conf`.
- A successful save triggers a WAF hot reload. A reload failure
  triggers an **auto rollback**.

## A.6 Logs and cache

### A.6.1 Log retrieval

```bash
curl -s -H "Authorization: Bearer <your-personal-access-token>" \
     "http://<host>/tukuyomi-api/logs/read?tail=100&country=JP" | jq .
```

### A.6.2 Cache feature

Cache rules and internal cache store settings are **versioned per DB
table**. `data/conf/cache-rules.json` remains seed / import material
for an empty DB. Internal cache store settings are seeded from DB
defaults when the normalized rows are missing;
`data/conf/cache-store.json` is meaningful only on the explicit no-DB
fallback path.

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

Behavior:

- A per-host cache scope **does not merge with the default scope**;
  on a match it **replaces** it.
- A matched response can be stored in the internal file-backed cache.
- The bounded **L1 memory cache** can be enabled.
- `POST /tukuyomi-api/cache-store/clear` clears everything
  immediately.
- Authenticated traffic and upstream responses with `Set-Cookie`
  are not stored.

Diagnostic headers:

- `X-Tukuyomi-Cacheable: 1`
- `X-Accel-Expires: <seconds>`
- `X-Tukuyomi-Cache: MISS|HIT`
