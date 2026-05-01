# Chapter 5. Routing, Upstreams, and Backend Pools

Chapters 3 and 4 covered **how to deploy** tukuyomi. From this chapter on,
we move into how a deployed tukuyomi **actually routes HTTP requests**.

Routing in tukuyomi is built on three components — `Routes`, `Upstreams`,
and `Backend Pools` — with clearly separated responsibilities. We start
with the three-layer model, then trace how a single request flows through
tukuyomi, what the `Backends` screen lets you do, the behavior of dynamic
DNS discovery and sticky sessions, and how to use `dry-run`.

## 5.1 The three-layer model — Routes / Upstreams / Backend Pools

The `Proxy Rules` screen presents an operator workflow in this order:

1. **Upstreams**: a catalog of direct backend nodes.
2. **Backend Pools**: per-route balancing groups that bundle named
   upstreams.
3. **Routes / Default route**: matches on host / path / method, plus a
   binding to a pool or upstream.

We look at each in turn.

### 5.1.1 Upstreams

`Upstreams` is the **catalog of direct backend nodes that Runtime Apps
do not own**. Each row uses one of:

- A static `url` (for example, `http://app.internal:8080`)
- DNS-based `discovery` (covered in §5.5)

Each upstream has a `name`, and that is the **only identifier** by which
Backend Pools and Routes refer to it.

Minimal example:

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

Each row in `Upstreams` has its own `Probe` button. Instead of probing
some vague target across the whole panel, **the probe runs against the
single configured upstream you click**. The UX is shaped to keep
operator confusion low.

Note that targets that `Runtime Apps` (PHP-FPM / PSGI) listen on appear
as **server-owned generated backends** materialized by `Runtime Apps`.
They do not appear in `Upstreams`, and `Runtime Apps` does not rewrite
the configured upstream URL. A configured upstream named `primary`
remains the URL you wrote in `Proxy Rules > Upstreams` regardless of
what `Runtime Apps` materializes elsewhere.

### 5.1.2 Backend Pools

`Backend Pools` are **per-route balancing groups built from named
upstreams** defined in `Upstreams`. The `members[]` list contains
upstream names; URLs and discovery settings are not redeclared.

```json
{
  "backend_pools": [
    { "name": "site-localhost", "strategy": "round_robin", "members": ["localhost1", "localhost2"] },
    { "name": "site-app",       "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ]
}
```

`strategy` can be `round_robin`, `least_conn`, `hash`, etc. Hash
strategies combine `hash_policy` and `hash_key`.

### 5.1.3 Routes and the default route

`routes[]` is evaluated **first-match in ascending `priority` order**.
The full route-selection order is:

1. Explicit `routes[]`
2. A generated host fallback route derived from the DB `sites` domain
3. `default_route`
4. `upstreams[]`

Route matches can be specified on host and path:

- Host match: exact, or `*.example.com` suffix match
- Path match: `exact`, `prefix`, or `regex`

Route binding is one of:

- `action.backend_pool`: the standard balanced binding.
- `action.upstream`: a direct upstream name (a row from `Upstreams`) or
  a server-generated Runtime App upstream name.

Per-route additions:

- `action.canary_upstream` and `action.canary_weight_percent`: route-level
  canary
- `action.host_rewrite` / `action.path_rewrite.prefix` /
  `action.query_rewrite`: outbound rewriting
- `action.request_headers` / `action.response_headers`: bounded header
  control

Finally, **`response_header_sanitize`** kicks in as the final
response-header safety gate. It is structural and cannot be bypassed.

### 5.1.4 A minimal route-scoped backend pool

A small example that exercises all three layers:

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

## 5.2 Request flow — the order one request travels

To understand how route match and binding compose, it helps to know the
order tukuyomi follows for a single request:

1. **Request metadata resolution**
   - Compute resolved metadata from country / IP reputation / various
     headers.
2. **Route classification and rewrite planning**
   - Decide the first-match route and plan host / path / query
     rewriting.
   - The `proxy_route` log is emitted at this point.
   - `selected_upstream` / `selected_upstream_url` are **not yet
     decided**, so they are not in the log here.
3. **Country block / request-security plugins / rate limit / WAF**
   - The request is inspected in this order.
4. **Final target selection**
   - Pick exactly one target from the backend pool.
5. **Proxy transport, or direct static / php-fpm serving**
   - Either proxy to the chosen target, or serve directly from static /
     PHP-FPM.

`proxy_access` and post-selection transport logs only emit
`selected_upstream` / `selected_upstream_url` once step 4 has decided a
target. **The route-stage log (`proxy_route`) and the post-selection log
(`proxy_access`) carry different meanings**, and you should not conflate
them.

### 5.2.1 Behavior on upstream failure

What is returned on upstream failure depends on the route's
`error_html_file` and `error_redirect_url`:

- Both unset: the default `502 Bad Gateway`.
- `error_html_file` set: a maintenance page for HTML clients, plain-text
  `503` for everything else.
- `error_redirect_url` set: `GET` / `HEAD` are redirected; everything
  else gets plain-text `503`.

## 5.3 The Backends screen — runtime backend operations

The `Backends` screen lists direct upstream backend objects and is also
the **operations panel that lets you tune them at runtime**.

Operable objects:

- **Static direct upstreams** defined in `Upstreams`.
- Targets **materialized by DNS discovery**.

Available runtime operations:

- `enabled`
- `draining`
- `disabled`
- A positive `weight_override`

These overrides are stored in the DB `upstream_runtime` domain
(`data/conf/upstream-runtime.json` is seed / export). A backend without
overrides behaves exactly as configured in DB `proxy_rules`.

It is important to keep clear what is and is not operable:

| object | operable in `Backends` |
|---|---|
| Static direct upstream (a `Upstreams` row) | yes |
| Target materialized by DNS discovery | yes |
| Runtime App generated target | **no** (handled in `Runtime Apps`) |
| URL written directly into a route | no |

So a backend dynamically generated by Runtime Apps does not appear in
`Backends`; the corresponding control is the process-lifecycle controls
in `Runtime Apps`. A URL written **directly** into `action.upstream` is
also outside the scope of `Backends`; you edit the proxy rule itself.

### 5.3.1 drain / disable / unhealthy semantics

A backend in any of `draining` / `disabled` / `unhealthy` is **dropped
from new target selection**. In-flight connections continue, while only
new ones are rerouted.

`proxy_access` logs include the following fields about the selected
backend's runtime state:

- `selected_upstream_admin_state`
- `selected_upstream_health_state`
- `selected_upstream_effective_selectable`
- `selected_upstream_effective_weight`
- `selected_upstream_inflight`

Blocked requests **do not** carry these selected-backend fields by
design.

## 5.4 Forwarded headers and observability headers

For ordinary `http://` / `https://` upstream proxying, tukuyomi
**automatically attaches** the following:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

If you opt into `emit_upstream_name_request_header=true`, an additional
header is added:

- `X-Tukuyomi-Upstream-Name`

This is an internal observability header with a few safety
characteristics:

- `[proxy]` **strips** any inbound header of the same name first, then
  re-emits.
- It is added **only when the final target is a configured named
  upstream from `Proxy Rules > Upstreams`**.
- It is **not** added for direct route URLs or Runtime App generated
  targets.
- It **cannot** be overridden from a route-level `request_headers`.

These runtime-managed headers are not overridable from
`request_headers`.

## 5.5 Dynamic DNS backend discovery

For environments such as containers / Kubernetes where backend addresses
are **managed by DNS**, use `upstreams[].discovery`. Routes / Backend
Pools still refer to the canonical upstream name, while the actual
target set behind it is materialized from DNS resolution results.

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

Discovery rules:

- `type=dns` resolves A / AAAA records. `hostname`, `scheme`, and
  `port` are required.
- `type=dns_srv` resolves `_service._proto.name` and uses the SRV port.
- `scheme` is `http` or `https` only; `fcgi` and `static` are not in
  scope for discovery.
- DNS is **not** resolved per request. The refresh cadence is governed
  by `refresh_interval_sec`.
- If the **first** lookup fails and there is no last-good, that
  upstream has **zero selectable targets**.
- If a **subsequent** lookup fails, the **last-good target set is
  retained**.
- `Backends` and health status show the materialized targets and any
  discovery errors.

## 5.6 Backend pool sticky sessions

`backend_pools[].sticky_session` makes the proxy **issue a signed
affinity cookie** of its own. While `hash_policy=cookie` only uses the
existing application cookie as a hash input, `sticky_session` has the
proxy itself emit and update a load-balancer cookie.

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

Important behaviors:

- A valid sticky cookie **takes precedence** over round-robin /
  least-conn / hash selection.
- A sticky target is ignored if it is invalid / expired / tampered /
  unknown / disabled / draining / unhealthy.
- The cookie value is signed and stores **only** the selected target
  identifier and an expiry. **The backend URL is not included.**
- The signing key is **process-local** and generated at startup. Old
  cookies after a restart are safely rejected and refreshed in the next
  response.
- `same_site=none` requires `secure=true`.

A route that consumes a sticky pool just points `action.backend_pool` at
the pool name, exactly as in §5.1.4.

## 5.7 Rewrites and route actions

Route actions let you shape the outbound side in a bounded way.
Combining host / path / query rewrites with header controls, a route
might look like this:

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

This route takes requests for `api.example.com/servicea/...`, rewrites
the host to `service-a.internal`, rewrites the path prefix from
`/servicea/` to `/service-a/`, and routes them to the direct upstream
`service-a`.

## 5.8 Validating routes with dry-run

Before and after editing proxy rules, you can ask "**which route would
this host / path classify into?**" via
`/tukuyomi-api/proxy-rules/dry-run`.

```bash
curl -sS \
  -H "Authorization: Bearer ${WAF_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

`dry-run` does not actually pass traffic; it only returns the route
classification result. It is useful for confirming that a new route or
rewrite hits as intended before sending live traffic.

Related route logs:

- `proxy_route`
- `original_host` / `original_path` / `original_query`
- `rewritten_host` / `rewritten_path` / `rewritten_query`
- `selected_route`

`proxy_route` is emitted **after** route classification but **before**
final target selection, so it does not carry selected-upstream fields.

## 5.9 Bridge to the next chapter

We have now walked through how routing is composed, how a request
flows, and how to operate backends at runtime.

Chapter 6 covers what happens after target selection: **which HTTP
protocol tukuyomi speaks to the chosen upstream** — HTTP/1.1, HTTP/2
over TLS, h2c upstreams, and how mixed topologies behave.
