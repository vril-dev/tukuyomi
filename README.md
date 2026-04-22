# tukuyomi

Coraza + CRS WAF reverse proxy / API gateway

[English](README.md) | [Japanese](README.ja.md)

![Admin Top](docs/images/ui-samples/01-status.png)

## Overview

`tukuyomi` is the general-purpose reverse proxy / API gateway in the Tukuyomi family.
It combines Coraza WAF + OWASP CRS with built-in route management, embedded admin UI/API,
optional static and PHP-FPM hosting, cache, and app-edge policy controls.

It is designed for operators who want one product to cover:

- reverse proxy and route management
- WAF and false-positive tuning
- rate, country, bot, semantic, and IP reputation controls
- built-in admin UI/API
- optional static hosting, PHP-FPM, and scheduled jobs
- single-binary or Docker deployment

## Product Positioning

`tukuyomi` is now the canonical application-edge WAF / reverse proxy product.
The former `tukuyomi-proxy` line has been integrated into this repository and
continues here under the `tukuyomi` product name.

Archived `tukuyomi-proxy` binary releases remain available from
`tukuyomi-releases`, but that repository is no longer the update channel for
proxy/WAF development. New proxy, routing, cache, WAF tuning, PHP-FPM, and
scheduled task work belongs to `tukuyomi`.

See [docs/product-comparison.md](docs/product-comparison.md) for the current
family comparison.

## Rule Files and First Setup

This repository intentionally does **not** bundle the full OWASP CRS files.
It ships a minimal bootstrappable base rule file, `data/rules/tukuyomi.conf`.

Fetch CRS first for normal runtime use:

```bash
make crs-install
```

Use a prepared baseline if you want a copy-ready preset for the embedded admin UI and
default upstream wiring:

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

Before production use, replace the sample values in:

- `data/conf/config.json`
- `data/conf/proxy.json`
- `data/conf/sites.json` when site ownership / TLS is enabled
- `conf/scheduled-tasks.json` when scheduled tasks are enabled

## Quick Start

### Local Preview

A simple local preview flow is:

```bash
make preset-apply PRESET=minimal
make ui-preview-up
```

`make ui-preview-up` runs `make crs-install` automatically on first launch when
`data/rules/crs` is not installed yet.

Then open:

- Admin UI: `http://localhost:9090/tukuyomi-ui`
- Admin API: `http://localhost:9090/tukuyomi-api`

If you use `UI_PREVIEW_PERSIST=1`, preview-specific config is kept across `ui-preview-down` / `ui-preview-up`.

### Runtime Config Model

`tukuyomi` keeps configuration split by responsibility:

- `.env`: Docker-only runtime wiring
- `data/conf/config.json`: global runtime, listener, admin, storage, and path config
- `data/conf/proxy.json`: live proxy transport and routing config
- `data/conf/proxy.json.backend_pools[]`: route-scoped balancing groups built from named upstream members
- `data/conf/upstream-runtime.json`: opt-in runtime overrides for direct named upstreams from `Proxy Rules > Upstreams`
- `data/conf/sites.json`: site ownership and TLS binding
- `data/conf/rules/*.conf`: managed bypass `extra_rule` files
- `data/php-fpm/vhosts.json`: PHP-FPM vhost definitions, internal `generated_target`, and canonical `linked_upstream_name`
- `conf/scheduled-tasks.json`: scheduled task definitions

Managed bypass override rules under `data/conf/rules/*.conf` are edited from
`Override Rules`. They are not loaded into the base WAF rule set at
normal startup; they are loaded only when `waf-bypass.json` references them via
`extra_rule`.

For the detailed operator model, see:

- [docs/reference/operator-reference.md](docs/reference/operator-reference.md)
- [docs/operations/listener-topology.md](docs/operations/listener-topology.md)

`Proxy Rules > Upstreams` is the direct backend node catalog. `Proxy Rules >
Backend Pools` groups routable upstream names into route-scoped balancing sets,
and routes normally bind to `action.backend_pool`. `Backends` lists canonical
backend objects used by routing and keeps runtime operations on the direct
named upstream nodes themselves.

In the structured `Proxy Rules` editor, the operator workflow is shown in this
order:

1. `Upstreams`
2. `Backend Pools`
3. `Routes` / `Default route`

Each `Upstreams` row provides its own `Probe` action so connectivity checks are
run against a specific configured upstream instead of a generic panel-wide
target.

Direct named upstreams from `Proxy Rules > Upstreams` can be drained, disabled,
or given a runtime weight override from `Backends` without editing
`proxy.json`. Those runtime-only overrides live in
`data/conf/upstream-runtime.json`.

For route-scoped web balancing, define backend nodes in `upstreams[]`, group
them in `backend_pools[]`, then bind routes to those pools with
`action.backend_pool`.

When a Vhost needs to participate in the same routing namespace,
`linked_upstream_name` is required and must already exist in `Proxy Rules >
Upstreams`. The Vhost binds to that configured upstream, and the effective
runtime resolves that upstream as a vhost-backed target while the legacy
`generated_target` remains an internal compatibility field for vhost
materialization. A configured upstream bound by a Vhost cannot be removed from
`Proxy Rules > Upstreams` until the Vhost is relinked.
Vhost-bound configured upstreams are visible in `Backends` as status-only canonical
objects, but runtime enable/drain/disable and runtime weight override remain
limited to direct named upstreams in this first slice.

Standard `http://` and `https://` upstream proxying automatically adds:

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

Optional `emit_upstream_name_request_header=true` also adds:

- `X-Tukuyomi-Upstream-Name`

This internal observability header is emitted only when the final target is a
configured named upstream from `Proxy Rules > Upstreams`. Direct route URLs and
generated vhost targets do not receive it, and route-level `request_headers`
cannot override it.

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

## Deployment Guides

Choose one of these deployment models:

- Single binary / systemd:
  - [docs/build/binary-deployment.md](docs/build/binary-deployment.md)
- Docker / container platforms:
  - [docs/build/container-deployment.md](docs/build/container-deployment.md)
- Split public/admin listener example:
  - [docs/build/config.split-listener.example.json](docs/build/config.split-listener.example.json)

Container platform examples:

- ECS single-instance:
  - [docs/build/ecs-single-instance.task-definition.example.json](docs/build/ecs-single-instance.task-definition.example.json)
  - [docs/build/ecs-single-instance.service.example.json](docs/build/ecs-single-instance.service.example.json)
- Kubernetes single-instance:
  - [docs/build/kubernetes-single-instance.example.yaml](docs/build/kubernetes-single-instance.example.yaml)
- Azure Container Apps single-instance:
  - [docs/build/azure-container-apps-single-instance.example.yaml](docs/build/azure-container-apps-single-instance.example.yaml)

## Documentation Map

### Core Operator Reference

- Operator reference:
  - [docs/reference/operator-reference.md](docs/reference/operator-reference.md)
- Admin API OpenAPI:
  - [docs/api/admin-openapi.yaml](docs/api/admin-openapi.yaml)
- Request security plugin model:
  - [docs/request_security_plugins.md](docs/request_security_plugins.md)

### Security and Tuning

- WAF tuning:
  - [docs/operations/waf-tuning.md](docs/operations/waf-tuning.md)
- FP Tuner API contract:
  - [docs/operations/fp-tuner-api.md](docs/operations/fp-tuner-api.md)
- Upstream HTTP/2 and h2c:
  - [docs/operations/upstream-http2.md](docs/operations/upstream-http2.md)
- Static fastpath evaluation:
  - [docs/operations/static-fastpath-evaluation.md](docs/operations/static-fastpath-evaluation.md)

### PHP and Scheduled Tasks

- PHP-FPM runtime and VHosts:
  - [docs/operations/php-fpm-vhosts.md](docs/operations/php-fpm-vhosts.md)
- Scheduled tasks and scheduler deployment:
  - [docs/operations/php-scheduled-tasks.md](docs/operations/php-scheduled-tasks.md)

### Database, Metrics, and Regression

- DB operations:
  - [docs/operations/db-ops.md](docs/operations/db-ops.md)
- Benchmark baseline:
  - [docs/operations/benchmark-baseline.md](docs/operations/benchmark-baseline.md)
- Regression matrix:
  - [docs/operations/regression-matrix.md](docs/operations/regression-matrix.md)
- Release binary smoke:
  - [docs/operations/release-binary-smoke.md](docs/operations/release-binary-smoke.md)

## Quality Gates

Local verification:

```bash
make ci-local
```

Extended local regression, including deployment-guide replay:

```bash
make ci-local-extended
```

Typical required checks in CI are:

- `ci / go-test`
- `ci / mysql-logstore-test`
- `ci / compose-validate`
- `ci / waf-test (file)`
- `ci / waf-test (sqlite)`

## License

tukuyomi is released under the BSD 2-Clause License, the same permissive license
family used by nginx. See [LICENSE](LICENSE).

Third-party dependency notices are listed in [NOTICE](NOTICE). Dependency
license metadata is available through `coraza/src/go.mod` / `coraza/src/go.sum`
and `web/tukuyomi-admin/package-lock.json`.

## What Is tukuyomi?

**tukuyomi** evolves from **mamotama**, an OSS WAF built on nginx + Coraza WAF.

The name is inspired by **「護りたまえ」(mamoritamae)**, meaning *"grant protection"*.
While mamotama focused on protection as its core principle, tukuyomi represents a
more structured and operationally visible approach to web protection.
