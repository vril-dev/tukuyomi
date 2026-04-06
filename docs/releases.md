# Release Notes

This file keeps product-facing release notes for `[web] tukuyomi`.

- Draft entries may be edited before the release tag is pushed.
- Historical details that are not summarized here can still be traced from the
  Git tags and commit history.

## v0.2.0 (2026-04-06)

### Highlights

- Embedded the Admin UI into the `tukuyomi` binary.
  - The optional Vite frontend is now a dev-only path.
  - Browser admin traffic can stay on the same origin as the Go runtime.
- Added standalone-oriented runtime work so `client -> front proxy/LB -> tukuyomi -> apps`
  is a first-class deployment shape.
  - trusted proxy boundary controls
  - trusted country-header chain
  - internal response-header sanitizing
- Expanded the built-in response-cache path.
  - in-memory cache
  - request coalescing
  - stale-cache resilience and refresh backoff
  - disk-backed cache mode
- Moved browser admin auth from embedded reusable keys to session cookies.
  - added login / logout / session endpoints
  - added CSRF protection for state-changing browser admin requests
  - direct `X-API-Key` access remains available for CLI and automation

### Operations And Deployment

- Added binary deployment guidance under [`docs/build/binary-deployment.md`](./build/binary-deployment.md).
- Added container deployment guidance under [`docs/build/container-deployment.md`](./build/container-deployment.md).
- Added sample deployment assets:
  - [`docs/build/tukuyomi.service.example`](./build/tukuyomi.service.example)
  - [`docs/build/tukuyomi.env.example`](./build/tukuyomi.env.example)
  - [`docs/build/Dockerfile.example`](./build/Dockerfile.example)
- Added `make go-build` for local binary builds.
- Added deployment smoke coverage for both documented paths:
  - `make binary-deployment-smoke`
  - `make container-deployment-smoke`
  - `make deployment-smoke`

### Admin And Observability

- Added standalone operational log parity for Admin UI `waf / intr / accerr` views.
- Added Admin UI support for:
  - log-output profiles
  - cache runtime visibility
- Updated the admin OpenAPI document for session-based auth:
  - `/tukuyomi-api/auth/session`
  - `/tukuyomi-api/auth/login`
  - `/tukuyomi-api/auth/logout`

### Operator Notes

- Set `WAF_ADMIN_SESSION_SECRET` in all non-local environments.
- Do not treat `VITE_*` values as secrets.
- Review these settings when running behind ALB, nginx, HAProxy, or CDN fronts:
  - `WAF_TRUSTED_PROXY_CIDRS`
  - `WAF_COUNTRY_HEADER_NAMES`
  - `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- Response-cache runtime is now an explicit deployment choice.
  - `off`
  - `memory`
  - `disk`

### Validation Summary

Validated during the `v0.2.0` work:

- `go test ./...`
- `go test -race ./...`
- `make ui-test`
- `make ui-build`
- `make standalone-regression-fast`
- `make standalone-regression-extended`
- `make binary-deployment-smoke`
- `make container-deployment-smoke`
- `make deployment-smoke`
- targeted benchmark scenarios for direct and front-proxy topologies
