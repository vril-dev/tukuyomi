[English](standalone-regression.md) | [日本語](standalone-regression.ja.md)

# Standalone Runtime Regression Matrix

This document defines the repeatable regression path for the standalone-shaped
tukuyomi runtime:

- `client -> tukuyomi -> app`
- `client -> ALB/nginx/cloudflare -> tukuyomi -> app`

It is intentionally split into a fast local path and a heavier path.

## Fast Path

Run one direct-to-`tukuyomi` example from the repo root:

```bash
make standalone-regression-fast EXAMPLE=api-gateway
```

What this covers today:

- `go test ./...`
- `docker compose config`
- direct `tukuyomi` health check
- direct `tukuyomi` admin UI check
- direct `tukuyomi` admin API status check
- direct `tukuyomi` admin logs endpoint check
- direct app proxy pass-through check
- direct WAF block check

## Broader Example Sweep

Run the direct-`tukuyomi` smoke wrapper against all shipped examples:

```bash
make standalone-smoke-all
```

This gives broader topology coverage for:

- `examples/api-gateway`
- `examples/nextjs`
- `examples/wordpress`

## Extended Path

Run the heavier local baseline:

```bash
make standalone-regression-extended
```

This currently runs:

- `make check`
- `make standalone-smoke-all`
- `make standalone-policy-fixture`
- `make deployment-smoke`

For `api-gateway`, the standalone wrapper also verifies that repeated login
requests eventually hit `429`, and temporary bypass/country policy fixtures are
applied and restored through the admin API.

If you only want the policy-fixture pass without the broader standalone sweep,
run:

```bash
make standalone-policy-fixture EXAMPLE=api-gateway
```

If you only want the deployment-guide validation bundle without the broader
standalone sweep, run:

```bash
make deployment-smoke
```

## Matrix Status

| Area | Status today | How to run | Expected result |
| --- | --- | --- | --- |
| Health check | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /healthz = 200` |
| Admin UI | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-admin/ = 200` |
| Admin API status | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-api/status = 200` |
| Admin logs API parity | Automated | `standalone-regression-fast` / `standalone-smoke` | `src=waf/intr/accerr` returns `200`, and after smoke `intr/accerr` contain at least one line |
| Normal app proxy | Automated | `standalone-regression-fast` / `standalone-smoke` | protected host reaches app |
| WAF block | Automated | `standalone-regression-fast` / `standalone-smoke` | simple XSS probe returns `403` |
| Rate limit | Partially automated | `standalone-regression-extended` (`api-gateway`) | repeated login requests eventually return `429` |
| Bypass rules | Automated | `standalone-policy-fixture` / `standalone-regression-extended` (`api-gateway`) | temporary bypass makes `/v1/whoami` pass while another path still blocks |
| Country block | Automated | `standalone-policy-fixture` / `standalone-regression-extended` (`api-gateway`) | trusted front-proxy `JP` returns `403`, untrusted headers are ignored or degraded to `UNKNOWN` as configured |
| Binary deployment guide | Automated | `deployment-smoke` / `standalone-regression-extended` | staged binary build + runtime tree passes `/healthz`, Admin UI, admin login/session/logout + CSRF checks, and protected-host smoke |
| Container deployment guide | Automated | `deployment-smoke` / `standalone-regression-extended` | `docs/build/Dockerfile.example` image passes `/healthz`, Admin UI, admin login/session/logout + CSRF checks, and protected-host smoke |
| Cache advanced semantics | Pending later slice | N/A | stale serve / coalescing / disk-backed behavior still differs from `nginx proxy_cache` |

## Why Some Checks Are Still Manual

One runtime area is intentionally left as pending in this phase:

- cache semantics still need a later replacement slice

That is not a regression in the current standalone smoke harness; it is a known
unfinished standalone-runtime gap.
