[English](standalone-regression.md) | [日本語](standalone-regression.ja.md)

# Standalone Runtime Regression Matrix

This document defines the repeatable regression path for the standalone-shaped
`[web]` runtime:

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

For `api-gateway`, the standalone wrapper also verifies that repeated login
requests eventually hit `429`.

## Matrix Status

| Area | Status today | How to run | Expected result |
| --- | --- | --- | --- |
| Health check | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /healthz = 200` |
| Admin UI | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-admin/ = 200` |
| Admin API status | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-api/status = 200` |
| Admin logs API reachability | Automated | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-api/logs/read?src=waf&tail=1 = 200` |
| Normal app proxy | Automated | `standalone-regression-fast` / `standalone-smoke` | protected host reaches app |
| WAF block | Automated | `standalone-regression-fast` / `standalone-smoke` | simple XSS probe returns `403` |
| Rate limit | Partially automated | `standalone-regression-extended` (`api-gateway`) | repeated login requests eventually return `429` |
| Bypass rules | Manual for now | admin API + reproducer curl | bypass path should pass while non-bypass path still blocks |
| Country block | Manual for now | trusted front-proxy fixture + reproducer curl | blocked country should return `403`, untrusted headers should degrade to `UNKNOWN` |
| nginx-style log parity (`accerr` / `intr`) | Pending later slice | N/A | currently tied to front `nginx` behavior |
| Cache behavior without nginx | Pending later slice | N/A | currently tied to front `nginx` cache |

## Why Some Checks Are Still Manual

Two runtime areas are intentionally left as manual/pending in this phase:

- country-based policy needs a dedicated trusted front-proxy fixture
- cache and nginx-log parity belong to later replacement slices

Those are not regressions in the current standalone smoke harness; they are
known unfinished standalone-runtime gaps.
