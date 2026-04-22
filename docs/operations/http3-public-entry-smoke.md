# tukuyomi HTTP/3 Public-Entry Smoke

This document defines the dedicated runtime smoke for built-in HTTPS + HTTP/3 on `tukuyomi`.

## Command

```bash
make http3-public-entry-smoke
```

## What it validates

The smoke starts a temporary local runtime with:

- built binary
- built-in TLS enabled
- built-in HTTP/3 enabled
- temporary self-signed certificate for `127.0.0.1` and `localhost`
- local echo upstream for routed traffic

It proves:

- the HTTPS listener becomes healthy
- HTTPS responses advertise `Alt-Svc`
- routed proxy traffic still works over the HTTPS entrypoint
- `/tukuyomi-api/status` reports `server_http3_enabled=true` and `server_http3_advertised=true`
- an actual HTTP/3 request over UDP succeeds against the live runtime

## Why this is a dedicated command

This smoke is intentionally separate from `make smoke`, `make deployment-smoke`, and `make ci-local` because it depends on:

- TLS runtime boot
- UDP availability on the local host
- a temporary self-signed certificate
- a Go-based HTTP/3 probe

That makes it useful for release readiness and operator validation, but too environment-sensitive for the normal fast smoke path.

## Expected prerequisites

- Go toolchain
- Docker is not required for this smoke
- `curl`, `jq`, `python3`, `rsync`, and `install`
- local UDP loopback is available

## Recommended usage

Run this command when you changed:

- `server.http3.*`
- built-in TLS listener behavior
- `Alt-Svc` handling
- runtime startup that could affect the HTTPS/HTTP/3 listener pair

It is also the right dedicated command before publicly recommending `tukuyomi` as a direct HTTPS/HTTP/3 entrypoint.

## Related docs

- regression command map: [regression-matrix.md](regression-matrix.md)
- benchmark baseline: [benchmark-baseline.md](benchmark-baseline.md)
