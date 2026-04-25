[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

This example places tukuyomi in front of a minimal Next.js app.

## Start

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

`./setup.sh` seeds the runtime DB from the built-in `nextjs` import profile
before the stack starts.

- App URL: `http://localhost:${CORAZA_PORT:-19091}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

## Smoke tests

```bash
./smoke.sh
```

`./smoke.sh` verifies that the app is reachable and that the internal response
cache returns `X-Tukuyomi-Cache: MISS` followed by `HIT` for a static fixture.
The example bootstraps a smoke-only admin user so the script can enable and
clear the internal cache store before probing. Override the credentials only
when the example runtime was started with different bootstrap credentials:

```bash
ADMIN_USERNAME='admin' ADMIN_PASSWORD='your-admin-password' ./smoke.sh
```

You can still run a manual WAF block check:

```bash
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

The request should be blocked by WAF (`403`).
