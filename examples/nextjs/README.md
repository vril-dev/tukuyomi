[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

This example places tukuyomi in front of a minimal Next.js app.

## Start

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

- App URL: `http://localhost:${NGINX_PORT:-18081}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

## Smoke tests

```bash
curl -i "http://localhost:18081/"
curl -i "http://localhost:18081/?q=<script>alert(1)</script>"
```

The second request should be blocked by WAF (`403`).

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

This verifies that the app sees the protected host on `/api/whoami` and that a simple XSS probe is blocked with `403`.

## Direct Local Cache Check

To verify the standalone in-memory cache without example `nginx`:

```bash
WAF_RESPONSE_CACHE_MODE=memory docker compose up -d --build
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/"
```

The first response should include `X-Tukuyomi-Cache-Status: MISS`, and the second should become `HIT`.
