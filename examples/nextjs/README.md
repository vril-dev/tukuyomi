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
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

The second request should be blocked by WAF (`403`).
