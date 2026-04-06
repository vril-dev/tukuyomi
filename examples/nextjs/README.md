[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

This example places tukuyomi in front of a minimal Next.js app.

## Start

Direct standalone path:

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

- App URL: `http://localhost:${CORAZA_PORT:-19091}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/nextjs
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18081}`

## Smoke tests

```bash
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

The second request should be blocked by WAF (`403`).

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

Thin front proxy smoke:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

This verifies that the app sees the protected host on `/api/whoami` and that a simple XSS probe is blocked with `403`.

## Direct Local Cache Check

To verify the standalone cache without example `nginx`:

```bash
WAF_RESPONSE_CACHE_MODE=memory docker compose up -d --build
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/"
```

The first response should include `X-Tukuyomi-Cache-Status: MISS`, and the second should become `HIT`.

To verify restart-friendly disk-backed cache instead:

```bash
WAF_RESPONSE_CACHE_MODE=disk docker compose up -d --build
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/"
```

If you want to inspect a Cloudflare-style country header via the optional front proxy:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18081/api/whoami"
```
