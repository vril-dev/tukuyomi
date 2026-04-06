[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: API Gateway (Rate-limit focused)

This example protects a JSON API and applies stricter limits on auth endpoints.

## Start

Direct standalone path:

```bash
cd examples/api-gateway
./setup.sh
docker compose up -d --build
```

- API base URL: `http://localhost:${CORAZA_PORT:-19093}/v1`
- Coraza API: `http://localhost:${CORAZA_PORT:-19093}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/api-gateway
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18083}/v1`

## Smoke tests

```bash
curl -i "http://localhost:19093/v1/health"
curl -i -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
```

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

Thin front proxy smoke:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

This sends traffic with `Host: protected.example.test`, verifies the origin sees that host, and checks that a simple XSS probe is blocked with `403`.

To mimic a Cloudflare-style country header through the optional front proxy:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18083/v1/health"
```

If you want to try a clone of your own site, keep the smoke script and swap the example app behind tukuyomi with your clone. The same `PROTECTED_HOST=... ./smoke.sh` flow still applies.

Rate-limit check (expect `429` after repeated calls):

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
done
```
