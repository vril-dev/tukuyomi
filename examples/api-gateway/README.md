[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: API Gateway (Rate-limit focused)

This example protects a JSON API and applies stricter limits on auth endpoints.
`./setup.sh` provisions the example DB from the built-in `api-gateway` import
profile before you start the stack.

## Start

```bash
cd examples/api-gateway
./setup.sh
docker compose up -d --build
```

- API base URL: `http://localhost:${CORAZA_PORT:-19093}/v1`
- Coraza API: `http://localhost:${CORAZA_PORT:-19093}/tukuyomi-api/status`

## Smoke tests

```bash
curl -i "http://localhost:19093/v1/health"
curl -i -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
```

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

This sends traffic with `Host: protected.example.test`, verifies the protected-host route matches, and checks that a simple XSS probe is blocked with `403`.

If you want to point the gateway at another upstream, rerun `./setup.sh` and
then update proxy rules through the admin UI or API before `docker compose up`.
When you change `PROTECTED_HOST`, update the protected-host route in the same
place so the route still matches.

Rate-limit check (expect `429` after repeated calls):

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
done
```
