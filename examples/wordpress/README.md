[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress (High Paranoia)

This example puts tukuyomi in front of WordPress and enables CRS with higher paranoia.

## Start

Direct standalone path:

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

- WordPress URL: `http://localhost:${CORAZA_PORT:-19092}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/wordpress
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18082}`

## Notes

- `WAF_CRS_SETUP_FILE=rules/crs-setup-high-paranoia.conf` is used.
- `tx.blocking_paranoia_level` and `tx.detection_paranoia_level` are set to `2`.
- Login endpoint `/wp-login.php` has stricter rate limits.

## Protected Host Smoke

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

Thin front proxy smoke:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

On the default local stack, the smoke script bootstraps WordPress automatically before testing. It then hits `/tukuyomi-whoami.php`, verifies that the WordPress PHP runtime sees the protected host, and confirms a simple XSS probe is blocked with `403`.

Cloudflare-style country header flow via the optional front proxy:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18082/tukuyomi-whoami.php"
```
