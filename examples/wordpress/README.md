[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress (High Paranoia)

This example puts tukuyomi in front of WordPress and enables CRS with higher paranoia.

## Start

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

- WordPress URL: `http://localhost:${NGINX_PORT:-18082}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

## Notes

- `WAF_CRS_SETUP_FILE=rules/crs-setup-high-paranoia.conf` is used.
- `tx.blocking_paranoia_level` and `tx.detection_paranoia_level` are set to `2`.
- Login endpoint `/wp-login.php` has stricter rate limits.

## Protected Host Smoke

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

On the default local stack, the smoke script bootstraps WordPress automatically before testing. It then hits `/tukuyomi-whoami.php`, verifies that the WordPress PHP runtime sees the protected host, and confirms a simple XSS probe is blocked with `403`.
