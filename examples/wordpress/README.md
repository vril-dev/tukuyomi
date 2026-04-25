[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress (High Paranoia)

This example puts tukuyomi in front of WordPress and enables CRS with higher paranoia.

## Start

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

`./setup.sh` seeds the runtime DB from the built-in `wordpress` import profile
before the stack starts.

- WordPress URL: `http://localhost:${CORAZA_PORT:-19092}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

## Notes

- `./setup.sh` installs the high-paranoia CRS setup as the DB-imported CRS setup asset.
- `tx.blocking_paranoia_level` and `tx.detection_paranoia_level` are set to `2`.
- Login endpoint `/wp-login.php` has stricter rate limits.

## Smoke tests

```bash
./smoke.sh
```

`./smoke.sh` verifies that WordPress is reachable, the admin status endpoint is
available, and an XSS probe is blocked by WAF (`403`).
The example includes a smoke-only admin API key for the status check.
