[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress (High Paranoia)

This example puts tukuyomi in front of WordPress and enables CRS with higher paranoia.

## Start

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

- WordPress URL: `http://localhost:${CORAZA_PORT:-19092}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

## Notes

- `data/conf/config.json` uses `paths.crs_setup_file=rules/crs-setup-high-paranoia.conf`.
- `tx.blocking_paranoia_level` and `tx.detection_paranoia_level` are set to `2`.
- Login endpoint `/wp-login.php` has stricter rate limits.
