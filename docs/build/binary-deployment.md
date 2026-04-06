# Binary Deployment

This guide is for Linux hosts that run the binary directly under `systemd`.

Typical environments:

- on-prem Linux server
- VPS
- VM
- EC2

## Build

Build on a workstation or build host:

```bash
make setup
make ui-build-sync
make go-build
```

This produces `bin/tukuyomi`.

To rerun the documented flow as a repo smoke check:

```bash
make binary-deployment-smoke
```

Important:

- `VITE_API_KEY` is embedded into the built admin UI
- set `VITE_API_KEY`, `VITE_APP_BASE_PATH`, and `VITE_CORAZA_API_BASE` before `make ui-build-sync` if you do not want the defaults

## Runtime Layout

The binary expects a working directory that contains:

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/rules/
/opt/tukuyomi/logs/
```

Minimum config payload:

- `conf/cache.conf`
- `conf/waf.bypass`
- `conf/country-block.conf`
- `conf/rate-limit.conf`
- `conf/bot-defense.conf`
- `conf/semantic.conf`
- `conf/notifications.conf`
- `rules/tukuyomi.conf`
- `rules/crs/crs-setup.conf`
- `rules/crs/rules/*.conf`

Optional or auto-created:

- `conf/log-output.json` is created on first start if missing
- `conf/crs-disabled.conf` can start empty and is written when CRS toggles are changed

Install example:

```bash
sudo install -d -m 755 /opt/tukuyomi/bin /opt/tukuyomi/conf /opt/tukuyomi/rules /opt/tukuyomi/logs/coraza /opt/tukuyomi/logs/nginx
sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo rsync -a data/conf/ /opt/tukuyomi/conf/
sudo rsync -a data/rules/ /opt/tukuyomi/rules/
sudo touch /opt/tukuyomi/conf/crs-disabled.conf
```

## Environment File

Use an env file such as `/etc/tukuyomi/tukuyomi.env`.

Template:

- [tukuyomi.env.example](/home/ky491/git/vril/tukuyomi/docs/build/tukuyomi.env.example)

Minimum values to review:

- `WAF_APP_URL`
- `WAF_RULES_FILE`
- `WAF_BYPASS_FILE`
- `WAF_API_KEY_PRIMARY`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_CRS_ENABLE`
- `WAF_CRS_SETUP_FILE`
- `WAF_CRS_RULES_DIR`
- `WAF_CRS_DISABLED_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` or `WAF_DB_PATH`

If a front layer exists, run traffic as:

`client -> ALB/nginx/HAProxy/Cloudflare -> tukuyomi -> app`

and restrict `WAF_TRUSTED_PROXY_CIDRS` to only that front layer.

## systemd

Sample unit:

- [tukuyomi.service.example](/home/ky491/git/vril/tukuyomi/docs/build/tukuyomi.service.example)

Install:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 644 docs/build/tukuyomi.env.example /etc/tukuyomi/tukuyomi.env
sudo install -m 644 docs/build/tukuyomi.service.example /etc/systemd/system/tukuyomi.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi
sudo systemctl status tukuyomi
```

## Notes

- The sample unit uses `WorkingDirectory=/opt/tukuyomi`, so relative `conf/`, `rules/`, and `logs/` paths keep working
- If you want mutable runtime config, keep `conf/` and `rules/` outside the binary and update those files in place
- If you switch to DB-backed multi-node operation, prefer MySQL over SQLite
