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

- only `VITE_APP_BASE_PATH` and `VITE_CORAZA_API_BASE` are build-time Admin UI values
- admin secrets stay server-side; the browser uses `/tukuyomi-api/auth/login` to mint same-origin session cookies after startup

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

- [tukuyomi.env.example](tukuyomi.env.example)

Minimum values to review:

- `WAF_APP_URL`
- `WAF_RULES_FILE`
- `WAF_BYPASS_FILE`
- `WAF_API_KEY_PRIMARY`
- `WAF_API_KEY_SECONDARY`
- `WAF_ADMIN_SESSION_SECRET`
- `WAF_ADMIN_SESSION_TTL_SEC`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_EXPOSE_WAF_DEBUG_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_CRS_ENABLE`
- `WAF_CRS_SETUP_FILE`
- `WAF_CRS_RULES_DIR`
- `WAF_CRS_DISABLED_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` or `WAF_DB_PATH`
- `WAF_ADMIN_EXTERNAL_MODE`
- `WAF_ADMIN_TRUSTED_CIDRS`

If a front layer exists, run traffic as:

`client -> ALB/nginx/HAProxy/Cloudflare -> tukuyomi -> app`

and restrict `WAF_TRUSTED_PROXY_CIDRS` to only that front layer.
`WAF_TRUSTED_PROXY_CIDRS` does not decide admin exposure. The default tukuyomi posture is `WAF_ADMIN_EXTERNAL_MODE=api_only_external`, which keeps the embedded admin UI limited to trusted/private direct peers while leaving the authenticated admin API reachable to untrusted external clients. Use `WAF_ADMIN_EXTERNAL_MODE=deny_external` when remote admin API access is unnecessary, and set `WAF_ADMIN_TRUSTED_CIDRS` if your front layer reaches tukuyomi from non-private source IPs.

## Secret Handling

- Keep `WAF_API_KEY_PRIMARY`, `WAF_API_KEY_SECONDARY`, `WAF_ADMIN_SESSION_SECRET`, `WAF_DB_DSN`, and `WAF_FP_TUNER_API_KEY` in the server-side env file only
- The embedded Admin UI no longer needs any build-time secret
- Browser operators sign in once, receive same-origin session cookies, and then use the Admin UI normally
- CLI / automation can continue to call admin endpoints with `X-API-Key`

## systemd

Sample unit:

- [tukuyomi.service.example](tukuyomi.service.example)

Install:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 644 docs/build/tukuyomi.env.example /etc/tukuyomi/tukuyomi.env
sudo chown root:root /etc/tukuyomi/tukuyomi.env
sudo chmod 600 /etc/tukuyomi/tukuyomi.env
sudo install -m 644 docs/build/tukuyomi.service.example /etc/systemd/system/tukuyomi.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi
sudo systemctl status tukuyomi
```

## Notes

- The sample unit uses `WorkingDirectory=/opt/tukuyomi`, so relative `conf/`, `rules/`, and `logs/` paths keep working
- `make binary-deployment-smoke` now validates unauthenticated session state, valid login, invalid session rejection, CSRF enforcement, and logout
- If you want mutable runtime config, keep `conf/` and `rules/` outside the binary and update those files in place
- If you switch to DB-backed multi-node operation, prefer MySQL over SQLite
