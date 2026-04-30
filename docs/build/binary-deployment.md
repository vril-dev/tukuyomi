# Binary Deployment

This guide is for Linux hosts that run `tukuyomi` as a single binary under `systemd`.

Typical environments:

- on-prem Linux server
- VPS
- VM
- EC2

## Build

Build on a workstation or build host:

```bash
make setup
make build
```

This produces `bin/tukuyomi`.

If you only need the Go binary and already refreshed the embedded Gateway and Center UI, use:

```bash
make go-build
```

For reproducible release artifacts, use:

```bash
make release-linux-all VERSION=v0.8.0
```

## One-Shot Install

For a direct Linux host install, this builds the binary, creates the runtime
tree, runs DB migration, imports WAF/CRS assets, seeds a first DB, and installs
systemd units. `INSTALL_ROLE` defaults to `gateway`:

```bash
make install TARGET=linux-systemd
```

Install Center on a control-plane host:

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

Common overrides:

```bash
make install TARGET=linux-systemd \
  INSTALL_ROLE=gateway \
  PREFIX=/opt/tukuyomi \
  INSTALL_ENABLE_SCHEDULED_TASKS=0 \
  INSTALL_DB_SEED=auto
```

Behavior:

- `PREFIX` defaults to `/opt/tukuyomi`
- `INSTALL_ROLE=gateway` installs `tukuyomi.service`, `tukuyomi.env`,
  `conf/config.json`, WAF/CRS asset import, first-run gateway DB seed, and the
  optional scheduled-task timer
- `INSTALL_ROLE=center` installs `tukuyomi-center.service`,
  `tukuyomi-center.env`, and `conf/config.center.json`; it runs DB migration
  only and skips WAF/CRS import, gateway seed, and scheduled tasks
- when `PREFIX` is under the invoking user's home directory,
  `INSTALL_CREATE_USER=auto` uses that user as the runtime user and skips
  `useradd`
- a home-directory runtime tree is owned by that login user and primary group
- for system paths such as `/opt/tukuyomi`, the default creates or reuses the
  `tukuyomi` system user/group
- for service-account installs on system paths, the deployment root, `bin/`,
  `scripts/`, and `conf/` stay root-managed, while `db/`, `audit/`, `cache/`,
  and `data/` are writable by the runtime user
- existing role config/env files are preserved by default
- host install uses `sudo` only for privileged filesystem/systemd operations, so
  the build can run as the invoking user
- newly created env files and systemd units are rendered for the selected
  `PREFIX`
- role config files are root-owned `0640` with read access granted only through
  the service group
- env files stay root-owned `0640` because they are expected to carry secrets
- `INSTALL_DB_SEED=auto` runs `db-import` only when the SQLite DB is not present yet
- the first DB seed creates a default upstream named `primary`; update it to
  the real backend endpoint before exposing the proxy to traffic
- rerunning against an existing DB migrates schema and refreshes WAF/CRS assets
- for an empty MySQL / PostgreSQL DB, set `INSTALL_DB_SEED=always` explicitly
- the scheduled-task timer is enabled by default; use
  `INSTALL_ENABLE_SCHEDULED_TASKS=0` when this host should not execute scheduled
  tasks
- staging / smoke flows can use `DESTDIR=<tmp> INSTALL_ENABLE_SYSTEMD=0`

To run explicitly as the login user:

```bash
make install TARGET=linux-systemd \
  PREFIX="$HOME/tukuyomi" \
  INSTALL_USER="$(id -un)" \
  INSTALL_GROUP="$(id -gn)" \
  INSTALL_CREATE_USER=0
```

For ECS / Kubernetes / Azure Container Apps, render deployment artifacts rather
than mutating the host. See [container-deployment.md](container-deployment.md).

## Runtime Layout

The binary expects a working directory that contains:

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/db/
/opt/tukuyomi/audit/
/opt/tukuyomi/cache/
/opt/tukuyomi/data/persistent/
/opt/tukuyomi/data/tmp/
```

Bundle-provided bootstrap/examples:

- `conf/config.json`
- `conf/crs-disabled.conf`
- `scripts/update_country_db.sh`

Optional operator-supplied seed/import files before the first DB import:

- `conf/cache-rules.json`
- `conf/waf-bypass.json`
- `conf/waf-bypass.sample.json`
- `conf/country-block.json`
- `conf/rate-limit.json`
- `conf/bot-defense.json`
- `conf/semantic.json`
- `conf/notifications.json`
- `conf/ip-reputation.json`
- `conf/scheduled-tasks.json`
- `conf/upstream-runtime.json`
- staged WAF/CRS import material under `data/tmp/...` via `make crs-install`

These seed an empty DB or support import/export workflows. Once the matching
normalized DB domain exists, runtime loads normalized domains directly from DB
and does not require those files to be restored. After import, production
startup only requires `conf/config.json` for DB bootstrap plus the DB rows.

Additional PHP-FPM files used before first DB import:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

After import, the executable bundle remains required when using bundled PHP-FPM,
but `inventory.json`, `vhosts.json`, `runtime.json`, and `modules.json` are not
runtime authority.

Scheduled-task execution state uses:

- `data/scheduled-tasks/`

Additional files when you want managed GeoIP country updates:

- `scripts/update_country_db.sh`

Install example:

```bash
sudo install -d -m 755 \
  /opt/tukuyomi/bin \
  /opt/tukuyomi/conf \
  /opt/tukuyomi/db \
  /opt/tukuyomi/audit \
  /opt/tukuyomi/cache/response \
  /opt/tukuyomi/data/persistent \
  /opt/tukuyomi/data/tmp \
  /opt/tukuyomi/seeds/conf \
  /opt/tukuyomi/scripts

sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo install -m 755 scripts/update_country_db.sh /opt/tukuyomi/scripts/update_country_db.sh
sudo cp -R seeds/conf/. /opt/tukuyomi/seeds/conf/

sudo install -o root -g tukuyomi -m 640 data/conf/config.json /opt/tukuyomi/conf/config.json

sudo install -o root -g tukuyomi -m 640 /dev/null /opt/tukuyomi/conf/crs-disabled.conf
```

Notes:

- do not copy `data/conf/*.bak` into production
- `config.json` is the DB connection bootstrap; release samples keep only the `storage` block
- `conf/proxy.json` is optional seed/import/export material for DB `proxy_rules`
- `conf/sites.json` is optional seed/import/export material for DB `sites`
- the public release bundle ships `conf/config.json` and bundled empty-DB runtime seeds under `seeds/conf/`
- when configured files such as `conf/proxy.json` or policy JSON are absent, `make db-import` reads `seeds/conf/` before falling back to built-in compatibility defaults
- `make crs-install` stages the default base WAF rule seed from `seeds/waf/rules/tukuyomi.conf` and imports it into DB
- CRS files are temporary import material for DB `waf_rule_assets`; `make crs-install` stages them under `data/tmp` and cleans up
- `sites.json`, `scheduled-tasks.json`, `upstream-runtime.json`, policy JSON,
  cache-rules JSON, WAF bypass JSON, and PHP-FPM JSON manifests are DB
  seed/export artifacts after DB bootstrap
- render or mount `config.json` from your secret manager or config-management layer in production for `storage.db_driver`, `storage.db_path`, and `storage.db_dsn`
- run `make db-migrate`, then `make crs-install` to install/import WAF rule assets, then `make db-import` for the remaining seed material before first start. `db-import` does not re-import WAF rule assets
- the embedded `Settings` page edits DB `app_config`; restart the service after listener/runtime/storage policy/observability changes
- the public release bundle ships a companion `bin/geoipupdate` binary for `Options -> GeoIP Update -> Update now`
- `GEOIPUPDATE_BIN` remains available if you want to override the bundled updater path
- the official managed-country refresh wrapper is `./scripts/update_country_db.sh`
- managed GeoIP country DB, `GeoIP.conf`, and update status are DB-backed; do not ship a `data/geoip` fallback directory
- managed bypass override rules are DB `override_rules`; do not ship a `conf/rules` fallback directory
- WAF/access events are written to DB `waf_events`; `paths.log_file` is only a legacy import source when you intentionally ingest an old `waf-events.ndjson`
- `extra_rule` values remain logical compatibility references to DB-managed override rules

## Persistent Byte Storage

Runtime artifacts that must remain durable as files/objects, rather than DB
rows, are managed by `persistent_storage`. The current primary user is
site-managed ACME: account keys, challenge tokens, and certificate cache.

The default backend is local:

```json
{
  "persistent_storage": {
    "backend": "local",
    "local": {
      "base_dir": "data/persistent"
    }
  }
}
```

- on single-node on-prem / VPS deployments, include `/opt/tukuyomi/data/persistent` in backups
- for scale-out or node replacement, use the S3 backend or an operator-managed shared mount instead of node-local storage
- the S3 backend stores only non-secret bucket / region / endpoint / prefix settings in DB `app_config`
- pass `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, and `AWS_SESSION_TOKEN` through env or platform secret injection
- Azure Blob Storage and Google Cloud Storage fail closed until their provider adapters are implemented; they do not silently fall back to local

Configure site-managed ACME per site on the `Sites` page by selecting
`tls.mode=acme`. `production` / `staging` selects the Let's Encrypt production
or staging CA, and account email is optional. ACME HTTP-01 needs
`server.tls.redirect_http=true` with `server.tls.http_redirect_addr=:80`, or
equivalent port 80 forwarding.

Proxy engine selection is a restart-required DB `app_config` setting:

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` is the built-in engine and uses Tukuyomi's own response bridge while preserving the same parser, transport, routing, health, retry, TLS, cache, route response headers, 1xx informational responses, trailers, streaming flush behavior, native Upgrade/WebSocket tunnel, and response-sanitize pipeline
- the legacy `net_http` bridge has been removed; config validation rejects any engine value other than `tukuyomi_proxy`
- HTTP/1.1 and explicit upstream HTTP/2 modes use Tukuyomi native upstream transports; HTTPS `force_attempt` falls back to native HTTP/1.1 only when ALPN does not select `h2`
- Upgrade/WebSocket handshake requests stay inside `tukuyomi_proxy`; WebSocket frame payloads after `101 Switching Protocols` are tunnel data
- benchmark your real workload before production rollout
- `waf.engine.mode` currently accepts only the available `coraza` engine; `mod_security` is recognized as an unavailable future adapter and is rejected fail-closed until an adapter is compiled in

## Split Public/Admin Listeners

When you want the public proxy on `:80` / `:443` but keep the embedded admin
UI/API on a separate high port, set `admin.listen_addr`.

Sample:

- [config.split-listener.example.json](config.split-listener.example.json)

Typical shape:

```json
{
  "server": {
    "listen_addr": ":443",
    "tls": {
      "enabled": true,
      "redirect_http": true,
      "http_redirect_addr": ":80"
    }
  },
  "admin": {
    "listen_addr": ":9091",
    "external_mode": "deny_external"
  }
}
```

Operator contract:

- `server.listen_addr` remains the public listener
- `admin.listen_addr` moves admin UI/API/auth off the public listener
- `admin.external_mode` and `admin.trusted_cidrs` still apply on the admin
  listener
- built-in TLS / HTTP redirect / HTTP/3 stay public-listener-only in this
  slice
- `admin.listen_addr` must not collide with `server.listen_addr` or
  `server.tls.http_redirect_addr`

## Optional PHP-FPM Runtime Bundles

If you also want PHP-FPM `/options` and `/runtime-apps` on a binary deployment, build and stage a runtime bundle.

For the standard `/opt/tukuyomi` layout:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85
```

To stage into a different deployment root:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85 DEST=/srv/tukuyomi
```

When `make install PREFIX="$HOME/tukuyomi"` installed into the login user's
home directory, copy to the same deployment root. This normally does not require
`sudo`.

```bash
make php-fpm-build RUNTIME=php85
make php-fpm-copy RUNTIME=php85 DEST="$HOME/tukuyomi"
```

Notes:

- `php-fpm-copy` syncs `data/php-fpm/binaries/<runtime_id>/` into the binary deployment tree; import inventory/module metadata with `make db-import` before removing PHP-FPM JSON manifests
- after staging, refresh Options Runtime Inventory or restart `tukuyomi` when needed
- remove an unneeded staged runtime bundle with `sudo make php-fpm-prune RUNTIME=php85`; it checks DB Runtime App references and the runtime pid before deleting `binaries/<runtime_id>` and `runtime/<runtime_id>`
- `data/php-fpm/runtime/` is not copied; `tukuyomi` generates it later from Runtime App definitions
- Docker is needed only for `php-fpm-build`; runtime execution does not depend on Docker after the bundle is staged
- PHP, base image libraries, and PECL extension security updates remain operator-managed: rebuild and restage the bundle when you need those updates

## Environment File

Use an env file such as `/etc/tukuyomi/tukuyomi.env`.

Template:

- [tukuyomi.env.example](tukuyomi.env.example)

Primary values:

- `WAF_CONFIG_FILE`
- `WAF_PROXY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_BLOB_DIR`

Optional security-audit key overrides:

- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY`
- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID`
- `WAF_SECURITY_AUDIT_HMAC_KEY`
- `WAF_SECURITY_AUDIT_HMAC_KEY_ID`

S3 credentials required only when `persistent_storage.backend=s3`:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_REGION` / `AWS_DEFAULT_REGION`

## Overload Tuning

Keep overload controls in DB `app_config` under `server`:

- `max_concurrent_requests` is the process-wide guard.
- `max_concurrent_proxy_requests` is the data-plane guard.
- Queue settings are active only when the matching `max_concurrent_*` value is greater than `0`.
- `max_queued_proxy_requests` plus `queued_proxy_request_timeout_ms` absorb short proxy bursts without leaving requests in an unbounded wait.
- `max_queued_requests` defaults to `0`; keep it `0` or very small unless you explicitly want admin/API requests to wait under pressure.
- Set `max_concurrent_requests` higher than `max_concurrent_proxy_requests` if you want to preserve admin/API headroom during proxy saturation.
- Watch `/tukuyomi-api/status` for `server_overload_global` / `server_overload_proxy`, and `/tukuyomi-api/metrics` for `tukuyomi_overload_*`.

## Secret Handling

- keep `admin.session_secret` in managed app config, not in the browser
- use `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` / `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` only for first-owner bootstrap when the admin user table is empty
- browser operators sign in with username/password and receive same-origin DB-backed session cookies
- CLI / automation should use per-user personal access tokens, not shared admin API keys
- default `tukuyomi` posture is `admin.external_mode=api_only_external`; move to `deny_external` if remote admin API access is unnecessary
- if you intentionally set `admin.external_mode=full_external` on a non-loopback listener, add front-side allowlists/auth because startup will only warn, not block
- widening `admin.trusted_cidrs` to public or catch-all networks also re-exposes the embedded admin UI/API to those sources and only triggers a warning
- if `security_audit.key_source=env`, keep the encryption and HMAC keys in the env file instead of `config.json`

## systemd

Sample unit:

- [tukuyomi.service.example](tukuyomi.service.example)
- [tukuyomi-center.service.example](tukuyomi-center.service.example)
- [tukuyomi.socket.example](tukuyomi.socket.example)
- [tukuyomi-admin.socket.example](tukuyomi-admin.socket.example)
- [tukuyomi-redirect.socket.example](tukuyomi-redirect.socket.example)
- [tukuyomi-http3.socket.example](tukuyomi-http3.socket.example)
- [tukuyomi-scheduled-tasks.service.example](tukuyomi-scheduled-tasks.service.example)
- [tukuyomi-scheduled-tasks.timer.example](tukuyomi-scheduled-tasks.timer.example)
- [tukuyomi.env.example](tukuyomi.env.example)
- [tukuyomi-center.env.example](tukuyomi-center.env.example)

The gateway sample unit keeps `User=tukuyomi` and adds
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, so `:80` / `:443` binds work without
running the service as root full-time. The Center unit starts `tukuyomi center`
and does not require low-port bind capabilities by default.
For graceful binary replacement, prefer systemd socket activation. The socket
units hold the public/admin/redirect/HTTP3 listeners while the service process
shuts down and restarts.

Install:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi.env.example /etc/tukuyomi/tukuyomi.env
sudo install -m 644 docs/build/tukuyomi.service.example /etc/systemd/system/tukuyomi.service
sudo install -m 644 docs/build/tukuyomi-scheduled-tasks.service.example /etc/systemd/system/tukuyomi-scheduled-tasks.service
sudo install -m 644 docs/build/tukuyomi-scheduled-tasks.timer.example /etc/systemd/system/tukuyomi-scheduled-tasks.timer
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi
sudo systemctl enable --now tukuyomi-scheduled-tasks.timer
sudo systemctl status tukuyomi
```

Center install:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi-center.env.example /etc/tukuyomi/tukuyomi-center.env
sudo install -m 644 docs/build/tukuyomi-center.service.example /etc/systemd/system/tukuyomi-center.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi-center
sudo systemctl status tukuyomi-center
```

Socket activation install:

```bash
sudo install -m 644 docs/build/tukuyomi.socket.example /etc/systemd/system/tukuyomi.socket
sudo install -m 644 docs/build/tukuyomi-admin.socket.example /etc/systemd/system/tukuyomi-admin.socket
sudo install -m 644 docs/build/tukuyomi-redirect.socket.example /etc/systemd/system/tukuyomi-redirect.socket
sudo install -m 644 docs/build/tukuyomi-http3.socket.example /etc/systemd/system/tukuyomi-http3.socket
sudo mkdir -p /etc/systemd/system/tukuyomi.service.d
sudo install -m 644 docs/build/tukuyomi.service.socket-activation.conf.example /etc/systemd/system/tukuyomi.service.d/socket-activation.conf
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi.socket
sudo systemctl enable --now tukuyomi.service
```

Only enable socket units that match effective DB `app_config`. `ListenStream` /
`ListenDatagram` must match `server.listen_addr`, `admin.listen_addr`,
`server.tls.http_redirect_addr`, and the HTTP/3 UDP port. The process validates
the inherited socket address and fails closed on mismatch.

If you enable admin, redirect, or HTTP/3 socket units, uncomment the matching
`Sockets=` lines in the service drop-in. This keeps manual
`systemctl restart tukuyomi.service` replacements on the same inherited
descriptors instead of falling back to direct bind.

Graceful replacement:

```bash
sudo install -m 755 build/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo systemctl restart tukuyomi.service
```

With socket activation enabled, systemd keeps the listening sockets open while
the old process drains accepted HTTP requests and the new process starts on the
same descriptors. `SIGTERM`, `SIGINT`, and `SIGHUP` all trigger graceful
shutdown. Long-lived Upgrade/WebSocket connections are tracked and waited on up
to `server.graceful_shutdown_timeout_sec` before force close. HTTP/3 UDP socket
handoff is supported, but existing QUIC connections do not survive process
replacement.

## Notes

- the sample unit uses `WorkingDirectory=/opt/tukuyomi`; relative `conf/`, `audit/`, and `data/tmp/` paths stay inside the deployment root
- `server.graceful_shutdown_timeout_sec` defaults to `30`; set it higher if you intentionally keep long-lived WebSocket sessions during deploys
- the scheduled-task service uses the same working directory and env file, so `run-scheduled-tasks` sees the same `conf/` and `data/scheduled-tasks/` tree as the main service
- the sample unit includes `CAP_NET_BIND_SERVICE`, so direct binds such as `server.listen_addr=:443` and `server.tls.http_redirect_addr=:80` work under `User=tukuyomi`
- split-listener deployments normally keep `admin.listen_addr` on a high port
  such as `:9091`, so no extra capability is needed for the admin listener
- `admin.listen_addr` only splits ports. Source controls such as
  `admin.external_mode` and `admin.trusted_cidrs` still decide who can reach
  the admin plane
- the first slice of split listeners does not provide built-in TLS on
  `admin.listen_addr`; use a trusted private network or front-proxy TLS
  termination there
- that capability only covers low-port binds. Switching `php-fpm` to a different UID/GID such as `www-data` still requires starting `tukuyomi` as root
- when `tukuyomi` is a direct public entrypoint, open both TCP and UDP on the listener port if you enable built-in HTTP/3
- for extracted release bundles, `testenv/release-binary/` remains the quickest smoke path
- to validate this staged-runtime flow locally before rollout, run `make binary-deployment-smoke`
