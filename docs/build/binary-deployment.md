# Binary Deployment

This guide is for Linux hosts that run `tukuyomi` as a single binary under `systemd`.

Typical environments:

- on-prem Linux server
- VPS
- VM
- EC2

## Build

Build on a workstation or build host:

Prerequisites:

- `make`
- Go toolchain 1.26.11 or newer
- Node.js 24 LTS + npm 11+ for Gateway / Center UI builds, or Docker

When local Node.js 24 LTS + npm 11+ is unavailable, the default
`tools/npm-node24.sh` wrapper uses Docker image `node:24-alpine`. In that case,
the installing user must be able to access the Docker API. Installing Docker is
not enough by itself; on a typical Linux host the user must be added to the
`docker` group and then log in again.

On a minimal Ubuntu VPS, prepare the host for example with:

```bash
sudo apt update
sudo apt install -y make curl ca-certificates git docker.io
sudo usermod -aG docker "$USER"
```

After logging in again, confirm that `docker ps` works. If the distribution Go
package is too old, install Go 1.26.11 or newer from the official Go tarball.

```bash
make setup
make build
```

This produces `bin/tukuyomi`.

Gateway and Center UI builds require Node.js 24 LTS and npm 11+. The Makefile
uses `tools/npm-node24.sh` by default, so build targets use a local Node 24/npm
11 runtime when available and otherwise fall back to Docker image
`node:24-alpine`. Set `NPM=/path/to/npm` only when you intentionally want to
override that wrapper.

If you only need the Go binary and already refreshed the embedded Gateway and Center UI, use:

```bash
make go-build
```

For reproducible release artifacts, use:

```bash
make release-linux-all
```

`VERSION` is derived from the current Git tag or release branch. Set
`VERSION=vX.Y.Z` only when you intentionally need an override.

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

Install Center behind a same-host Gateway front:

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center-protected
```

Common overrides:

```bash
make install TARGET=linux-systemd \
  INSTALL_ROLE=gateway \
  PREFIX=/opt/tukuyomi \
  INSTALL_ENABLE_SCHEDULED_TASKS=0 \
  INSTALL_DB_SEED=auto
```

Set the first-login owner explicitly when you do not want the installer to
generate one:

```bash
TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME=admin \
TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD='replace-with-a-long-random-password' \
make install TARGET=linux-systemd INSTALL_ROLE=center-protected
```

Behavior:

- `PREFIX` defaults to `/opt/tukuyomi`
- `INSTALL_ROLE=gateway` installs `tukuyomi.service`, `tukuyomi.env`,
  `conf/config.json`, WAF/CRS asset import, first-run gateway DB seed, and the
  optional scheduled-task timer
- Gateway installs write `runtime.process_model=supervised`. The supervisor
  owns TCP listeners and activates the initial worker after readiness. Existing
  Gateway configs are migrated with a targeted `runtime.process_model` update
  during install. The first migration from a legacy single-process Gateway still
  needs a normal service restart because listener ownership changes. HTTP/3 is
  rejected until UDP handoff is implemented.
- `INSTALL_ROLE=center` installs `tukuyomi-center.service`,
  `tukuyomi-center.env`, and `conf/config.center.json`; it runs DB migration
  only and skips WAF/CRS import, gateway seed, and scheduled tasks
- `INSTALL_ROLE=center-protected` installs both `tukuyomi.service` and
  `tukuyomi-center.service`; Center listens on loopback, while the Gateway seed
  routes `/center-ui`, the operator-facing `/center-manage-api`, and the
  Gateway/device-facing `/center-api` path to `http://127.0.0.1:9092`. Remote
  Gateways poll below `/center-api/v1`. It also
  enables Gateway IoT / Edge device authentication and locally bootstraps the
  matching Center approval. For first-host setup, this role also opens the
  embedded Gateway admin UI with `admin.external_mode=full_external` so the
  operator can finish TLS / Let's Encrypt, listener port, and Gateway front
  settings. After setup, close it from Gateway Settings by changing
  `admin.external_mode` back to `api_only_external` or `deny_external`. To keep
  the stricter first-boot posture, install with
  `INSTALL_CENTER_PROTECTED_GATEWAY_ADMIN_EXTERNAL_MODE=api_only_external`.
  Because this role includes a local Gateway, it also installs the Gateway
  scheduled-task timer by default.
- `INSTALL_CENTER_API_BASE_PATH` controls the Center UI management API path.
  It defaults to `/center-manage-api`. `INSTALL_CENTER_GATEWAY_API_BASE_PATH`
  controls the public Gateway/device API path and defaults to `/center-api`.
- In `center-protected`, restrict operator-facing Center routes such as
  `/center-ui` and the `/center-manage-api` management route with Proxy Rules
  `access.allow_cidrs`. Keep the Gateway/device API route `/center-api/v1`
  open when remote Gateways must poll through that path.
- Center has three source IP allowlists for direct exposure:
  `TUKUYOMI_CENTER_CLIENT_ALLOW_CIDRS` for Center UI clients,
  `TUKUYOMI_CENTER_MANAGE_API_ALLOW_CIDRS` for the management API, and
  `TUKUYOMI_CENTER_API_ALLOW_CIDRS` for the Gateway/device API. Empty client
  and Gateway/device lists allow any source. The management API defaults to
  loopback plus private/local CIDRs.
- `TUKUYOMI_CENTER_REQUIRE_SIGNED_DEVICE_UPLOAD_HEADERS=true` makes Center
  reject device uploads that are not signed in request headers. Gateways older
  than 1.6.7 do not send those headers, so turn it on after every Gateway runs
  1.6.7 or later. The default is `false`.
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
- after DB migration, host install runs the admin bootstrap for each installed
  role DB. If no bootstrap password is provided, or if the development
  placeholder password is still present, the installer generates a random
  first-login password and prints it once at the end of the install log.
  Existing admin users are never reset.
- `INSTALL_DB_SEED=auto` runs `db-import` only when the SQLite DB is not present yet
- the first DB seed creates a default upstream named `primary`; update it to
  the real backend endpoint before exposing the proxy to traffic
- rerunning against an existing DB migrates schema and re-imports WAF/CRS assets,
  which replaces every WAF rule asset, including rules edited in the UI. On an
  installed environment, set `INSTALL_REFRESH_WAF_ASSETS=0` to keep the current
  assets (a first install has none and cannot start without the import), or
  `CRS_VERSION=<tag>` to choose the CRS version. See
  [Updating the OWASP CRS](#updating-the-owasp-crs)
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
- the public release bundle ships `conf/config.json` and the bundled empty-DB runtime seed at `seeds/conf/config-bundle.json`
- when configured files such as `conf/proxy.json` or policy JSON are absent, `make db-import` reads `seeds/conf/config-bundle.json` before falling back to built-in compatibility defaults
- `make crs-install` stages the default base WAF rule seed from `seeds/waf/rules/tukuyomi.conf` and imports it into DB
- CRS files are temporary import material for DB `waf_rule_assets`; `make crs-install` downloads the default CRS version, stages it under `data/tmp`, and removes the staging directory after the import. To use another version, see [Updating the OWASP CRS](#updating-the-owasp-crs)
- the config bundle domains for sites, scheduled tasks, upstream runtime,
  policies, cache rules, WAF bypass, and PHP-FPM/PSGI manifests are DB
  seed/export artifacts after DB bootstrap
- render or mount `config.json` from your secret manager or config-management layer in production for `storage.db_driver`, `storage.db_path`, and `storage.db_dsn`
- run `make db-migrate`, then `make crs-install` to install/import WAF rule assets, then `make db-import` for the remaining seed material before first start. `db-import` does not re-import WAF rule assets
- the embedded `Settings` page edits DB `app_config`; restart the service after listener/runtime/storage policy/observability changes
- the public release bundle ships a companion `bin/geoipupdate` binary for `Options -> GeoIP Update -> Update now`
- `GEOIPUPDATE_BIN` remains available if you want to override the bundled updater path
- the official managed-country refresh wrapper is `./scripts/update_country_db.sh`
- managed GeoIP country DB, `GeoIP.conf`, and update status are DB-backed; do not ship a `data/geoip` fallback directory
- managed bypass override rules (`extra_rule` bodies) are DB `waf_rule_assets` of kind `bypass_extra_rule`; do not ship a `conf/rules` fallback directory. Re-importing WAF rule assets replaces them
- WAF/access events are written to DB `waf_events`; `paths.log_file` is only a legacy import source when you intentionally ingest an old `waf-events.ndjson`
- `extra_rule` values remain logical compatibility references to DB-managed override rules

## Persistent Byte Storage

Runtime artifacts that must remain durable as files/objects, rather than DB
rows, are managed by `persistent_storage`. Current users include TLS binding
ACME material and WAF log archives.

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

Configure ACME on the `TLS` page by adding a TLS binding with `mode=acme`.
`production` / `staging` selects the Let's Encrypt production or staging CA,
and account email is optional. ACME HTTP-01 requires the DNS name to resolve to
this host and external TCP/80 and TCP/443 reachability.

For direct VPS or bare-metal rollouts from a setup port to `:80` / `:443`, use
this sequence:

1. In `Settings` -> `Listener & Network`, configure `Public listener rows` with
   an HTTP listener on `:80` and an HTTPS listener on `:443`. During setup,
   keeping the `:80` row at `HTTP behavior=serve` leaves a plain HTTP access
   path available while TLS is being tested.
2. Enable `Enable built-in TLS on the public listener`, then click
   `Save config only`.
3. Restart the Gateway with `systemctl restart tukuyomi`.
4. On the `TLS` page, add a TLS binding with `TLS mode=acme` and
   `Hosts=<DNS name>`. Start with `staging` to verify the HTTP-01 challenge and
   HTTPS reachability.
5. After `https://<DNS name>/tukuyomi-ui/` works, change `ACME environment` to
   `production` and apply the TLS binding again.

Accessing `https://<IP address>/...` still warns because the certificate is for
the DNS name. Always verify with the DNS name listed in the TLS binding
`Hosts` field. A browser that previously saw the staging certificate may keep a
warning state; after switching to `production`, confirm again in a new tab or
private window.

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
- request bodies are inspected by default (`waf.request_body.mode=enforce`, up to 16 KiB per request); include body-heavy traffic in the benchmark

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
- Docker is needed only for `php-fpm-build`; runtime execution does not depend on Docker after the bundle is staged. Each build pulls the current official PHP base image (`docker build --pull`), so the build host needs access to the container registry (Docker Hub by default)
- PHP, base image libraries, and PECL extension security updates remain operator-managed: rebuild and restage the bundle when you need those updates, then confirm the PHP version in `detected_version` of `data/php-fpm/binaries/<runtime_id>/runtime.json`

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
- `POST /auth/login` returning HTTP 401 means the submitted credentials did not
  match an existing admin user. Plain HTTP is not the cause of that status; use
  HTTPS or a TLS-terminating front proxy before real production exposure.
- browser operators sign in with username/password and receive same-origin DB-backed session cookies
- CLI / automation should use per-user personal access tokens, not shared admin API keys
- default `tukuyomi` posture is `admin.external_mode=api_only_external`; move to `deny_external` if remote admin API access is unnecessary. `INSTALL_ROLE=center-protected` is the exception: it starts with `full_external` so operators can complete first-host TLS and listener setup, then should be tightened again from Gateway Settings.
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
If you use explicit `server.public_listeners`, every enabled low-port listener
has the same low-port requirement.
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

After first boot, Center `Settings` can persist standalone listen address,
API/UI base path, and manual TLS certificate/key settings. Listener and TLS
changes apply after restarting `tukuyomi-center`.

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

## Updating the OWASP CRS

OWASP CRS is not part of the binary. The staging script downloads it, and the
running service reads it from DB `waf_rule_assets`. To move an existing
installation to another CRS version, or to re-import the same version, import
the WAF rule assets into that installation's DB again.

- the default version is `v4.23.0`
- `make install` takes the version from `CRS_VERSION=<tag>`;
  `scripts/stage_waf_rule_assets.sh <stage-root> [crs-version]` and
  `scripts/install_crs.sh [crs-version]` take it as an argument
- `make crs-install` and `make crs-ensure` always stage the default version
- staging downloads the CRS archive from GitHub, so the host that runs it needs
  `curl`, `tar`, and outbound HTTPS

### What an import replaces and keeps

An import (`tukuyomi db-import-waf-rule-assets`, which `make crs-install`,
`make crs-ensure`, `make install`, and the image build in
[Dockerfile.example](Dockerfile.example) all run) does not merge. It writes a
new active set of **all** WAF rule assets built only from the staged files: the
base rule seed `tukuyomi.conf`, the CRS rules and data, and `crs-setup.conf`.
This also happens when the CRS version does not change.

Replaced by the staged files:

- base rules edited on the `Rules` screen, including exclusions written by FP
  Tuner; `tukuyomi.conf` returns to the seed's content, and to enabled even if
  you had disabled it on the `Rules` screen
- base rule files added on the `Rules` screen, with their enabled state and order
- bypass snippets (`Rules` > Advanced > `Bypass snippets`), which are stored as
  rule assets of kind `bypass_extra_rule`
- `crs-setup.conf` additions. When
  `WAF_RULE_SEED_CRS_SETUP_OVERRIDE=<file>` is set at staging time, the content
  of that file is appended to the end of `crs-setup.conf`; pass the same file
  again

Kept:

- the CRS rule-set selection: the list of disabled CRS rule file names (DB
  `crs_disabled_rules`) stays after an import. Files added by the new version
  start enabled, and a name that was removed or renamed no longer has any
  effect. Check the selection on the `Rules` screen after updating
- bypass entries, but not their snippets: right after the import, a bypass path
  whose snippet is gone is inspected with the default rules, and the log shows
  `[BYPASS][RULE][WARN] ... (fallback=default-rules)`
- proxy, sites, TLS, and admin settings, admin users, and WAF events

The imported base rules and CRS are in use once the service restarts.

Older versions of the rule assets stay in the DB, but the admin UI and API have
no way to list or restore them, so an import cannot be undone from there. Back
up the DB first.

### With `make install`

`make install` runs this import every time, because `INSTALL_REFRESH_WAF_ASSETS`
defaults to `1`. Re-running the installer to upgrade the binary therefore also
replaces local rule edits.

```bash
# keep the current WAF rule assets (only on an installation that already has them)
make install TARGET=linux-systemd INSTALL_REFRESH_WAF_ASSETS=0

# choose the CRS version explicitly
make install TARGET=linux-systemd CRS_VERSION=<crs-version>
```

- use `INSTALL_REFRESH_WAF_ASSETS=0` only on an installed environment; on a first
  install there are no rule assets yet and the service cannot start
- by default the installer restarts a running service at the end, which loads the
  imported rules
- `INSTALL_ROLE=center` does not import WAF rule assets
- a `WAF_RULE_SEED_CRS_SETUP_OVERRIDE` file does not reach the staging script when
  the installer escalates with `sudo`, because `sudo` drops the variable by
  default; run the installer as root, or use the procedure below

### Without local rule edits

The installed tree (`/opt/tukuyomi` by default) has no `install_crs.sh`, no
`stage_waf_rule_assets.sh`, and no `seeds/waf/`. Use the `scripts/` and
`seeds/waf/rules/` of the extracted release tarball, and run the commands below
from that directory.

First back up the DB. For SQLite, take an online backup of the file set in
`storage.db_path` (`db/tukuyomi.db` under the deployment root by default). This
needs the `sqlite3` command-line tool, and `umask 077` keeps the copy private:

```bash
sudo -u tukuyomi sh -c 'umask 077; sqlite3 /opt/tukuyomi/db/tukuyomi.db ".backup /opt/tukuyomi/db/tukuyomi.db.bak.$(date +%Y%m%d%H%M%S)"'
```

Or stop the service and copy `tukuyomi.db` together with `tukuyomi.db-wal` and
`tukuyomi.db-shm` when they exist. For MySQL / PostgreSQL use your normal dump.

Then stage, import, and restart. The import runs as the runtime user from the
deployment root, like the installer does. The commands are chained with `&&` so
that a failed step stops the rest, and the subshell keeps `cd` from leaking:

```bash
ROOT=/opt/tukuyomi
STAGE="$ROOT/data/tmp/waf-rule-assets"

sudo rm -rf "$STAGE" &&
sudo install -d -m 755 "$STAGE" &&
sudo ./scripts/stage_waf_rule_assets.sh "$STAGE" <crs-version> &&
sudo chown -R tukuyomi:tukuyomi "$STAGE" &&
(cd "$ROOT" && sudo -H -u tukuyomi env \
  WAF_CONFIG_FILE=conf/config.json \
  WAF_RULE_ASSET_FS_ROOT=data/tmp/waf-rule-assets \
  ./bin/tukuyomi db-import-waf-rule-assets) &&
sudo rm -rf "$STAGE" &&
sudo systemctl restart tukuyomi
```

If a step fails, the staging directory stays; the first line removes it on the
next run.

To carry over a `WAF_RULE_SEED_CRS_SETUP_OVERRIDE` file, run the staging line as
`sudo env WAF_RULE_SEED_CRS_SETUP_OVERRIDE=<file> ./scripts/stage_waf_rule_assets.sh "$STAGE" <crs-version>`;
a variable set in front of `sudo` does not reach the script.

When the deployment root is under the login user's home directory, the runtime
user is that user: drop `sudo` and `chown` from the staging and import
commands. Restarting the service still needs `sudo`.

### With local rule edits

Rules changed in the UI (edits to `tukuyomi.conf`, FP Tuner exclusions, added base
rule files, and bypass snippets) exist only in the DB, so the import replaces
them. Before the import, save the full response of
`GET <admin.api_base_path>/rules` (`/tukuyomi-api/rules` by default). The `files`
array has the `path`, `kind`, `raw`, and `enabled` of each file, in order. Open
the URL in a browser that is signed in to the admin UI and save the JSON; the
admin API also accepts a personal access token with `admin:read` (create one
under *Personal access tokens* on the admin UI `User` page), but do not
put the token on a command line that others can see.

After the import, put the rules back on the `Rules` screen, or with
`PUT <admin.api_base_path>/rules` (`{path, kind, raw}`, plus `enabled` for base
rules; `PUT .../rules:order` restores the order of base rule files). Put the
bypass snippets back first: while the snippet that a bypass entry refers to is
missing, a bypass configuration that contains that entry cannot be saved from
the UI or API. Then restart the service.

The saved base rule overwrites the new release's seed `tukuyomi.conf`. Compare
the saved file with that seed first, and merge a change in the seed by hand.
`PUT .../rules` validates each file against the imported CRS, so a rule that
does not load under the new version is rejected.

### Containers

- If the DB is the SQLite file baked into the image at build time, as in
  [Dockerfile.example](Dockerfile.example), rebuild the image and replace the
  container. The image build stages the default CRS version; to pin another one,
  add the version as the second argument of the `stage_waf_rule_assets.sh` line.
  Replacing the container also discards everything else in that DB: admin users,
  settings, and events, not only the rules.
- If the DB lives outside the image (a volume, MySQL, or PostgreSQL), import once
  with the new image, then recreate the container. Stage on the host with the
  scripts of the release tarball, mount the stage directory read-only into a
  one-off container that has the same `conf/config.json` and DB access as the
  service, and run `db-import-waf-rule-assets` with `WAF_RULE_ASSET_FS_ROOT`
  pointing at it:

  ```bash
  STAGE="$(mktemp -d)" &&
  ./scripts/stage_waf_rule_assets.sh "$STAGE" <crs-version> &&
  chmod -R a+rX "$STAGE" &&
  docker run --rm \
    -v "$STAGE:/waf-rule-assets:ro" \
    -e WAF_RULE_ASSET_FS_ROOT=/waf-rule-assets \
    -e WAF_CONFIG_FILE=/app/conf/config.json \
    <the same -v / -e / network options as the service> \
    <image> /app/tukuyomi db-import-waf-rule-assets &&
  rm -rf "$STAGE"
  ```

  The binary is `/app/tukuyomi` in the image built from `Dockerfile.example` and
  `/app/server` in the repository `server/Dockerfile` image.
- Every replica that shares the DB loads the imported rules when it restarts.

### Development tree

```bash
make crs-install
```

then restart the process. For another version, stage it by hand and import it
from the `data` work directory:

```bash
./scripts/stage_waf_rule_assets.sh data/tmp/waf-rule-assets <crs-version> &&
WAF_RULE_ASSET_FS_ROOT=tmp/waf-rule-assets make db-import-waf-rule-assets &&
rm -rf data/tmp/waf-rule-assets
```

`make db-import-waf-rule-assets` only imports what is already staged under
`WAF_RULE_ASSET_FS_ROOT`; it does not download CRS and it fails when nothing is
staged.

### Gateways with Center-assigned WAF rules

Update the rule bundle in Center and assign it again, instead of importing on
the Gateway. If the Gateway's rules change after an assignment, that assignment
is not applied: it stays `blocked` with `local WAF rules changed after
assignment`. After the Gateway has sent its new rules to Center, assign again.

### Verify the active version

Open the `Rules` screen and look for the `OWASP CRS ver.` line at the top of
`crs-setup.conf`. This shows what the DB holds, so check it after the restart.
The `[WAF] Reloaded base rules (N files)` log line only counts files; it does
not show the CRS version.

### Roll back

The admin UI and API cannot restore an older version of the rule assets. Restore
the DB backup taken before the import (stop the service, restore, start it;
settings and WAF events written after the backup are lost too). When restoring
a `.backup` copy, delete `tukuyomi.db-wal` and `tukuyomi.db-shm` first, or the
old WAL can be applied on top of it; a copy taken with the service stopped is
restored as all three files together. Alternatively, or import the
previous CRS version again with the procedure above, which replaces local rule
edits in the same way.

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
