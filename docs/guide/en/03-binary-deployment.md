# Chapter 3. Binary deployment (systemd)

This chapter covers running tukuyomi as a **single binary managed by
systemd** on a Linux host. The expected environment is on-prem Linux,
VPS, or any cloud VM (EC2 / GCE / Azure VM, and so on). Container
deployment is the subject of Chapter 4.

Unlike the preview from Chapter 2, what we cover here is **a deployment
that holds up in production**. We walk through service-user creation,
the `/opt/tukuyomi` runtime layout, systemd units, socket activation,
PHP-FPM bundles, secret delivery via the env file, and overload
backpressure tuning.

## 3.1 The big picture

systemd deployment broadly proceeds in this order:

1. Build the tukuyomi binary from source.
2. Run `make install TARGET=linux-systemd` to do everything from the
   build through the systemd-unit install in one shot.
3. Add split listener, PHP-FPM bundles, or socket activation as needed.
4. Override the env file and DB `app_config` with production values.
5. Start and enable the service.

`make install` carries most of steps 1 to 5 for you. We start by
understanding what `make install` does, then look one at a time at
"what is decided by `make install`, and what you tune by hand
afterwards".

## 3.2 Build

First, build the tukuyomi binary on the build host or your workstation.

```bash
make setup
make build
```

The result is `bin/tukuyomi`. The Gateway / Center admin UIs are
embedded into the binary at build time.

If the UI is already up to date and you only want to rebuild the Go
binary:

```bash
make go-build
```

To produce a reproducible release artifact, declare the version
explicitly:

```bash
make release-linux-all VERSION=v0.8.0
```

## 3.3 One-shot install: `make install TARGET=linux-systemd`

When installing directly on a Linux host, the following one-liner runs
**build → runtime tree → DB migrate → WAF/CRS asset import → first-run
DB seed → systemd unit install** in a single step:

```bash
make install TARGET=linux-systemd
```

Omitting `INSTALL_ROLE` defaults the role to `gateway`. To install the
Center on a control-plane host, set it explicitly:

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

If the Center should be reachable through a same-host Gateway security
front, install the protected Center role:

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

Each behavior is described below.

### 3.3.1 PREFIX and the runtime user

- `PREFIX` defaults to `/opt/tukuyomi`.
- If `PREFIX` is under the home directory of the user running install,
  `INSTALL_CREATE_USER=auto` reuses that user as the runtime user and
  does not run `useradd`.
- A runtime tree under home is owned by the user's login user / primary
  group.
- For a system path such as `/opt/tukuyomi`, the default is to create
  (or reuse) the system user / group `tukuyomi`.
- When deployed to a system path under a service account, the
  deployment root and `bin/`, `scripts/`, `conf/` are root-owned, while
  `db/`, `audit/`, `cache/`, `data/` are writable by the runtime user
  — a clean privilege split.

The build itself runs as a regular user. `sudo` is only required for
the host-install operations that need privileges (creating the system
user, writing to `/opt/tukuyomi`, installing systemd units).

### 3.3.2 Per-role behavior

`INSTALL_ROLE` decides which host shape is installed:

| Target | gateway | center | center-protected |
|---|---|---|---|
| service unit | `tukuyomi.service` | `tukuyomi-center.service` | both |
| env file | `tukuyomi.env` | `tukuyomi-center.env` | both |
| config | `conf/config.json` | `conf/config.center.json` | both |
| WAF/CRS import | yes | no | yes, for the Gateway front |
| First-run gateway DB seed | yes | no | yes, with Center routes |
| Scheduled-task timer | yes | no | no |
| DB migration | yes | yes | both DBs |

The Center role does not carry WAF/CRS import or scheduled tasks
because the Center is a control plane that approves and manages
Gateways; it does not own edge data-plane assets.

The `center-protected` role is the packaged same-host shape for exposing
Center safely. Center keeps its loopback listener, and the Gateway front
starts with path-scoped routes for `/center-ui` and `/center-api` to
`http://127.0.0.1:9092`. During install, the role also enables Gateway
IoT / Edge device authentication and bootstraps the matching Center approval
locally. The Gateway private key stays in the Gateway DB; Center receives only
the public key identity. If an existing DB contains conflicting device trust,
the bootstrap fails instead of replacing it silently.

### 3.3.3 DB seeding

- `INSTALL_DB_SEED=auto` (the default) only runs `db-import` on the
  very first install when no SQLite DB exists yet.
- The first-run DB seed creates a default upstream named `primary`.
  Adjust it to your real backend endpoint before pointing real proxy
  traffic at it.
- When re-run with an existing DB, only `db migrate` and a WAF/CRS
  asset refresh happen.
- For an empty MySQL or PostgreSQL DB, pass `INSTALL_DB_SEED=always`
  explicitly.

### 3.3.4 Enabling scheduled tasks

The scheduled-task timer is enabled by default. If this host is not
supposed to run scheduled tasks (for example, in a replicated frontend
where a separate singleton-scheduler host runs them), pass:

```bash
make install TARGET=linux-systemd INSTALL_ENABLE_SCHEDULED_TASKS=0
```

Chapter 12 covers scheduled-task deployment patterns.

### 3.3.5 Permissions on secret files

- Role config files are placed root-owned with mode `0640`. Read access
  is granted only to the service group.
- Env files are kept root-owned with mode `0640` on the assumption
  that they contain secrets.
- When an env or config file already exists, `make install` **does not
  overwrite it by default**.

### 3.3.6 Package staging / smoke

For CI package staging or smoke tests, you can build a staged tree
without engaging systemd:

```bash
DESTDIR=<tmp> INSTALL_ENABLE_SYSTEMD=0 make install TARGET=linux-systemd
```

### 3.3.7 Running under your login user

If you do not want to create a system user and prefer to run tukuyomi
under your login user, e.g. under `$HOME/tukuyomi`:

```bash
make install TARGET=linux-systemd \
  PREFIX="$HOME/tukuyomi" \
  INSTALL_USER="$(id -un)" \
  INSTALL_GROUP="$(id -gn)" \
  INSTALL_CREATE_USER=0
```

For ECS / Kubernetes / Azure Container Apps, you do not use `make
install`; use `make deploy-render` instead. See the next chapter,
"Container deployment".

## 3.4 Runtime layout

`make install` creates a runtime tree under `PREFIX` that looks like:

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/db/
/opt/tukuyomi/audit/
/opt/tukuyomi/cache/
/opt/tukuyomi/data/persistent/
/opt/tukuyomi/data/tmp/
```

Bundled bootstrap / example files:

- `conf/config.json`
- `conf/crs-disabled.conf`
- `scripts/update_country_db.sh`

Optional seed / import files placed by the operator before the first
DB import:

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
- WAF/CRS import material that `make crs-install` stages under
  `data/tmp/...`

Keep in mind the rule from Chapter 1: **the DB is the runtime
authority, JSON is seed / import / export material**. These JSON files
are used for **initial seeding and import / export I/O**; once the
corresponding DB rows are populated, the runtime no longer requires
the file to exist. **After the import completes, the only files the
runtime needs at startup are `conf/config.json` and the DB rows.**

### 3.4.1 PHP-FPM-specific initial files

For PHP-FPM Runtime Apps, place the following before the first DB
import:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

After import, when bundled PHP-FPM is in use the executable bundle is
still required, but `inventory.json` / `vhosts.json` / `runtime.json`
/ `modules.json` are no longer the runtime authority (the DB is).

### 3.4.2 Scheduled-task directory

Scheduled-task runtime state lives under:

- `data/scheduled-tasks/`

If you also use the managed GeoIP country-DB refresh, add:

- `scripts/update_country_db.sh`

### 3.4.3 A worked manual-install example

If you want to lay the tree down by hand instead of `make install`, it
looks like this:

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

### 3.4.4 Things to watch for when laying the tree

- Do not carry `data/conf/*.bak` into production.
- `config.json` is the **DB connection bootstrap**. The release sample
  keeps only the `storage` block.
- `conf/proxy.json` is optional seed / import / export material for DB
  `proxy_rules`.
- `conf/sites.json` is optional seed / import / export material for DB
  `sites`.
- The public release bundle ships `conf/config.json` and runtime seed
  for an empty DB at `seeds/conf/config-bundle.json`.
- When `conf/proxy.json` or a policy JSON is missing, `make db-import`
  reads `seeds/conf/config-bundle.json`, and if even that is absent, falls back to a
  built-in compatibility default.
- The default base WAF rule seed is staged from
  `seeds/waf/rules/tukuyomi.conf` and imported to the DB by
  `make crs-install`.
- CRS files are temporary import material for DB `waf_rule_assets`;
  `make crs-install` stages them under `data/tmp` and cleans up.
- `sites.json` / `scheduled-tasks.json` / `upstream-runtime.json`,
  policy JSON, cache-rules JSON, WAF bypass JSON, and PHP-FPM JSON
  manifests are all DB seed / export artifacts after the DB
  bootstraps.
- In production, render `config.json` from a secret manager / config
  management system for `storage.db_driver` /
  `storage.db_path` / `storage.db_dsn`.
- Before the first start, run `make db-migrate` then
  `make crs-install` to install / import WAF rule assets, then `make
  db-import` for the remaining seed material. `db-import` does not
  re-import WAF rule assets.
- The embedded `Settings` screen edits DB `app_config`. Restart the
  service after listener / runtime / storage policy / observability
  changes.
- The public release bundle includes a companion `bin/geoipupdate` for
  `Options → GeoIP Update → Update now`. Override the bundled updater
  path with `GEOIPUPDATE_BIN` if needed.
- The official wrapper for managed country refresh is
  `./scripts/update_country_db.sh`.
- The managed GeoIP country DB, `GeoIP.conf`, and update status are
  all DB-backed. There is no `data/geoip` fallback directory.
- Managed bypass override rules live in DB `override_rules`. There is
  no `conf/rules` fallback directory.
- WAF / access events are written directly to DB `waf_events`.
  `paths.log_file` is a legacy import source used only when you
  explicitly want to ingest an old `waf-events.ndjson`.
- The `extra_rule` value remains as a logical compatibility reference
  pointing into the DB-managed override rules.

## 3.5 Persistent byte storage

Runtime artifacts that live as files / objects rather than in the DB
are managed under `persistent_storage`. The current main use is the
**site-managed ACME account key, challenge token, and certificate
cache**.

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

- For single-node on-prem / VPS deployments, include
  `/opt/tukuyomi/data/persistent` in your backups.
- For scale-out or node-replacement scenarios, use **the S3 backend or
  a shared mount** instead of local.
- The S3 backend stores **only non-secret information** in DB
  `app_config` — bucket, region, endpoint, prefix, and the like.
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
  `AWS_SESSION_TOKEN` are delivered via env or platform secret
  injection.
- Azure Blob Storage / Google Cloud Storage are fail-closed until a
  provider adapter ships — there is no implicit fallback to local.

Site-managed ACME selects `tls.mode=acme` per-site on the `Sites`
screen. `production` / `staging` chooses Let's Encrypt's production
or staging CA, and the account email is optional. Because HTTP-01 is
used, set `server.tls.redirect_http=true` and
`server.tls.http_redirect_addr=:80`, or arrange equivalent port-80
forwarding.

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

- `tukuyomi_proxy` is the built-in engine. It keeps the same parser,
  upstream transport, routing, health, retry, TLS, cache, route
  response headers, 1xx informational responses, trailers, streaming
  flush behavior, native Upgrade / WebSocket tunnel, and
  response-sanitize pipeline, while using Tukuyomi's own response
  bridge.
- The legacy `net_http` bridge has been removed. Any value other than
  `tukuyomi_proxy` for the engine is rejected at config validation.
- HTTP/1.1 and explicit upstream HTTP/2 modes use the Tukuyomi native
  upstream transport. HTTPS `force_attempt` falls back to native
  HTTP/1.1 only when ALPN does not select `h2`.
- Upgrade / WebSocket handshakes are handled inside `tukuyomi_proxy`.
  WebSocket frame payloads after `101 Switching Protocols` are
  treated as tunnel data.
- Benchmark with real workloads before rolling out to production
  (Chapter 17).
- `waf.engine.mode` currently accepts only the `coraza` engine.
  `mod_security` is a known mode reserved for a future adapter; it
  fails closed in config validation until that adapter is compiled
  in.

## 3.6 Public/admin listener split

When you want to put the public proxy on `:80` / `:443` while exposing
the embedded admin UI / API on a separate high port, set
`admin.listen_addr`. A typical configuration:

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

A full sample lives at `docs/build/config.split-listener.example.json`.

Operator contract:

- `server.listen_addr` stays the public listener.
- Setting `admin.listen_addr` removes the admin UI / API / auth from
  the public listener.
- `admin.external_mode` and `admin.trusted_cidrs` continue to apply on
  the admin listener.
- Built-in TLS / HTTP redirect / HTTP/3 are public-listener-only in
  this slice.
- `admin.listen_addr` cannot collide with `server.listen_addr` or
  `server.tls.http_redirect_addr`.

## 3.7 Optional PHP-FPM runtime bundle

To use `/options` and `/runtime-apps` from a binary deployment, build
and place the PHP-FPM runtime bundle.

For the default layout under `/opt/tukuyomi`:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85
```

To stage somewhere else:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85 DEST=/srv/tukuyomi
```

If you installed into a login user's home with
`make install PREFIX="$HOME/tukuyomi"`, point copy at the same
location. `sudo` is typically not needed in that case:

```bash
make php-fpm-build RUNTIME=php85
make php-fpm-copy RUNTIME=php85 DEST="$HOME/tukuyomi"
```

PHP-FPM bundle notes:

- `php-fpm-copy` syncs `data/php-fpm/binaries/<runtime_id>/` into the
  binary deployment tree. Run `make db-import` to import inventory and
  module metadata before deleting the PHP-FPM JSON manifests.
- After placement, refresh the runtime inventory under Options or
  restart `tukuyomi` if needed.
- `sudo make php-fpm-prune RUNTIME=php85` removes unused staged
  bundles. Confirm DB Runtime App references and live PIDs first; only
  then `binaries/<runtime_id>` and `runtime/<runtime_id>` are removed.
- `data/php-fpm/runtime/` is not copy material. It is generated from
  Runtime App definitions after `tukuyomi` starts.
- Docker is required only at `php-fpm-build` time. Once the bundle is
  in place, running `tukuyomi` does not need Docker.
- Security updates for PHP / base image library / PECL extensions
  require rebuilding and replacing the bundle.

## 3.8 Environment file

Use an env file like `/etc/tukuyomi/tukuyomi.env`. The template is
`docs/build/tukuyomi.env.example`.

Common values to review:

- `WAF_CONFIG_FILE`
- `WAF_PROXY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_BLOB_DIR`

Optional security-audit key overrides:

- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY`
- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID`
- `WAF_SECURITY_AUDIT_HMAC_KEY`
- `WAF_SECURITY_AUDIT_HMAC_KEY_ID`

S3 credentials, only required when `persistent_storage.backend=s3`:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_REGION` / `AWS_DEFAULT_REGION`

## 3.9 Overload tuning

Overload backpressure is tuned under the `server` block of DB
`app_config`:

- `max_concurrent_requests` is the process-wide guard.
- `max_concurrent_proxy_requests` is the data-plane guard.
- Queueing applies only when the corresponding `max_concurrent_*` is
  greater than `0`.
- `max_queued_proxy_requests` and
  `queued_proxy_request_timeout_ms` let you absorb a proxy burst
  briefly without unbounded waits.
- `max_queued_requests` defaults to `0`. Keep it at `0` or very small
  unless you specifically intend to queue admin / API requests.
- To keep headroom for admin / API while the proxy saturates, set
  `max_concurrent_requests` higher than `max_concurrent_proxy_requests`.
- Watch `server_overload_global` / `server_overload_proxy` from
  `/tukuyomi-api/status`, and `tukuyomi_overload_*` from
  `/tukuyomi-api/metrics`.

## 3.10 Secret handling

Principles for secret handling:

- `admin.session_secret` is server-side only. Never expose it to the
  browser.
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` /
  `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` are only for the **first-run
  owner bootstrap** when the admin user table is empty.
- Browser operators sign in with a username / password and receive a
  same-origin DB-backed session cookie.
- CLI / automation use **per-user personal access tokens**, not a
  shared admin API key.
- The default posture is `admin.external_mode=api_only_external`.
  Tighten to `deny_external` if remote admin API is not needed.
- When you must use `admin.external_mode=full_external` on a
  non-loopback listener, do not rely solely on the startup warning —
  add front-side allowlisting / authentication.
- Widening `admin.trusted_cidrs` to a public / catch-all network also
  re-exposes the embedded admin UI / API to that trusted source. The
  startup warning alone is not a safeguard.
- Place encryption and HMAC keys in the env file only when using
  `security_audit.key_source=env`.

## 3.11 systemd units

Sample unit files for systemd deployment live under `docs/build/`:

- `tukuyomi.service.example`
- `tukuyomi-center.service.example`
- `tukuyomi.socket.example`
- `tukuyomi-admin.socket.example`
- `tukuyomi-redirect.socket.example`
- `tukuyomi-http3.socket.example`
- `tukuyomi-scheduled-tasks.service.example`
- `tukuyomi-scheduled-tasks.timer.example`
- `tukuyomi.env.example`
- `tukuyomi-center.env.example`

The Gateway sample unit keeps `User=tukuyomi` while granting
`AmbientCapabilities=CAP_NET_BIND_SERVICE`, so low ports such as `:80`
/ `:443` can be bound **without staying as root**. The Center unit
launches `tukuyomi center` and does not require low-port-bind
capability by default.

Center standalone listener settings start in `tukuyomi-center.env` and can
then be edited from Center `Settings`. The editable values are the Center
listen address, API/UI base paths, and manual TLS certificate/key paths.
Listener and TLS changes apply after restarting `tukuyomi-center`.

For graceful binary replacement, use systemd **socket activation**.
The socket units hold the public / admin / redirect / HTTP3 listeners,
which separates the service-process shutdown / restart from the
listener-bind race.

### 3.11.1 Gateway registration

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

### 3.11.2 Center registration

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi-center.env.example /etc/tukuyomi/tukuyomi-center.env
sudo install -m 644 docs/build/tukuyomi-center.service.example /etc/systemd/system/tukuyomi-center.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi-center
sudo systemctl status tukuyomi-center
```

### 3.11.3 Socket activation

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

Notes for socket activation:

- Enable **only the socket units that match your effective DB
  `app_config`**.
- `ListenStream` / `ListenDatagram` must match `server.listen_addr` /
  `admin.listen_addr` / `server.tls.http_redirect_addr` / the HTTP/3
  UDP port.
- The process verifies inherited socket addresses and fails closed on
  mismatch.
- When you enable the admin / redirect / HTTP/3 socket units,
  uncomment the matching `Sockets=` lines in the service drop-in.
  This way `systemctl restart tukuyomi.service` keeps using the same
  inherited descriptors instead of falling back to a direct bind.

### 3.11.4 Graceful replacement

```bash
sudo install -m 755 build/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo systemctl restart tukuyomi.service
```

When socket activation is enabled, systemd holds the listening
sockets, the old process drains accepted HTTP requests, and the new
process starts on the same descriptors. `SIGTERM` / `SIGINT` /
`SIGHUP` all initiate a graceful shutdown. Long-lived connections
(Upgrade / WebSocket) are tracked and waited on up to
`server.graceful_shutdown_timeout_sec`, after which they are force
closed. HTTP/3 UDP socket handoff is supported, but existing QUIC
connections do not survive process replacement.

## 3.12 Notes

- Sample units use `WorkingDirectory=/opt/tukuyomi`, so the relative
  paths `conf/`, `audit/`, and `data/tmp/` stay inside the deployment
  root.
- `server.graceful_shutdown_timeout_sec` defaults to `30`. Raise it if
  you keep WebSockets open across deploys.
- The scheduled-task service uses the same working directory and env
  file, so `run-scheduled-tasks` sees the same `conf/` and
  `data/scheduled-tasks/` as the main service.
- Sample units grant `CAP_NET_BIND_SERVICE`, which permits direct
  binds for `server.listen_addr=:443` and
  `server.tls.http_redirect_addr=:80`.
- For split-listener deployments, `admin.listen_addr=:9091` (a high
  port) is typical, so additional capabilities for the admin listener
  are not required.
- `admin.listen_addr` only splits ports. Reachability remains
  controlled by `admin.external_mode` and `admin.trusted_cidrs`.
- In Gateway split-listener deployments, the `admin.listen_addr` side
  has no built-in TLS. Operate it on a trusted private network or
  behind a front proxy that terminates TLS. Center standalone has its
  own manual TLS listener controls in Center `Settings`.
- This capability is **for low-port binds only**. Switching `php-fpm`
  to a UID/GID other than `tukuyomi` (for example, `www-data`) still
  needs root start-up.
- If you expose `tukuyomi` directly and enable built-in HTTP/3, open
  both TCP and UDP on the listener port.
- For an unpacked release bundle, `testenv/release-binary/` is the
  fastest smoke path.
- Use `make binary-deployment-smoke` to validate the staged-runtime
  flow locally before rollout.

## 3.13 Bridge to the next chapter

We have walked through the systemd binary deployment from end to end:
the big picture, what `make install` does, the runtime layout,
persistent byte storage, the listener split, PHP-FPM bundles, the env
file, overload tuning, secret handling, and systemd registration with
socket activation.

The next chapter covers running the same tukuyomi as a container —
support tiers, the recommended topology per tier, ECS / Kubernetes /
Azure Container Apps deployment artifacts, shared writable paths, and
config / secret delivery.
