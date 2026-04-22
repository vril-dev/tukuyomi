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

If you only need the Go binary and already refreshed the embedded Admin UI, use:

```bash
make go-build
```

For reproducible release artifacts, use:

```bash
make release-linux-all VERSION=v0.8.0
```

## Runtime Layout

The binary expects a working directory that contains:

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/rules/
/opt/tukuyomi/logs/
```

Minimum runtime files:

- `conf/config.json`
- `conf/proxy.json`
- `conf/sites.json`
- `conf/cache-store.json`
- `conf/cache-rules.json`
- `conf/waf-bypass.json`
- `conf/waf-bypass.sample.json`
- `conf/country-block.json`
- `conf/rate-limit.json`
- `conf/bot-defense.json`
- `conf/semantic.json`
- `conf/notifications.json`
- `conf/ip-reputation.json`
- `rules/tukuyomi.conf`
- `rules/crs/crs-setup.conf`
- `rules/crs/rules/*.conf`

Additional files when you also want PHP-FPM `/options` and `/vhosts`:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

Additional files when you want `/scheduled-tasks`:

- `conf/scheduled-tasks.json`

Additional files when you want managed bypass override rules:

- `conf/rules/*.conf`

Additional files when you want managed GeoIP country updates:

- `data/geoip/`
- `scripts/update_country_db.sh`

Install example:

```bash
sudo install -d -m 755 \
  /opt/tukuyomi/bin \
  /opt/tukuyomi/conf \
  /opt/tukuyomi/data/geoip \
  /opt/tukuyomi/rules \
  /opt/tukuyomi/scripts \
  /opt/tukuyomi/logs/coraza \
  /opt/tukuyomi/logs/proxy

sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo install -m 755 scripts/update_country_db.sh /opt/tukuyomi/scripts/update_country_db.sh

for f in config.json proxy.json sites.json scheduled-tasks.json cache-store.json cache-rules.json waf-bypass.json waf-bypass.sample.json country-block.json rate-limit.json bot-defense.json semantic.json notifications.json ip-reputation.json; do
  sudo install -m 644 "data/conf/${f}" "/opt/tukuyomi/conf/${f}"
done

if [[ -d data/conf/rules ]]; then
  sudo install -d -m 755 /opt/tukuyomi/conf/rules
  for f in data/conf/rules/*; do
    [[ -f "${f}" ]] || continue
    sudo install -m 644 "${f}" "/opt/tukuyomi/conf/rules/$(basename "${f}")"
  done
fi

if [[ -f data/geoip/README.md ]]; then
  sudo install -m 644 data/geoip/README.md /opt/tukuyomi/data/geoip/README.md
fi

sudo install -m 644 data/rules/tukuyomi.conf /opt/tukuyomi/rules/tukuyomi.conf
sudo install -d -m 755 /opt/tukuyomi/rules/crs
sudo DEST_DIR=/opt/tukuyomi/rules/crs ./scripts/install_crs.sh
sudo touch /opt/tukuyomi/conf/crs-disabled.conf
```

Notes:

- do not copy `data/conf/*.bak` into production
- `config.json` is the main server-side config contract for `tukuyomi`
- render or mount `config.json` from your secret manager or config-management layer in production
- the embedded `Settings` page edits the same `conf/config.json` surface for global product settings, but that flow is `Save config only`; restart the service after listener/runtime/storage/observability changes
- the public release bundle ships a companion `bin/geoipupdate` binary for `Options -> GeoIP Update -> Update now`
- `GEOIPUPDATE_BIN` remains available if you want to override the bundled updater path
- the official managed-country refresh wrapper is `./scripts/update_country_db.sh`
- `data/geoip/country.mmdb`, `data/geoip/GeoIP.conf`, and `data/geoip/update-status.json` are operator-managed runtime artifacts; do not bake them into generic release bundles
- managed bypass override rules live under `conf/rules/*.conf`; they are edited from `Rules -> Override Rules` and are loaded only when `waf-bypass.json` references them via `extra_rule`
- the release bundle ships `conf/rules/search-endpoint.conf` as a harmless standalone sample
- the paired sample reference is `conf/waf-bypass.sample.json`

Proxy engine selection is also a restart-required `conf/config.json` setting:

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
- Upgrade/WebSocket handshake requests stay inside `tukuyomi_proxy`; WebSocket frame payloads after `101 Switching Protocols` are tunnel data
- benchmark your real workload before production rollout

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

If you also want PHP-FPM `/options` and `/vhosts` on a binary deployment, build and stage a runtime bundle.

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

Notes:

- `php-fpm-copy` syncs `data/php-fpm/binaries/<runtime_id>/` into the binary deployment tree and creates `inventory.json` / `vhosts.json` if they are absent
- remove an unneeded staged runtime bundle with `sudo make php-fpm-prune RUNTIME=php85`; it checks staged `vhosts.json` references and the runtime pid before deleting `binaries/<runtime_id>` and `runtime/<runtime_id>`
- `data/php-fpm/runtime/` is not copied; `tukuyomi` generates it later from vhost definitions
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

## Overload Tuning

Keep overload controls in `conf/config.json` under `server`:

- `max_concurrent_requests` is the process-wide guard.
- `max_concurrent_proxy_requests` is the data-plane guard.
- Queue settings are active only when the matching `max_concurrent_*` value is greater than `0`.
- `max_queued_proxy_requests` plus `queued_proxy_request_timeout_ms` absorb short proxy bursts without leaving requests in an unbounded wait.
- `max_queued_requests` defaults to `0`; keep it `0` or very small unless you explicitly want admin/API requests to wait under pressure.
- Set `max_concurrent_requests` higher than `max_concurrent_proxy_requests` if you want to preserve admin/API headroom during proxy saturation.
- Watch `/tukuyomi-api/status` for `server_overload_global` / `server_overload_proxy`, and `/tukuyomi-api/metrics` for `tukuyomi_overload_*`.

## Secret Handling

- keep `admin.api_key_primary`, `admin.api_key_secondary`, and `admin.session_secret` in `conf/config.json`, not in the browser
- browser operators sign in once and receive same-origin session cookies
- CLI / automation can continue to call `/tukuyomi-api/*` with `X-API-Key`
- default `tukuyomi` posture is `admin.external_mode=api_only_external`; move to `deny_external` if remote admin API access is unnecessary
- if you intentionally set `admin.external_mode=full_external` on a non-loopback listener, add front-side allowlists/auth because startup will only warn, not block
- widening `admin.trusted_cidrs` to public or catch-all networks also re-exposes the embedded admin UI/API to those sources and only triggers a warning
- if `security_audit.key_source=env`, keep the encryption and HMAC keys in the env file instead of `config.json`

## systemd

Sample unit:

- [tukuyomi.service.example](tukuyomi.service.example)
- [tukuyomi.socket.example](tukuyomi.socket.example)
- [tukuyomi-admin.socket.example](tukuyomi-admin.socket.example)
- [tukuyomi-redirect.socket.example](tukuyomi-redirect.socket.example)
- [tukuyomi-http3.socket.example](tukuyomi-http3.socket.example)
- [tukuyomi-scheduled-tasks.service.example](tukuyomi-scheduled-tasks.service.example)
- [tukuyomi-scheduled-tasks.timer.example](tukuyomi-scheduled-tasks.timer.example)

The sample unit keeps `User=tukuyomi` and adds `AmbientCapabilities=CAP_NET_BIND_SERVICE`, so `:80` / `:443` binds work without running the service as root full-time.
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

Only enable socket units that match your `conf/config.json`. `ListenStream` /
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

- the sample unit uses `WorkingDirectory=/opt/tukuyomi`, so relative `conf/`, `rules/`, and `logs/` paths keep working
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
