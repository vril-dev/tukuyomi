[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM Runtime and Runtime App Operations

This document covers the optional PHP-FPM workflow exposed through `/options`, `/runtime-apps`, and `/proxy-rules`.

## Ownership Boundaries

- `/options`
  - built runtime inventory
  - materialization and process visibility
- `/runtime-apps`
  - source of truth for managed `php-fpm` applications
  - runtime listen host, FastCGI listen port, docroot, runtime, rewrite, access rules, basic auth, and PHP ini overrides
  - generated backend ownership
- `/proxy-rules`
  - direct backends, backend pools, and explicit routes for traffic not owned by Runtime Apps
  - PHP-FPM application backend settings move to `/runtime-apps`
  - configured upstream URLs are never rewritten by `/runtime-apps`
  - do not treat raw `fcgi://` transport details as the normal operator entrypoint

## Data Layout

PHP-FPM operator-managed data lives under `data/php-fpm/`.

- `inventory.json`
  - local runtime inventory metadata
- `vhosts.json`
  - persisted managed PHP-FPM Runtime App definitions
- `binaries/<runtime_id>/`
  - built runtime bundle, `php-fpm` wrapper, `php` CLI wrapper, `runtime.json`, and `modules.json`
- `runtime/<runtime_id>/`
  - generated `php-fpm.conf`, pool files, pid/log files, and listen artifacts

Generic sample docroots live under `data/vhosts/samples/`.

The default path wiring is controlled by effective DB `app_config` defaults:

- `paths.php_runtime_inventory_file`
- `paths.vhost_config_file`

## Runtime Build and Inventory Workflow

PHP runtimes appear in `/options` only after you build them.

Build a runtime bundle:

```bash
make php-fpm-build VER=8.3
```

Stage it into a binary deployment layout:

```bash
sudo make php-fpm-copy RUNTIME=php83
```

Safely remove it from a binary deployment layout:

```bash
sudo make php-fpm-prune RUNTIME=php83
```

Supported versions:

- `8.3`
- `8.4`
- `8.5`

After a successful build:

1. Open `/options`.
2. Confirm the runtime card is present.
3. Review:
   - display name / detected version
   - binary path
   - CLI binary path
   - bundled module list
   - configured run user/group
   - materialized target usage count
   - runtime process state
4. Run `Load` to refresh the runtime list.

If a runtime bundle is removed from `data/php-fpm/binaries/<runtime_id>/`, it disappears from `/options` on the next load.

Notes:

- `php-fpm-copy` defaults to `/opt/tukuyomi`; override with `DEST=/srv/tukuyomi` when needed
- `php-fpm-prune` uses the same default destination and checks staged Runtime App references in `vhosts.json` plus the runtime pid before deleting the staged bundle
- Docker is required only while building the runtime bundle; runtime execution does not depend on Docker once the bundle is staged
- PHP, base image library, and PECL extension security updates are operator-managed, so rebuild and restage the bundle when those updates are needed
- the bundled runtime includes the major DB extensions needed for SQLite, MySQL/MariaDB, and PostgreSQL
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- verify the bundled module set from `/options` or with `data/php-fpm/binaries/<runtime_id>/php -m`

## Runtime App Workflow

Use `/runtime-apps` when you need to define managed PHP-FPM application ownership.

`/runtime-apps` is visible only after at least one runtime bundle is built and detected.

Each runtime app requires:

- `name`
- `hostname`
- `listen_port`
- `document_root`
- `runtime_id`

Optional controls:

- `try_files`
- rewrite rules
- access rules
- runtime app-level basic auth
- access-rule-level basic auth
- `php_value`
- `php_admin_value`

Typical flow:

1. Open `/runtime-apps`.
2. Add a runtime app.
3. Fill the required fields.
4. Add rewrite/access/auth/ini settings as needed.
5. Run `Validate`.
6. Run `Apply`.
7. Use `Rollback` only when you need to restore the previous saved snapshot.

Runtime App behavior is centralized and nginx-style. Files in the document root such
as `.htaccess` are not parsed, imported, watched, or re-read at request time.
Legacy `override_file_name` fields in old config files are accepted only for
migration and are normalized away on validate/apply.

## Upstreams to Runtime Apps Boundary

Do not model Tukuyomi-owned PHP-FPM applications as direct backends in `Proxy Rules > Upstreams`; move those connection settings to `/runtime-apps`.

- `Proxy Rules > Upstreams`
  - direct backends such as external HTTP/HTTPS services
  - configured upstream URLs are used exactly as shown and are not rebound to Runtime App targets
- `/runtime-apps`
  - runtime listen host, docroot, runtime, and FastCGI listen port ownership for PHP-FPM/static apps
  - generated backend publication into the effective runtime

## Generated Runtime App Backends

Saving a runtime app publishes a generated backend for its configured listener.
The `hostname` JSON field is the runtime listen host/address, not a virtual host
name or Host-header match.

After a runtime app is saved:

- `/runtime-apps` persists the definition into `data/php-fpm/vhosts.json`
- the runtime layer materializes pool/config data under `data/php-fpm/runtime/<runtime_id>/`
- the effective proxy runtime gets a generated upstream named by `generated_target`
- configured upstream URLs in `Proxy Rules > Upstreams` are left unchanged
- operator routes or the default route in `Proxy Rules` select the generated upstream when traffic should reach the Runtime App-backed app

Route order is controlled by `Proxy Rules`:

- explicit `routes[]`
- generated site host fallback routes
- `default_route`
- `upstreams[]`

Notes:

- `hostname` plus `listen_port` is the PHP-FPM FastCGI listen target
- do not treat `http://<hostname>:<listen_port>` as an HTTP upstream
- the server owns `generated_target` as the generated backend alias and pool name; the admin UI does not expose it as operator input
- normal operation routes to the generated upstream target from `Proxy Rules`

Keep PHP runtime details in `/runtime-apps`. Keep public traffic selection in
`Proxy Rules`; do not hand-write raw `fcgi://` URLs when the generated upstream
target already represents the listener.

## Process Lifecycle

For active `php-fpm` Runtime Apps, tukuyomi supervises one `php-fpm` master per active `runtime_id`.

- adding or changing a `php-fpm` Runtime App can start or restart the owning runtime
- removing the last referencing `php-fpm` Runtime App stops that runtime
- runtime status is visible from `/options`

You can also control a built runtime explicitly:

```bash
make php-fpm-up RUNTIME=php83
make php-fpm-reload RUNTIME=php83
make php-fpm-down RUNTIME=php83
```

To remove a built runtime bundle when it is no longer referenced:

```bash
make php-fpm-remove RUNTIME=php83
```

The runtime is launched under a dedicated non-root user/group when configured.

## Tests and Smoke

Focused validation helpers:

```bash
make php-fpm-test
make php-fpm-smoke VER=8.3
```
