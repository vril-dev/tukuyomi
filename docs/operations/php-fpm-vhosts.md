[English](php-fpm-vhosts.md) | [日本語](php-fpm-vhosts.ja.md)

# PHP-FPM Runtime and Vhost Operations

This document covers the optional PHP-FPM workflow exposed through `/options`, `/vhosts`, and `/proxy-rules`.

## Ownership Boundaries

- `/options`
  - built runtime inventory
  - materialization and process visibility
- `/vhosts`
  - source of truth for managed `php-fpm` applications
  - host, port, docroot, rewrite, access rules, basic auth, and PHP ini overrides
  - configured upstream binding through `linked_upstream_name`
- `/proxy-rules`
  - route binding only
  - bind traffic to configured upstream names referenced by `/vhosts`
  - do not treat raw `fcgi://` transport details as the normal operator entrypoint

## Data Layout

PHP-FPM operator-managed data lives under `data/php-fpm/`.

- `inventory.json`
  - local runtime inventory metadata
- `vhosts.json`
  - persisted managed PHP-FPM vhost definitions
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
- `php-fpm-prune` uses the same default destination and checks staged `vhosts.json` references plus the runtime pid before deleting the staged bundle
- Docker is required only while building the runtime bundle; runtime execution does not depend on Docker once the bundle is staged
- PHP, base image library, and PECL extension security updates are operator-managed, so rebuild and restage the bundle when those updates are needed
- the bundled runtime includes the major DB extensions needed for SQLite, MySQL/MariaDB, and PostgreSQL
  - `sqlite3`, `pdo_sqlite`
  - `mysqli`, `pdo_mysql`, `mysqlnd`
  - `pgsql`, `pdo_pgsql`
- verify the bundled module set from `/options` or with `data/php-fpm/binaries/<runtime_id>/php -m`

## Vhost Workflow

Use `/vhosts` when you need to define managed PHP-FPM application ownership.

`/vhosts` is visible only after at least one runtime bundle is built and detected.

Each vhost requires:

- `name`
- `hostname`
- `listen_port`
- `document_root`
- `linked_upstream_name`
- `runtime_id`

Optional controls:

- `try_files`
- rewrite rules
- access rules
- vhost-level basic auth
- access-rule-level basic auth
- `php_value`
- `php_admin_value`

Typical flow:

1. Open `/vhosts`.
2. Add a vhost.
3. Fill the required fields.
4. Add rewrite/access/auth/ini settings as needed.
5. Run `Validate`.
6. Run `Apply`.
7. Use `Rollback` only when you need to restore the previous saved snapshot.

Vhost behavior is centralized and nginx-style. Files in the document root such
as `.htaccess` are not parsed, imported, watched, or re-read at request time.
Legacy `override_file_name` fields in old config files are accepted only for
migration and are normalized away on validate/apply.

## Linked Upstreams and Route Binding

Saving a vhost does not publish traffic by itself.

After a vhost is saved:

- `/vhosts` persists the definition into `data/php-fpm/vhosts.json`
- the runtime layer materializes pool/config data under `data/php-fpm/runtime/<runtime_id>/`
- the configured upstream named by `linked_upstream_name` becomes vhost-backed in the effective proxy runtime
- `linked_upstream_name` is required and must reference an existing entry from `Proxy Rules > Upstreams`

Use `/proxy-rules` to bind real traffic:

- set `routes[].action.upstream` to the vhost `linked_upstream_name`
- or point `default_route.action.upstream` to that configured upstream name

Notes:

- `listen_port` is the PHP-FPM FastCGI listen port
- do not treat `http://127.0.0.1:<listen_port>` as an HTTP upstream
- the server owns `generated_target` as an internal compatibility alias and pool name; the admin UI does not expose it as operator input
- normal operator flow should reference `linked_upstream_name` from routes or the default route
- if `linked_upstream_name` binds to an existing configured upstream, that direct upstream cannot be removed from `Proxy Rules > Upstreams` until the Vhost changes

Keep `Proxy Rules` focused on routing. Managed PHP application details should stay in `/vhosts`, not as raw `fcgi://` or generated-target edits inside `conf/proxy.json`.

## Process Lifecycle

For active `php-fpm` vhosts, tukuyomi supervises one `php-fpm` master per active `runtime_id`.

- adding or changing a `php-fpm` vhost can start or restart the owning runtime
- removing the last referencing `php-fpm` vhost stops that runtime
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
