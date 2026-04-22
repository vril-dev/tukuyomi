# PHP-FPM Data Layout

`data/php-fpm/` keeps operator-managed assets for optional PHP-FPM support.

- `inventory.json`
  - local runtime inventory metadata; built runtimes are discovered from `binaries/`
- `vhosts.json`
  - persisted vhost definitions that later generate runtime targets
- `binaries/`
  - built `php-fpm` runtime bundles grouped by `runtime_id`
- `runtime/`
  - generated `php-fpm.conf`, pool files, pid files, and sockets

Generic vhost sample docroots live under `data/vhosts/samples/`.

The sample assets below intentionally use repository-relative paths only.
