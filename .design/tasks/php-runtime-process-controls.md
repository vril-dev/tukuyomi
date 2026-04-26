# PHP Runtime Process Controls Tasks

Source plan: `.design/plans/php-runtime-process-controls.md`

## Scope

Add operator-facing controls for vhost-managed PHP-FPM runtime processes without moving process ownership into Vhosts.

## Tasks

- [x] Extend admin UI PHP runtime response types to include process action, PID, timestamps, generated targets, and effective identity.
- [x] Add Runtime Inventory actions for materialized runtimes:
  - `Start` calls `POST /api/php-runtimes/:runtime_id/up`.
  - `Stop` calls `POST /api/php-runtimes/:runtime_id/down`.
  - `Reload` calls `POST /api/php-runtimes/:runtime_id/reload`.
- [x] Update Runtime Inventory cards with process state, generated targets, timestamps, and last error details.
- [x] Disable process actions in read-only mode and while a runtime operation is in flight.
- [x] Load PHP runtime materialization/process state in Vhosts and show php-fpm runtime state summary per vhost.
- [x] Add an `Open Runtime` link from Vhosts to the Runtime Inventory surface.
- [x] Keep restart/reload actions out of Vhost rows.
- [x] Validate with UI build and relevant Go PHP runtime tests.

## Acceptance

- A stopped materialized runtime can be started from Runtime Inventory.
- A running materialized runtime can be stopped or reloaded from Runtime Inventory.
- Vhost cards show whether their selected runtime is running, stopped, manually stopped, or failed.
- Vhost cards link to Runtime Inventory but do not expose Restart/Reload controls.
- Read-only sessions cannot invoke runtime process actions.
