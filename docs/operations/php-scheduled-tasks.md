[English](php-scheduled-tasks.md) | [日本語](php-scheduled-tasks.ja.md)

# Scheduled Tasks

This document covers the `/scheduled-tasks` workflow for command-line jobs managed from the admin UI but executed outside the request path.

## Ownership Boundaries

- `/scheduled-tasks`
  - source of truth for persisted task definitions
  - cron schedule, command line, env, timeout, and last-run status
- external scheduler
  - runs `tukuyomi run-scheduled-tasks`
  - provides the actual minute-based invocation
  - stays separate from the main HTTP server process

## Data Layout

Persisted task definitions live in the normalized `scheduled_tasks` DB domain.
`conf/scheduled-tasks.json` is an empty-DB seed/export file, not the runtime
source of truth after bootstrap.

Last-run status snapshots live in the `scheduled_task_runtime_state` DB table.

Generated runtime artifacts still live under `data/scheduled-tasks/`.

- `locks/`
  - per-task lock files
- `logs/`
  - per-task logs

The default path wiring is controlled by effective DB `app_config` defaults:

- `paths.scheduled_task_config_file`

## Task Model

Each task stores a cron-style full command line.

Example:

```text
date
```

Stdout and stderr are captured automatically into `data/scheduled-tasks/logs/`.

This keeps the scheduled-task model simple:

- no bundled-runtime selector
- no separate PHP binary field
- no separate working directory field
- no separate args array

If you want a bundled PHP runtime, point the command line at its `php` wrapper directly. If you want a host-installed PHP, point the command line at `/usr/bin/php8.5` or similar.

## UI Workflow

Typical flow:

1. Open `/scheduled-tasks`.
2. Add a task.
3. Enter `name`, `schedule`, and the full `command`.
4. Add optional `env` lines and `timeout`.
5. Run `Validate`.
6. Run `Apply`.

Notes:

- use absolute paths for predictable execution
- status is updated when the external scheduler runs the one-shot runner
- the task log path shown in the UI comes from `data/scheduled-tasks/logs/`

## Runner Command

The external scheduler should invoke:

```bash
./bin/tukuyomi run-scheduled-tasks
```

That command:

- loads `conf/config.json`
- opens the configured DB store
- reads the normalized `scheduled_tasks` DB domain directly, seeding from `conf/scheduled-tasks.json` only when the domain is missing
- executes only jobs whose cron expression matches the current minute
- runs each task through `/bin/sh -lc`
- records task status in `scheduled_task_runtime_state`
- records lock/log artifacts under `data/scheduled-tasks/`

It does not start a cron daemon. Run it from your platform scheduler.

## Binary Deployment Pattern

For Linux binary deployments, use `systemd timer`.

Examples:

- [docs/build/tukuyomi-scheduled-tasks.service.example](../build/tukuyomi-scheduled-tasks.service.example)
- [docs/build/tukuyomi-scheduled-tasks.timer.example](../build/tukuyomi-scheduled-tasks.timer.example)

The timer fires every minute and the service runs the one-shot command above.

## Container Deployment Pattern

For container deployments, there are two ownership shapes.

### 1. Current official default: single-instance sidecar

Use a scheduler sidecar when the whole proxy deployment is still the official
single-instance mutable topology.

Requirements:

- mount the same `conf/` and `data/scheduled-tasks/` paths seen by the main `tukuyomi` container
- if the command line points at a bundled PHP path under `data/php-fpm/`, mount `data/php-fpm/` too
- run the same binary with `run-scheduled-tasks`

The repository compose path now exposes a real sidecar service for proxy-owned commands:

```bash
make compose-up-scheduled-tasks
```

Equivalent raw compose command:

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

Application jobs such as `artisan schedule:run` still need an application tree mounted into both `coraza` and `scheduled-task-runner`. Use a deployment-specific override file such as [docs/build/docker-compose.scheduled-tasks.app.example.yml](../build/docker-compose.scheduled-tasks.app.example.yml).

The current sidecar execution model is explicit: a shell loop invokes the image's proxy binary with `run-scheduled-tasks` and then sleeps until the next minute boundary.

Failure policy is explicit too: if `run-scheduled-tasks` returns non-zero, the sidecar exits non-zero and relies on container restart policy instead of hiding the fault.

Keep the scheduler separate from the main proxy container instead of embedding `crond` into the request-serving process. `make ui-preview-up` now starts a preview-scoped scheduler sidecar as well. Watch sidecar logs and restart count when debugging persistent scheduler faults.

### 2. Guarded future shape: replicated frontend plus dedicated singleton scheduler

If you move beyond the current official single-instance topology and experiment
with replicated immutable frontends, do not run one scheduler sidecar inside
every frontend replica.

- set `admin.read_only=true` on the frontend replicas
- keep config changes rollout-driven
- do not run one scheduler sidecar per frontend replica
- assign scheduled-task ownership to one dedicated singleton scheduler role

That singleton scheduler role still mounts the same:

- `conf/`
- `data/scheduled-tasks/`
- `logs/`
- `data/php-fpm/` when bundled runtimes are used

See also:

- [container-deployment.md](../build/container-deployment.md)
- [ecs-replicated-frontend-scheduler.task-definition.example.json](../build/ecs-replicated-frontend-scheduler.task-definition.example.json)
- [kubernetes-replicated-frontend-scheduler.example.yaml](../build/kubernetes-replicated-frontend-scheduler.example.yaml)
- [azure-container-apps-scheduler-singleton.example.yaml](../build/azure-container-apps-scheduler-singleton.example.yaml)

## Preview Manual Check

Use this when you want to verify the preview path with its own isolated scheduler sidecar:

```bash
make ui-preview-up
make ui-preview-down
```

Preview keeps its own isolated DB-backed scheduled-task config, so edits made through the preview UI do not mutate the normal runtime config.

By default, `ui-preview-up` recreates the isolated preview SQLite DB on each start, so previously saved preview tasks and DB rows do not keep running by accident.

If you want preview edits to survive `down/up`, opt into retained preview DB state:

```bash
UI_PREVIEW_PERSIST=1 make ui-preview-up
UI_PREVIEW_PERSIST=1 make ui-preview-down
```

When `UI_PREVIEW_PERSIST=1` is set, preview keeps its own preview SQLite DB. That means you can save listener changes in `Settings`, then confirm them with `ui-preview-down/up` without losing the preview state stored in DB.

Split preview listeners are supported as long as the preview listener settings use host-reachable binds such as `:80` and `:9090`. Do not use `localhost:80`, `127.0.0.1:80`, or `[::1]:9090` in preview listener settings; `ui-preview-up` rejects loopback binds because they do not match Docker-published ports.

For a repeatable local regression run across binary, Docker sidecar, and preview-sidecar paths, use:

```bash
make scheduled-tasks-smoke
```

For preview persistence and split-port parity only, use:

```bash
make ui-preview-smoke
```

## Bundled PHP CLI

`make php-fpm-build` produces both:

- `data/php-fpm/binaries/<runtime_id>/php-fpm`
- `data/php-fpm/binaries/<runtime_id>/php`

That means a built runtime bundle can serve both PHP-FPM workloads and scheduled PHP CLI jobs, but scheduled tasks refer to the CLI path directly in the command line instead of going through `/options`.

The bundled PHP CLI uses the same extension set as the bundled PHP-FPM runtime, including SQLite, MySQL/MariaDB, and PostgreSQL support.

## GeoIP Country DB Automation

Managed country DB refresh supports both manual and scheduled execution.

Binary/repository wrapper:

```bash
./scripts/update_country_db.sh
```

Direct binary subcommand:

```bash
./bin/tukuyomi update-country-db
```

Container image command:

```bash
/app/server update-country-db
```

Operator flow:

1. Upload `GeoIP.conf` from `Options -> GeoIP Update`. In DB mode it is stored in runtime DB authority.
2. Run `Update now` once and confirm success.
3. Add a scheduled task that runs one of the commands above for your deployment shape.
