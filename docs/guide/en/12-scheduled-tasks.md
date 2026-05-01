# Chapter 12. Scheduled tasks

The closing chapter of Part V covers tukuyomi's **scheduled tasks** —
**command-line jobs defined through the admin UI but executed outside
the request path**. The intended use cases are Laravel `artisan
schedule:run`, Movable Type background processing, GeoIP DB
auto-refresh, and any in-house aggregation batch.

![Scheduled Tasks screen](../../images/ui-samples/19-scheduled-tasks.png)

## 12.1 Separation of concerns — define vs. trigger

The first thing to nail down for scheduled tasks is that **defining a
task** and **triggering it on the minute** live in clearly separate
places.

- **`/scheduled-tasks`**
  - The **source of truth** for task definitions.
  - Manages cron schedule, command line, env, timeout, and last-run
    state.
- **External scheduler**
  - Invokes **`tukuyomi run-scheduled-tasks`**.
  - Owns minute-cadence triggering.
  - Runs **separately from the main HTTP server process**.

In other words, tukuyomi itself does not embed a cron daemon.
**A platform-side scheduler (a systemd timer, a sidecar, or a dedicated
scheduler container) runs `tukuyomi run-scheduled-tasks` as a
process distinct from the main HTTP server** — that is the basic shape.

## 12.2 Data layout

The source of truth for saved task definitions is the normalized
`scheduled_tasks` DB domain. `conf/scheduled-tasks.json` is **seed /
export for an empty DB**, not the runtime source of truth after
bootstrap. The same rule from Chapter 3 — "DB is the runtime
authority, JSON is seed / import / export" — applies here.

Last-run state is recorded in the `scheduled_task_runtime_state` DB
table. Generated runtime artifacts live under
`data/scheduled-tasks/`:

- `locks/`: per-task lock files
- `logs/`: per-task logs

The default path is governed by the effective DB `app_config`:

- `paths.scheduled_task_config_file`

## 12.3 Task model

Each task carries **a single cron-style command line**:

```text
date
```

stdout / stderr are **automatically saved under
`data/scheduled-tasks/logs/`**. You do not have to specify a file
name or a rotation policy.

Restricting the task to this shape keeps the model small on purpose:

- No bundled-runtime selector.
- No PHP-binary-only fields.
- No working directory.
- No args array.

To use the bundled PHP runtime, write that **`php` wrapper directly
into the command line**. To use a host-installed PHP, write
`/usr/bin/php8.5` directly. There is **deliberately no UI field that
lets you "select a runtime"** — that is the design decision.

## 12.4 UI workflow

The typical flow:

1. Open `/scheduled-tasks`.
2. Add a task.
3. Fill in `name`, `schedule`, and the full `command`.
4. Add `env` and `timeout` if needed.
5. Run **`Validate`**.
6. Run **`Apply`**.

Notes:

- To avoid execution drift, **prefer absolute paths**.
- Status updates come from **the external scheduler invoking the
  one-shot runner**, not from someone clicking around the UI.
- The log paths shown in the UI live under
  `data/scheduled-tasks/logs/`.

## 12.5 The runner command

The single command an external scheduler runs:

```bash
./bin/tukuyomi run-scheduled-tasks
```

This command:

- Reads `conf/config.json`.
- Opens the configured DB store.
- Reads the normalized `scheduled_tasks` DB domain **directly**.
  When the domain is missing, it seeds from
  `conf/scheduled-tasks.json`.
- Runs **only the jobs whose schedule matches the current minute**.
- Launches each task with **`/bin/sh -lc`**.
- Records task status in `scheduled_task_runtime_state`.
- Records lock / log artifacts under `data/scheduled-tasks/`.

Once again, **tukuyomi has no cron daemon of its own**. Drive it from
the platform-side scheduler.

## 12.6 Binary deployment pattern

For Linux binary deployment, the standard pattern is a **systemd
timer**.

Sample units:

- `docs/build/tukuyomi-scheduled-tasks.service.example`
- `docs/build/tukuyomi-scheduled-tasks.timer.example`

The timer fires **once a minute** and the service runs the one-shot
command from §12.5. The Chapter 3 §3.11 registration example already
includes `enable --now tukuyomi-scheduled-tasks.timer` — that is what
brings this timer up.

## 12.7 Container deployment pattern

For container deployment, ownership splits into two shapes.

### 12.7.1 Current official default: single-instance sidecar

When the proxy is in the official single-instance mutable topology,
use a **scheduler sidecar** (this matches the official topology in
§4.2).

Requirements:

- Mount the same `conf/` and `data/scheduled-tasks/` as the main
  `tukuyomi` container.
- If the command line points to a bundled PHP path under
  `data/php-fpm/`, mount `data/php-fpm/` too.
- Run the **same binary with `run-scheduled-tasks`**.

Through the repository's compose flow you can run a real sidecar
service for proxy-owned commands:

```bash
make compose-up-scheduled-tasks
```

The raw compose command:

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

For **application jobs** like `artisan schedule:run`, mount the
application tree into both `coraza` and `scheduled-task-runner`. Use
`docs/build/docker-compose.scheduled-tasks.app.example.yml` as the
deployment-specific override.

The current sidecar execution model is **explicit**: a shell loop
calls the in-image proxy binary with `run-scheduled-tasks`, then
sleeps until the next minute boundary.

The failure policy is also **explicit**: when
`run-scheduled-tasks` returns non-zero, the sidecar exits non-zero,
and the fault is handed to the container restart policy instead of
swallowed.

We **prefer separating the scheduler over running `crond`** alongside
the main proxy container. `make gateway-preview-up` also brings up a
preview-only scheduler sidecar. Track persistent scheduler faults via
**sidecar logs and restart counts**.

### 12.7.2 The future guarded shape: replicated frontend + dedicated singleton scheduler

When you intentionally leave the official single-instance topology
and try a replicated immutable frontend, **do not place a scheduler
sidecar on each frontend replica**.

- Frontend replicas use **`admin.read_only=true`**.
- Configuration changes go through **rollouts**.
- Do not load a scheduler sidecar on each frontend replica.
- Scheduled-task ownership moves to a **dedicated singleton scheduler
  role**.

The singleton scheduler also mounts the same source of truth:

- `conf/`
- `data/scheduled-tasks/`
- `logs/`
- `data/php-fpm/` if you are using bundled runtimes.

Reference artifacts:

- `docs/build/ecs-replicated-frontend-scheduler.task-definition.example.json`
- `docs/build/kubernetes-replicated-frontend-scheduler.example.yaml`
- `docs/build/azure-container-apps-scheduler-singleton.example.yaml`

This is **not** support for a distributed mutable runtime. It is the
pattern for **explicitly carving scheduler ownership out when you
replicate frontends**.

## 12.8 Manual preview check

To verify the preview path including the scheduler, the same preview
commands from Chapter 2 work directly:

```bash
make gateway-preview-up
make gateway-preview-down
```

Preview uses a **preview-specific DB-backed scheduled-task config**
that is **separate from production**, so changes you make through the
preview UI do not contaminate the regular runtime config.

By default `gateway-preview-up` rebuilds the preview-only SQLite DB on
every run, so old preview tasks and DB rows are not carried forward.

To keep preview edits across `down/up`, persist the preview DB state:

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
```

With `GATEWAY_PREVIEW_PERSIST=1` the preview SQLite DB is retained,
so listener changes saved through `Settings` survive a preview
`down/up`.

Split preview listeners are usable, but **bind them to host-reachable
addresses** like `:80` / `:9090`. Loopback binds such as
`localhost:80` / `127.0.0.1:80` / `[::1]:9090` **do not pair with
Docker publish**, and `gateway-preview-up` exits with an explicit
error.

To regression-test all three paths — binary, Docker sidecar, and
preview sidecar — at once:

```bash
make scheduled-tasks-smoke
```

To exercise just preview persistence and split-port parity:

```bash
make gateway-preview-smoke
```

## 12.9 Bundled PHP CLI

`make php-fpm-build` produces **both** of these:

- `data/php-fpm/binaries/<runtime_id>/php-fpm`
- `data/php-fpm/binaries/<runtime_id>/php`

In other words, the built runtime bundle is usable for both
**PHP-FPM workloads and scheduled PHP CLI jobs**. Scheduled tasks
reference the CLI path **directly** in the command line; they do not
go through `/options`.

The bundled PHP CLI uses the same extension set as the bundled
PHP-FPM runtime, so it can talk to **SQLite / MySQL (MariaDB) /
PostgreSQL out of the box**.

## 12.10 GeoIP country DB auto-refresh

Refresh of the managed country DB supports both **manual** and
**scheduled** invocation.

binary / repository wrapper:

```bash
./scripts/update_country_db.sh
```

Binary subcommand:

```bash
./bin/tukuyomi update-country-db
```

Container image command:

```bash
/app/server update-country-db
```

Operator flow:

1. **`Options → GeoIP Update`** uploads `GeoIP.conf` (in DB mode it
   is stored in the runtime DB authority).
2. Run **`Update now`** once and confirm success.
3. Depending on deployment, **add a scheduled task** that calls one
   of the commands above.

That way, the country DB refresh is something the operator does not
have to remember to run.

## 12.11 Recap

- **Task definitions live in `/scheduled-tasks`; triggering happens
  in an external scheduler.** tukuyomi has no built-in cron daemon.
- The task model is a **single cron-style command line** — no
  superfluous fields like runtime selectors, args arrays, or working
  directories.
- The trigger command is the one-shot **`tukuyomi
  run-scheduled-tasks`**.
- Deployment patterns are **systemd timer** (binary), **sidecar**
  (single-instance container), or **dedicated singleton scheduler**
  (replicated).
- The bundled PHP CLI is also usable from **scheduled PHP CLI jobs**.
- Register the GeoIP auto-refresh as a scheduled task.

## 12.12 Bridge to the next chapter

We have walked through the major features from edge to runtime apps.
Part VI shifts to operations and troubleshooting. Chapter 13 starts
with **DB operations** in tukuyomi — choosing between SQLite / MySQL /
PostgreSQL, what is stored, retention, backup, and recovery.
