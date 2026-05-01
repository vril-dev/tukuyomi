# Chapter 2. Quick start

This chapter walks through bringing up a local preview of tukuyomi and
reaching both the Gateway UI and the Gateway API in a browser. Starting from
a freshly cloned tukuyomi source tree, the goal is the shortest path to
"tukuyomi is running, and I can interact with it".

Production deployment (systemd / Docker / ECS / Kubernetes) is covered in
Chapters 3 and 4. Treat this preview as a starting point that you will grow
into a production setup as you read those chapters.

## 2.1 Prerequisites

This chapter assumes you are trying the preview on a local development
machine. If you have the following ready, you can move straight on:

- Linux or WSL2 (macOS works too, but the book assumes Linux).
- A Go toolchain plus the build dependencies (`make`, the Go compiler,
  Node.js).
- `make` and `git`.

WAF and CRS rule assets are arranged automatically by the Make targets that
need them. You do not need to lay them down by hand.

## 2.2 How rule files and initial setup fit together

Before we run the commands, it helps to understand "what goes where, and in
what order".

For licensing reasons, tukuyomi does not bundle OWASP CRS itself in the
repository. Instead, a minimal base-rule seed required to start is bundled
under `seeds/waf/rules/`.

The standard runtime sequence is:

1. **Create the DB schema** (`make db-migrate`).
2. **Place the CRS seed file**.
3. **Import the WAF rule asset into the DB** (`make crs-install`).

A shortcut exists that performs steps 1 through 3 as a unit, and the preview
command we use in this chapter calls that shortcut internally. You do not
need to run the three steps yourself.

```bash
make db-migrate
make crs-install
```

## 2.3 Apply a preset

Common starter configurations are bundled as **presets**. To bring up a
preview, apply the minimal preset first.

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

The `minimal` preset places only two files:

- `.env`
- `data/conf/config.json`

In other words, **the preset only lays down the bare-bones bootstrap
configuration**. Proxy routes and site configuration are not yet in the DB
or in JSON when you have just applied the preset.

> **Note: fallback when JSON is missing**
>
> Even if you have not prepared `conf/proxy.json` or `conf/sites.json`,
> `make db-import` will not fail. It first reads
> `seeds/conf/config-bundle.json`, and falls back to a compatibility default if
> even that is missing. You can ignore this when you are only trying out the
> preview.

## 2.4 Bring up the preview

From here we use the `preview` target, which is meant for trying out only
the Gateway UI and the local runtime flow.

```bash
make gateway-preview-up
```

This single command runs everything in sequence:

1. `make db-migrate` to create the DB schema.
2. Place the CRS seed file if it is missing.
3. Import the WAF rule asset into the DB.
4. Start the Gateway in preview mode.

In other words, steps 1 to 3 from §2.2 **run automatically**.

When startup succeeds, the following URLs are reachable from a browser:

- Gateway UI: `http://localhost:9090/tukuyomi-ui`
- Gateway API: `http://localhost:9090/tukuyomi-api`

Open `tukuyomi-ui` first; you will be asked to sign in as a configured
administrator. Use the initial credentials provided by the `minimal` preset,
and the status screen (the same screenshot we showed in Chapter 1) appears.

## 2.5 Persisting preview state

By default, `make gateway-preview-up` **re-initializes its dedicated
preview-only SQLite DB on every run**. The preview-only configuration files
are reset as well, so every `down → up` starts from a clean slate.

If you want to keep settings made through the preview across restarts, opt
in to persist mode with an environment variable:

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
```

In this mode the preview configuration and DB state are kept between
`gateway-preview-down` and `gateway-preview-up`.

## 2.6 A guided tour of the Gateway UI

The Gateway UI gathers the screens that operators use day to day. On your
first preview session, opening them in this order makes the rest of the book
easier to follow.

1. **Status** (the first screen)
   - Current health of WAF / proxy / runtime, recent request trends, and
     overload backpressure state at a glance.
2. **Logs**
   - WAF events (DB `waf_events`) and a request timeline. The first screen
     to open when you tune false positives (Chapter 7).
3. **Rules**
   - Lists the base WAF and CRS rule assets imported into the DB.
4. **Override Rules**
   - The screen where you register **narrow mitigations** for WAF false
     positives as managed bypass entries (Chapter 7).
5. **Proxy Rules**
   - The editor for the three layers — Routes / Upstreams / Backend Pools
     (Chapter 5).
6. **Backends**
   - The operations panel for direct named upstreams: drain / disable /
     weight override (Chapter 5).
7. **Sites**
   - Site ownership and TLS binding (Chapter 15).
8. **Cache Rules / Country Block / Rate Limit / Bot Defense / Semantic
   Security / IP Reputation / Notifications**
   - Per-policy request-boundary controls. Covered across Chapters 7 to 9.
9. **vhosts**
   - Editor for PHP-FPM / PSGI Runtime Apps (Chapters 10–11).
10. **Scheduled Tasks**
    - Editor and runner for scheduled jobs (Chapter 12).
11. **Options / Settings**
    - Product-wide settings — listener / admin / storage / paths and so on,
      saved to `app_config_*` (Appendix A).
12. **FP Tuner**
    - The operator screen for the AI-assisted false-positive reduction
      flow (Chapter 8).

In this preview you do not need to drill into every screen. The point is to
do a quick reconnaissance — "which screen shows up in which chapter?" — so
the chapters that follow have somewhere to land.

## 2.7 Stopping and cleaning up

Stop the preview with:

```bash
make gateway-preview-down
```

If you did not pass `GATEWAY_PREVIEW_PERSIST=1`, the preview DB and
configuration files are cleared at this point. The next `make
gateway-preview-up` starts from a clean slate again.

## 2.8 Before you head to production

Once the preview works, keep two things in mind as you read on:

1. Preview and production **start through different paths**. Production
   starts via systemd units or containers, and the source of truth is
   `data/conf/config.json` plus the DB rows. Unlike the preview, the DB is
   not re-initialized on every start.
2. What preview and production **have in common** is the structural fact
   that **the DB is the runtime authority**. Settings you change through the
   UI in preview are operations against the same screens and tables in
   production deployments.

Chapter 3 details what `make install TARGET=linux-systemd` actually does
for systemd deployments; Chapter 4 covers the container-deployment tier
shapes and the canonical topology. Reading those chapters with the preview
fresh in mind makes the configuration keys much easier to picture.
