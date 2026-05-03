# Chapter 1. Introducing tukuyomi

This chapter takes a bird's-eye view of where tukuyomi sits as a product, and
why it can be called a *single-binary application-edge control plane*.
Concrete configuration and Make targets come from Chapter 2 onwards; the goal
here is to draw a map of the terrain and the vocabulary.

## 1.1 Where tukuyomi sits

tukuyomi unifies an **edge component placed in front of the web** and the
**application execution layer behind it** into a single Go binary. It carries
out the following responsibilities in one process:

- Reverse proxy (routing and transport)
- Coraza WAF + OWASP CRS inspection
- Rate / country / bot / semantic / IP-reputation controls
- Embedded admin UI / admin API
- Optional static hosting / PHP-FPM / PSGI runtime
- Optional scheduled jobs (with a bundled PHP CLI)
- Optional IoT / Edge device-identity enrollment via Tukuyomi Center

Because all of this is bundled into a single binary, **deploying one tukuyomi
instance gives you almost everything that goes in front of a web application**.

![Admin status screen](../../images/ui-samples/01-status.png)

## 1.2 Why "single-binary application-edge control plane"

tukuyomi describes itself as a **single-binary application-edge control
plane**. The phrase is a little long, so it is worth breaking down.

### single-binary

tukuyomi is distributed as a single Go binary. Both the Gateway role and the
Center role (the central management side) are compiled into the same binary.
Which role a given process runs is decided by `INSTALL_ROLE` at install time
or by configuration at startup.

That means:

- Each deployment target collapses to "one binary plus one configuration
  file".
- A single `make install TARGET=linux-systemd` builds, installs, runs DB
  migrations, imports WAF/CRS assets, and lays down systemd units.
- A first-party container image is also provided, so systemd deployment and
  container deployment are both supported out of the box.

### application-edge

The phrase `application-edge` is meant to make tukuyomi's scope of
responsibility explicit.

tukuyomi handles the edge that sits **immediately in front of an
application**. It is not a CDN or a global load balancer; it is the layer that
sits directly in front of a PHP-FPM, Perl/Starman, Go, or Node process —
right next to the application processes you are operating.

That is why the feature set is shaped around:

- Per-application routing
- Per-application WAF tuning (narrow false-positive mitigations)
- Lifecycle management of application processes themselves (PHP-FPM / PSGI)

In other words, tukuyomi is optimized for operating workflows where **you
distinguish one specific application from another**.

### control plane

`control plane` is the other pillar of the design. tukuyomi keeps its
authoritative runtime state **in the database**:

- WAF / CRS rule assets (`waf_rule_assets`)
- Proxy routes and transport configuration (`proxy_*`)
- Runtime Apps vhost configuration (`vhosts` / `vhost_*`)
- Managed bypass (`override_rules`)
- PHP-FPM / PSGI runtime inventory (`php_runtime_*` / `psgi_runtime_*`)
- Global / listener / admin / storage / paths blocks (`app_config_*`)

These are written through the UI / API, persisted to the DB, and read by
tukuyomi at runtime. The JSON files (`proxy.json` / `sites.json` /
`scheduled-tasks.json` and so on) are reorganized as **seed for an empty DB**
and as **import / export material**. The runtime authority lives in the DB.

The result is:

- Runtime behavior changes are atomic via the UI / API.
- Configuration diffs are tracked through DB versioning.
- Import / export between hosts goes through JSON.

That operational character is why this layer earns the name "control plane".

## 1.3 Typical scenarios

Here are some concrete shapes tukuyomi is designed for. Treat them as a map
to the topics covered in later chapters.

### WAF + reverse proxy on a Web / VPS

This is the most basic shape. You install tukuyomi on a single Linux host
(VPS, bare metal, or a cloud VM) with `make install TARGET=linux-systemd`,
and a single process handles TLS termination, HTTP/3, the WAF, rate
controls, and the reverse proxy.

In this shape, IoT / Edge mode stays OFF.

### WAF + reverse proxy on containers / Kubernetes

This shape runs tukuyomi on a container platform — ECS / Fargate, Kubernetes
(AKS / GKE), Azure Container Apps, and so on. tukuyomi defines three support
tiers — **single-instance (mutable)**, **replicated (immutable rolling
update)**, and **distributed (mutable cluster)** — and provides deployment
samples for each.

### Replacing an existing PHP / Movable Type host

This shape moves an existing host that runs PHP-FPM or PSGI (Movable Type
and friends) over to tukuyomi, edge included. tukuyomi manages PHP-FPM /
PSGI runtime inventory and vhosts in the DB and starts them as Runtime
Apps. `Proxy Rules` then routes traffic to the target the runtime is
listening on.

### Center-approved IoT / Edge gateway

A more specialized shape: an IoT / Edge deployment mode that requires a
device identity approved by Tukuyomi Center. The Gateway generates an
Ed25519 device identity locally and submits a signed enrollment request to
the Center, attaching the enrollment token issued by the Center. Once the
operator approves it on the Center side, the Gateway holds an officially
recognized identity.

This mode is OFF by default in Web / VPS deployments and is enabled only for
IoT / Edge deployments. Chapter 16 covers the details.

## 1.4 The source of truth — DB vs. JSON

To close the chapter, here is one rule that underpins the whole operations
story for tukuyomi:

> **The source of truth for runtime behavior is the DB. JSON files are seed
> for an empty DB and import / export material; they are not the runtime
> authority.**

Concretely, the configuration material is split as follows:

- `.env`: container / runtime deltas only.
- `data/conf/config.json`: the bootstrap configuration needed before the DB
  is opened (a thin JSON centered on the `storage` block).
- DB `app_config_*`: product-wide configuration — global runtime, listener,
  admin, storage policy, paths, and so on.
- DB `proxy_*`: live proxy transport / routing configuration.
- DB `vhosts` / `vhost_*`: live Runtime Apps configuration.
- DB `waf_rule_assets`: base WAF and CRS rule / data assets.
- DB `override_rules`: managed bypass rule bodies.
- DB `php_runtime_*` / `psgi_runtime_*`: PHP-FPM / PSGI runtime inventory.
- `seeds/conf/config-bundle.json`: bundled production seed for an empty DB.
- `data/conf/proxy.json`, `sites.json`, `upstream-runtime.json`,
  `scheduled-tasks.json` and similar: seed / import / export material.
- `data/php-fpm/*.json`, `data/psgi/*.json`: seed / import / export material
  for PHP-FPM / PSGI.

Two key points:

1. **Once production is running, the runtime reads the DB, not the JSON
   files.** `make crs-install` and `make db-import` pull the necessary rule
   assets and configuration into the DB, and from that moment on the DB is
   the authority.
2. **The JSON files are I/O for import / export only.** Use them when you
   seed a new host, when you bring state from another host, or when you want
   to track operator changes in git.

This rule appears repeatedly from Chapter 3 onwards. Whenever you wonder
"where do I write this configuration?", come back to this split.

## 1.5 Bridge to the next chapter

We have established that tukuyomi is **"the edge directly in front of an
application, packaged as a single binary, with a DB-backed control plane"**.

Chapter 2 stops short of building a production setup and instead brings up a
local preview, then gets you to the Gateway UI and Gateway API. Readers who
have not touched tukuyomi before should run through Chapter 2 first; the
configuration keys discussed in Chapter 3 onwards become much easier to
picture once you have driven the UI.
