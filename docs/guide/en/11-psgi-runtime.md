# Chapter 11. PSGI runtime (Movable Type, etc.)

Following the PHP-FPM chapter, this chapter covers **Runtime Apps for
PSGI (Perl Web Server Gateway Interface)**. tukuyomi's PSGI support is
designed to put Movable Type and other Perl PSGI applications **under
tukuyomi management without a separate reverse-proxy stack**.

The three-screen framework from Chapter 10 (`/options`,
`/runtime-apps`, `/proxy-rules`) is broadly the same for PSGI; this
chapter focuses on the differences.

## 11.1 Runtime model

The PSGI runtime model is straightforward:

- `make psgi-build VER=5.38` builds a **Perl / Starman runtime bundle**
  under `data/psgi/binaries/perl538`.
- The runtime inventory is shown at `/options` and persisted in DB
  `psgi_runtime_inventory`.
- A PSGI Runtime App **selects one runtime** and defines:
  - `app_root`
  - `psgi_file`
  - **A static `document_root`**
  - The runtime listen `hostname` / `listen_port`
  - **Worker count** and **max requests**
  - **Use of `extlib`**
  - Environment variables
- tukuyomi **supervises one Starman process per PSGI Runtime App**.
  This is **deliberately different** from PHP-FPM, which puts multiple
  pools under one master.

Where PHP-FPM has one master per `runtime_id` with multiple vhost
pools below it, PSGI has a **1:1 correspondence between Runtime App
and Starman process**. This split exists because Perl / Starman tends
to use significant memory and worker tuning is best done at the vhost
level.

## 11.2 The Movable Type shape

A typical PSGI Runtime App for Movable Type looks like:

- `app_root`: the unpacked Movable Type application directory.
- `psgi_file`: `mt.psgi`.
- `document_root`: the public static directory, typically
  `mt-static`.
- `try_files`: `$uri`, `$uri/`, `@psgi`.
- `include_extlib`: enable when the application has its own `extlib/`.

`try_files` evaluates static file → `@psgi` sentinel in order.
**Static files are served directly from `document_root`**, while
dynamic requests hit the **`@psgi` sentinel and flow into Starman**.
This keeps static asset serving (images, CSS, etc.) on the edge so
Starman can focus on application processing.

Note that **tukuyomi does not manage the Movable Type application
configuration**:

- `mt-config.cgi`
- `CGIPath`
- Database DSN
- Plugin configuration

These are the application's responsibility; tukuyomi does not
generate them. tukuyomi only:

- Validates runtime files / paths before saving the PSGI Runtime App.
- Surfaces application-specific configuration errors **as PSGI
  process startup errors**.

A Movable Type misconfiguration in `mt-config.cgi` shows up in the
Starman startup log.

The public traffic flow is the same as for PHP-FPM. **Public traffic
is routed from `Proxy Rules` to the generated PSGI upstream target**.
The Runtime App's `hostname` is **Starman's listen host / address**,
not a public VirtualHost name.

## 11.3 Process controls

After saving and materializing a PSGI Runtime App, control the process
with:

```bash
make psgi-up     RUNTIME_APP=mt-site
make psgi-reload RUNTIME_APP=mt-site
make psgi-down   RUNTIME_APP=mt-site
```

The same operations are available from **PSGI Processes** in
`/options`.

PHP-FPM controls are at the **runtime (language version) level** with
`make php-fpm-up RUNTIME=php83`, while PSGI controls are at the
**Runtime App level**. With one Starman process per Movable Type
site, when you co-host multiple sites you operate each one with its
own `RUNTIME_APP=...`.

## 11.4 Build

The PSGI runtime bundle build commands:

```bash
make psgi-build VER=5.38
# or
make psgi-build RUNTIME=perl538
```

Current aliases:

- `perl536`
- `perl538`
- `perl540`

The build produces these artifacts under
`data/psgi/binaries/<runtime_id>/`:

- `perl`
- `starman`
- `runtime.json`
- `modules.json`

### 11.4.1 Major modules included in the bundled runtime

The bundled runtime ships with the major optional modules used by
Movable Type:

- **PSGI / Plack** ecosystem
- **MySQL / SQLite DB drivers**
- **Image drivers**: `GD` / `Imager`
- **Archive / XML helpers**
- **XML-RPC over Plack**
- **SMTP TLS / SASL**
- **Cache helpers**
- **OpenID-era compatibility modules**
- **`IPC::Run`**

Reiterating: **`mt-config.cgi` is the application's responsibility**.
For image processing, configure `ImageDriver GD` or `ImageDriver
Imager` on the Movable Type side.

## 11.5 Notes

- A PSGI listener is identified by the **(hostname, listen_port)
  tuple**.
- **Starman workers consume memory per Runtime App.** For Movable
  Type, set worker count **explicitly to a small number** until
  traffic justifies more.
- As with PHP-FPM, `generated_target` is server-owned and is referenced
  from `Proxy Rules` as a generated upstream. There is no need to
  hand-write a raw protocol URL like `fcgi://`.

## 11.6 Recap

- The PSGI runtime is the mechanism for putting Movable Type and
  other Perl PSGI applications under tukuyomi management.
- Build the runtime bundle with `make psgi-build VER=...` (or
  `RUNTIME=perl538`).
- **Runtime App and Starman process are 1:1.** Tune worker count and
  max requests per vhost.
- Static assets come from `document_root`; dynamic requests flow
  through the `@psgi` sentinel to Starman.
- Application configuration like `mt-config.cgi` is **outside
  tukuyomi management**.

## 11.7 Bridge to the next chapter

Chapter 12 covers the third leg of Runtime Apps: **scheduled tasks**.
The chapter is about running cron-style PHP CLI tasks on tukuyomi in
a structured way and choosing the right deployment pattern for binary
or container deployment.
