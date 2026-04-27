[English](psgi-vhosts.md) | [日本語](psgi-vhosts.ja.md)

# PSGI Runtime And Runtime Apps

PSGI support is intended for Movable Type and other Perl PSGI apps that should be managed by tukuyomi without running a separate reverse proxy stack.

## Runtime Model

- `make psgi-build VER=5.38` builds a bundled Perl/Starman runtime under `data/psgi/binaries/perl538`.
- The runtime inventory is exposed on `/options` and persisted in DB as `psgi_runtime_inventory`.
- A PSGI Runtime App selects one runtime and defines `app_root`, `psgi_file`, static `document_root`, runtime listen `hostname`/`listen_port`, worker count, max requests, optional `extlib`, and environment variables.
- tukuyomi supervises one Starman process per PSGI Runtime App. This is intentionally different from PHP-FPM, where one PHP-FPM master can own multiple pools.

## Movable Type Shape

For Movable Type, use:

- `app_root`: extracted Movable Type application directory
- `psgi_file`: `mt.psgi`
- `document_root`: the public static directory, usually `mt-static`
- `try_files`: `$uri`, `$uri/`, `@psgi`
- `include_extlib`: enabled when the application carries `extlib/`

Static files are served directly from `document_root`; dynamic requests fall through to Starman through the `@psgi` sentinel.
Movable Type application config such as `mt-config.cgi`, `CGIPath`, database DSN, and plugin settings remains application-owned. tukuyomi validates runtime files and paths before saving a PSGI Runtime App, but application-specific config errors are reported by the PSGI process at start time.

Route public traffic from `Proxy Rules` to the generated PSGI upstream target.
The Runtime App `hostname` field is the Starman listen host/address, not a public
VirtualHost name.

## Process Controls

Once a PSGI Runtime App is saved and materialized:

```sh
make psgi-up RUNTIME_APP=mt-site
make psgi-reload RUNTIME_APP=mt-site
make psgi-down RUNTIME_APP=mt-site
```

The same controls are available from `/options` under PSGI Processes.

## Build

```sh
make psgi-build VER=5.38
# or
make psgi-build RUNTIME=perl538
```

Supported aliases are currently `perl536`, `perl538`, and `perl540`.

The build writes:

- `data/psgi/binaries/<runtime_id>/perl`
- `data/psgi/binaries/<runtime_id>/starman`
- `data/psgi/binaries/<runtime_id>/runtime.json`
- `data/psgi/binaries/<runtime_id>/modules.json`

The bundled runtime includes MT-oriented optional modules for common production
flows: PSGI/Plack, MySQL/SQLite DB drivers, `GD` and `Imager` image drivers,
archive/XML helpers, XML-RPC over Plack, SMTP TLS/SASL support, cache helpers,
OpenID-era compatibility modules, and `IPC::Run`.
Movable Type still owns `mt-config.cgi`; set `ImageDriver GD` or
`ImageDriver Imager` there when image processing is needed.

## Notes

- PSGI listeners are identified by the configured `hostname` and `listen_port` pair.
- Starman workers consume memory per Runtime App. Keep the worker count explicit and small for Movable Type unless traffic requires otherwise.
