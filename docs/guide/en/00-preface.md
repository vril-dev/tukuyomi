# Preface

This book is an English-language guide to deploying and operating
**tukuyomi**, an application-edge control plane built around the Coraza +
OWASP CRS WAF.

tukuyomi bundles a reverse proxy, the WAF, request-boundary security controls,
optional PHP-FPM / PSGI Runtime Apps, scheduled jobs, and Center-approved
IoT / Edge device enrollment into a **single binary**. It is designed to be
deployed in front of a web service as a WAF + reverse proxy, while also
managing PHP / Perl Runtime Apps and scheduled jobs from the same binary.

## Who this book is for

- Engineers responsible for deploying and operating a WAF and reverse proxy
  in front of a web service.
- Anyone looking for a single-binary, structured WAF + reverse-proxy product.
- Operators who run PHP-FPM or PSGI applications in-house and want to unify
  their execution layer with the edge.
- Teams who need a Center-approved device identity for IoT / Edge gateways.

The book assumes you are already familiar with the basics of Linux, Docker,
HTTP/HTTPS, TLS, systemd, and reverse proxies. Prior experience with Coraza or
OWASP CRS is not required.

## Reference version

This book is written against **tukuyomi v1.2.0**.

If a configuration key or Make target name changes in a later release, treat
the release notes attached to each GitHub Releases tag and the latest
`README.md` in the upstream repository as the authoritative source.

## How to read

Reading Parts I through VII in order takes you from initial validation, to
production operation, to performance evaluation, to regression checks.

Readers who already run tukuyomi and want a single topic can jump straight to
the relevant chapter via the table of contents. Each chapter follows the same
shape — overview → mechanics → configuration example → operational notes —
and reads as a self-contained unit.

The closing **Appendix A: Operator reference** is a dictionary-style reference
that lists every block of `data/conf/config.json` and DB `app_config_*`. When
you need to look up a specific configuration key, going to Appendix A first is
often faster than scanning the prose.

## Conventions

- Source paths, configuration files, DB table names, and Make target names use
  the same spelling as the upstream repository — for example `Proxy Rules >
  Backend Pools`, `make crs-install`, the `waf_events` table — and appear
  verbatim in the text.
- Inline command snippets and key names are typeset as `code` so that they
  remain searchable when you grep the upstream sources.

With that out of the way, Chapter 1 takes the bird's-eye view: where tukuyomi
sits in the picture, and what it bundles into a single binary.
