# tukuyomi Regression Matrix

This document maps the existing local validation commands to the operator-facing guarantees they actually provide.
Use it when you need to choose the smallest command that still proves the behavior you care about.

## Command intent

| Command | Primary purpose | When to run it |
| --- | --- | --- |
| `make smoke` | Fast admin and routed-proxy regression against the normal compose stack | Before everyday commits and config changes |
| `make deployment-smoke` | Replay the documented binary/systemd and sample-container guides | Before changing `docs/build`, packaging, or runtime layout |
| `make release-binary-smoke` | Build/extract the public tarball and validate the bundle-local Docker smoke | Before publishing binary artifacts |
| `make http3-public-entry-smoke` | Validate the built-in HTTPS + HTTP/3 listener with a live runtime | After changing TLS/HTTP/3 listener behavior or before recommending direct H3 ingress |
| `make smoke-extended` | `smoke` + `deployment-smoke` | Before releases or when you changed both runtime and deployment docs |
| `make ci-local` | `check` + `smoke` | Local CI baseline before opening a PR |
| `make ci-local-extended` | `check` + `smoke-extended` | Local release/readiness sweep |
| `make gotestwaf` | WAF effectiveness and false-positive regression | Before releases and after CRS / request-inspection changes |
| `make bench` / `make bench-proxy` | Proxy transport throughput/latency baseline | After proxy transport tuning changes |
| `make bench-waf` | WAF allow/block throughput/latency baseline | After WAF inspection, CRS, bypass, or logging changes |
| `make bench-full` | Proxy and WAF performance baselines | Before performance-sensitive releases |

## Guarantee matrix

Benchmark targets are intentionally omitted from this deterministic guarantee matrix.
They produce human-reviewed performance artifacts and may fail on optional thresholds, but they are not routine CI gates.

Legend:

- `yes`: directly validated by the command
- `partial`: indirectly covered, but not the command's main assertion set
- `no`: not covered by routine automation

| Behavior | `make smoke` | `make deployment-smoke` | `make release-binary-smoke` | `make http3-public-entry-smoke` | `make smoke-extended` | `make ci-local` | `make ci-local-extended` | `make gotestwaf` |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Admin login creates signed session cookie | yes | yes | yes | no | yes | yes | yes | no |
| Admin session status endpoint works after login | yes | yes | yes | no | yes | yes | yes | no |
| Session logout invalidates browser auth | yes | yes | yes | no | yes | yes | yes | no |
| Session-backed mutating admin calls include CSRF token | yes | yes | yes | no | yes | yes | yes | no |
| Embedded admin UI is reachable | yes | yes | no | no | yes | yes | yes | no |
| Routed proxy behavior (host/path/query/header rewrite) | yes | yes | yes | yes | yes | yes | yes | no |
| Client-facing gzip response compression | yes | yes | yes | no | yes | yes | yes | no |
| Built-in HTTPS listener boot with manual certificate | no | no | no | yes | no | no | no | no |
| HTTPS response advertises `Alt-Svc` | no | no | no | yes | no | no | no | no |
| Actual HTTP/3 request over UDP succeeds | no | no | no | yes | no | no | no | no |
| Deterministic WAF block on the release fixture | no | no | yes | no | no | no | no | yes |
| Binary / systemd deployment guide validity | no | yes | no | no | yes | no | yes | no |
| Container deployment guide validity | no | yes | no | no | yes | no | yes | no |
| Release-binary runtime layout and staged writable paths | no | no | yes | no | no | no | no | no |
| WAF effectiveness against larger attack suites | no | no | no | no | no | no | no | yes |

## What each command really proves

### `make smoke`

This is the fastest operator-facing regression for the normal compose stack.
It proves:

- the embedded admin UI is served
- login transitions the browser from API key bootstrap to signed session cookie
- `/auth/session` and `/auth/logout` behave correctly
- session-backed admin mutations send `X-CSRF-Token`
- routed proxy rules validate, dry-run, apply, and affect live traffic
- client-facing gzip is emitted when the client sends `Accept-Encoding: gzip`

It does not prove deployment guides, release-binary layout, GoTestWAF coverage, or HTTP/3 public entry.

### `make deployment-smoke`

This replays the operator docs under `docs/build/`.
It proves:

- the staged binary/systemd-style runtime tree is sufficient to boot `tukuyomi`
- split public/admin listener mode still works from a staged binary
- the sample container image in `docs/build/Dockerfile.example` is runnable
- the same admin session, CSRF, routed proxy, and gzip checks used by `make smoke` still pass after packaging
- split mode still keeps admin paths off the public listener and arbitrary proxy traffic off the admin listener
- expected writable runtime paths and generated audit logs exist

It is the right command after changing deployment docs, startup layout, sample Dockerfiles, or packaged assets.

### `make smoke-extended`

This is the release-oriented combination:

- all normal compose-stack smoke guarantees
- plus both deployment-guide replays

Use it when you want confidence that runtime behavior and operator docs still line up.

### `make release-binary-smoke`

This is the dedicated top-level smoke for the public tarball itself.
It proves:

- the release tarball can be built and extracted locally
- the extracted bundle contains a runnable `testenv/release-binary/`
- the bundle-local setup and smoke scripts still work
- admin session flow, routed proxy behavior, gzip, and deterministic WAF blocking still work from the public artifact

Use it before uploading release assets or publishing a version in `[release]`.

### `make http3-public-entry-smoke`

This is the dedicated live-runtime smoke for the built-in HTTPS + HTTP/3 listener.
It proves:

- `tukuyomi` can boot with built-in TLS enabled
- HTTPS responses advertise `Alt-Svc`
- `/tukuyomi-api/status` reports the HTTP/3 listener as enabled and advertised
- an actual HTTP/3 request over UDP succeeds against the live runtime
- routed proxy traffic still works when entering through the HTTPS listener

It is intentionally separate from the normal smoke ladder because it depends on TLS, UDP, and a temporary self-signed certificate.

### `make ci-local`

This is the local PR baseline:

- `make check`
  - Go tests
  - UI tests
  - compose config validation
- plus `make smoke`

It is the smallest "would I be comfortable opening a PR" gate.

### `make ci-local-extended`

This is the stronger local release/readiness gate:

- everything from `make ci-local`
- plus deployment-guide replays via `make smoke-extended`

Use it before tagging, packaging, or rewriting deployment documentation.

### `make gotestwaf`

This does not validate admin UI or deployment guides.
It proves:

- the current WAF configuration blocks enough true-positive attacks to satisfy the configured threshold
- optional false-positive and bypass thresholds still hold
- reports are produced under `data/tmp/gotestwaf/`

Use it after CRS, request-inspection, bypass, semantic, or rate-limit changes that could alter enforcement behavior.

### `make bench` / `make bench-proxy`

This is the proxy transport benchmark.
It measures the existing proxy tuning presets across the configured request count and concurrency levels, then writes Markdown and JSON artifacts under `data/tmp/reports/proxy/`.

Use it after changing upstream transport, buffering, compression, timeout, retry, or response handling behavior.

### `make bench-waf`

This is the WAF inspection benchmark.
It probes allow/block scenarios for their expected status, then measures throughput and latency across the configured concurrency levels.

Use it after changing CRS selection, request inspection, WAF logging, bypass behavior, or policy code that could add WAF-path overhead.
Use `make gotestwaf` separately when the question is detection quality rather than performance.

### `make bench-full`

This runs proxy and WAF benchmark targets in order.
Use it before performance-sensitive release work or when a change crosses both proxy transport and WAF inspection paths.

## Recommended confidence ladder

| Confidence level | Command |
| --- | --- |
| Quick runtime sanity | `make smoke` |
| Local CI baseline | `make ci-local` |
| Deployment-doc validation | `make deployment-smoke` |
| Public binary artifact validation | `make release-binary-smoke VERSION=vX.Y.Z` |
| Release readiness without WAF corpus | `make ci-local-extended` |
| Release readiness with WAF corpus | `make ci-local-extended && make gotestwaf` |
| Proxy performance comparison | `make bench-proxy` |
| WAF performance comparison | `make bench-waf` |
| Combined performance comparison | `make bench-full` |
| Direct HTTPS/HTTP/3 entry readiness | `make http3-public-entry-smoke` |
| Full public binary release readiness | `make ci-local-extended && make gotestwaf && make release-binary-smoke VERSION=vX.Y.Z` |

## Known routine-validation gaps

These areas are still outside the normal command set:

- full multi-arch public tarball smoke from one arbitrary workstation
  - `release-binary-smoke` now documents host-native default behavior, but non-native artifacts still need matching hardware, a release host, or explicit emulation policy

## Related docs

- binary/systemd deployment: [binary-deployment.md](../build/binary-deployment.md)
- container deployment: [container-deployment.md](../build/container-deployment.md)
- release-binary smoke: [release-binary-smoke.md](release-binary-smoke.md)
- HTTP/3 public-entry smoke: [http3-public-entry-smoke.md](http3-public-entry-smoke.md)
