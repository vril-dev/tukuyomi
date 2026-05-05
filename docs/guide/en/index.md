---
title: "tukuyomi Operation Guide"
subtitle: "Deploying and operating an application-edge control plane built around Coraza + CRS WAF"
language: en
audience: "Engineers who deploy and operate tukuyomi (infra / SRE / platform)"
version: "based on 1.3.0"
build: "pandoc → HTML → Chrome headless"
---

# tukuyomi Operation Guide (English Edition)

This book is a structured edition of the English documentation in the tukuyomi
repository (`README.md` and `docs/**/*.md`), re-organized so that an engineer
can read it from cover to cover.

## Editorial policy

- **Audience**: SRE / infra engineers introducing tukuyomi, and operators with
  prior WAF / reverse-proxy experience. Linux, Docker, HTTP, TLS, and systemd
  fundamentals are assumed.
- **Tone**: technical prose. Configuration keys, table names, and Make targets
  are kept verbatim from the upstream repository.
- **Structure**: every chapter follows the same flow ─ overview → mechanics →
  configuration example → operational notes.
- **Consistency**: setting key names, table names, and Make targets match the
  upstream repository exactly so that readers can trace any reference back to
  the source.

## Table of contents

### Part I — Introduction

- **Chapter 1. Introducing tukuyomi** — Where the product sits, and the picture
  of a single-binary application-edge control plane.
- **Chapter 2. Quick start** — Bringing up a local preview with
  `make preset-apply` and `make gateway-preview-up`, and reaching the Gateway
  UI / API.

### Part II — Deployment

- **Chapter 3. Binary deployment (systemd)** — `make install TARGET=linux-systemd`
  in detail: runtime layout, persistent byte storage, public/admin listener
  split, PHP-FPM bundles, environment file, overload tuning, secret handling,
  socket activation. (source: docs/build/binary-deployment.md)
- **Chapter 4. Container deployment** — Support tiers, the current official
  topology, ECS / Kubernetes / Azure Container Apps deployment artifacts,
  shared writable paths, config / secret delivery.
  (source: docs/build/container-deployment.md)

### Part III — Reverse proxy

- **Chapter 5. Routing, Upstreams, and Backend Pools** — The three-layer model,
  route-scoped pool examples, sticky sessions, dynamic DNS backend discovery,
  the `Backends` panel, and runtime operations on direct named upstreams.
  (sources: README.md, docs/reference/operator-reference.md)
- **Chapter 6. Upstream HTTP/2 and h2c** — `force_http2` / `h2c_upstream`
  semantics, mixed topologies, TLS controls, and how direct route targets
  behave. (source: docs/operations/upstream-http2.md)

### Part IV — WAF and request security

- **Chapter 7. Tuning WAF false positives** — Capturing evidence, scoping
  impact, narrow mitigations (`override_rules` / managed bypass), CRS review,
  validation, change management. (source: docs/operations/waf-tuning.md)
- **Chapter 8. FP Tuner API and AI integration** — Propose / Apply contract,
  simulate vs. real apply, related env, OpenAI- / Claude Messages-compatible
  command providers. (source: docs/operations/fp-tuner-api.md)
- **Chapter 9. Request-time security plugins** — The boundary between metadata
  resolvers and request-security plugins, the `SecurityEvent` contract,
  ordering, bounded shared feedback, registration, a minimal example, and
  design rules. (source: docs/request_security_plugins.md)

### Part V — Runtime Apps and scheduled tasks

- **Chapter 10. PHP-FPM runtime and Runtime Apps** — Responsibilities, data
  layout, runtime build and inventory, the Runtime App flow, the upstream /
  Runtime App boundary, process lifecycle, smoke tests.
  (source: docs/operations/php-fpm-vhosts.md)
- **Chapter 11. PSGI runtime (Movable Type, etc.)** — Runtime model, the
  Movable Type shape, process controls, build.
  (source: docs/operations/psgi-vhosts.md)
- **Chapter 12. Scheduled tasks** — Separation of concerns, data layout, task
  model, UI workflow, runner command, binary / container deployment patterns,
  bundled PHP CLI, GeoIP refresh.
  (source: docs/operations/php-scheduled-tasks.md)

### Part VI — Operations and troubleshooting

- **Chapter 13. DB operations (SQLite / MySQL / PostgreSQL)** — Driver
  selection, what is stored (`waf_events`, versioned runtime config,
  `config_blobs`, `schema_migrations`), retention / pruning, backup, SQLite
  vacuum, recovery. (source: docs/operations/db-ops.md)
- **Chapter 14. Listener topology and reuse-port** — The current decision and
  why it is parked, host / runtime matrix, Docker published-port policy,
  benchmark / smoke gate shape, reopen checklist.
  (sources: docs/operations/listener-topology.md, reuseport-policy.md,
  reuseport-evaluation.md)
- **Chapter 15. HTTP/3 and TLS** — Built-in TLS termination, ACME automatic
  TLS, the dedicated HTTP/3 listener, `server.tls.redirect_http`,
  HTTP/3 public-entry smoke.
  (sources: operator-reference.md, docs/operations/http3-public-entry-smoke.md)
- **Chapter 16. IoT / Edge device enrollment** — Roles, operator flow,
  Center-managed device views, runtime deployment, preview URL, Center URL
  rules, identity and fingerprint, token handling, troubleshooting.
  (source: docs/operations/device-auth-enrollment.md)
- **Chapter 17. Remote SSH** — Center-managed maintenance access without an
  inbound Gateway SSH port, Web Terminal, CLI handoff, session policy,
  termination, scrollback, troubleshooting. (source: docs/remote-ssh.md)

### Part VII — Performance and regression

- **Chapter 18. Benchmark and regression matrix** — `make bench-proxy` /
  `make bench-waf` / `make bench-full`, input parameters, the canonical
  output, profile capture, threshold policy, the role of the `make smoke`
  family, the recommended confidence ladder, release-binary smoke.
  (sources: benchmark-baseline.md, regression-matrix.md,
  release-binary-smoke.md)
- **Chapter 19. Static fast-path evaluation** — The decision and reasons,
  where zero-copy fits poorly, the bounded fast-paths already in place,
  conditions for reopening. (source: docs/operations/static-fastpath-evaluation.md)

### Appendices

- **Appendix A. Operator reference** — Every block of `data/conf/config.json`
  and DB `app_config_*`, inbound timeout boundary, overload backpressure,
  persistent file storage, host-network hardening, the admin dashboard, the
  Make target index, the admin API.
  (sources: docs/reference/operator-reference.md, docs/api/admin-openapi.yaml)
- **Appendix B. Release notes (v1.3.0 / v1.2.0 / v1.1.0)** — Remote SSH
  Web Terminal and session controls (v1.3.0); Center, IoT / Edge enrollment,
  `INSTALL_ROLE`, device approval lifecycle (v1.2.0); DB-backed runtime
  authority, admin authentication overhaul, `make install` (v1.1.0).
  (source: GitHub Releases tags)

## File layout

```
books/tukuyomi-en/
├── index.md            … this file (TOC and editorial policy)
├── 00-preface.md       … Preface
├── 01-introduction.md  … Chapter 1
├── 02-quickstart.md    … Chapter 2
├── 03-...〜19-...md    … Chapters 3 to 19
├── A-operator-reference.md
└── B-release-notes.md
```

UI sample images are shared from `docs/images/ui-samples/` and referenced from
this book with the relative path `../../images/ui-samples/`.

## Build notes

- Single PDF: chapter files are concatenated by pandoc in the order listed in
  this file; cover, table of contents, and chapter numbers are generated
  automatically.
- HTML intermediate: pandoc HTML5 output is rendered with Noto Sans CJK / IPAex
  fonts, chapter-front page-break CSS, and monospace styling for code blocks.
- Print: `google-chrome --headless --print-to-pdf` writes the final PDF; A4
  margins are unified via `@page`, with the page number centered in the
  footer.
- Build script: `scripts/build-pdf-en.sh`.
