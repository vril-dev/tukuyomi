# Appendix B. Release notes

This appendix collects excerpts from the release notes for the latest releases
— including this book's reference version — polished for book reading. They are
presented newest-first: **v1.3.0**, **v1.2.0**, then **v1.1.0**. For later
releases, treat the release notes attached to GitHub Releases tags as the
authoritative source.

This book is written against **v1.3.0**. Remote SSH first appears as an
operator-facing chapter in v1.3.0. Center / IoT / Edge enrollment first appears
in v1.2.0. v1.1.0 is included as the preceding major step (DB-backed runtime
authority, the admin auth overhaul, and `make install`).

---

# Section B-1 — v1.3.0 release notes

> Reference base: v1.2.x

v1.3.0 extends the Center-managed Gateway model with **Remote SSH**. The
feature behind **Chapter 17** lets operators open short-lived maintenance
sessions through Center without exposing an inbound SSH port on the Gateway.

## B1.1 Major changes

- **Remote SSH Web Terminal** is added to the Center device menu.
- **CLI handoff** remains available through `tukuyomi remote-ssh`.
- Center records Remote SSH session state, mode, reason, TTL, timestamps,
  Gateway attachment, operator attachment, close reason, and termination.
- Gateway runs an embedded SSH server only for signed, Center-approved pending
  sessions.
- Browser terminal scrollback is configurable per Web Terminal session.
- Operators can terminate pending or active sessions from Center.

## B1.2 Operational notes

- Remote SSH is disabled by default on both Center and Gateway.
- A Gateway must be approved by Center before Remote SSH can be used.
- Web Terminal connection pickup depends on the Gateway's Center polling
  interval. A wait near one polling interval can be normal.
- TTL and idle timeout close sessions even if the browser remains open.
- Browser scrollback is display history, not an audit recording.
- Gateway refuses to start a shell as root unless a run-as user is configured.

## B1.3 Compatibility and migration

- A DB migration adds the Remote SSH operator mode used to distinguish CLI and
  Web Terminal sessions.
- Existing Gateway proxy traffic behavior is unchanged while Remote SSH remains
  disabled.
- The CLI path remains supported for emergency and automation workflows.

---

# Section B-2 — v1.2.0 release notes

> Reference base: v1.1.8

v1.2.0 adds **Tukuyomi Center**, **IoT / Edge enrollment**, and the
**device approval workflow**, while tidying up install role and
frontend build safety. The features behind **Chapter 16** of this book
ship in this release.

## B2.1 Major changes

- **Center mode is added to the same single binary.** Use
  `INSTALL_ROLE` at host install time to install Gateway and Center
  separately.
- **The Center UI is added.** It covers login, status, user account
  management, and device-enrollment approval.
- **IoT / Edge mode is added on the Gateway.** When enabled, public
  proxy traffic is locked until the local Gateway identity is
  approved by the Center.
- **One-time enrollment tokens** are added on the Center side. The
  Gateway generates an Ed25519 device identity and submits a signed
  enrollment request to the Center.
- The **registered-device lifecycle** is added on the Center side —
  including approval revocation and archiving of revoked devices.
- A revoked Gateway can **resubmit for approval with a new token while
  keeping the same device identity**.
- Local validation gains **`make center-preview-up`**,
  **`make gateway-preview-up`**, and **`make fleet-preview-up`**.
- Frontend dependency locks are updated and **all npm audit findings
  are resolved**. The Gateway UI is **page-level code-split**, and
  Vite's chunk-size warning is gone.

## B2.2 Operational notes

- **IoT / Edge mode is OFF by default.** On Web / VPS deployments,
  enable it only when you intentionally want this Gateway approved by
  the Center as an edge device.
- In IoT / Edge mode, **the Gateway's public proxy path rejects
  traffic while the device is unapproved**. The local recovery admin
  UI / API remains usable.
- Center approval is **not yet a push channel**. The Gateway
  refreshes Center device state via UI action or the configured
  polling interval.
- Enrollment tokens are **one-time secrets**. The Center shows the
  full token only at creation time. **Do not try to recover a lost
  token; create a new one.**
- The Gateway stores the generated device private key locally. The
  Center stores a public key fingerprint and the approval state.
- The public key fingerprint shown on Gateway / Center is
  **lowercase hex of SHA-256 of the DER-encoded Ed25519 public key**.
- A Gateway whose local state is `pending` or `approved` **rejects
  enrollment requests** to avoid accidentally consuming a replacement
  token.
- A Gateway can resubmit only in **replacement states**: `revoked`,
  `archived`, `failed`, `product_changed`.
- Revoking an enrollment token also revokes devices registered with
  it — except that **archived devices are not restored** for audit
  retention.
- **Archive hides** revoked devices from the default registered-device
  list. It **does not delete** the audit trail.
- `tukuyomi center` is a separate process mode from the Gateway, but
  the binary is the **same single binary**.

## B2.3 Deployment

- `make install TARGET=linux-systemd INSTALL_ROLE=gateway` installs
  the Gateway.
- `make install TARGET=linux-systemd INSTALL_ROLE=center` installs
  the Center.
- `INSTALL_ROLE` defaults to **`gateway`** for backwards
  compatibility.
- The installer generates **role-appropriate systemd units and
  runtime environment files**.
- The preview flow now splits into **Gateway / Center / fleet**:
  - `make gateway-preview-up`
  - `make center-preview-up`
  - `make fleet-preview-up`
- `GATEWAY_PREVIEW_PERSIST=1` keeps Gateway preview DB / config state
  across preview restarts.
- `CENTER_PREVIEW_PERSIST=1` keeps Center preview DB state across
  preview restarts.

## B2.4 Admin UI

- Gateway Options gains **IoT / Edge mode**, **Center enrollment
  status**, **Center URL**, **enrollment token entry**, and
  **Center status refresh**.
- Gateway Options exposes the **Center polling interval** for IoT /
  Edge status refresh.
- The Gateway shows **proxy traffic as available or locked** based on
  device approval state.
- **The Center UI matches the Gateway admin UI's visual style.**
- **Center Status focuses on device overview counts.**
- **Center Device Approvals** manages enrollment tokens, pending
  approvals, registered devices, revoked devices, and archived
  devices.
- **Center User** manages username, email, password, and personal
  access tokens.
- **Browser sessions for Gateway and Center are separated** — you can
  be logged into both UIs from the same browser at once.

## B2.5 Build / development

- Gateway / Center UI build requires **Node.js 24 LTS** and
  **`npm >=11`**.
- **`.nvmrc` now points at Node 24.**
- CI already uses Node 24. The sample deployment Dockerfile builds the
  UI with Node 24 too.
- Gateway UI routes are **lazy-loaded** so large admin pages do not
  bloat the initial JavaScript bundle.
- After the dependency lock update,
  `npm audit --audit-level=moderate` is **0 findings** for both
  Gateway and Center UIs.

## B2.6 Documentation

- Device-enrollment operation docs are added: **Center token
  creation, Gateway approval request, Center approval, status
  refresh, re-approval**.
- The root README adds **IoT / Edge enrollment and Center install
  flow**.
- Binary deployment docs add **`INSTALL_ROLE=gateway|center`**.
- **A Center service / env deployment example** is added.
- Old product-family comparison pages are removed. **Tukuyomi is
  documented as a single product with Gateway / Center / Web / IoT
  capability**, not as separate product names.

## B2.7 Compatibility and migration

- **A DB migration is required before starting v1.2.0.**
- The new schema adds **Center enrollment tokens, the Gateway edge
  device identity, the Center status cache, device revocation, and
  device archive state**.
- `INSTALL_ROLE` defaults to `gateway`, so **existing Gateway install
  commands still install the Gateway as before**.
- While `edge.enabled=false`, **existing non-IoT traffic behavior is
  unchanged**.
- The bundled config example explicitly states `edge.enabled` and
  defaults to **false**.
- **UI builds on Node 18 are not supported.** Follow `.nvmrc` and the
  package `engines` and use Node 24 LTS.

## B2.8 Known limitations

- The current Center scope is **device enrollment and approval**.
  Gateway config push, log collection, and Gateway binary upgrade
  management are **not yet implemented**.
- Center state refresh is **polling-based**. Immediate push from the
  Center to the Gateway is **not in this release**.
- Proxy-path protection through device approval **only operates when
  IoT / Edge mode is enabled**.

---

# Section B-3 — v1.1.0 release notes

> Reference base: v1.0.1

v1.1.0 **moves runtime configuration to DB management**, hardens the
deployment procedure, and lays the groundwork for **operating across
multiple environments**. The rule that this book references throughout
— "the DB is the runtime authority, JSON is seed / import / export" —
is established firmly in this release.

## B3.1 Major changes

- **Normalized runtime configuration is now authoritative in the
  DB.** `config.json` mostly carries the bootstrap minimum needed to
  start, such as DB connection details.
- **WAF rule assets are managed as DB-backed assets.** Both base
  rule assets and operator-added assets are supported.
- **WAF event persistence is now asynchronous** to reduce impact on
  the proxy path.
- **Admin access drops the static admin API key** in favor of
  **DB-backed admin user authentication** (Argon2id password hash,
  signed browser session, CSRF protection).
- **Per-site ACME TLS settings are configurable in `Sites`.** Choose
  production / staging and an optional account email.
- **ACME cache material can persist on local or S3.** Azure Blob /
  GCS exist as configuration values, but the adapters are not
  implemented in this build, so selecting them produces a validation
  error.
- Production seed data lives in **`seeds/conf/config-bundle.json`**. Edit the
  bundle domains when adjusting initial-import data, not Go code.
- **`make install TARGET=linux-systemd`** is added for Linux host
  install. **`make deploy-render`** generates deployment artifacts
  for container platforms.

## B3.2 Operational notes

- **The file-backed runtime fallback for policy / rule domains is
  removed from the active runtime path.** Restore or seed via the DB
  import flow rather than relying on `data/conf/rules`,
  `data/rules`, or `data/geoip` restoration.
- WAF rule material that Coraza needs as a filesystem view is staged
  under **`data/tmp`**.
- Keep `conf/config.json` **minimal**. The storage bootstrap is
  required, but policy and runtime domains live in the DB.
- **For local validation only**, set
  `admin.allow_insecure_defaults` explicitly.
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` and
  `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` create the **initial
  administrator account**. The step is skipped when an admin user
  already exists.
- Adjust initial import data by editing `seeds/conf/config-bundle.json`. After import,
  the data normalized in the DB is the runtime authority.
- `make ui-preview-up` generates a Git-untracked preview-only
  configuration `conf/config.ui-preview.json` and sets a random
  session secret. It does **not** weaken or rewrite the
  Git-tracked startup configuration.
- Persistent storage provider credentials are read from the
  environment or platform identity. **They are not stored in JSON
  config.**
- When installing under a login user's home directory, the installer
  defaults to using that user as the runtime user and skips
  `useradd`. For system prefixes such as `/opt/tukuyomi`, it still
  defaults to creating the `tukuyomi` system user.
- The first install seed creates a default upstream named **`primary`**.
  Replace it with your real backend endpoint before sending real
  proxy traffic.

## B3.3 Admin UI

- The admin UI logs in with **username / password** and issues a
  **signed browser session cookie**.
- **Rules / Rule Sets are restructured** to fit DB-backed assets and
  Coraza's responsibilities.
- Security navigation **separates Coraza-specific settings from
  request controls**.
- **Logs display newest-first.** The list copy action is removed; on
  narrow screens, horizontal scroll is used instead.
- Cache Rules **save / error feedback appears next to the relevant
  action**.
- **`Sites`** edits ACME settings for site-level automatic TLS.
- **`Settings`** manages persistent storage configuration, admin
  session state, and operator identity metadata. Credentials are
  not stored.

## B3.4 Deployment

- **`make install TARGET=linux-systemd`** runs build, runtime tree
  creation, DB migration, WAF / CRS asset import, the optional
  first-run DB seed, and systemd-unit installation.
- **`make deploy-render`** generates deployment artifacts for
  container images, ECS, Kubernetes, and Azure Container Apps.
- **`make ui-preview-up`** builds and syncs the admin UI, generates a
  preview bootstrap config, resets and seeds a preview SQLite DB, and
  starts `coraza` and the scheduled-task runner.
- PHP-FPM runtime bundles are built with **`make php-fpm-build
  RUNTIME=<id>`** and placed into the installed tree with
  **`make php-fpm-copy`**.
- The runtime layout **separates responsibilities** for persistent
  data, temporary material, cache, audit output, and the DB file.

## B3.5 Fixes

- After moving to the DB-backed runtime, **PHP runtime inventory
  auto-discovery is preserved**.
- **Load order is fixed** so that PHP runtime cleanup before vhost
  load does not erase installed runtimes.
- Managed GeoIP update is fixed to treat **only the country edition**
  as the active country DB.
- The cache store runtime directory's **prepare and mount behavior**
  is fixed.
- **Runtime user selection** for installs under a home prefix is
  fixed.
- The DB-backed policy screens no longer conflict on **first save**
  when the installed DB has no active version of the relevant
  policy domain.
- Editing a host scope in Cache Rules **no longer remounts the
  editor mid-typing**, preserving focus.
- SMTP notification address validation **correctly rejects values
  without `host:port`**.
- Scheduled Tasks smoke tests now check **task state and stdout /
  stderr log output** across the binary, compose, and preview
  paths.
- `make ui-preview-up` **starts on the preview-only configuration
  even when** the startup config has no `admin.session_secret`.

## B3.6 Compatibility and migration

- **A DB migration is required before starting v1.1.0.**
- The admin authentication migration adds **`admin_users` /
  `admin_sessions` / `admin_api_tokens`**. **Existing static admin
  API keys can no longer be used for UI login.**
- **File seed material is usable for first-run import or explicit
  import workflows**, but treat the active runtime after import as
  DB-backed.
- **Changing `admin.session_secret` invalidates browser sessions and
  the admin tokens HMAC-peppered with the old secret.**
- **Azure Blob / GCS persistent storage settings are reserved for
  future adapters.** Selecting them in this build returns a
  validation error.

---

That covers the v1.3.0, v1.2.0, and v1.1.0 release notes, the main body, and
appendices A and B.

The book follows the upstream repository documentation -- `README.md` and
`docs/**/*.md` -- as primary sources. When in doubt, prefer the upstream
documentation.
