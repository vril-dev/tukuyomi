# Chapter 4. Container deployment

This chapter covers running tukuyomi as a container. The platforms in scope
are ECS / Fargate, AKS / GKE / generic Kubernetes, Azure Container Apps, and
plain Docker / Docker Compose.

As with systemd deployment in Chapter 3, the underlying rule is "**the DB is
the runtime authority, JSON is seed / import / export material**". Container
deployment adds two more design questions: **what to mount** and **how
replicated / immutable to go**. We begin with the support tiers that frame
those decisions, then walk through platform-specific shapes.

## 4.1 Support tiers — how replicated can you go?

Container deployment for tukuyomi falls into three tiers today.

### Tier 1: mutable single-instance

**This is the only tier that is officially supported today.**

- One deployment unit.
- One public-facing `coraza` container, plus one internal
  `scheduled-task-runner` sidecar.
- The following writable paths are shared between them:
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - `/app/data/persistent` (when using local `persistent_storage`)
  - `/app/data/php-fpm` (when using bundled PHP-FPM)
- Live admin mutation is **allowed**.

The ECS / AKS / GKE / Azure Container Apps shapes later in this chapter
all assume Tier 1.

### Tier 2: immutable replicated rollout

**Not yet closed.** Some implementation guards are still pending:

- Multi-replica frontend is a follow-up.
- Configuration changes assume **rollout**, not live admin mutation.
- Frontend replicas require `admin.read_only=true`.
- Scheduler ownership must move from "co-located on each frontend" to a
  **dedicated singleton role**.

Until these guards are closed, replicated mutable admin deployment is not
treated as an official path.

### Tier 3: distributed mutable cluster

**Not supported.**

- No distributed config propagation.
- No leader election.
- No cluster-wide scheduler ownership.
- No multi-writer mutable runtime model.

## 4.2 The current official topology

On a container platform, the official topology is fixed as:

```text
client -> ALB / ingress / platform ingress -> coraza
```

with `scheduled-task-runner` running inside the same deployment unit.

Operational conditions:

- **Always exactly one** running unit.
- **Do not stack revisions** during rollout.
- `coraza` and `scheduled-task-runner` share the same writable runtime
  paths.
- Only `coraza` is exposed through the platform ingress / load balancer.

## 4.3 Public/admin listener split (containers)

Just as with systemd, you can place the public proxy listener on `:80` /
`:443` and split the admin UI / API onto a separate high port via
`admin.listen_addr`. Reference the sample at
`docs/build/config.split-listener.example.json`.

Operator contract:

- `server.listen_addr` stays the public listener.
- Setting `admin.listen_addr` removes the admin UI / API / auth from the
  public listener.
- Admin reachability is still controlled by `admin.external_mode` and
  `admin.trusted_cidrs`.
- Built-in TLS / HTTP redirect / HTTP/3 are public-listener-only.
- The listener split and the source guard are separate concerns; do not
  conflate them.
- On a container platform, **publish / route only the public listener**
  unless you specifically want to expose admin to a private network.

## 4.4 Container reload and rolling updates

Rather than re-execing the process inside the container, treat replacement
as a **platform rollout**:

- Readiness watches the public listener.
- Start the new task / pod before removing the old one.
- Stop new connections to the old task / pod at the ingress / load
  balancer.
- Keep the old task / pod alive for at least
  `server.graceful_shutdown_timeout_sec`.
- Within plain Docker / Kubernetes, **do not rely on systemd socket
  activation**.
- HTTP/3 does not guarantee QUIC connection continuity across process
  replacement, so client reconnects can occur during task / pod
  replacement.

## 4.5 If you go replicated immutable

If you intentionally pursue Tier 2 (replicated immutable frontend), do
**not** simply duplicate the single-instance sidecar; split roles
explicitly.

**Frontend replica role**:

- Serves HTTP only.
- Multiple replicas behind a platform ingress.
- `admin.read_only=true`.
- Holds no scheduled tasks.

**Dedicated scheduler role**:

- Stays singleton.
- Runs the same `run-scheduled-tasks` loop.
- Has no public ingress.
- Mounts the same source of truth: `/app/conf`,
  `/app/data/scheduled-tasks`, `/app/audit`, optionally
  `/app/data/persistent` / `/app/data/php-fpm`.

This is **not** a distributed mutable runtime. It is a design choice that
**explicitly carves scheduler ownership out** when you replicate frontends.

## 4.6 Build options

There are two practical ways to build a tukuyomi container image.

### 4.6.1 Use the repository Dockerfile directly

Build the embedded Gateway / Center UI first and use `server/Dockerfile`
as is.

```bash
make build
docker build -f server/Dockerfile -t tukuyomi:local server
```

This uses the repository Dockerfile together with the up-to-date
`server/internal/handler/admin_ui_dist` and
`server/internal/center/center_ui_dist`.

### 4.6.2 Use a deployment-style Dockerfile

`docs/build/Dockerfile.example` does the UI build, the Go build, runtime
config copy, and CRS install all inside the image build.

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

In this image, the binary path is `/app/tukuyomi`. The sample artifacts in
the rest of the chapter assume this image.

## 4.7 Rendering deployment artifacts

For cloud / container platforms you do not use `make install`. Instead,
generate manifests, review them, and feed them into the platform's apply
flow.

```bash
make deploy-render TARGET=container-image          IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=ecs                      IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=kubernetes               IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=azure-container-apps     IMAGE_URI=registry.example.com/tukuyomi:1.1.0
```

The output goes under `dist/deploy/<target>/` by default.

- `container-image`: a deployment Dockerfile and a local build helper (no
  registry push).
- `ecs`: artifacts for a single-instance task / service and for a replicated
  scheduler (no AWS API calls).
- `kubernetes`: YAML for single-instance and dedicated scheduler (no
  `kubectl apply`).
- `azure-container-apps`: YAML for single-instance and scheduler singleton
  (no Azure API calls).

To overwrite existing output, pass `DEPLOY_RENDER_OVERWRITE=1`.

## 4.8 Shared writable paths

For the official Tier 1 mutable single-instance, the **minimum required**
writable paths are:

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent` (when `persistent_storage.backend=local`)

If your operations cannot tolerate ephemeral local state, mount these from
the platform side.

Additionally:

- Mount `/app/data/php-fpm` if you use the **bundled PHP runtime** for
  `/options` / `/runtime-apps` / scheduled PHP CLI jobs.
- Mount along the lines of `/app/cache/response` (matching
  `cache_store.store_dir`) if you want the **internal response cache store**
  to survive node replacement.

The response cache is a cache, not the DB / runtime authority.

WAF / CRS import material is staged under `/app/data/tmp` and imported
into DB `waf_rule_assets`. The runtime reads **the active WAF / CRS asset
from the DB**, not from a mounted rules directory.

## 4.9 Config and secrets

`tukuyomi` uses `conf/config.json` as the DB connection bootstrap; all the
operator-managed app / proxy configuration is read from normalized DB
tables.

Typical production pattern:

- Render `conf/config.json` from a secret manager / config management
  system for `storage.db_driver` / `storage.db_path` /
  `storage.db_dsn`.
- Mount or bake `seeds/conf/config-bundle.json` as the bundled seed for an empty DB. When
  configured files like `conf/proxy.json` or policy JSON are present, they
  take precedence.
- Before the first start, run `make db-migrate` then `make crs-install` to
  install / import WAF rule assets, then `make db-import` for the rest of
  the seed material. `db-import` does not re-import WAF rule assets.
- Treat `conf/sites.json` / `conf/scheduled-tasks.json` /
  `conf/upstream-runtime.json` as seed / export files for an empty DB; the
  authoritative source after bootstrap is the normalized DB row.
- Limit runtime env injection mostly to:
  - `WAF_CONFIG_FILE`
  - `WAF_PROXY_AUDIT_FILE`
  - `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` /
    `AWS_SESSION_TOKEN` / `AWS_REGION` / `AWS_DEFAULT_REGION` when
    `persistent_storage.backend=s3`
  - Security-audit key overrides when `security_audit.key_source=env`
- The embedded `Settings` screen edits DB `app_config`. Recreate / restart
  the container to apply listener / runtime / storage policy /
  observability changes.

Site-managed ACME picks `tls.mode=acme` per-site on the `Sites` screen.
The ACME cache lives under the `acme/` namespace of `persistent_storage`.
For single-instance with the local backend, mount
`/app/data/persistent`; for replicated / node-replacement scenarios use
the **S3 backend or a shared mount**. Azure Blob / GCS backends are
fail-closed until a provider adapter ships.

Proxy engine selection is, as in Chapter 3, a restart-required surface:

```json
{ "proxy": { "engine": { "mode": "tukuyomi_proxy" } } }
```

Values to keep server-side only:

- `admin.session_secret`
- The initial owner bootstrap credentials when using
  `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` /
  `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD`
- Optional security-audit encryption / HMAC keys
- For an intentional replicated immutable rollout, frontend replicas use
  `admin.read_only=true`, and scheduled-task execution moves to a
  dedicated singleton role
- The default posture is `admin.external_mode=api_only_external`. Tighten
  to `deny_external` when remote admin API is not needed
- For non-loopback listeners with `full_external`, treat front-side
  allowlisting / authentication as mandatory
- Widening `admin.trusted_cidrs` to a public network re-exposes the
  embedded admin UI / API; the startup warning alone is not a safeguard
- Base WAF and CRS assets become DB `waf_rule_assets` after import.
  Image-baked files are seed material, not the runtime authority
- Managed bypass override rules live in DB `override_rules`; `extra_rule`
  values remain as logical compatibility references

## 4.10 Per-platform topologies

The samples below assume the deployment image from §4.6.2 (binary path
`/app/tukuyomi`). When you use `server/Dockerfile`, replace the scheduler
sidecar's `PROXY_BIN=/app/tukuyomi` with `PROXY_BIN=/app/server`.

### 4.10.1 ECS / Fargate

Place two containers in one task:

- `coraza`
- `scheduled-task-runner`

Lock the ECS service to single-instance:

- `desiredCount=1`
- Do not stack revisions during rollout
  - For example: `minimumHealthyPercent=0`
  - For example: `maximumPercent=100`

Sample artifacts:

- `docs/build/ecs-single-instance.task-definition.example.json`
- `docs/build/ecs-single-instance.service.example.json`

The samples mount each of the following as a separate EFS:

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`
- `/app/data/php-fpm`

The task definition sample also declares `9091/tcp` for
`admin.listen_addr`. Keep the ECS service load balancer on `9090` unless
you intentionally add a private admin target group.

If you eventually move to replicated immutable frontend:

- Public frontend service uses `admin.read_only=true`.
- Move scheduler ownership outside the frontend task set.
- Scheduled tasks are owned by **one dedicated scheduler task**, not
  individual replicas.

Dedicated scheduler artifacts:

- `docs/build/ecs-replicated-frontend-scheduler.task-definition.example.json`
- `docs/build/ecs-replicated-frontend-scheduler.service.example.json`

### 4.10.2 AKS / GKE / generic Kubernetes

Lock the Deployment to:

- `replicas: 1`
- `strategy: Recreate`
- 2 containers in 1 Pod

`Recreate` exists so that the **mutable single-instance model never
overlaps two Pods, even briefly, during rollout**.

Sample: `docs/build/kubernetes-single-instance.example.yaml`

The sample uses separate PVCs:

- `tukuyomi-conf`
- `tukuyomi-scheduled-tasks`
- `tukuyomi-audit`
- `tukuyomi-persistent`
- `tukuyomi-php-fpm`

It also defines two services:

- A public `Service` on `9090`.
- An internal `tukuyomi-admin` `Service` on `9091`.

Use the admin Service only on a private cluster network or behind a
separate internal ingress / LB.

For multi-replica frontend in the future:

- Frontend Pods use `admin.read_only=true`.
- Configuration changes go through rollouts.
- Move `scheduled-task-runner` from each replica to a **dedicated
  singleton workload**.

Dedicated scheduler artifact:
`docs/build/kubernetes-replicated-frontend-scheduler.example.yaml`

### 4.10.3 Azure Container Apps

Lock to single-instance:

- `activeRevisionsMode: Single`
- `minReplicas: 1`
- `maxReplicas: 1`
- 2 containers in the same revision

Sample: `docs/build/azure-container-apps-single-instance.example.yaml`

The sample assumes the following Azure Files storage definitions already
exist in the Container Apps environment:

- `proxyconf`
- `proxyscheduledtasks`
- `proxyaudit`
- `proxypersistent`
- `proxyphpfpm`

The Azure Container Apps sample keeps a single primary ingress. Even when
`admin.listen_addr` is enabled, keep the admin port **on the private
path** in this slice and arrange separate internal exposure outside.

When moving to a replicated frontend:

- Set `admin.read_only=true`.
- Keep exactly one scheduler owner.
- Do not run scheduled tasks on each frontend replica.

Dedicated scheduler artifact:
`docs/build/azure-container-apps-scheduler-singleton.example.yaml`

### 4.10.4 Local validation / operator reference

The Docker Compose flow shipped in the repository is kept as a reference
for validating the same topology locally:

```bash
make compose-up-scheduled-tasks
```

The natural workflow is to validate the topology locally first, then
translate it to platform manifests.

## 4.11 Typical communication paths

The cloud path is usually:

```text
client -> ALB / nginx / ingress -> tukuyomi container -> app container/service
```

When there is a fronting layer, **narrow the trusted proxy range in DB
`app_config` to that layer alone**.

If you expose `tukuyomi` itself as the direct public entrypoint and
enable built-in HTTP/3, **open both TCP and UDP** on the listener port.

## 4.12 Notes

- The embedded Gateway / Center UI is generated at image build time, not
  at runtime.
- `scripts/install_crs.sh` runs at image build time or at startup.
- To change policy files at runtime, mount `/app/conf`. WAF / CRS assets
  are imported into the DB from the staging area under `/app/data/tmp`.
- The repository `docker-compose.yml` includes a
  `scheduled-task-runner` sidecar under the `scheduled-tasks` profile.
- The current sidecar implementation is explicit: a shell loop calls the
  in-image proxy binary with `run-scheduled-tasks`, then sleeps until
  the next minute boundary.
- The failure policy is also explicit. If `run-scheduled-tasks` returns
  non-zero, the sidecar exits non-zero and hands the fault to the
  container restart policy instead of swallowing it.
- The `coraza` image bundles MaxMind's `geoipupdate` at
  `/app/bin/geoipupdate`. For image-first managed country refresh, run
  `/app/server update-country-db` directly.
- The local Compose flow assumes proxy-owned paths only:

  ```bash
  make compose-up-scheduled-tasks
  ```

- The raw compose command:

  ```bash
  PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  ```

- To run an application command like `artisan schedule:run`, mount the
  application tree into both `coraza` and `scheduled-task-runner`. See
  `docs/build/docker-compose.scheduled-tasks.app.example.yml` for an
  override file.

- Compose with the app tree:

  ```bash
  SCHEDULED_TASK_APP_ROOT=/srv/myapp \
  SCHEDULED_TASK_APP_MOUNT=/app/workloads/myapp \
  docker compose \
    -f docker-compose.yml \
    -f docs/build/docker-compose.scheduled-tasks.app.example.yml \
    --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  ```

- `make gateway-preview-up` also starts a preview-only scheduler sidecar.
- The default preview re-initializes on every run. `gateway-preview-up`
  rebuilds the preview-only SQLite DB each time, so old preview tasks,
  listener changes, and DB rows are not carried forward.

- To keep preview DB state across runs:

  ```bash
  GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
  GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
  ```

- `GATEWAY_PREVIEW_PERSIST=1` keeps
  `data/<dirname(storage.db_path)>/tukuyomi-gateway-preview.db` (for
  example, with `storage.db_path` of `db/tukuyomi.db`, the preview DB is
  `data/db/tukuyomi-gateway-preview.db`).
- `gateway-preview-up` derives publish ports from the active preview
  `app_config` stored in the preview DB. Only on the first run does it
  use `conf/config.json` plus `GATEWAY_PREVIEW_PUBLIC_ADDR` /
  `GATEWAY_PREVIEW_ADMIN_ADDR` overrides as a base. With a single
  listener it publishes the public port; with split listeners it
  publishes both. Health checks favor the admin listener when split.

- Bootstrapping a split preview:

  ```bash
  GATEWAY_PREVIEW_PERSIST=1 \
  GATEWAY_PREVIEW_PUBLIC_ADDR=:80 \
  GATEWAY_PREVIEW_ADMIN_ADDR=:9090 \
  make gateway-preview-up
  ```

  Verify at:
  - public proxy: `http://127.0.0.1:80`
  - admin UI: `http://127.0.0.1:9090/tukuyomi-ui`
  - admin API: `http://127.0.0.1:9090/tukuyomi-api`

- Do not use loopback binds such as `localhost:80`, `127.0.0.1:80`, or
  `[::1]:9090` in preview listener settings. Loopback bind inside the
  container does not work with host publish, and `gateway-preview-up`
  fails explicitly.
- After saving listener changes from `Settings`, verify them with
  `GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down && GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up`.
  Listener changes themselves persist in the preview DB, but
  `docker compose restart` does not rebuild the changed port publish.
- Track scheduler faults via the sidecar's exit / restart and container
  logs. A persistent fault should show up as restart churn.
- When a scheduled task references a bundled PHP path such as
  `/app/data/php-fpm/binaries/php85/php`, also mount `/app/data/php-fpm`
  in the scheduler container.
- The platform health endpoint is `/healthz` on `9090`.
- For verifying the packaged binary rather than custom container paths,
  the fastest entry point is `testenv/release-binary/` shipped with the
  release tarball.
- Validate the sample container flow locally before rollout with
  `make container-deployment-smoke`. To validate the entire
  container-platform contract, use `make container-platform-smoke`. To
  exercise just preview persistence and split-port parity, use
  `make gateway-preview-smoke`.

## 4.13 Bridge to the next chapter

We have walked through the two official deployment paths — systemd
(Chapter 3) and containers (this chapter). In both, **the DB is the
runtime authority and JSON is seed / import / export material** stays
the same.

Part III — "Reverse proxy" (Chapters 5 and 6) — explains how that
configuration plane drives **actual routing**: the three-layer model of
Routes / Upstreams / Backend Pools, runtime operations on the
`Backends` screen, and how upstream HTTP/2 is handled.
