# Container Deployment

This guide is for container-first `tukuyomi` deployments such as:

- ECS
- AKS
- GKE
- Azure Container Apps
- generic Docker or Kubernetes environments

## Support Tiers

Treat container-platform support in three tiers.

### Tier 1: Mutable single-instance

This is the official supported path today.

- one deployment unit only
- one public `coraza` container
- one internal `scheduled-task-runner` sidecar
- shared writable paths for:
  - `/app/conf`
  - `/app/data/geoip` when request country resolution uses managed `.mmdb`
  - `/app/data/scheduled-tasks`
  - `/app/logs`
  - `/app/data/php-fpm` when bundled runtimes are used
- live admin mutation is allowed

This is the path documented below for ECS, AKS, GKE, Azure Container Apps, and
generic container platforms.

### Tier 2: Immutable replicated rollout

This is not closed yet.

- multiple frontend replicas are a future official path
- config changes must happen by rollout, not by live admin mutation
- `admin.read_only=true` is required on those frontend replicas
- scheduled-task ownership must move to a dedicated singleton role instead of
  riding in every frontend replica

Until the rest of those guards are closed, do not treat replicated mutable
admin deployments as official.

### Tier 3: Distributed mutable cluster

This remains unsupported.

- no distributed config propagation
- no leader election
- no cluster-wide scheduler ownership
- no multi-writer mutable runtime model

## Official Topology Today

For container platforms, the current official topology is:

`client -> ALB/ingress/platform ingress -> coraza`

plus a sibling internal container:

`scheduled-task-runner`

Operational constraints:

- keep the deployment at one running unit only
- avoid overlapping revisions during rollout
- keep the writable runtime paths shared between `coraza` and
  `scheduled-task-runner`
- expose only the `coraza` container to the platform ingress or load balancer

## Split Public/Admin Listeners

When you need the public proxy listener on `:80` / `:443` but want admin UI/API
on a separate high port, set `admin.listen_addr` in DB `app_config`.

Sample:

- [config.split-listener.example.json](config.split-listener.example.json)

Operator contract:

- `server.listen_addr` remains the public listener
- `admin.listen_addr` moves admin UI/API/auth off the public listener
- `admin.external_mode` and `admin.trusted_cidrs` still decide who can reach
  the admin plane
- built-in TLS / HTTP redirect / HTTP/3 remain public-listener-only in this
  slice
- do not mistake split listeners for exposure control; port split and source
  guard solve different problems
- on container platforms, publish or route only the public listener unless you
  intentionally expose the admin listener on a private network path

## Container Reload / Rolling Update

Graceful process reload inside a container should be handled as a platform
rollout, not as in-container reexec.

- keep readiness pointed at the public listener
- start the new task/pod before removing the old one
- let the ingress or load balancer stop sending new connections to the old
  task/pod
- keep the old task/pod alive for at least `server.graceful_shutdown_timeout_sec`
- do not rely on systemd socket activation inside ordinary Docker/Kubernetes
  containers
- HTTP/3 clients may reconnect during a task/pod replacement because QUIC
  connection continuity is not preserved across process replacement

## Replicated Immutable Shape

When you intentionally move toward replicated immutable frontends, split the
roles explicitly instead of copying the single-instance sidecar model.

Frontend replica role:

- serves HTTP only
- may run multiple replicas behind the platform ingress
- sets `admin.read_only=true`
- does not own scheduled-task execution

Dedicated scheduler role:

- stays singleton
- runs the same `run-scheduled-tasks` loop
- has no public ingress
- mounts the same source-of-truth paths as the frontend for:
  - `/app/conf`
  - `/app/data/geoip`
  - `/app/data/scheduled-tasks`
  - `/app/logs`
  - `/app/data/php-fpm` when bundled runtimes are used

This does not imply distributed mutable runtime support. It only makes
scheduler ownership explicit when the frontend is replicated.

## Build Choices

There are two practical choices.

### 1. Use the repository Dockerfile directly

Refresh the embedded Admin UI first:

```bash
make ui-build-sync
docker build -f coraza/Dockerfile -t tukuyomi:local coraza
```

This path uses the repository Dockerfile and the prepared `coraza/src/internal/handler/admin_ui_dist` tree.

### 2. Use a deployment Dockerfile that builds UI and binary from scratch

Sample:

- [Dockerfile.example](Dockerfile.example)

Build:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

This path builds the Admin UI in-image, builds the Go binary, copies runtime config, and installs CRS during the image build.

## Shared Writable Paths

Minimum writable paths for the official mutable single-instance path:

- `/app/conf`
- `/app/data/geoip`
- `/app/data/scheduled-tasks`
- `/app/logs`

Mount those from your platform unless you intentionally accept ephemeral local
state.

When you also use bundled PHP runtimes for `/options`, `/vhosts`, or scheduled
PHP CLI jobs, mount `/app/data/php-fpm` as well.

`/app/rules` is seed material for DB `waf_rule_assets`. After import, runtime
loads active WAF/CRS assets from DB rather than from that directory.

## Config and Secrets

`tukuyomi` uses `conf/config.json` for DB connection bootstrap, then reads
operator-managed app/proxy config from normalized DB tables.

Typical production pattern:

- render `conf/config.json` from your secret manager or config-management layer for `storage.db_driver`, `storage.db_path`, and `storage.db_dsn`
- mount or bake `conf/proxy.json` and policy files as seed/import/export material
- run `make db-migrate`, then `make crs-install` to install/import WAF rule assets, then `make db-import` for the remaining seed material before first start
- treat `conf/sites.json`, `conf/scheduled-tasks.json`, and `conf/upstream-runtime.json` as empty-DB seed/export files; normalized DB rows are authoritative after bootstrap
- use runtime env injection only for:
  - `WAF_CONFIG_FILE`
  - `WAF_PROXY_AUDIT_FILE`
  - security-audit key env overrides when `security_audit.key_source=env`
- the embedded `Settings` page edits DB `app_config`; recreate/restart the container to apply listener/runtime/storage policy/observability updates

Proxy engine selection is part of the same restart-required config surface:

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` is the built-in engine and uses Tukuyomi's own response bridge while preserving the same parser, transport, routing, health, retry, TLS, cache, route response headers, 1xx informational responses, trailers, streaming flush behavior, native Upgrade/WebSocket tunnel, and response-sanitize pipeline
- the legacy `net_http` bridge has been removed; config validation rejects any engine value other than `tukuyomi_proxy`
- HTTP/1.1 and explicit upstream HTTP/2 modes use Tukuyomi native upstream transports; HTTPS `force_attempt` falls back to native HTTP/1.1 only when ALPN does not select `h2`
- Upgrade/WebSocket handshake requests stay inside `tukuyomi_proxy`; WebSocket frame payloads after `101 Switching Protocols` are tunnel data
- rebuild/restart the container and benchmark real traffic before production rollout

Keep these server-side:

- `admin.api_key_primary`
- `admin.api_key_secondary`
- `admin.session_secret`
- optional security-audit encryption and HMAC keys
- when you intentionally prototype immutable replicated rollouts, set
  `admin.read_only=true` on the frontend replicas and move scheduled-task
  execution to a dedicated singleton role
- default `tukuyomi` posture is `admin.external_mode=api_only_external`; use `deny_external` when remote admin API access is unnecessary
- if you override to `full_external` on a non-loopback listener, treat front-side allowlists/auth as mandatory
- widening `admin.trusted_cidrs` to public or catch-all networks also re-exposes the embedded admin UI/API to those sources and only triggers a warning
- base WAF and CRS assets are DB `waf_rule_assets` after import; image-baked files are seed material, not runtime authority
- managed bypass override rules are DB `override_rules`; `extra_rule` values remain logical compatibility references

## Platform Mapping

All samples below assume the deployment image built from
[Dockerfile.example](Dockerfile.example), which installs the binary at
`/app/tukuyomi`.

If you instead use `coraza/Dockerfile`, replace scheduler-side
`PROXY_BIN=/app/tukuyomi` with `PROXY_BIN=/app/server`.

### ECS / Fargate

Use one task with two containers:

- `coraza`
- `scheduled-task-runner`

Keep the ECS service single-instance too:

- `desiredCount=1`
- no overlapping rollout
  - for example `minimumHealthyPercent=0`
  - and `maximumPercent=100`

Sample artifacts:

- [ecs-single-instance.task-definition.example.json](ecs-single-instance.task-definition.example.json)
- [ecs-single-instance.service.example.json](ecs-single-instance.service.example.json)

These samples use separate EFS-backed mounts for:

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/logs`
- `/app/data/php-fpm`

The task-definition sample also declares `9091/tcp` for `admin.listen_addr`.
Keep the ECS service load balancer pointed at `9090` unless you intentionally
add a private admin target group or internal service path for `9091`.

If you later split to replicated immutable frontends:

- keep the public frontend service read-only with `admin.read_only=true`
- keep scheduler ownership out of the frontend task set
- run scheduled tasks from one dedicated scheduler task instead of every
  replica

Dedicated scheduler artifacts:

- [ecs-replicated-frontend-scheduler.task-definition.example.json](ecs-replicated-frontend-scheduler.task-definition.example.json)
- [ecs-replicated-frontend-scheduler.service.example.json](ecs-replicated-frontend-scheduler.service.example.json)

### AKS / GKE / generic Kubernetes

Use one Deployment with:

- `replicas: 1`
- `strategy: Recreate`
- two containers in one Pod

`Recreate` matters here because the mutable single-instance model should not
briefly overlap two frontend Pods during rollout.

Sample artifact:

- [kubernetes-single-instance.example.yaml](kubernetes-single-instance.example.yaml)

The sample uses separate PVCs for:

- `tukuyomi-conf`
- `tukuyomi-scheduled-tasks`
- `tukuyomi-logs`
- `tukuyomi-php-fpm`

The sample now includes:

- a public Service on `9090`
- an internal `tukuyomi-admin` Service on `9091`

Use the admin Service only on a private cluster network or behind a separate
internal ingress/LB path.

If you later introduce multiple frontend Pods:

- keep frontend Pods read-only with `admin.read_only=true`
- keep config changes rollout-driven
- move `scheduled-task-runner` to one dedicated singleton workload instead of
  colocating it in every replica

Dedicated scheduler artifact:

- [kubernetes-replicated-frontend-scheduler.example.yaml](kubernetes-replicated-frontend-scheduler.example.yaml)

### Azure Container Apps

Use one container app revision with:

- `activeRevisionsMode: Single`
- `minReplicas: 1`
- `maxReplicas: 1`
- two containers in the same revision

Sample artifact:

- [azure-container-apps-single-instance.example.yaml](azure-container-apps-single-instance.example.yaml)

The sample expects Azure Files storage definitions already present in the
Container Apps environment for:

- `proxyconf`
- `proxyscheduledtasks`
- `proxylogs`
- `proxyphpfpm`

Azure Container Apps still has one primary ingress target in the sample. When
you enable `admin.listen_addr`, keep that admin port private unless you add a
separate internal exposure path for it outside this first slice.

If you later experiment with multiple frontend instances:

- turn on `admin.read_only=true`
- keep only one scheduler owner
- do not let every frontend replica run scheduled tasks

Dedicated scheduler artifact:

- [azure-container-apps-scheduler-singleton.example.yaml](azure-container-apps-scheduler-singleton.example.yaml)

### Generic local or operator validation path

The repository compose path remains the local runnable reference for the same
topology:

```bash
make compose-up-scheduled-tasks
```

Use it to validate the topology locally before turning it into a platform
manifest.

## Typical Traffic Shape

Typical cloud path:

`client -> ALB/nginx/ingress -> tukuyomi container -> app container/service`

If a front layer exists, restrict the trusted proxy ranges in DB `app_config` to only that layer.

If `tukuyomi` itself is the direct public entrypoint and built-in HTTP/3 is enabled, open the listener port for both TCP and UDP.

## Notes

- the embedded Admin UI is produced during image build, not at runtime
- `scripts/install_crs.sh` can be run at image build time or startup time depending on your policy
- for mutable runtime policy files, mount `/app/conf` and `/app/rules` instead of baking everything into the image
- the repository `docker-compose.yml` now provides a real scheduler sidecar service named `scheduled-task-runner` behind the `scheduled-tasks` profile
- the current sidecar model is explicit: a shell loop runs the image's proxy binary with `run-scheduled-tasks`, then sleeps until the next minute boundary
- failure policy is explicit too: if `run-scheduled-tasks` returns non-zero, the sidecar exits non-zero and relies on container restart policy instead of hiding the fault
- the `coraza` image ships MaxMind `geoipupdate` under `/app/bin/geoipupdate`
- for image-first managed country refresh, the direct command is `/app/server update-country-db`
- local compose path for proxy-owned commands only:

```bash
make compose-up-scheduled-tasks
```

- equivalent raw compose command:

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- application commands such as `artisan schedule:run` need the application tree mounted into both `coraza` and `scheduled-task-runner`
- use an override file such as [docker-compose.scheduled-tasks.app.example.yml](docker-compose.scheduled-tasks.app.example.yml)
- example with an app tree:

```bash
SCHEDULED_TASK_APP_ROOT=/srv/myapp \
SCHEDULED_TASK_APP_MOUNT=/app/workloads/myapp \
docker compose \
  -f docker-compose.yml \
  -f docs/build/docker-compose.scheduled-tasks.app.example.yml \
  --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- `make ui-preview-up` starts the preview-scoped scheduler sidecar too
- default preview behavior is reset-on-start:
  `ui-preview-up` rewrites `conf/scheduled-tasks.ui-preview.json` to `{"tasks":[]}` and removes the isolated preview SQLite DB on each start so old preview tasks and DB rows do not carry over
- opt into retained preview config and DB state with:

```bash
UI_PREVIEW_PERSIST=1 make ui-preview-up
UI_PREVIEW_PERSIST=1 make ui-preview-down
```

- when `UI_PREVIEW_PERSIST=1` is set, `ui-preview-up/down` keeps:
  - `conf/config.ui-preview.json`
  - `conf/proxy.ui-preview.json`
  - `conf/scheduled-tasks.ui-preview.json`
  - `data/php-fpm/inventory.ui-preview.json`
  - `data/php-fpm/vhosts.ui-preview.json`
  - `data/logs/coraza/tukuyomi-ui-preview.db`
- `ui-preview-up` now derives published ports from `conf/config.ui-preview.json`
  - single listener preview publishes the public listener port
  - split listener preview publishes both public and admin listener ports
  - healthcheck follows the admin listener in split mode
- example split preview config:

```json
{
  "server": {
    "listen_addr": ":80"
  },
  "admin": {
    "listen_addr": ":9090"
  }
}
```

- that yields:
  - public proxy: `http://127.0.0.1:80`
  - admin UI: `http://127.0.0.1:9090/tukuyomi-ui`
  - admin API: `http://127.0.0.1:9090/tukuyomi-api`
- do not use loopback listener binds such as `localhost:80`, `127.0.0.1:80`, or `[::1]:9090` in preview config
  - preview rejects them because container-local loopback bind does not match host-published ports
- when you save listener changes through `Settings`, use `UI_PREVIEW_PERSIST=1 make ui-preview-down` then `UI_PREVIEW_PERSIST=1 make ui-preview-up`
  - plain `docker compose restart` does not recreate changed published ports
- operational signal for scheduler faults is container exit/restart plus sidecar logs; persistent faults should show up as restart churn
- if a scheduled task command line points at a bundled PHP path such as `/app/data/php-fpm/binaries/php85/php`, mount `/app/data/php-fpm` into that scheduler container too
- the platform health endpoint is `/healthz` on port `9090`
- release tarballs already include `testenv/release-binary/` when you want a quick packaged-binary smoke instead of a custom container path
- to validate this sample container path locally before rollout, run `make container-deployment-smoke`
- to validate the wider container-platform contract before rollout, run `make container-platform-smoke`
  this also checks scheduled-task ownership, replicated read-only prerequisites, and sample platform artifacts
- to validate preview persistence and split-port parity locally, run `make ui-preview-smoke`
