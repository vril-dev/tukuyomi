# Container Deployment

This guide is for container-first deployments such as:

- ECS
- AKS
- GKE
- Azure Container Apps
- generic Docker or Kubernetes environments

## Build Choices

There are two practical choices.

### 1. Use the repository Dockerfile directly

```bash
docker build -f coraza/Dockerfile -t tukuyomi:local .
```

This builds the admin UI, embeds it into the Go binary, and produces a runnable image.

### 2. Use a deployment Dockerfile that bakes config and rules

Sample:

- [Dockerfile.example](Dockerfile.example)

Build:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

This is useful when you want a self-contained image with `/app/conf` and `/app/rules` already included.

To rerun the documented flow as a repo smoke check:

```bash
make container-deployment-smoke
```

## Runtime Paths

Minimum runtime paths:

- `/app/conf`
- `/app/rules`
- `/app/logs`

If you do not bake config into the image, mount those paths from your platform.

Notes:

- `conf/log-output.json` is created on first start if missing
- `conf/crs-disabled.conf` can start empty
- `Dockerfile.example` already sets the baked-in file path envs for `/app/conf` and `/app/rules`

## Minimum Environment Review

- `WAF_APP_URL`
- `WAF_RULES_FILE`
- `WAF_BYPASS_FILE`
- `WAF_API_KEY_PRIMARY`
- `WAF_API_KEY_SECONDARY`
- `WAF_ADMIN_SESSION_SECRET`
- `WAF_ADMIN_SESSION_TTL_SEC`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_ADMIN_EXTERNAL_MODE`
- `WAF_ADMIN_TRUSTED_CIDRS`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_CRS_ENABLE`
- `WAF_CRS_SETUP_FILE`
- `WAF_CRS_RULES_DIR`
- `WAF_CRS_DISABLED_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` or `WAF_DB_PATH`

## Typical Traffic Shape

Typical cloud path:

`client -> ALB/nginx/ingress -> tukuyomi container -> app container/service`

If a front layer exists, restrict `WAF_TRUSTED_PROXY_CIDRS` to that layer only.
`WAF_TRUSTED_PROXY_CIDRS` only affects forwarded-header trust. Admin reachability is separate:

- default `[web]` posture is `WAF_ADMIN_EXTERNAL_MODE=api_only_external`
- trusted/private direct peers in `WAF_ADMIN_TRUSTED_CIDRS` can reach admin UI and API
- untrusted external clients can reach only the authenticated admin API
- use `WAF_ADMIN_EXTERNAL_MODE=deny_external` when remote admin API access is unnecessary
- if your front proxy or LB reaches tukuyomi from non-private source IPs, set `WAF_ADMIN_TRUSTED_CIDRS` to those direct-peer ranges so the embedded admin UI remains reachable through that layer

## Secret Handling

- Inject `WAF_API_KEY_PRIMARY`, `WAF_API_KEY_SECONDARY`, `WAF_ADMIN_SESSION_SECRET`, `WAF_DB_DSN`, and `WAF_FP_TUNER_API_KEY` at runtime through your platform secret store or env injection
- No build-time admin secret is required for the embedded Admin UI
- Browser users sign in once and receive same-origin session cookies
- CLI / automation can keep using `X-API-Key`

## Notes

- The embedded admin UI is produced during image build, not at runtime
- `make container-deployment-smoke` now validates unauthenticated session state, login/logout, invalid session rejection, and CSRF enforcement
- For mutable runtime policy files, mount `/app/conf` and `/app/rules` instead of baking everything into the image
- For multi-node operation, prefer `db + mysql`
