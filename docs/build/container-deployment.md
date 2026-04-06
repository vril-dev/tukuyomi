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

- [Dockerfile.example](/home/ky491/git/vril/tukuyomi/docs/build/Dockerfile.example)

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
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
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

## Notes

- The embedded admin UI is produced during image build, not at runtime
- `VITE_API_KEY` is a build-time value for the admin UI
- For mutable runtime policy files, mount `/app/conf` and `/app/rules` instead of baking everything into the image
- For multi-node operation, prefer `db + mysql`
