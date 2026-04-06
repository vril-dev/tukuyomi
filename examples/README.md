[English](README.md) | [日本語](README.ja.md)

# tukuyomi examples

The examples below show practical deployment patterns with tukuyomi as the front WAF layer.

| Example | Target use case | Path |
| --- | --- | --- |
| Next.js | Frontend app protection with static-asset cache rules | `examples/nextjs` |
| WordPress (High Paranoia) | CMS protection with stricter CRS setup | `examples/wordpress` |
| API Gateway | REST API protection with rate-limit-first policy | `examples/api-gateway` |

## Common flow

```bash
cd examples/<name>
./setup.sh
docker compose up -d --build
```

This default path starts the standalone runtime:

- `client -> tukuyomi -> app`
- safe direct defaults (`WAF_TRUSTED_PROXY_CIDRS` empty, internal response headers hidden)

To add a thin `nginx` front proxy for local smoke or balancer-style validation:

```bash
FRONT_PROXY_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
WAF_TRUSTED_PROXY_CIDRS="$FRONT_PROXY_TRUSTED_PROXY_CIDRS" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

`setup.sh` downloads OWASP CRS into `data/rules/crs/` and creates `.env` from `.env.example` when missing.

## Topologies

| Mode | Flow | Use case |
| --- | --- | --- |
| Direct (default) | `client -> tukuyomi -> app` | Standalone runtime, ECS sidecar-less validation, direct cache/log testing |
| Thin front proxy | `client -> nginx-like front -> tukuyomi -> app` | Local smoke for ALB/nginx-style fronting, trusted proxy and forwarded header checks |
| Legacy full nginx feature mode | `client -> nginx -> tukuyomi -> app` with nginx cache/log focus | Compare legacy cache/header behavior before removing nginx dependency from production stories |

Some examples also include `./smoke.sh`. For host-based confidence checks, run it with a protected host fixture:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

For the optional front-proxy path:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

To mimic a Cloudflare-style country header flow through the front proxy, add `CF-IPCountry` on the client request. The bundled `nginx` front normalizes it into `X-Country-Code` for tukuyomi.

For a repo-level Docker smoke run, use:

```bash
./scripts/ci_example_smoke.sh api-gateway
./scripts/ci_example_smoke.sh nextjs
./scripts/ci_example_smoke.sh wordpress
```

For direct `tukuyomi` checks without sending client traffic through example `nginx`, use:

```bash
./scripts/run_standalone_regression.sh api-gateway
make standalone-smoke-all
```

For repeatable latency/RPS baseline capture, use:

```bash
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
make benchmark-baseline
```

The benchmark runner disables example rate-limit rules by default while it
starts its own stack. Set `BENCH_DISABLE_RATE_LIMIT=0` if you want to measure
policy throttling instead.
