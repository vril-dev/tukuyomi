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

`setup.sh` downloads OWASP CRS into `data/rules/crs/` and creates `.env` from `.env.example` when missing.

Some examples also include `./smoke.sh`. For host-based confidence checks, run it with a protected host fixture:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

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
