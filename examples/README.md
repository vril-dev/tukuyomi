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

`setup.sh` stages OWASP CRS under `data/tmp`, imports WAF rule assets into DB, removes the stage, and creates `.env` from `.env.example` when missing.

Some examples also include `./smoke.sh`. For host-based confidence checks, run it with a protected host fixture:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```
