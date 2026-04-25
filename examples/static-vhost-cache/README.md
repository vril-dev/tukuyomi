[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Static Vhost Cache

This example verifies the direct static vhost path with the internal response
cache. It is meant to catch regressions where static vhost responses are marked
cacheable but never expose `X-Tukuyomi-Cache: MISS` followed by `HIT`.

## Start

```bash
cd examples/static-vhost-cache
./setup.sh
docker compose up -d --build
./smoke.sh
```

- App URL: `http://localhost:${CORAZA_PORT:-19094}/test.html`
- Coraza API: `http://localhost:${CORAZA_PORT:-19094}/tukuyomi-api/status`

`./smoke.sh` enables and clears the internal cache store, then checks that
`/test.html` returns `MISS` on the first request and `HIT` on the second. It
also verifies cache-store stats progressed by at least one miss, store, and hit.
