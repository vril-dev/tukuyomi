[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Static Vhost Cache

この example は、direct static vhost 経路と internal response cache を検証します。
static vhost response が cacheable なのに `X-Tukuyomi-Cache: MISS`、次に
`HIT` を返さない regression を検出するためのものです。

## Start

```bash
cd examples/static-vhost-cache
./setup.sh
docker compose up -d --build
./smoke.sh
```

- App URL: `http://localhost:${CORAZA_PORT:-19094}/test.html`
- Coraza API: `http://localhost:${CORAZA_PORT:-19094}/tukuyomi-api/status`

`./smoke.sh` は internal cache store を有効化して clear したあと、`/test.html`
への 1 回目の request が `MISS`、2 回目が `HIT` になることを確認します。
cache-store stats でも miss / store / hit がそれぞれ 1 以上進むことを確認します。
