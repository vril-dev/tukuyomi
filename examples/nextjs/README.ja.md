[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

この example は、最小構成の Next.js app の front に tukuyomi を置きます。

## Start

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

`./setup.sh` は stack 起動前に built-in の `nextjs` import profile から
runtime DB を seed します。

- App URL: `http://localhost:${CORAZA_PORT:-19091}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

## Smoke tests

```bash
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

2 本目の request は WAF により `403` で block されるはずです。
