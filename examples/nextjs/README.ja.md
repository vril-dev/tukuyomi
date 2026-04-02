[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

この example は、最小構成の Next.js app の front に tukuyomi を置きます。

## Start

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

- App URL: `http://localhost:${NGINX_PORT:-18081}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

## Smoke tests

```bash
curl -i "http://localhost:18081/"
curl -i "http://localhost:18081/?q=<script>alert(1)</script>"
```

2 本目の request は WAF により `403` で block されるはずです。

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

これにより `/api/whoami` で app 側が protected host を見ていることと、簡単な XSS probe が `403` で block されることを検証します。
