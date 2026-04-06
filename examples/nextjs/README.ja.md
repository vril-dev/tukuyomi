[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: Next.js

この example は、最小構成の Next.js app の front に tukuyomi を置きます。

## Start

Direct standalone path:

```bash
cd examples/nextjs
./setup.sh
docker compose up -d --build
```

- App URL: `http://localhost:${CORAZA_PORT:-19091}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19091}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/nextjs
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18081}`

## Smoke tests

```bash
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

2 本目の request は WAF により `403` で block されるはずです。

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

thin front proxy 経由の smoke:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

これにより `/api/whoami` で app 側が protected host を見ていることと、簡単な XSS probe が `403` で block されることを検証します。

## Direct Local Cache Check

example 側の `nginx` を通さず、standalone の in-memory cache を確認したい場合:

```bash
WAF_RESPONSE_CACHE_MODE=memory docker compose up -d --build
curl -i "http://localhost:19091/"
curl -i "http://localhost:19091/"
```

1本目は `X-Tukuyomi-Cache-Status: MISS`、2本目は `HIT` になるはずです。

optional front proxy 経由で Cloudflare-style の country header を見たい場合:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18081/api/whoami"
```
