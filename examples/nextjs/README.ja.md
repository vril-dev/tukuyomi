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
./smoke.sh
```

`./smoke.sh` は app の到達性に加え、static fixture に対して internal response
cache が `X-Tukuyomi-Cache: MISS`、次に `HIT` を返すことを確認します。
この example は smoke 用の admin user を bootstrap するため、script は
internal cache store を有効化して clear してから確認します。runtime を別の
bootstrap credential で起動した場合だけ credential を上書きしてください。

```bash
ADMIN_USERNAME='admin' ADMIN_PASSWORD='your-admin-password' ./smoke.sh
```

WAF block は手動でも確認できます。

```bash
curl -i "http://localhost:19091/?q=<script>alert(1)</script>"
```

この request は WAF により `403` で block されるはずです。
