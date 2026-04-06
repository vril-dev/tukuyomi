[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: API Gateway（rate-limit 重視）

この example は JSON API を保護し、auth endpoint に対してより strict な limit を適用します。

## Start

Direct standalone path:

```bash
cd examples/api-gateway
./setup.sh
docker compose up -d --build
```

- API base URL: `http://localhost:${CORAZA_PORT:-19093}/v1`
- Coraza API: `http://localhost:${CORAZA_PORT:-19093}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/api-gateway
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18083}/v1`

## Smoke tests

```bash
curl -i "http://localhost:19093/v1/health"
curl -i -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
```

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

thin front proxy 経由で確認する場合:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

これは `Host: protected.example.test` を付けて traffic を送り、origin 側でその host が見えていることを確認した上で、簡単な XSS probe が `403` で block されることを検証します。

optional front proxy 経由で Cloudflare-style の country header flow を見たい場合:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18083/v1/health"
```

clone 済みの自分のサイトで試したい場合は、smoke script はそのまま残し、tukuyomi の背後にある example app を clone したアプリへ差し替えてください。同じ `PROTECTED_HOST=... ./smoke.sh` の flow を使えます。

Rate-limit check（繰り返すと `429` を期待）:

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
done
```
