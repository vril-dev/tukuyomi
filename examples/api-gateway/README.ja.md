[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: API Gateway（rate-limit 重視）

この example は JSON API を保護し、auth endpoint に対してより strict な limit を適用します。

## Start

```bash
cd examples/api-gateway
./setup.sh
docker compose up -d --build
```

- API base URL: `http://localhost:${CORAZA_PORT:-19093}/v1`
- Coraza API: `http://localhost:${CORAZA_PORT:-19093}/tukuyomi-api/status`

## Smoke tests

```bash
curl -i "http://localhost:19093/v1/health"
curl -i -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
```

Protected host smoke:

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

これは `Host: protected.example.test` を付けて traffic を送り、protected-host route が match することを確認した上で、簡単な XSS probe が `403` で block されることを検証します。

clone 済みの自分のサイトで試したい場合は、smoke script はそのまま残し、`data/conf/proxy.json` の背後にある example upstream を差し替えてください。`PROTECTED_HOST` を変える時は、protected-host route が引き続き match するように `data/conf/proxy.json` の `routes[].match.hosts` も同じ hostname に更新してください。

Rate-limit check（繰り返すと `429` を期待）:

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST "http://localhost:19093/v1/auth/login" -H 'content-type: application/json' -d '{"username":"demo","password":"demo"}'
done
```
