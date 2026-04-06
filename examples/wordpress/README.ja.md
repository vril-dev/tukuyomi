[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress（High Paranoia）

この example は WordPress の front に tukuyomi を置き、より高い paranoia で CRS を有効にします。

## Start

Direct standalone path:

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

- WordPress URL: `http://localhost:${CORAZA_PORT:-19092}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

Thin front proxy path:

```bash
cd examples/wordpress
./setup.sh
WAF_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

- Front URL: `http://localhost:${NGINX_PORT:-18082}`

## Notes

- `WAF_CRS_SETUP_FILE=rules/crs-setup-high-paranoia.conf` を使います。
- `tx.blocking_paranoia_level` と `tx.detection_paranoia_level` は `2` に設定しています。
- login endpoint `/wp-login.php` にはより strict な rate limit を適用しています。

## Protected Host Smoke

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

thin front proxy 経由の smoke:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

default の local stack では、smoke script が test の前に WordPress を自動 bootstrap します。その後 `/tukuyomi-whoami.php` を叩き、WordPress の PHP runtime が protected host を見ていることを確認し、簡単な XSS probe が `403` で block されることを検証します。

optional front proxy 経由で Cloudflare-style の country header flow を見たい場合:

```bash
curl -i -H 'Host: protected.example.test' -H 'CF-IPCountry: JP' "http://localhost:18082/tukuyomi-whoami.php"
```
