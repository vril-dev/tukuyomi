[English](README.md) | [日本語](README.ja.md)

# tukuyomi example: WordPress（High Paranoia）

この example は WordPress の front に tukuyomi を置き、より高い paranoia で CRS を有効にします。

## Start

```bash
cd examples/wordpress
./setup.sh
docker compose up -d --build
```

`./setup.sh` は stack 起動前に built-in の `wordpress` import profile から
runtime DB を seed します。

- WordPress URL: `http://localhost:${CORAZA_PORT:-19092}`
- Coraza API: `http://localhost:${CORAZA_PORT:-19092}/tukuyomi-api/status`

## Notes

- `./setup.sh` が high-paranoia CRS setup を DB import される CRS setup asset として配置します。
- `tx.blocking_paranoia_level` と `tx.detection_paranoia_level` は `2` に設定しています。
- login endpoint `/wp-login.php` にはより strict な rate limit を適用しています。
