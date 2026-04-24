[English](README.md) | [日本語](README.ja.md)

# tukuyomi examples

以下の example は、tukuyomi を front gateway / WAF layer として使う実運用寄りの構成パターンを示します。

| Example | 対象ユースケース | Path |
| --- | --- | --- |
| Next.js | embedded gateway 直下での frontend app protection | `examples/nextjs` |
| WordPress (High Paranoia) | より strict な CRS 設定での CMS protection | `examples/wordpress` |
| API Gateway | route rule と rate limit を組み合わせる REST API protection | `examples/api-gateway` |

## Common flow

```bash
cd examples/<name>
./setup.sh
docker compose up -d --build
```

`setup.sh` は OWASP CRS を `data/tmp` 配下へ一時 stage し、WAF rule asset を DB へ import してから stage を削除します。`.env` が無い場合は `.env.example` から生成します。

一部の example には `./smoke.sh` もあります。host-based な確認をしたい場合は、protected host fixture を付けて実行します。

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```
