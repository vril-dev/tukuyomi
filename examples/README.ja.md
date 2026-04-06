[English](README.md) | [日本語](README.ja.md)

# tukuyomi examples

以下の example は、tukuyomi を front WAF layer として使う実運用寄りの構成パターンを示します。

| Example | 対象ユースケース | Path |
| --- | --- | --- |
| Next.js | static-asset cache rule を含む frontend app protection | `examples/nextjs` |
| WordPress (High Paranoia) | より strict な CRS 設定での CMS protection | `examples/wordpress` |
| API Gateway | rate-limit-first policy を使う REST API protection | `examples/api-gateway` |

## Common flow

```bash
cd examples/<name>
./setup.sh
docker compose up -d --build
```

`setup.sh` は `data/rules/crs/` に OWASP CRS をダウンロードし、`.env` が無い場合は `.env.example` から生成します。

一部の example には `./smoke.sh` もあります。host-based な確認をしたい場合は、protected host fixture を付けて実行します。

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

repo-level の Docker smoke は次を使います。

```bash
./scripts/ci_example_smoke.sh api-gateway
./scripts/ci_example_smoke.sh nextjs
./scripts/ci_example_smoke.sh wordpress
```

example 側の `nginx` を client 経路に入れず、direct に `tukuyomi` を確認したい場合は次を使います。

```bash
./scripts/run_standalone_regression.sh api-gateway
make standalone-smoke-all
```
