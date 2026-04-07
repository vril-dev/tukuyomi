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

この default path は standalone runtime を起動します。

- `client -> tukuyomi -> app`
- safe direct default（`WAF_TRUSTED_PROXY_CIDRS` は空、internal response header は非公開）
- admin exposure の既定は `WAF_ADMIN_EXTERNAL_MODE=api_only_external` のままで、埋め込み管理UIは trusted/private な直結 peer に限定され、認証付き管理APIは到達可能です

local smoke や balancer 相当の確認で thin `nginx` front proxy を足したい場合:

```bash
FRONT_PROXY_TRUSTED_PROXY_CIDRS="127.0.0.1/32,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16"
WAF_TRUSTED_PROXY_CIDRS="$FRONT_PROXY_TRUSTED_PROXY_CIDRS" \
WAF_FORWARD_INTERNAL_RESPONSE_HEADERS=true \
docker compose --profile front-proxy up -d --build
```

`setup.sh` は `data/rules/crs/` に OWASP CRS をダウンロードし、`.env` が無い場合は `.env.example` から生成します。

## Topologies

| Mode | Flow | 用途 |
| --- | --- | --- |
| Direct（default） | `client -> tukuyomi -> app` | standalone runtime、ECS sidecar-less validation、direct cache/log 確認 |
| Thin front proxy | `client -> nginx-like front -> tukuyomi -> app` | ALB/nginx 風 front の local smoke、trusted proxy と forwarded header の確認 |
| Legacy full nginx feature mode | `client -> nginx -> tukuyomi -> app` で nginx cache/log を重視 | nginx 依存を減らす前に従来の cache/header 挙動と比較する |

一部の example には `./smoke.sh` もあります。host-based な確認をしたい場合は、protected host fixture を付けて実行します。

```bash
PROTECTED_HOST=protected.example.test ./smoke.sh
```

optional front-proxy path を通したい場合:

```bash
PROTECTED_HOST=protected.example.test EXAMPLE_TOPOLOGY=front ./smoke.sh
```

Cloudflare-style の country header flow を front proxy 経由で見たい場合は、client request に `CF-IPCountry` を付けてください。同梱の `nginx` front がこれを `X-Country-Code` に正規化して tukuyomi へ渡します。

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

繰り返し比較できる latency/RPS baseline を取る場合は次を使います。

```bash
make benchmark-scenario EXAMPLE=api-gateway TOPOLOGY=front SCENARIO=pass
make benchmark-baseline
```

benchmark runner が stack を自分で起動する場合、example の rate-limit は
default で無効化されます。policy throttling 自体を測りたい場合は
`BENCH_DISABLE_RATE_LIMIT=0` を付けてください。
