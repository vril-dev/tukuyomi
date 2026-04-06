[English](standalone-regression.md) | [日本語](standalone-regression.ja.md)

# Standalone Runtime 回帰マトリクス

この文書は、`[web]` の standalone 形態に対する繰り返し可能な回帰確認手順を定義します。

- `client -> tukuyomi -> app`
- `client -> ALB/nginx/cloudflare -> tukuyomi -> app`

fast local path と、少し重い path を分けて扱います。

## Fast Path

repo root から、direct に `tukuyomi` を叩く example を 1 つ実行します。

```bash
make standalone-regression-fast EXAMPLE=api-gateway
```

現時点でカバーする項目:

- `go test ./...`
- `docker compose config`
- direct `tukuyomi` health check
- direct `tukuyomi` admin UI check
- direct `tukuyomi` admin API status check
- direct `tukuyomi` admin logs endpoint check
- direct app proxy pass-through check
- direct WAF block check

## Broader Example Sweep

同じ direct-`tukuyomi` smoke wrapper を、同梱 example 全体へ流します。

```bash
make standalone-smoke-all
```

対象:

- `examples/api-gateway`
- `examples/nextjs`
- `examples/wordpress`

## Extended Path

少し重いローカル基準確認を実行します。

```bash
make standalone-regression-extended
```

現時点では次を実行します。

- `make check`
- `make standalone-smoke-all`
- `make standalone-policy-fixture`
- `make deployment-smoke`

さらに `api-gateway` については、login を連打したとき最終的に `429` が返ることに加えて、bypass / country block の一時 fixture を admin API 経由で適用し、最後に復元するところまで確認します。

standalone 一式までは不要で、policy fixture だけ回したい場合は次を使います。

```bash
make standalone-policy-fixture EXAMPLE=api-gateway
```

standalone 一式までは不要で、deployment guide の検証だけ回したい場合は次を使います。

```bash
make deployment-smoke
```

## Matrix Status

| 項目 | 現状 | 実行方法 | 期待結果 |
| --- | --- | --- | --- |
| Health check | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | `GET /healthz = 200` |
| Admin UI | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-admin/ = 200` |
| Admin API status | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | `GET /tukuyomi-api/status = 200` |
| Admin logs API の parity | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | `src=waf/intr/accerr` が `200` を返し、smoke 後は `intr/accerr` に少なくとも 1 行入る |
| 通常 app proxy | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | protected host で app に到達する |
| WAF block | 自動化済み | `standalone-regression-fast` / `standalone-smoke` | 簡単な XSS probe が `403` |
| Rate limit | 一部自動化 | `standalone-regression-extended`（`api-gateway`） | login 連打で最終的に `429` |
| Bypass rules | 自動化済み | `standalone-policy-fixture` / `standalone-regression-extended`（`api-gateway`） | 一時 bypass により `/v1/whoami` は通り、別 path は block 維持 |
| Country block | 自動化済み | `standalone-policy-fixture` / `standalone-regression-extended`（`api-gateway`） | trusted front-proxy の `JP` は `403`、信頼できない header は無視または `UNKNOWN` に落ちる |
| Binary deployment guide | 自動化済み | `deployment-smoke` / `standalone-regression-extended` | staged binary build + runtime tree が `/healthz`、Admin UI、admin login/session/logout + CSRF 検証、protected-host smoke を通す |
| Container deployment guide | 自動化済み | `deployment-smoke` / `standalone-regression-extended` | `docs/build/Dockerfile.example` image が `/healthz`、Admin UI、admin login/session/logout + CSRF 検証、protected-host smoke を通す |
| cache の高度な意味論 | 後続 slice | N/A | stale serve / coalescing / disk-backed はまだ `nginx proxy_cache` と差がある |

## まだ手動の項目がある理由

この phase では、次の 1 領域を pending のまま残しています。

- cache の意味論は後続 slice の置き換え対象

これは現行 standalone smoke harness の不具合ではなく、standalone runtime 化の未完了ギャップです。
