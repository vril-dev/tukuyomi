# tukuyomi Reuse-Port Host Matrix and Policy

この文書は、`tukuyomi` で listener fan-out を将来再評価する場合の policy を定義したものです。

feature を再開する文書ではありません。どの host/runtime の評価を意味のあるものとして扱うか、どの topology を scope に入れるか、再開前にどの benchmark/smoke gate を通すべきかを定めます。

## 方針の要約

- listener fan-out は引き続き supported runtime の外に置く
- 将来の再開は、実装したい気持ちではなく host/runtime policy から始める
- Docker bridge の published-port 挙動は、再開条件の必須要件にはしない
- もし Docker published-port support 自体が欲しいなら、それは別 deliverable として切る

## Host/runtime matrix

| Tier | Host/runtime class | 例 | Policy status | 理由 |
| --- | --- | --- | --- | --- |
| A | Linux VM または bare metal の direct host bind | `:443` を直接公開する entrypoint | Required | listener accept fan-out を評価する最も信頼できるケース |
| A | host networking か同等の direct socket ownership を持つ Linux container | host-network container で bridge publish を使わない | containerized direct entrypoint が target なら Required | direct socket ownership に近い |
| B | 外部 LB/CDN の背後だが、`tukuyomi` 自体は local listener を直接持つ | LB -> VM / host-network container -> `tukuyomi` | Optional | 想定 deployment shape に合うなら確認価値がある |
| C | Docker bridge + published host port | `docker compose` の `19090:9090` 形式 | reopen gate としては Out of scope | local DX にはよいが、listener fan-out の性能 gate としては信用しにくい |
| C | Desktop VM forwarding などの non-Linux host-network abstraction | Docker Desktop や nested forwarding | Out of scope | client と listener の間に変数が多すぎる |

## 「Required」の意味

再開の議論は、Tier A の根拠が無い限り前に進めません。

必要なこと:

- 少なくとも 1 つの Tier A host/runtime class で benchmark 改善が再現できる
- 同じ class で単純な listener smoke が clean に通る
- その改善が `tukuyomi` の実 runtime shape を有効にした後でも残る
  - WAF
  - routing
  - retry/health logic
  - compression
  - cache

## Docker published-port policy

Docker bridge の published-port 挙動は別論点として扱います。

現時点の policy:

- Docker published-port が不安定でも、それだけで将来の再開可能性を完全否定しない
- 逆に、Docker published-port が通っただけで再開根拠にもならない
- bridge-published local/container runtime を product requirement にしたいなら、独立した task と smoke contract を持たせる

これにより、local 開発体験の都合だけで production-grade listener の判断が引きずられないようにします。

## Benchmark gate shape

将来の再開では、既存 benchmark harness を使った固定レシピの比較を必須にします。

基本コマンド:

```bash
HOST_CORAZA_PORT=19090 \
WAF_LISTEN_PORT=9090 \
WAF_API_KEY_PRIMARY=dev-only-change-this-key-please \
BENCH_REQUESTS=120 \
WARMUP_REQUESTS=20 \
BENCH_CONCURRENCY=1,20 \
BENCH_DISABLE_RATE_LIMIT=1 \
./scripts/benchmark_proxy_tuning.sh
```

比較するもの:

- single-listener baseline
- fan-out 候補 topology

再開の最低条件:

- target topology で connection-reset 症状が出ない
- preset / concurrency のどの row でも fail-rate が `0%` を超えない
- candidate topology で全 row が non-2xx に崩れるような現象がない
- target concurrency で意味のある改善が少なくとも 1 つある
  - RPS が明確に良い
  - または p95 / p99 が明確に良い
- 改善しない row で大きな regression が出ない

ここは意図的に厳しめです。listener fan-out は platform complexity を増やすので、僅差の勝ちは採用理由になりません。

## Smoke gate shape

最低限、対象 topology で次を通す必要があります。

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

評価 topology に TLS が含まれるなら、実 listener port への HTTPS smoke と、必要に応じて admin/API path の sanity も追加します。

smoke の目的は feature coverage ではありません。listener topology 自体が安定していると示すことです。

## 再開 checklist

listener fan-out を再開してよいのは、次をすべて満たした時だけです。

1. 想定 deployment topology を先に文書化している
2. 評価対象が Tier A である
   - もしくは Tier B を含める明確な理由がある
3. benchmark 比較が固定レシピで行われている
4. 同じ topology で smoke が clean
5. bottleneck が upstream/WAF ではなく listener accept 分散にあると説明できる

## 関連文書

- 現在の判断文書:
  - [listener-topology.ja.md](listener-topology.ja.md)
- 評価結果:
  - [reuseport-evaluation.ja.md](reuseport-evaluation.ja.md)
- benchmark baseline:
  - [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
