# tukuyomi SO_REUSEPORT ホスト別評価方針

この文書では、`tukuyomi` で `SO_REUSEPORT` / リスナー分散を将来再評価する場合の方針を定義します。

この文書は、機能再開を決めるものではありません。どのホスト / ランタイムでの評価を有効な根拠として扱うか、どの構成を評価対象に含めるか、再開前にどのベンチマーク / smoke を通すべきかを定めます。

## 方針の要約

- リスナー分散は、引き続きサポート対象の実行構成には含めない
- 将来再評価する場合は、実装都合ではなくホスト / ランタイム方針から始める
- Docker bridge のポート公開挙動は、再評価の必須条件にはしない
- Docker のポート公開サポート自体が必要な場合は、別の作業項目として扱う

## ホスト / ランタイム別マトリクス

| Tier | ホスト / ランタイム種別 | 例 | 方針 | 理由 |
| --- | --- | --- | --- | --- |
| A | Linux VM または bare metal での direct host bind | `:443` を直接公開する entrypoint | 必須 | listener accept 分散を評価するうえで最も信頼できるケース |
| A | host networking か同等の direct socket ownership を持つ Linux container | host-network container で bridge publish を使わない | containerized direct entrypoint を対象にするなら必須 | direct socket ownership に近い |
| B | 外部 LB/CDN の背後だが、`tukuyomi` 自体は local listener を直接持つ | LB -> VM / host-network container -> `tukuyomi` | 任意 | 想定する配置構成に合うなら確認価値がある |
| C | Docker bridge + published host port | `docker compose` の `19090:9090` 形式 | 再評価の判定条件としては対象外 | ローカル開発体験には有用だが、リスナー分散の性能判断には使いにくい |
| C | Desktop VM forwarding などの non-Linux host-network abstraction | Docker Desktop や nested forwarding | 対象外 | client と listener の間に変数が多すぎる |

## 「必須」の意味

再評価の議論は、Tier A の根拠がない限り前に進めません。

必要なこと:

- 少なくとも 1 つの Tier A ホスト / ランタイム種別でベンチマーク改善を再現できる
- 同じ種別で単純なリスナー smoke が安定して通る
- その改善が `tukuyomi` の実際の実行構成を有効にした後でも残る
  - WAF
  - routing
  - retry/health logic
  - compression
  - cache

## Docker ポート公開の扱い

Docker bridge のポート公開挙動は、リスナー分散の再評価とは別論点として扱います。

現時点の方針:

- Docker のポート公開が不安定でも、それだけで将来の再評価可能性を完全には否定しない
- 逆に、Docker のポート公開が通っただけでは採用根拠にしない
- bridge 経由でポート公開する local/container runtime を製品要件にする場合は、独立した作業項目と smoke テスト仕様を持たせる

これにより、ローカル開発体験の都合だけで本番向けリスナーの判断が引きずられないようにします。

## ベンチマーク判定条件

将来再評価する場合は、既存のベンチマーク用スクリプトを使い、固定レシピでの比較を必須にします。

基本コマンド:

```bash
HOST_CORAZA_PORT=19090 \
WAF_LISTEN_PORT=9090 \
WAF_ADMIN_USERNAME=admin \
WAF_ADMIN_PASSWORD=dev-only-change-this-password-please \
BENCH_REQUESTS=120 \
WARMUP_REQUESTS=20 \
BENCH_CONCURRENCY=1,20 \
BENCH_DISABLE_RATE_LIMIT=1 \
./scripts/benchmark_proxy_tuning.sh
```

比較対象:

- 単一リスナー baseline
- リスナー分散の候補構成

再開の最低条件:

- 対象構成で connection-reset 症状が出ない
- preset / concurrency のどの行でも fail-rate が `0%` を超えない
- 候補構成で全行が non-2xx に崩れるような現象がない
- 対象 concurrency で意味のある改善が少なくとも 1 つある
  - RPS が明確に良い
  - または p95 / p99 が明確に良い
- 改善しない行で大きな性能低下が出ない

ここは意図的に厳しめです。リスナー分散は実行基盤の複雑さを増やすため、僅差の勝ちは採用理由になりません。

## Smoke 判定条件

最低限、対象構成で次を通す必要があります。

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

評価構成に TLS が含まれる場合は、実 listener port への HTTPS smoke と、必要に応じて admin/API path の疎通確認も追加します。

smoke の目的は機能網羅ではありません。listener topology 自体が安定していることを示すためのものです。

## 再評価チェックリスト

リスナー分散を再評価してよいのは、次をすべて満たした時だけです。

1. 想定する deployment topology を先に文書化している
2. 評価対象が Tier A である
   - もしくは Tier B を含める明確な理由がある
3. ベンチマーク比較が固定レシピで行われている
4. 同じ構成で smoke が安定して通る
5. ボトルネックが upstream/WAF ではなく listener accept 分散にあると説明できる

## 関連文書

- 現在の判断文書:
  - [listener-topology.ja.md](listener-topology.ja.md)
- 評価結果:
  - [reuseport-evaluation.ja.md](reuseport-evaluation.ja.md)
- benchmark baseline:
  - [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
