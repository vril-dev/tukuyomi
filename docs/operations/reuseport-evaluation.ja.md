# tukuyomi SO_REUSEPORT 評価

この文書では、実験的に検証した `SO_REUSEPORT` / 複数リスナー分散の評価結果を記録します。

`tukuyomi` は、現時点ではリスナー分散を正式機能として提供していません。この文書は、採用見送りの判断を記憶ではなく、実行したコマンドと計測結果に基づいて残すためのものです。

## 結論

- 実験的なリスナー分散について、Docker のポート公開経路はサポート対象とみなさない
- 評価したローカルホストでは、安定したベンチマーク改善は確認できなかった
- この 2 点が同時に解消されるまでは、リスナー分散をサポート対象の実行構成へ戻さない

## Docker ポート公開での症状

評価中、実験的なリスナー分散を有効にした実行環境を Docker でポート公開すると、単純なヘルスチェックでも失敗することがありました。

確認に使ったコマンド:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

観測した失敗:

```text
curl: (56) Recv failure: Connection reset by peer
```

この時点で、正式機能として提供しない理由としては十分です。公開リスナーの直接待ち受けを想定する機能が、一般的なローカル Docker ポート公開経路で不安定になる状態は許容できません。

## 評価で使ったベンチマーク手順

評価では、同じホスト上で既存のローカルベンチマーク用スクリプトを使い、リスナー構成だけを切り替えて比較しました。

実行コマンド:

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

- single-listener baseline
- `reuse_port=true` と `listener_count=2` を使う実験的なリスナー分散

## 計測結果

### 単一リスナー baseline

計測時は次の結果でした。

- `balanced@20`: `fail_rate=0.00%`, `p95=1019ms`, `rps=58.15`
- `low-latency@20`: `fail_rate=0.00%`, `p95=1017ms`, `rps=57.88`
- `buffered-guard@20`: `fail_rate=0.00%`, `p95=1173ms`, `rps=99.23`

### 実験的なリスナー分散 (`reuse_port=true`, `listener_count=2`)

計測時は次の結果でした。

- `balanced@20`: `fail_rate=28.33%`, `p95=5002ms`, `rps=19.81`
- `low-latency@1`: `fail_rate=100.00%` で全応答が non-2xx
- `low-latency@20`: `fail_rate=100.00%` で全応答が non-2xx
- `buffered-guard@1`: `fail_rate=6.67%`, `p95=3083ms`, `rps=4.34`
- `buffered-guard@20`: 単一リスナー baseline に対して明確な改善なし

これは「小さな性能低下」や「ホスト側の揺らぎ」として扱える範囲ではなく、明確な採用見送りの結果です。

## 解釈

評価したホストでは、TCP accept の分散が実際のボトルネック解消につながる根拠は得られませんでした。

むしろ確認できたのは次の点です。

- Docker ポート公開時の挙動が不安定であること
- 負荷条件によってベンチマーク結果が大きく崩れること
- リスナー構成を複雑化するだけの、一貫したスループット / レイテンシ改善がないこと

そのため、優先順位は今のままです。

1. upstream transport の調整
2. メトリクス / 可観測性
3. バックプレッシャー / キューイング
4. cache / compression / runtime の調整
5. リスナー分散は、ホスト / ランタイムの根拠が十分に揃った時だけ再検討

## 再開条件

リスナー分散を再検討する場合は、少なくとも次の条件を満たす必要があります。

- 対象となるホスト構成でベンチマーク改善を再現できる
- Docker ポート公開の smoke が安定して通る
  - もしくは Docker でポート公開するローカル実行環境をサポート範囲外にすることを明示する
- 想定する配置トポロジーを先に文書化する
- bottleneck が upstream/WAF ではなく listener accept 分散にあると説明できる

## 関連文書

- 現在の判断文書:
  - [listener-topology.ja.md](listener-topology.ja.md)
- 再開 policy:
  - [reuseport-policy.ja.md](reuseport-policy.ja.md)
- benchmark baseline:
  - [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
