# 第14章　Listener トポロジと Reuse-Port

本章では、tukuyomi がなぜ現時点で **single-listener topology を supported
runtime としているか**、`SO_REUSEPORT` / multi-listener fan-out を採用しない
判断の根拠、そして将来 fan-out を再導入するなら満たすべき条件、を整理します。

これは「最新機能をすぐ使う」ためのチューニング章ではなく、**「複雑性を増やす
変更をしないという判断を、再現可能な形で残す」** ための章です。tukuyomi の
listener 関連の挙動を tune したくなったときに、最初に立ち戻るべき方針が
ここに集約されています。

## 14.1　現在の判断

最初に結論を並べます。

- **supported runtime は single TCP listener** のまま維持する
- 任意の HTTP redirect listener は **single-socket** のままにする
- built-in HTTP/3 listener は **single UDP socket** のままにする
- 現時点では **`SO_REUSEPORT` / multi-listener fan-out は採用しない**
- public HTTP/1.1 data-plane listener は **Tukuyomi native HTTP/1.1 server**
  で処理し、admin listener は分離した **control-plane server path** のまま
  にする

つまり、`tukuyomi` に **lower-level な listener fan-out knob は追加しない**
というのが現時点の答えです。

## 14.2　評価止まりにした理由

`SO_REUSEPORT` / multi-listener の試作は、**実際に review まで進めた** 上で、
**安全かつ一貫した改善が確認できなかった**、という経緯があります。

review で確認した主な観察:

- **Docker の port publish を使った smoke で `connection reset by peer` が
  出ることがあった**
- **local benchmark でも workload による偏りが強く**、安定した改善ではなく
  大きな regression が出るケースがあった
- `tukuyomi` は WAF inspection、routing、retry / health、compression、
  cache でも時間を使うため、**TCP accept fan-out が最初の bottleneck とは
  限らない**

そのため、現時点の `tukuyomi` は **single-listener topology を supported
runtime とする** 立場を取っています。

### 14.2.1　Docker published-port で観測した症状

評価中、実験的 listener fan-out を有効にした Docker port-published runtime
は、**単純な health probe でも失敗することがありました**。

確認に使った probe:

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

観測した失敗:

```text
curl: (56) Recv failure: Connection reset by peer
```

これだけでも、feature を ship しない理由として十分です。direct public
listener を目指す機能が、**一般的な local Docker publish 経路で不安定** な
のは許容できないからです。

### 14.2.2　Benchmark での結果

review では、同じ host 上で既存の local benchmark harness を使い、listener
topology だけを切り替えて比較しました。

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

比較したもの:

- single-listener baseline
- `reuse_port=true` と `listener_count=2` を使う実験的 fan-out

#### Single-listener baseline

記録した run では次の結果でした。

- `balanced@20`: `fail_rate=0.00%`, `p95=1019ms`, `rps=58.15`
- `low-latency@20`: `fail_rate=0.00%`, `p95=1017ms`, `rps=57.88`
- `buffered-guard@20`: `fail_rate=0.00%`, `p95=1173ms`, `rps=99.23`

#### 実験的 fan-out（`reuse_port=true`, `listener_count=2`）

同条件での fan-out 側の結果は次のとおりでした。

- `balanced@20`: `fail_rate=28.33%`, `p95=5002ms`, `rps=19.81`
- `low-latency@1`: `fail_rate=100.00%` で全応答が non-2xx
- `low-latency@20`: `fail_rate=100.00%` で全応答が non-2xx
- `buffered-guard@1`: `fail_rate=6.67%`, `p95=3083ms`, `rps=4.34`
- `buffered-guard@20`: single-listener baseline に対して明確な改善なし

これは「小さな regression」や「host noise」の範疇ではなく、**明確な no-go
判定** に該当します。

## 14.3　当面の方針

評価結果を踏まえて、当面の方針は次のとおりです。

- **既定の single-listener topology を維持** する
- throughput 調整は、まず **`make bench` と transport metrics** で詰める
- listener fan-out を再検討する **前に**、次を優先する
  - upstream transport tuning（第6章）
  - cache
  - compression
  - backpressure（第3章 3.9）

「listener を fan-out すれば速くなる」という感覚的な判断ではなく、
**bottleneck が listener accept にあるという証拠** を先に取る、というのが
ここでの態度です。

## 14.4　Host / runtime matrix

将来 listener fan-out を再評価するときに **どの host / runtime の評価を
意味のあるものとして扱うか** を、policy として明示しておきます。

| Tier | Host / runtime class | 例 | Policy status | 理由 |
|---|---|---|---|---|
| A | Linux VM または bare metal の direct host bind | `:443` を直接公開する entrypoint | **Required** | listener accept fan-out を評価する最も信頼できるケース |
| A | host networking か同等の direct socket ownership を持つ Linux container | host-network container で bridge publish を使わない | containerized direct entrypoint が target なら **Required** | direct socket ownership に近い |
| B | 外部 LB / CDN の背後だが、`tukuyomi` 自体は local listener を直接持つ | LB → VM / host-network container → `tukuyomi` | **Optional** | 想定 deployment shape に合うなら確認価値がある |
| C | Docker bridge + published host port | `docker compose` の `19090:9090` 形式 | reopen gate としては **Out of scope** | local DX には良いが、listener fan-out の性能 gate としては信用しにくい |
| C | Desktop VM forwarding などの non-Linux host-network abstraction | Docker Desktop や nested forwarding | **Out of scope** | client と listener の間に変数が多すぎる |

### 14.4.1　「Required」の意味

再開の議論は、**Tier A の根拠が無い限り前に進めない** という立場です。
具体的に必要なのは次です。

- 少なくとも 1 つの **Tier A host / runtime class** で benchmark 改善が
  再現できる
- 同じ class で **単純な listener smoke が clean** に通る
- その改善が `tukuyomi` の **実 runtime shape を有効にした後でも残る**
  - WAF
  - routing
  - retry / health logic
  - compression
  - cache

## 14.5　Docker published-port policy

Docker bridge の published-port 挙動は、**別論点として扱います**。

現時点の policy:

- Docker published-port が不安定でも、それだけで将来の再開可能性を **完全
  否定はしない**
- 逆に、**Docker published-port が通っただけで再開根拠にもならない**
- bridge-published local / container runtime を product requirement に
  したいなら、**独立した task と smoke contract を持たせる**

これにより、**local 開発体験の都合だけで production-grade listener の判断が
引きずられない** ようにしています。

## 14.6　Benchmark gate shape（再開時の比較条件）

将来の再開では、**既存 benchmark harness を使った固定レシピでの比較を必須**
にします。

基本コマンドは 14.2.2 節と同じです。比較するのは

- **single-listener baseline**
- **fan-out 候補 topology**

の 2 つです。

再開の最低条件は次のとおりです。

- target topology で **connection-reset 症状が出ない**
- preset / concurrency のどの row でも **fail-rate が `0%` を超えない**
- candidate topology で **全 row が non-2xx に崩れる現象がない**
- target concurrency で **意味のある改善が少なくとも 1 つある**
  - RPS が明確に良い
  - または p95 / p99 が明確に良い
- 改善しない row で **大きな regression が出ない**

ここは意図的に厳しめに設定しています。**listener fan-out は platform
complexity を増やすので、僅差の勝ちは採用理由になりません**。

## 14.7　Smoke gate shape

最低限、対象 topology で次を通す必要があります。

```bash
curl -fsS http://127.0.0.1:19090/healthz
```

評価 topology に TLS が含まれるなら、

- 実 listener port への HTTPS smoke
- 必要に応じて admin / API path の sanity

も追加します。

smoke の目的は **feature coverage ではなく、listener topology 自体が安定
していると示すこと** です。

## 14.8　再開 checklist

listener fan-out を再開してよいのは、次を **すべて満たした時だけ** です。

1. 想定 deployment topology を **先に文書化** している
2. 評価対象が **Tier A** である（もしくは Tier B を含める明確な理由がある）
3. benchmark 比較が **固定レシピ** で行われている
4. 同じ topology で **smoke が clean**
5. bottleneck が **upstream / WAF ではなく listener accept 分散** にあると
   説明できる

## 14.9　ここまでの整理

- 現時点では `SO_REUSEPORT` / multi-listener fan-out を **採用しない**。
  single-listener が supported runtime。
- 評価では Docker published-port での `connection reset` と、benchmark での
  大きな fail-rate 増加が観測された。
- bottleneck の根拠は WAF / routing / cache 側にもあるので、まず upstream
  transport tuning / metrics / backpressure / cache / compression を優先する。
- 将来再開する場合は **Tier A host での benchmark 改善 + clean smoke +
  bottleneck の説明** を前提条件として要求する。

## 14.10　次章への橋渡し

listener topology を理解したので、次は **「その single listener が、HTTPS
や HTTP/3 をどう扱うか」** を見ていきます。第15章では、built-in TLS
termination、ACME 自動更新、HTTP/3 専用 UDP listener、HTTP/3 public-entry
smoke を扱います。
