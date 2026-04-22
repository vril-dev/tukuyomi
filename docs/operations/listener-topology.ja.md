# tukuyomi Listener Topology

この文書は、`tukuyomi` の listener topology に関する現時点の判断をまとめたものです。

## 現在の判断

- supported runtime は single TCP listener のまま維持する
- 任意の HTTP redirect listener は single-socket のままにする
- built-in HTTP/3 listener は single UDP socket のままにする
- 現時点では `SO_REUSEPORT` / multi-listener fan-out は採用しない

現時点の答えは no です。`tukuyomi` に lower-level な listener fan-out knob は追加しません。

## 評価止まりにした理由

`SO_REUSEPORT` / multi-listener の試作を実際に review まで進めましたが、安全かつ一貫した改善が確認できませんでした。

review で確認したこと:

- Docker の port publish を使った smoke で `connection reset by peer` が出ることがあった
- local benchmark でも workload による偏りが強く、安定した改善ではなく大きな regression が出るケースがあった
- `tukuyomi` は WAF inspection、routing、retry/health、compression、cache でも時間を使うので、TCP accept fan-out が最初の bottleneck とは限らない

そのため、現時点の `tukuyomi` は single-listener topology を supported runtime とします。

## 当面の方針

- 既定の single-listener topology を維持する
- throughput 調整は、まず `make bench` と transport metrics で詰める
- listener fan-out を再検討する前に、upstream transport tuning、cache、compression、backpressure を優先する

## 再検討条件

今後 listener fan-out を再導入するなら、少なくとも次が必要です。

- 対象 host class で再現可能な benchmark 改善
- Docker / published-port でも素直に通る smoke
- bottleneck が upstream/WAF ではなく listener accept 分散にあるという根拠

## 関連文書

- benchmark baseline: [benchmark-baseline.ja.md](benchmark-baseline.ja.md)
- reuse-port evaluation: [reuseport-evaluation.ja.md](reuseport-evaluation.ja.md)
- reuse-port host matrix and policy: [reuseport-policy.ja.md](reuseport-policy.ja.md)
- HTTP/3 public-entry smoke: [http3-public-entry-smoke.ja.md](http3-public-entry-smoke.ja.md)
