# static fast-path 評価

`tukuyomi` は `nginx` のような純粋な file-serving proxy ではありません。この文書では、現在の runtime 責務を踏まえたうえで、static fast-path や zero-copy 戦略を進める価値があるかを整理します。

## 判断

現時点では、general な static fast-path / zero-copy 実装は進めません。

## 理由

`tukuyomi` のレスポンス処理は、今も user space で扱うのが自然な layer を複数持っています。

- request 側の WAF inspection は upstream へ流す前に必ず走る
- route selection、retry、health、circuit の判断が upstream 選択に入る
- response header sanitation は live response と cached replay の両方に適用される
- client-facing compression は transform 対象レスポンスで body buffering を必要とする
- cache replay でも `X-Request-ID` や WAF hit metadata のような request-scoped header を再注入する

このため、`nginx` の `sendfile` 的な generic fast-path は、ごく一部のレスポンスにしか効かない一方で、通常 runtime の複雑さだけを増やしやすいです。

## zero-copy が噛み合いにくい場所

### live upstream response

- body は通常 local file ではなく upstream socket から届く
- `tukuyomi` はその周辺で buffering、compression、sanitize、retry を行うことがある
- その layer を通したあとに clean な zero-copy handoff を作るのは難しい

### cache replay を general 戦略にすること

- cached replay 自体はすでに upstream latency を避けている
- 現在の cache design は
  - bounded な L1 memory replay
  - file-backed な L2 replay
  の 2 段になった
- L1 を有効化した後は、disk hit だけに効く最適化の対象は以前より狭い

## すでにある bounded fast-path

`tukuyomi` には、generic な static-file fast-path より workload に合った小さな最適化がすでにあります。

- cache hit は in-memory front cache から replay でき、disk read を避けられる
- file-backed cache hit でも upstream call 自体は回避できる
- upgrade / websocket 系トラフィックは buffering や response compression を通らない
- runtime preset で low-latency / buffered-control を切り替えられる

## 再検討する条件

今後これを reopen するのは、現在の cache / compression 方針を入れた後でも cached body replay が実測ボトルネックだと分かった時だけです。

少なくとも次のどれかが必要です。

- large immutable asset の cache hit body transfer が request latency の支配要因になっている
- CPU time が WAF / routing / compression ではなく cache replay copy path に集中している
- 対象 workload の大半が cache-hit static delivery で、security / rewrite layer がほぼ no-op になっている

## reopen 時の narrow slice

将来 reopen する場合でも、slice は極小に限定します。

- 対象は file-backed cache replay の body path だけ
- live upstream proxying は変えない
- request WAF inspection は bypass しない
- response header sanitation は bypass しない
- auth / cookie / API path / `Set-Cookie` に関する cache safety rule は弱めない

この slice は architectural promise ではなく、benchmark 付きの実験として扱うべきです。
