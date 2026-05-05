# 第19章　Static Fast-path 評価

第VII部の締めくくりとして、本章では **static fast-path / zero-copy** に
対する tukuyomi の判断を整理します。第14章（listener fan-out / reuse-port）
と同じく、**「やらない判断」を再現可能な形で残す** ことが目的です。

## 19.1　判断 ── 進めない

`tukuyomi` は `nginx` のような **純粋な file-serving proxy ではありません**。
そのうえで、現在の runtime 責務を踏まえると、

> **現時点では、general な static fast-path / zero-copy 実装は進めません。**

というのが結論です。

## 19.2　なぜ進めないのか

`tukuyomi` のレスポンス処理は、今も **user space で扱うのが自然な layer**
を複数持っています。

- request 側の **WAF inspection** は upstream へ流す前に必ず走る
- **route selection / retry / health / circuit** の判断が upstream 選択に
  入る
- **response header sanitation** は live response と cached replay の両方
  に適用される
- **client-facing compression** は transform 対象レスポンスで body buffering
  を必要とする
- **cache replay** でも `X-Request-ID` や WAF hit metadata のような
  request-scoped header を **再注入** する

このため、`nginx` の `sendfile` 的な **generic fast-path** は、ごく一部の
レスポンスにしか効かない一方で、**通常 runtime の複雑さだけを増やしやすい**、
というトレードオフになります。

## 19.3　Zero-copy が噛み合いにくい場所

「噛み合いにくい」と言っても抽象的なので、具体的に 2 箇所挙げておきます。

### 19.3.1　live upstream response

- body は通常 **local file ではなく upstream socket** から届く
- `tukuyomi` はその周辺で **buffering / compression / sanitize / retry** を
  行うことがある
- その layer を通したあとに **clean な zero-copy handoff** を作るのは難しい

### 19.3.2　cache replay を general 戦略にすること

- **cached replay 自体はすでに upstream latency を避けている**
- 現在の cache design は次の 2 段:
  - **bounded な L1 memory replay**
  - **file-backed な L2 replay**
- L1 を有効化したあとは、**disk hit だけに効く最適化** の対象は以前より
  狭い

つまり、「static fast-path で速くしたい」と感じる典型シーンは、現状の
cache 設計でかなり吸収できています。さらに踏み込んで zero-copy にする
価値が現実の workload にあるか、を見極めるのが先です。

## 19.4　すでにある bounded fast-path

`tukuyomi` には、generic な static-file fast-path より **workload に合った
小さな最適化** がすでに入っています。

- **cache hit は in-memory front cache から replay** でき、disk read を
  避けられる
- **file-backed cache hit でも upstream call 自体は回避** できる
- **upgrade / websocket 系トラフィック** は buffering や response compression
  を通らない
- runtime preset（第18章）で **low-latency / buffered-control** を切り替え
  られる

これらは「全部のレスポンスを zero-copy にする」のではなく、**用途に応じた
bounded な fast-path を積んでいる**、という設計です。

## 19.5　再検討する条件

今後この方針を reopen してもよいのは、**現在の cache / compression 方針を
入れたあとでも、cached body replay が実測ボトルネックだと分かった時だけ**
です。

少なくとも、次のどれかが必要です。

- **large immutable asset の cache hit body transfer** が request latency の
  支配要因になっている
- **CPU time が WAF / routing / compression ではなく、cache replay copy
  path に集中** している
- **対象 workload の大半が cache-hit static delivery** で、security /
  rewrite layer がほぼ no-op になっている

逆に言えば、これらの根拠が無いまま **「sendfile 的な fast-path を入れる」
という方向に舵を切らない** のが、現在の方針です。

## 19.6　Reopen 時の narrow slice

将来 reopen する場合でも、変更の **slice は極小に限定** します。

- 対象は **file-backed cache replay の body path だけ**
- **live upstream proxying は変えない**
- **request WAF inspection は bypass しない**
- **response header sanitation は bypass しない**
- **auth / cookie / API path / `Set-Cookie`** に関する cache safety rule
  は弱めない

この slice は **architectural promise ではなく、benchmark 付きの実験**
として扱うべきです。tukuyomi の安全境界（security / sanitize / cache
safety rule）は、いずれの最適化でも崩さない、というのがここでの強い
コミットメントです。

## 19.7　ここまでの整理

- generic な static fast-path / zero-copy は **採用しない**。
- 理由は、`tukuyomi` の response 処理に **user space で扱うべき layer**
  （WAF / routing / sanitize / compression / cache replay の header 注入）
  が複数あるため。
- すでに **bounded な fast-path**（in-memory L1 cache、file-backed L2、
  upgrade tunnel、runtime preset）が入っている。
- reopen は、**実測ボトルネック が cache replay copy path にあるとわかった
  ときだけ**。reopen 時も WAF / sanitize / cache safety rule は崩さない。

## 19.8　次章への橋渡し

これで本書の本編は完結です。続く付録では、第3章以降で何度も参照してきた
**運用リファレンス**（`data/conf/config.json` と DB `app_config_*` の
全 block、admin API、Make ターゲット一覧）を辞書代わりにまとめます。
本文を読みながら設定 key を引きたいときは、付録A を行き来してください。

最後に、付録B として **v1.2.0 と v1.1.0 のリリースノート抜粋** を新しい順に
収録します。本書執筆時点の機能 set を確認するときに参照してください。以後の
リリースノートは、GitHub Releases の release tag を一次情報としてください。
