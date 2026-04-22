# 製品比較

この表は、proxy 統合後の製品構成を前提にしています。

`tukuyomi-proxy` は現行の独立製品としては扱いません。proxy、routing、cache、
WAF tuning、PHP-FPM、scheduled tasks は `tukuyomi` に統合済みです。
過去に公開した `tukuyomi-proxy` バイナリは `tukuyomi-releases` に archive として残します。

凡例:

- `○`: ネイティブ対応 / 主機能
- `△`: 一部対応 / 委譲 / 計画中 / 条件付き
- `×`: スコープ外

| 機能 | `tukuyomi` | `tukuyomi-edge` | `tukuyomi-center` | `tukuyomi-verify` |
| --- | --- | --- | --- | --- |
| 主な役割 | WAF / reverse proxy / API gateway | device 側 edge runtime | center 側管理 | 外部検証 |
| WAF エンジン（Coraza / CRS） | ○ | ○ | × | △ 挙動を検証 |
| Reverse proxy / routing | ○ | ○ | × | × |
| Backend pool / load balancing | ○ | △ | × | × |
| 内蔵管理 UI/API | ○ | ○ | ○ | ○ report UI/API surface |
| 実行時ポリシー更新 | ○ | ○ | ○ | × |
| False-positive tuner | ○ | △ | × | △ 出力を検証 |
| Cache / bypass rules | ○ | ○ | × | △ scenario を検証 |
| Rate / country / bot / semantic / IP reputation 制御 | ○ | ○ | × | △ scenario を検証 |
| Static hosting / PHP-FPM option | ○ | × | × | × |
| Scheduled tasks | ○ | △ | △ | × |
| Single binary 実行 | ○ | ○ | ○ | ○ |
| Docker / container deployment | ○ | △ | △ | ○ |
| 共有 DB / multi-node operation | ○ | △ | ○ | × |
| Device identity / center link | × | ○ | ○ | △ manifest を消費 |
| Verification manifest export | ○ | ○ | ○ | ○ manifest を消費 |
| 配布状態 | 現行 canonical product | 計画 / archive 依存 | 別公開を予定 | 配布方針を検討中 |

## 命名

- 現行の WAF/proxy ドキュメント、binary、service example、source repository 参照は `tukuyomi` を使います。
- `tukuyomi-proxy` は過去 release の archive または migration note の文脈に限定します。
- runtime engine 値 `tukuyomi_proxy` は config 値であり、製品名ではありません。
