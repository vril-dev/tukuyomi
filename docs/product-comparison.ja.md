# 製品比較

この表は `tukuyomi` ファミリーの 3 製品を比較したものです。

- `tukuyomi`
- `tukuyomi-proxy`
- `tukuyomi-edge`

凡例:

- `○`: ネイティブ対応 / 主機能
- `△`: 一部対応 / 委譲 / 条件付き
- `×`: スコープ外

注記:

- `single binary` は実行形態を指し、Docker イメージ提供の有無とは別です。
- `DB / multi-node` は製品自身が共有ストア前提でスケールできるかを意味し、外部 control plane 連携とは別です。
- `host hardening` は host 側の L3/L4 tuning / firewall 管理を指し、CDN / ISP 側の upstream DDoS 対策は含みません。

| 機能 | `tukuyomi` | `tukuyomi-proxy` | `tukuyomi-edge` |
| --- | --- | --- | --- |
| WAF エンジン（Coraza / CRS） | ○ | ○ | ○ |
| リバースプロキシ | ○（app proxy 内蔵。`nginx` / LB 前段をよく併用） | ○（内蔵） | ○（内蔵） |
| Single binary 実行 | △（local binary は可能だが、前段 proxy / LB 併用が一般的） | ○ | ○ |
| 主な運用形態 | ○ Docker / compose または local binary | △ Docker または single binary | ○ host / `systemd` |
| Route / upstream 管理 | × | ○ | ○ |
| 実行時ポリシー更新 | ○ | ○ | ○ |
| 内蔵管理 UI | ○ | ○ | ○ |
| ログ / status UI | ○ | ○ | ○ |
| キャッシュ制御 | ○（内部 response cache + 必要に応じて前段 cache） | ○（内部キャッシュ + rules） | ○（内部キャッシュ + rules） |
| バイパスルール | ○ | ○ | ○ |
| IP reputation | ○ | ○ | ○ |
| Bot defense | ○ | ○ | ○ |
| Semantic security | ○ | ○ | ○ |
| Rate limit | ○ | ○ | ○ |
| Country 制御 | ○ | ○ | ○ |
| Device 認証 | × | × | ○ |
| Center / device identity 連携 | × | × | ○ |
| WebSocket 対応 | △（proxy pass-through） | △（upgrade pass-through） | △（upgrade pass-through） |
| TLS 終端 / ACME | △（前段 proxy / LB 管理） | ○ | ○ |
| 通知 | ○ | ○ | ○ |
| DB / MySQL 共有ストア | ○ | ○ | × |
| マルチノード運用 | ○ | ○ | × |
| Host レベル防御（L3/L4） | × | × | △（experimental） |
