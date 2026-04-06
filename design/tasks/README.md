# [web] Tasks

`[web]` の single-binary 化は一度に進めず、完了単位で小さく切って進める。

進め方:

1. 1 タスク = 1 つの目的に絞る
2. タスクごとに検証して commit する
3. 問題が見えたら、そのタスク配下の枝タスクを追加する
4. 既存の `[proxy]` / `[edge]` パターンは参考にするが、`[web]` の nginx 依存は別途評価する

初期タスク:

- `001-coraza-upgrade.md`
- `002-embed-admin-ui.md`
- `003-remove-web-container.md`
- `004-nginx-detachment-gap-analysis.md`
