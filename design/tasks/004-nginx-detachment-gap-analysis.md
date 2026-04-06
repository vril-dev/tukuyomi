# 004 Nginx Detachment Gap Analysis

目的:

- `[web]` から `nginx` を外した時に失う機能を洗い出し、代替案を決める

現時点で見えている論点:

- `proxy_cache` 依存のキャッシュ
- `logs/nginx` に依存する `access-error` / `interesting` ログ
- `X-Country-Code` 注入がなくなることによる country 系機能への影響
- `X-WAF-Hit` / `X-WAF-RuleIDs` の外部露出制御

完了条件:

- 機能ごとに「残す / 代替実装 / 廃止」を決める
- single-binary 化に必要な追加タスクを列挙する
