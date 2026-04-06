# 003 Remove Web Container

目的:

- `[web]` から `web:5173` 依存を外す
- compose / ECS で管理 UI 用の別コンテナを不要にする

完了条件:

- `docker-compose.yml` で `web` サービスが不要になる
- `nginx` 経由でも Go 直配信 UI が見える
- README の起動手順が更新される

注意点:

- この段階では `nginx` はまだ残ってよい
- まずは `ALB -> nginx -> tukuyomi` でも `ALB -> tukuyomi` でもなく、`compose` の責務整理を優先する
