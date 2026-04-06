# 002 Embed Admin UI

目的:

- `[web]` の React 管理 UI を build 済み asset として Go バイナリへ同梱する
- `web` コンテナなしでも管理 UI を配信できる状態にする

完了条件:

- 管理 UI の `dist` を Go 側へ同期できる
- Go バイナリが `/tukuyomi-admin` を直接配信できる
- 管理 UI から既存 Admin API を使って正常動作する

注意点:

- まずは UI 配信だけ。`nginx` 廃止はこのタスクに含めない
- base path と asset path の扱いを固定する

枝タスク候補:

- React build asset 同期の Makefile 化
- cache busting と `go:embed` 運用ルール整理
