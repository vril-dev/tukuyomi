# 001 Coraza Upgrade

Status:

- completed on 2026-04-06

目的:

- `[web]` の Coraza を最新安定版へ更新する
- まずは依存更新だけに絞り、single-binary 化とは分離する

完了条件:

- `coraza/src/go.mod` と `go.sum` が更新される
- README の Coraza バージョン表記が更新される
- 少なくとも以下が通る
  - `go test ./...` (`coraza/src`)
  - `go test -race ./...` (`coraza/src`)
  - `make ui-test`
  - `make compose-config`
  - `make compose-config-mysql`
  - `make example-smoke-all`
  - `make gotestwaf-file`
  - `make gotestwaf-sqlite`

枝タスク候補:

- Coraza 更新で API 互換差分が出た場合の修正
- GoTestWAF や example smoke の基準調整
- 更新後の管理画面キャプチャ更新

実施メモ:

- Coraza latest は `go list -m -json github.com/corazawaf/coraza/v3@latest` で `v3.6.0` を確認
- 実施した検証
  - `go test ./...`
  - `go test -race ./...`
  - `make ui-test`
  - `make compose-config`
  - `make compose-config-mysql`
  - `make mysql-logstore-test`
  - `make example-smoke-all`
  - `make gotestwaf-file`
  - `make gotestwaf-sqlite`
