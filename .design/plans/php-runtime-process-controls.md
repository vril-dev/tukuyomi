# PHP Runtime Process Controls

## 背景

Vhosts の `php-fpm` mode は PHP runtime と docroot/listen binding を宣言し、実プロセスは PHP runtime supervisor が起動・停止・再起動する。現状は API に `up` / `down` / `reload` があるが、admin UI では Runtime Inventory が状態表示中心で、operator が `php85` などの runtime を明示的に復旧・再起動する導線が不足している。

Backends は direct upstream の runtime 操作面に寄せるため、vhost-managed PHP-FPM target は Backends ではなく Vhosts / PHP Runtimes 側で扱う。

## 問題

- Vhost row からは、紐づく PHP runtime が停止している時の復旧導線が見えない。
- Runtime Inventory には process status はあるが、Start / Stop / Reload の操作がない。
- supervisor は想定外終了時に reconcile で再起動を試みるが、UI からは restart loop や last exit reason を判断しづらい。
- `Reload` が「停止して同じ materialization で起動」なのか、「設定反映」なのかが UI 上で曖昧。

## 目標

- PHP-FPM プロセス操作の責務を Vhosts ではなく PHP Runtime に明確化する。
- operator が `php85` のような runtime を UI から安全に `Start` / `Stop` / `Reload` できる。
- Vhosts は runtime の利用状況と状態を表示し、詳細操作先へ誘導する。
- 異常終了時の状態を、運用判断に足る粒度で表示する。

## 非目標

- PHP-FPM supervisor の全面再設計。
- systemd / container runtime への依存追加。
- Backends 画面に vhost-managed target を戻すこと。
- runtime inventory のビルド・配布モデル変更。

## 設計

### UI 配置

`Options > Runtime Inventory` を PHP Runtime の操作面として扱う。

各 runtime card に以下を表示する。

- runtime id / display name / detected version
- materialized vhost count
- process state: `running`, `stopped`, `manual_stopped`, `start_failed`, `exited`
- PID
- effective user/group
- generated targets
- last action
- last error
- started/stopped timestamp

各 runtime card に操作を置く。

- `Start`: materialized runtime が存在し、停止中の時だけ有効
- `Stop`: 実行中の時だけ有効
- `Reload`: 実行中の時だけ有効。現在の materialization で stop/start する

Vhosts 側は、php-fpm vhost row に runtime state summary と `Open Runtime` link を置く。Vhost row に `Restart` は置かない。理由は、1 runtime が複数 vhost を束ねるため、Vhost 単位の Restart 表現は影響範囲を誤認させる。

### API

既存 API を UI から利用する。

- `POST /api/php-runtimes/:runtime_id/up`
- `POST /api/php-runtimes/:runtime_id/down`
- `POST /api/php-runtimes/:runtime_id/reload`
- `GET /api/php-runtimes`

追加 API は原則不要。必要になった場合のみ、`GET /api/php-runtimes` の `processes[]` に不足フィールドを追加する。

### Supervisor 動作

現行の foreground `php-fpm -F -y <config>` 起動は維持する。

- `down` は manual stop として記録し、reconcile で自動起動しない。
- `up` は manual stop を解除し、materialized runtime を起動する。
- `reload` は manual stop を解除し、既存 process を停止してから同じ materialization で起動する。
- 想定外終了は `exited` として last error を残し、reconcile で再起動を試みる。

ゾンビ process は port を保持できないため、operator 向け説明では「port を握るのは生存中の orphan process」と明記する。supervisor 管理下の process は `SIGTERM` 後に timeout で `SIGKILL` する現行方針を維持する。

### 安全性

- Runtime 操作は admin mutate guard の対象にする。
- read-only mode では操作ボタンを disabled にする。
- `Stop` / `Reload` は対象 runtime の generated targets を表示して影響範囲を明確にする。
- `Reload` は running runtime のみ許可し、停止中の復旧は `Start` に限定する。
- runtime id は既存の normalized token matching に従い、未 materialized runtime は起動しない。

## 受け入れ条件

- Runtime Inventory で materialized PHP runtime を Start / Stop / Reload できる。
- Vhosts では php-fpm runtime の状態と詳細導線が見えるが、Restart 操作は置かない。
- read-only session では操作できない。
- `php85` が停止中の場合、Runtime Inventory から Start で復旧できる。
- `php85` が実行中の場合、Reload で PID が変わり、generated target の listen port が復旧する。
- 想定外終了時は `exited` / `last_error` が表示され、自動復旧の結果が分かる。

## 検証

- `go test ./internal/handler -run PHPRuntime`
- `go test ./...`
- `npm run build`
- UI 手動確認:
  - Runtime Inventory で Start / Stop / Reload の enabled state
  - Vhosts から Runtime Inventory への導線
  - read-only session の disabled state
