[English](php-scheduled-tasks.md) | [日本語](php-scheduled-tasks.ja.md)

# スケジュールタスク

この文書では、管理 UI で定義し、HTTP リクエスト処理とは別に実行するコマンドラインジョブの `/scheduled-tasks` 運用を説明します。

## 管理範囲

- `/scheduled-tasks`
  - 保存されるタスク定義の管理元
  - cron 形式のスケジュール、コマンドライン、環境変数、タイムアウト、最終実行状態の管理
- 外部スケジューラー
  - `tukuyomi run-scheduled-tasks` を起動
  - 実際の分単位の起動を担当
  - HTTP リクエストを処理するメインプロセスとは分離

## データ配置

保存されるタスク定義の正本は、正規化された `scheduled_tasks` DB ドメインです。`conf/scheduled-tasks.json` は空 DB 向けの初期データ / エクスポートファイルであり、初期化後の実行時に参照される正本ではありません。

最終実行状態のスナップショットは、`scheduled_task_runtime_state` DB テーブルに保存されます。

実行時に生成される成果物は、引き続き `data/scheduled-tasks/` 配下に保存されます。

- `locks/`
  - タスクごとのロックファイル
- `logs/`
  - タスクごとのログ

既定パスは、有効な DB 設定 `app_config` の既定値で制御します。

- `paths.scheduled_task_config_file`

## タスクモデル

各タスクは、cron 形式のスケジュールと完全なコマンドラインを 1 本持ちます。

例:

```text
date
```

stdout / stderr は、自動的に `data/scheduled-tasks/logs/` へ保存されます。

この形に寄せることで、スケジュールタスクのモデルを単純に保ちます。

- 同梱ランタイムを選択する専用項目は持たない
- PHP バイナリ専用項目は持たない
- 作業ディレクトリ専用項目は持たない
- 引数配列専用項目も持たない

同梱 PHP ランタイムを使う場合は、その `php` ラッパーをコマンドラインへ直接書きます。ホストにインストール済みの PHP を使う場合は、`/usr/bin/php8.5` などを直接指定します。

## UI 操作手順

基本手順:

1. `/scheduled-tasks` を開く
2. タスクを追加する
3. `name`、`schedule`、コマンド全体を `command` に入力する
4. 必要に応じて `env` と `timeout` を入力する
5. `Validate` を実行する
6. `Apply` を実行する

補足:

- 実行結果のぶれを避けるため、パスは絶対パスで指定することを推奨します
- ステータスは、外部スケジューラーが 1 回実行の runner を起動したタイミングで更新されます
- UI に表示されるログパスは `data/scheduled-tasks/logs/` 配下です

## 実行コマンド

外部スケジューラーからは、次のコマンドを実行します。

```bash
./bin/tukuyomi run-scheduled-tasks
```

このコマンドは、次の処理を行います。

- `conf/config.json` を読み込む
- 設定された DB ストアを開く
- 正規化された `scheduled_tasks` DB ドメインを直接読み込む。ドメインが存在しない場合だけ `conf/scheduled-tasks.json` から初期データを投入する
- 現在の分に一致するジョブだけを実行する
- 各タスクを `/bin/sh -lc` 経由で起動する
- タスクステータスを `scheduled_task_runtime_state` に記録する
- ロック / ログの成果物を `data/scheduled-tasks/` に記録する

cron daemon 自体は内蔵しません。OS やコンテナ基盤側のスケジューラーから起動してください。

## バイナリ配置での構成

Linux へバイナリ配置する場合は、`systemd timer` を使います。

例:

- [docs/build/tukuyomi-scheduled-tasks.service.example](../build/tukuyomi-scheduled-tasks.service.example)
- [docs/build/tukuyomi-scheduled-tasks.timer.example](../build/tukuyomi-scheduled-tasks.timer.example)

timer が毎分起動し、service が上記の 1 回実行コマンドを起動します。

## コンテナ配置での構成

コンテナ配置では、スケジュールタスクの所有形態を 2 つに分けます。

### 1. 現行の公式既定構成: single-instance sidecar

プロキシ全体が現行公式の single-instance mutable topology のままであれば、scheduler sidecar を使います。

必要条件:

- メインの `tukuyomi` コンテナと同じ `conf/` と `data/scheduled-tasks/` をマウントする
- コマンドラインが `data/php-fpm/` 配下の同梱 PHP パスを指す場合は、`data/php-fpm/` もマウントする
- 同じバイナリを `run-scheduled-tasks` 付きで起動する

リポジトリの compose 導線では、プロキシが所有するコマンド向けに sidecar サービスを使えます。

```bash
make compose-up-scheduled-tasks
```

同等の compose コマンドは次のとおりです。

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

`artisan schedule:run` のようなアプリケーション側ジョブは、アプリケーションツリーを `coraza` と `scheduled-task-runner` の両方へマウントする必要があります。配置環境ごとの上書きファイルとして [docs/build/docker-compose.scheduled-tasks.app.example.yml](../build/docker-compose.scheduled-tasks.app.example.yml) を使ってください。

現在の sidecar 実行モデルは明示的です。shell loop がイメージ内のプロキシバイナリを `run-scheduled-tasks` 付きで呼び出し、次の分境界まで sleep します。

障害時の扱いも明示的です。`run-scheduled-tasks` が non-zero を返した場合、sidecar も non-zero で終了し、障害を握り潰さずにコンテナの restart policy へ渡します。

リクエストを処理するメインのプロキシコンテナに `crond` を同居させるより、scheduler を分離する構成を推奨します。`make gateway-preview-up` でも preview 専用の scheduler sidecar を起動します。継続的な scheduler 障害は、sidecar のログと restart 回数で確認してください。

### 2. 将来の guarded 構成: replicated frontend + dedicated singleton scheduler

現行公式の single-instance topology を外れて replicated immutable frontend を試す場合、各 frontend replica に scheduler sidecar を 1 個ずつ載せないでください。

- frontend replica では `admin.read_only=true`
- 設定変更は rollout 経由
- 各 frontend replica に scheduler sidecar を 1 個ずつ載せない
- スケジュールタスクの所有権は dedicated singleton scheduler role に持たせる

その singleton scheduler role も、同じ管理元を参照するために次をマウントします。

- `conf/`
- `data/scheduled-tasks/`
- `logs/`
- 同梱ランタイムを使う場合は `data/php-fpm/`

参照:

- [container-deployment.ja.md](../build/container-deployment.ja.md)
- [ecs-replicated-frontend-scheduler.task-definition.example.json](../build/ecs-replicated-frontend-scheduler.task-definition.example.json)
- [kubernetes-replicated-frontend-scheduler.example.yaml](../build/kubernetes-replicated-frontend-scheduler.example.yaml)
- [azure-container-apps-scheduler-singleton.example.yaml](../build/azure-container-apps-scheduler-singleton.example.yaml)

## Preview 手動確認

scheduler を含む preview 経路を確認する場合は、次を実行します。

```bash
make gateway-preview-up
make gateway-preview-down
```

preview は通常系とは別に、preview 専用 DB で管理される scheduled-task config を使います。そのため、preview UI からの変更は通常の実行設定を変更しません。

既定では、`gateway-preview-up` のたびに preview 専用 SQLite DB を作り直します。以前の preview task や DB row は引き継ぎません。

`down/up` をまたいで preview の編集結果を残す場合は、preview 用 DB state を保持します。

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
```

`GATEWAY_PREVIEW_PERSIST=1` では preview SQLite DB を保持するため、`Settings` で保存したリスナー変更を preview の `down/up` で確認できます。

split preview listener も使用できますが、preview listener 設定の bind は `:80`, `:9090` のようなホストから到達可能な形式にしてください。`localhost:80`, `127.0.0.1:80`, `[::1]:9090` のような loopback bind は Docker のポート公開と噛み合わないため、`gateway-preview-up` は明示的なエラーで停止します。

バイナリ、Docker sidecar、preview sidecar の 3 経路をまとめて確認する回帰テストは次のとおりです。

```bash
make scheduled-tasks-smoke
```

preview persistence と split-port parity だけを個別に確認する場合は、次を実行します。

```bash
make gateway-preview-smoke
```

## 同梱 PHP CLI

`make php-fpm-build` は次の両方を生成します。

- `data/php-fpm/binaries/<runtime_id>/php-fpm`
- `data/php-fpm/binaries/<runtime_id>/php`

つまり、ビルド済みランタイムバンドルは PHP-FPM ワークロードと、スケジュール実行する PHP CLI ジョブの両方に使えます。スケジュールタスクでは `/options` を経由せず、その CLI パスをコマンドラインへ直接書きます。

同梱 PHP CLI は、同梱 PHP-FPM ランタイムと同じ拡張セットを使うため、SQLite / MySQL(MariaDB) / PostgreSQL を標準で扱えます。

## GeoIP Country DB 自動更新

管理対象の country DB 更新は、手動実行とスケジュール実行の両方に対応します。

バイナリ / リポジトリのラッパー:

```bash
./scripts/update_country_db.sh
```

バイナリのサブコマンド:

```bash
./bin/tukuyomi update-country-db
```

コンテナイメージのコマンド:

```bash
/app/server update-country-db
```

運用手順:

1. `Options -> GeoIP Update` から `GeoIP.conf` をアップロードする。DB mode では runtime DB authority に保存される
2. `Update now` を 1 回実行し、成功することを確認する
3. 配置形態に応じて、上記いずれかのコマンドを呼び出すスケジュールタスクを追加する
