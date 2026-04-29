[English](php-scheduled-tasks.md) | [日本語](php-scheduled-tasks.ja.md)

# Scheduled Tasks

この document は、管理UI で定義しつつ request path の外で実行する command-line job の `/scheduled-tasks` 運用をまとめたものです。

## 責務分離

- `/scheduled-tasks`
  - task 定義の source of truth
  - cron schedule、command line、env、timeout、最終実行状態の管理
- 外部 scheduler
  - `tukuyomi run-scheduled-tasks` を起動
  - 実際の minute 単位の起動を担当
  - main HTTP server process とは分離

## Data Layout

保存される task 定義の正は normalized `scheduled_tasks` DB domain です。
`conf/scheduled-tasks.json` は空 DB の seed/export file であり、bootstrap 後の
runtime source of truth ではありません。

最終実行状態は `scheduled_task_runtime_state` DB table に入ります。

生成される runtime artifact は引き続き `data/scheduled-tasks/` にあります。

- `locks/`
  - task ごとの lock file
- `logs/`
  - task ごとの log

既定 path は effective DB `app_config` の default で制御します。

- `paths.scheduled_task_config_file`

## Task Model

各 task は cron 風の full command line を 1 本持ちます。

例:

```text
date
```

stdout / stderr は自動的に `data/scheduled-tasks/logs/` へ保存されます。

この形に寄せることで、scheduled task の model は単純になります。

- bundled runtime selector は持たない
- PHP binary 専用 field は持たない
- Working Directory は持たない
- args array も持たない

bundled PHP runtime を使いたいなら、その `php` wrapper を command line へ直接書きます。host-installed PHP を使いたいなら `/usr/bin/php8.5` などを直接書きます。

## UI Workflow

典型的な flow:

1. `/scheduled-tasks` を開く
2. task を追加する
3. `name`、`schedule`、full `command` を入れる
4. 必要なら `env` と `timeout` を入れる
5. `Validate` を実行する
6. `Apply` を実行する

補足:

- 実行のぶれを避けるため、path は absolute path を推奨します
- status は外部 scheduler が one-shot runner を起動した時に更新されます
- UI に出る log path は `data/scheduled-tasks/logs/` 配下です

## Runner Command

外部 scheduler から実行する command はこれです。

```bash
./bin/tukuyomi run-scheduled-tasks
```

この command は:

- `conf/config.json` を読み込む
- 設定された DB store を開く
- normalized `scheduled_tasks` DB domain を直接読む。domain が無い時だけ `conf/scheduled-tasks.json` から seed する
- 現在 minute に一致する job だけを実行する
- 各 task を `/bin/sh -lc` で起動する
- task status を `scheduled_task_runtime_state` に記録する
- lock/log artifact を `data/scheduled-tasks/` に記録する

cron daemon 自体は持ちません。platform 側 scheduler から起動してください。

## Binary Deployment Pattern

Linux の binary deployment では `systemd timer` を使います。

example:

- [docs/build/tukuyomi-scheduled-tasks.service.example](../build/tukuyomi-scheduled-tasks.service.example)
- [docs/build/tukuyomi-scheduled-tasks.timer.example](../build/tukuyomi-scheduled-tasks.timer.example)

timer が毎分起動し、service が上記 one-shot command を実行します。

## Container Deployment Pattern

container deployment では ownership を 2 形態に分けます。

### 1. 現行 official default: single-instance sidecar

proxy 全体が official な single-instance mutable topology のままなら、
scheduler sidecar を使います。

必要条件:

- main `tukuyomi` container と同じ `conf/` と `data/scheduled-tasks/` を mount する
- command line が `data/php-fpm/` 配下の bundled PHP path を指すなら `data/php-fpm/` も mount する
- 同じ binary を `run-scheduled-tasks` 付きで起動する

repository の compose 導線では、proxy-owned command 向けに実体のある sidecar service を使えます。

```bash
make compose-up-scheduled-tasks
```

生の compose command はこれです。

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

`artisan schedule:run` のような application job は、application tree を `coraza` と `scheduled-task-runner` の両方へ mount する必要があります。deployment 専用の override file として [docs/build/docker-compose.scheduled-tasks.app.example.yml](../build/docker-compose.scheduled-tasks.app.example.yml) を使ってください。

現在の sidecar 実行モデルは明示的です。shell loop が image 内の proxy binary を `run-scheduled-tasks` 付きで呼び、次の minute 境界まで sleep します。

failure policy も明示的です。`run-scheduled-tasks` が non-zero を返したら sidecar も non-zero で終了し、fault を握り潰さずに container restart policy へ渡します。

request を捌く main proxy container に `crond` を同居させるより、scheduler を分離する方を推奨します。`make gateway-preview-up` でも preview 専用の scheduler sidecar を起動します。恒久的な scheduler fault は sidecar logs と restart 回数で追ってください。

### 2. 将来の guarded shape: replicated frontend + dedicated singleton scheduler

現行の official single-instance topology を外れて、replicated immutable frontend を試す場合は、各 frontend replica に scheduler sidecar を 1 個ずつ載せません。

- frontend replica では `admin.read_only=true`
- config 変更は rollout 経由
- 各 frontend replica に scheduler sidecar を 1 個ずつ載せない
- scheduled-task ownership は dedicated singleton scheduler role に持たせる

その singleton scheduler role も、同じ source of truth として次を mount します。

- `conf/`
- `data/scheduled-tasks/`
- `logs/`
- bundled runtime を使うなら `data/php-fpm/`

参照:

- [container-deployment.ja.md](../build/container-deployment.ja.md)
- [ecs-replicated-frontend-scheduler.task-definition.example.json](../build/ecs-replicated-frontend-scheduler.task-definition.example.json)
- [kubernetes-replicated-frontend-scheduler.example.yaml](../build/kubernetes-replicated-frontend-scheduler.example.yaml)
- [azure-container-apps-scheduler-singleton.example.yaml](../build/azure-container-apps-scheduler-singleton.example.yaml)

## Preview Manual Check

scheduler を含めた preview 経路を確認したい時はこれです。

```bash
make gateway-preview-up
make gateway-preview-down
```

preview は通常系とは別の preview 専用 DB-backed scheduled-task config を使うので、preview UI からの変更は通常の runtime config を汚しません。

既定では `gateway-preview-up` のたびに preview 専用 SQLite DB を作り直します。以前の preview task や DB row は引き継ぎません。

`down/up` をまたいで preview 編集結果を残したい時は、preview 用 DB state を保持します。

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
```

`GATEWAY_PREVIEW_PERSIST=1` では preview SQLite DB を保持するので、`Settings` で保存した listener 変更を preview の `down/up` で確認できます。

split preview listener も使えますが、preview listener 設定の bind は `:80`, `:9090` のような host 到達可能な形にしてください。`localhost:80`, `127.0.0.1:80`, `[::1]:9090` のような loopback bind は Docker publish と噛み合わないため、`gateway-preview-up` は明示エラーで止めます。

binary、Docker sidecar、preview sidecar の 3 経路をまとめて回す回帰確認はこれです。

```bash
make scheduled-tasks-smoke
```

preview persistence と split-port parity だけを個別に回すならこれです。

```bash
make gateway-preview-smoke
```

## Bundled PHP CLI

`make php-fpm-build` は次の両方を生成します。

- `data/php-fpm/binaries/<runtime_id>/php-fpm`
- `data/php-fpm/binaries/<runtime_id>/php`

つまり build 済み runtime bundle は、PHP-FPM workload と scheduled PHP CLI job の両方に使えます。scheduled task では `/options` を経由せず、その CLI path を command line へ直接書きます。

同梱 PHP CLI は、同梱 PHP-FPM runtime と同じ extension set を使うため、SQLite / MySQL(MariaDB) / PostgreSQL を標準で扱えます。

## GeoIP Country DB 自動更新

managed country DB の更新は、手動実行と scheduled automation の両方に対応します。

binary / repository の wrapper:

```bash
./scripts/update_country_db.sh
```

binary subcommand:

```bash
./bin/tukuyomi update-country-db
```

container image の command:

```bash
/app/server update-country-db
```

operator flow:

1. `Options -> GeoIP Update` から `GeoIP.conf` を upload（DB mode では runtime DB authority に保存されます）
2. `Update now` を 1 回実行して成功を確認
3. deployment 形態に応じて上記いずれかの command を呼ぶ scheduled task を追加
