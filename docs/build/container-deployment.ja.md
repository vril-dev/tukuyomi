# Container Deployment

この手順は、container-first の `tukuyomi` 配置向けです。

- ECS
- AKS
- GKE
- Azure Container Apps
- 一般的な Docker / Kubernetes 環境

## Support Tier

container platform 向けの support は 3 段階で整理します。

### Tier 1: mutable single-instance

現時点で official support するのはこれです。

- deployment unit は 1 個だけ
- 公開する `coraza` container が 1 個
- internal な `scheduled-task-runner` sidecar が 1 個
- 次の writable path を共有する
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - local `persistent_storage` を使うなら `/app/data/persistent`
  - bundled runtime を使うなら `/app/data/php-fpm`
- admin の live mutation を許可する

以下の ECS / AKS / GKE / Azure Container Apps の説明は、この Tier 1 を前提にしています。

### Tier 2: immutable replicated rollout

これはまだ閉じていません。

- frontend replica を複数にするのは follow-up
- config 変更は live admin mutation ではなく rollout 前提
- その frontend replica では `admin.read_only=true` が必須
- scheduler ownership も各 frontend replica 同居ではなく singleton role へ分離が必要

残りの guard が閉じるまでは、replicated mutable admin deployment を official path として扱いません。

### Tier 3: distributed mutable cluster

これは非対応です。

- distributed config propagation なし
- leader election なし
- cluster-wide scheduler ownership なし
- multi-writer mutable runtime model なし

## 現時点の official topology

container platform では、今の official topology を次で固定します。

`client -> ALB/ingress/platform ingress -> coraza`

に加えて、同じ deployment unit 内に:

`scheduled-task-runner`

を置きます。

運用上の条件:

- 稼働単位は常に 1 つ
- rollout 時に revision を重ねない
- `coraza` と `scheduled-task-runner` は同じ writable runtime path を共有する
- platform の ingress / load balancer へ出すのは `coraza` だけ

## public/admin listener 分離

public proxy listener を `:80` / `:443` に置きつつ、admin UI/API を別の
high port に分けたい場合は DB `app_config` の `admin.listen_addr` を
設定します。

sample:

- [config.split-listener.example.json](config.split-listener.example.json)

operator contract:

- `server.listen_addr` は public listener のまま
- `admin.listen_addr` を入れると admin UI/API/auth は public listener から外れる
- admin への到達可否は引き続き `admin.external_mode` と `admin.trusted_cidrs` が決める
- built-in TLS / HTTP redirect / HTTP/3 はこの slice では public listener 専用
- listener 分離と source guard は別物なので混同しない
- container platform では、意図的に private network へ出すのでなければ public listener だけを publish / route する

## Container Reload / Rolling Update

container 内で process reexec するのではなく、platform rollout として扱います。

- readiness は public listener を見る
- old task/pod を外す前に new task/pod を起動する
- ingress / load balancer から old task/pod への新規 connection を止める
- old task/pod は少なくとも `server.graceful_shutdown_timeout_sec` 以上残す
- 通常の Docker / Kubernetes container 内では systemd socket activation に依存しない
- HTTP/3 は process replacement をまたいだ QUIC connection continuity を保証しないため、task/pod replacement 中に client reconnect が発生し得る

## Replicated Immutable Shape

replicated immutable frontend へ意図的に寄せる場合は、single-instance の
sidecar model をそのまま複製せず、role を明示的に分離します。

frontend replica role:

- HTTP を捌くだけ
- platform ingress 配下で複数 replica を持てる
- `admin.read_only=true` を入れる
- scheduled-task 実行は持たない

dedicated scheduler role:

- singleton のまま
- 同じ `run-scheduled-tasks` loop を実行
- public ingress を持たない
- frontend と同じ source of truth として次を mount する
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - local `persistent_storage` を使うなら `/app/data/persistent`
  - bundled runtime を使うなら `/app/data/php-fpm`

これは distributed mutable runtime support を意味しません。frontend を
複製する時に scheduler ownership を明示的に切り出すだけです。

## Build の選択肢

実務上は 2 通りあります。

### 1. repository の Dockerfile をそのまま使う

先に埋め込み Admin UI を更新します。

```bash
make ui-build-sync
docker build -f coraza/Dockerfile -t tukuyomi:local coraza
```

この方法では、repository の Dockerfile と、更新済み `coraza/src/internal/handler/admin_ui_dist` をそのまま使います。

### 2. UI とバイナリを image 内で build する deployment Dockerfile を使う

sample:

- [Dockerfile.example](Dockerfile.example)

build:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

この方法では Admin UI build、Go build、runtime config copy、CRS install まで image build 内で完結します。

## Deployment artifact render

cloud/container platform 向けは `make install` ではなく、manifest を生成して
review してから各 platform の apply flow へ渡します。

```bash
make deploy-render TARGET=container-image IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=ecs IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=kubernetes IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=azure-container-apps IMAGE_URI=registry.example.com/tukuyomi:1.1.0
```

出力先は既定で `dist/deploy/<target>/` です。

- `container-image` は deployment Dockerfile と local build helper を生成します。registry push はしません
- `ecs` は single-instance task/service と replicated scheduler 用 artifact を生成します。AWS API は呼びません
- `kubernetes` は single-instance と dedicated scheduler 用 YAML を生成します。`kubectl apply` はしません
- `azure-container-apps` は single-instance と scheduler singleton YAML を生成します。Azure API は呼びません
- 既存 output を置き換える場合は `DEPLOY_RENDER_OVERWRITE=1` を指定します

## 共有 writable path

official な mutable single-instance path で最低限必要な writable path:

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`（`persistent_storage.backend=local` の場合）

ephemeral local state を許容しないなら、これらを platform 側で mount してください。

`/options`、`/vhosts`、または scheduled PHP CLI job で bundled PHP runtime も使う場合は、`/app/data/php-fpm` も mount してください。
internal response cache store を node replacement 後も残したい場合は、`cache_store.store_dir`
に合わせて `/app/cache/response` なども mount してください。これは cache であり、
DB/runtime authority ではありません。

WAF/CRS import material は `/app/data/tmp` 配下へ stage し、DB `waf_rule_assets`
へ import します。runtime は mounted rules directory ではなく DB の active WAF/CRS asset を読みます。

## Config と Secret

`tukuyomi` は `conf/config.json` を DB 接続 bootstrap に使い、その後の
operator-managed な app/proxy 設定は normalized DB table から読みます。

典型的な本番パターン:

- `conf/config.json` は `storage.db_driver`、`storage.db_path`、`storage.db_dsn` 用に secret manager / config management から render
- `seeds/conf/` を空 DB 向け同梱 seed set として mount または bake します。`conf/proxy.json` や各種 policy file など configured file がある場合はそちらが優先されます
- 初回起動前に `make db-migrate`、`make crs-install` の順で WAF rule asset を install/import し、その後残りの seed material 用に `make db-import` を実行します。`db-import` は WAF rule asset を再 import しません
- `conf/sites.json`、`conf/scheduled-tasks.json`、`conf/upstream-runtime.json` は空 DB の seed/export file として扱います。bootstrap 後の正は normalized DB row です
- runtime env injection は主に次だけ
  - `WAF_CONFIG_FILE`
  - `WAF_PROXY_AUDIT_FILE`
  - `persistent_storage.backend=s3` の場合だけ `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN`、`AWS_REGION` / `AWS_DEFAULT_REGION`
  - `security_audit.key_source=env` を使う場合の security-audit key override
- embedded `Settings` 画面は DB `app_config` を編集します。listener/runtime/storage policy/observability 系の変更を反映するには container を recreate/restart してください

site-managed ACME は `Sites` 画面で site ごとに `tls.mode=acme` を選択します。
ACME cache は `persistent_storage` の `acme/` namespace に保存します。single-instance で
local backend を使うなら `/app/data/persistent` を mount し、replicated / node replacement
前提なら S3 backend または共有 mount を使ってください。Azure Blob Storage / Google Cloud
Storage backend は provider adapter が入るまで fail closed します。

proxy engine 選択も同じ restart-required config surface です:

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は built-in engine で、同じ parser、transport、routing、health、retry、TLS、cache、route response headers、1xx informational responses、trailers、streaming flush behavior、native Upgrade/WebSocket tunnel、response-sanitize pipeline を維持したまま Tukuyomi 独自の response bridge を使います
- legacy `net_http` bridge は削除済みです。`tukuyomi_proxy` 以外の engine 値は config validation で拒否します
- HTTP/1.1 と明示的な upstream HTTP/2 mode は Tukuyomi native upstream transport を使います。HTTPS `force_attempt` は ALPN で `h2` が選ばれない場合だけ native HTTP/1.1 へ fallback します
- Upgrade/WebSocket handshake request は `tukuyomi_proxy` 内で処理します。`101 Switching Protocols` 後の WebSocket frame payload は tunnel data です
- 本番 rollout 前に container を rebuild/restart し、実 traffic で benchmark してください

server-side に閉じ込める値:

- `admin.session_secret`
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` / `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` を使う場合の初期 owner bootstrap credential
- 必要なら security-audit の encryption/HMAC key
- immutable replicated rollout を意図的に試すなら、frontend replica では `admin.read_only=true` にし、scheduled-task 実行は dedicated singleton role に切り出してください
- `tukuyomi` の既定 posture は `admin.external_mode=api_only_external` です。remote admin API が不要なら `deny_external` を使ってください
- non-loopback listener で `full_external` に上書きする場合は、front-side の allowlist/auth を必須として扱ってください
- `admin.trusted_cidrs` を public / catch-all network まで広げた場合も、埋め込み管理UI/API はその trusted source へ再露出され、起動時は warning のみです
- base WAF と CRS asset は import 後 DB `waf_rule_assets` です。image-baked file は seed material であり runtime authority ではありません
- managed bypass override rule は DB `override_rules` です。`extra_rule` の値は logical compatibility reference として残ります

## Platform 別の対応

以下の sample は、[Dockerfile.example](Dockerfile.example) で build した deployment image を前提にしています。この image では binary path は `/app/tukuyomi` です。

もし `coraza/Dockerfile` を使うなら、scheduler sidecar sample の
`PROXY_BIN=/app/tukuyomi` を `PROXY_BIN=/app/server` に置き換えてください。

### ECS / Fargate

1 task 内に次の 2 container を置きます。

- `coraza`
- `scheduled-task-runner`

ECS service 側も single-instance に固定します。

- `desiredCount=1`
- rollout で revision を重ねない
  - 例: `minimumHealthyPercent=0`
  - 例: `maximumPercent=100`

sample artifact:

- [ecs-single-instance.task-definition.example.json](ecs-single-instance.task-definition.example.json)
- [ecs-single-instance.service.example.json](ecs-single-instance.service.example.json)

sample では次を別 EFS mount として分けています。

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`
- `/app/data/php-fpm`

task-definition sample では `admin.listen_addr` 用に `9091/tcp` も宣言しています。
ただし ECS service の load balancer は、意図的に private admin target group
を追加しない限り `9090` のままにしてください。

将来 replicated immutable frontend へ切るなら、次を前提にしてください。

- public frontend service は `admin.read_only=true`
- scheduler ownership は frontend task set の外へ出す
- scheduled task は各 replica ではなく dedicated scheduler task 1 個だけが持つ

dedicated scheduler artifact:

- [ecs-replicated-frontend-scheduler.task-definition.example.json](ecs-replicated-frontend-scheduler.task-definition.example.json)
- [ecs-replicated-frontend-scheduler.service.example.json](ecs-replicated-frontend-scheduler.service.example.json)

### AKS / GKE / 一般的な Kubernetes

Deployment は次で固定します。

- `replicas: 1`
- `strategy: Recreate`
- 1 Pod に 2 container

ここで `Recreate` を使うのは、mutable single-instance model で rollout 中に 2 Pod を一瞬でも重ねないためです。

sample artifact:

- [kubernetes-single-instance.example.yaml](kubernetes-single-instance.example.yaml)

sample では次を別 PVC として分けています。

- `tukuyomi-conf`
- `tukuyomi-scheduled-tasks`
- `tukuyomi-audit`
- `tukuyomi-persistent`
- `tukuyomi-php-fpm`

sample には次も含めています。

- public 用 `Service` on `9090`
- internal 用 `tukuyomi-admin` `Service` on `9091`

admin Service は private cluster network か separate internal ingress/LB の
背後だけで使ってください。

将来 frontend Pod を複数にするなら、次を守ってください。

- frontend Pod は `admin.read_only=true`
- config 変更は rollout 経由
- `scheduled-task-runner` は各 replica 同居ではなく dedicated singleton workload へ移す

dedicated scheduler artifact:

- [kubernetes-replicated-frontend-scheduler.example.yaml](kubernetes-replicated-frontend-scheduler.example.yaml)

### Azure Container Apps

次で single-instance に寄せます。

- `activeRevisionsMode: Single`
- `minReplicas: 1`
- `maxReplicas: 1`
- 同じ revision に 2 container

sample artifact:

- [azure-container-apps-single-instance.example.yaml](azure-container-apps-single-instance.example.yaml)

sample では Container Apps environment 側に次の Azure Files storage 定義が既にある前提です。

- `proxyconf`
- `proxyscheduledtasks`
- `proxyaudit`
- `proxypersistent`
- `proxyphpfpm`

Azure Container Apps sample は引き続き primary ingress を 1 つだけ持ちます。
`admin.listen_addr` を有効にする場合も、この first slice では admin port を
private path のままにし、separate internal exposure は外側で組んでください。

将来 frontend instance を複数に寄せるなら、次が前提です。

- `admin.read_only=true` を入れる
- scheduler owner は 1 個だけにする
- 各 frontend replica に scheduled task を持たせない

dedicated scheduler artifact:

- [azure-container-apps-scheduler-singleton.example.yaml](azure-container-apps-scheduler-singleton.example.yaml)

### ローカル検証 / operator reference

repository 同梱の compose 導線は、同じ topology をローカルで確認するための reference として残します。

```bash
make compose-up-scheduled-tasks
```

platform manifest へ落とす前に、まずこの local topology で確認する運用が自然です。

## 典型的な通信経路

cloud では通常:

`client -> ALB/nginx/ingress -> tukuyomi container -> app container/service`

前段がある場合は、DB `app_config` の trusted proxy range をその前段だけに絞ってください。

`tukuyomi` 自体を direct public entrypoint にして built-in HTTP/3 を有効にする場合は、listener port の TCP/UDP を両方開けてください。

## Notes

- 埋め込み Admin UI は image build 時に生成され、runtime では build しません
- `scripts/install_crs.sh` は image build 時でも startup 時でも実行できます
- runtime で policy file を変更したい場合は `/app/conf` を mount してください。WAF/CRS asset は `/app/data/tmp` staging から DB へ import します
- repository 同梱の `docker-compose.yml` には、`scheduled-tasks` profile 配下で `scheduled-task-runner` sidecar が入ります
- 現在の sidecar 実装は明示的です。image 内の proxy binary を `run-scheduled-tasks` 付きで呼び、次の minute 境界まで sleep します
- failure policy も明示的です。`run-scheduled-tasks` が non-zero を返したら sidecar も non-zero で終了し、fault を握り潰さずに container restart policy へ渡します
- `coraza` image には MaxMind `geoipupdate` が `/app/bin/geoipupdate` として同梱されます
- image-first の managed country refresh では `/app/server update-country-db` を直接使えます
- ローカル compose 導線は proxy-owned path だけを前提にしています:

```bash
make compose-up-scheduled-tasks
```

- 生の compose command はこれです:

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- `artisan schedule:run` のような application command を動かすには、application tree を `coraza` と `scheduled-task-runner` の両方へ mount する必要があります
- override file の例:
  [docker-compose.scheduled-tasks.app.example.yml](docker-compose.scheduled-tasks.app.example.yml)
- app tree を足した compose 例:

```bash
SCHEDULED_TASK_APP_ROOT=/srv/myapp \
SCHEDULED_TASK_APP_MOUNT=/app/workloads/myapp \
docker compose \
  -f docker-compose.yml \
  -f docs/build/docker-compose.scheduled-tasks.app.example.yml \
  --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- `make ui-preview-up` では preview 専用の scheduler sidecar も一緒に起動します
- 既定の preview は毎回初期化されます
  - `ui-preview-up` のたびに preview 専用 SQLite DB を作り直すため、古い preview task、listener 変更、DB row は引き継ぎません
- preview 用 DB state を保持したい時はこれです

```bash
UI_PREVIEW_PERSIST=1 make ui-preview-up
UI_PREVIEW_PERSIST=1 make ui-preview-down
```

- `UI_PREVIEW_PERSIST=1` では次を保持します
  - `data/<dirname(storage.db_path)>/tukuyomi-ui-preview.db`
  - 例えば `storage.db_path` が `db/tukuyomi.db` なら preview DB は `data/db/tukuyomi-ui-preview.db` です
- `ui-preview-up` は preview DB に保存された active preview `app_config` から publish port を導出します
  - 初回起動時だけ `conf/config.json` と `UI_PREVIEW_PUBLIC_ADDR` / `UI_PREVIEW_ADMIN_ADDR` override を土台にします
  - single listener なら public listener port を publish
  - split listener なら public/admin の両方を publish
  - healthcheck は split 時は admin listener を優先
- split preview の bootstrap 例:

```bash
UI_PREVIEW_PERSIST=1 \
UI_PREVIEW_PUBLIC_ADDR=:80 \
UI_PREVIEW_ADMIN_ADDR=:9090 \
make ui-preview-up
```

- この場合の確認先はこうです
  - public proxy: `http://127.0.0.1:80`
  - admin UI: `http://127.0.0.1:9090/tukuyomi-ui`
  - admin API: `http://127.0.0.1:9090/tukuyomi-api`
- preview listener 設定で `localhost:80`, `127.0.0.1:80`, `[::1]:9090` のような loopback bind は使わないでください
  - container 内 loopback bind と host publish が噛み合わないため、preview は明示エラーで止めます
- `Settings` から listener を保存した後に preview で反映を確認する時は、`UI_PREVIEW_PERSIST=1 make ui-preview-down && UI_PREVIEW_PERSIST=1 make ui-preview-up` を使ってください
  - listener 変更自体は preview DB に残りますが、`docker compose restart` では changed port publish は作り直されません
- scheduler fault は sidecar の exit/restart と container logs で追います。恒久 fault は restart churn として見える想定です
- scheduled task の command line が `/app/data/php-fpm/binaries/php85/php` のような bundled PHP path を指す場合は、その scheduler container に `/app/data/php-fpm` も mount してください
- platform health endpoint は `/healthz` on `9090` です
- custom container path ではなく package 済みバイナリを確認したい場合は、release tarball 同梱の `testenv/release-binary/` が最短です
- rollout 前にこの sample container 導線をローカルで検証するなら `make container-deployment-smoke` を使ってください
- rollout 前に container platform 全体の契約まで確認するなら `make container-platform-smoke` を使ってください
  ここでは scheduled-task ownership、replicated read-only prerequisite、sample artifact parse まで見ます
- preview persistence と split-port parity の確認だけを個別に回すなら `make ui-preview-smoke` を使ってください
