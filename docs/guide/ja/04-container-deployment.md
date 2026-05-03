# 第4章　コンテナ配備

本章では、tukuyomi をコンテナとして運用する場合の配備方針を扱います。対象に
する platform は、ECS / Fargate、AKS / GKE / 一般的な Kubernetes、Azure
Container Apps、それに加えて素の Docker / Docker Compose です。

systemd 配備（第3章）と同じく、ここでも軸になる原則は「**DB が runtime
authority、JSON は seed / import / export 素材**」です。コンテナ配備では、
さらに「**何を mount するか**」「**どこまで replicated / immutable に振るか**」
という設計判断が加わります。最初に Tier 区分でその判断を整理し、それから
platform 別の具体例に下りていきます。

## 4.1　Support Tier ── どこまで replicated にできるか

tukuyomi のコンテナ配備は、現時点で次の 3 段階に整理されています。

### Tier 1: mutable single-instance

**現時点で official に support しているのはこれだけ** です。

- deployment unit は 1 個
- 公開する `coraza` container 1 個と、internal な `scheduled-task-runner`
  sidecar 1 個
- 次の writable path を共有する
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - local `persistent_storage` を使うなら `/app/data/persistent`
  - bundled PHP-FPM を使うなら `/app/data/php-fpm`
- admin の **live mutation を許可する**

本章で後述する ECS / AKS / GKE / Azure Container Apps の例は、いずれもこの
Tier 1 を前提にしています。

### Tier 2: immutable replicated rollout

これは **まだ閉じていません**。実装上はいくつかの guard が残っています。

- frontend replica を複数にするのは follow-up
- config 変更は live admin mutation ではなく **rollout 前提**
- frontend replica では `admin.read_only=true` が必須
- scheduler ownership を「各 frontend replica 同居」ではなく **singleton role
  に分離** する必要がある

これらの guard が閉じるまでは、replicated mutable admin deployment を official
path として扱いません。

### Tier 3: distributed mutable cluster

これは **非対応** です。

- distributed config propagation なし
- leader election なし
- cluster-wide scheduler ownership なし
- multi-writer mutable runtime model なし

## 4.2　現時点の official topology

コンテナ platform では、official な topology を次の形に固定します。

```text
client -> ALB / ingress / platform ingress -> coraza
```

そして同じ deployment unit の内側に、`scheduled-task-runner` を置きます。
運用上の条件は次のとおりです。

- 稼働単位は **常に 1 つ**
- rollout 時に revision を **重ねない**
- `coraza` と `scheduled-task-runner` は同じ writable runtime path を共有する
- platform の ingress / load balancer に出すのは `coraza` だけ

## 4.3　public/admin listener 分離（コンテナ版）

systemd 配備と同じく、public proxy listener を `:80` / `:443` に置き、
admin UI / API を別 high port に分けたい場合は、DB `app_config` の
`admin.listen_addr` を設定します。サンプルは
`docs/build/config.split-listener.example.json` を参照してください。

operator contract は次のとおりです。

- `server.listen_addr` は public listener のまま
- `admin.listen_addr` を入れると、admin UI / API / auth は public listener から
  外れる
- admin への到達可否は、引き続き `admin.external_mode` と
  `admin.trusted_cidrs` で決まる
- built-in TLS / HTTP redirect / HTTP/3 は、この slice では public listener
  専用
- listener 分離と source guard は別物なので混同しない
- コンテナ platform では、意図的に private network へ出すのでない限り、
  **public listener だけを publish / route する**

## 4.4　Container reload と rolling update

コンテナ内部で process を再 exec するのではなく、**platform rollout** として
扱います。具体的には次のようなルールです。

- readiness は public listener を見る
- old task / pod を外す前に new task / pod を起動する
- ingress / load balancer から old task / pod への新規 connection を止める
- old task / pod は少なくとも `server.graceful_shutdown_timeout_sec` 以上残す
- 通常の Docker / Kubernetes 内では **systemd socket activation には依存
  しない**
- HTTP/3 は process replacement をまたいだ QUIC connection continuity を
  保証しないため、task / pod replacement 中に client reconnect が発生し得る

## 4.5　Replicated immutable な構成にする場合

将来的に Tier 2（replicated immutable frontend）を意図的に試したい場合は、
single-instance の sidecar model をそのまま複製するのではなく、role を明示的に
分離します。

**frontend replica role**:

- HTTP を捌くだけ
- platform ingress 配下で複数 replica を持てる
- `admin.read_only=true` を入れる
- scheduled-task は持たない

**dedicated scheduler role**:

- singleton のまま
- 同じ `run-scheduled-tasks` loop を実行
- public ingress を持たない
- frontend と同じ source of truth として、`/app/conf`、
  `/app/data/scheduled-tasks`、`/app/audit`、必要なら `/app/data/persistent` /
  `/app/data/php-fpm` を mount する

これは distributed mutable runtime support を意味するわけではありません。
**frontend を複製するときに、scheduler ownership を明示的に切り出す** という
設計です。

## 4.6　Build の選択肢

tukuyomi のコンテナ image を作る方法は、実務上 2 通りです。

### 4.6.1　repository の Dockerfile をそのまま使う

先に埋め込みの Gateway / Center UI を build しておき、`server/Dockerfile` を
そのまま使います。

```bash
make build
docker build -f server/Dockerfile -t tukuyomi:local server
```

この方法では、repository の Dockerfile と、更新済みの
`server/internal/handler/admin_ui_dist` および
`server/internal/center/center_ui_dist` をそのまま使います。

### 4.6.2　deployment 用の Dockerfile を使う

`docs/build/Dockerfile.example` には、UI の build から Go の build、runtime
config の copy、CRS の install までを image build 内で完結させる構成が用意
されています。

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

この image では、binary path は `/app/tukuyomi` です。後段の sample artifact は
こちらの image を前提にしている点に注意してください。

## 4.7　Deployment artifact の render

cloud / コンテナ platform 向けは、`make install` ではなく、まず manifest を
generate してレビューしてから、各 platform の apply フローへ流す形にします。

```bash
make deploy-render TARGET=container-image          IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=ecs                      IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=kubernetes               IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=azure-container-apps     IMAGE_URI=registry.example.com/tukuyomi:1.1.0
```

出力先は既定で `dist/deploy/<target>/` です。

- `container-image`: deployment Dockerfile と local build helper を生成
  （registry push はしない）
- `ecs`: single-instance の task / service と、replicated scheduler 用の
  artifact を生成（AWS API は呼ばない）
- `kubernetes`: single-instance と dedicated scheduler 用の YAML を生成
  （`kubectl apply` はしない）
- `azure-container-apps`: single-instance と scheduler singleton 用の YAML を
  生成（Azure API は呼ばない）

既存 output を置き換えるときは `DEPLOY_RENDER_OVERWRITE=1` を指定します。

## 4.8　共有 writable path

Tier 1 の official な mutable single-instance で **最低限必要な writable path**
は次のとおりです。

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`（`persistent_storage.backend=local` の場合）

ephemeral local state を許容しない運用なら、これらを platform 側で mount して
ください。

加えて、

- `/options` / `/runtime-apps` / scheduled PHP CLI job で **bundled PHP runtime**
  を使う場合は、`/app/data/php-fpm` も mount
- internal **response cache store** を node replacement 後も残したい場合は、
  `cache_store.store_dir` に合わせて `/app/cache/response` なども mount

を追加します。response cache はあくまで cache であり、DB / runtime authority
ではありません。

WAF / CRS の import material は `/app/data/tmp` 配下に stage され、DB
`waf_rule_assets` へ import されます。runtime は mounted rules directory では
なく、**DB の active WAF / CRS asset** を読みます。

## 4.9　Config と Secret

`tukuyomi` は `conf/config.json` を DB 接続 bootstrap として使い、その後の
operator-managed な app / proxy 設定はすべて normalized DB table から読みます。

典型的な本番パターンは次のとおりです。

- `conf/config.json` は、`storage.db_driver` / `storage.db_path` /
  `storage.db_dsn` を **secret manager / config management から render**
- `seeds/conf/config-bundle.json` は空 DB 向けの同梱 seed として mount または bake する
  （`conf/proxy.json` や各種 policy file がある場合はそちらが優先される）
- 初回起動前に `make db-migrate` → `make crs-install` の順で WAF rule asset を
  install / import し、その後で残りの seed material 用に `make db-import` を
  実行する。`db-import` は WAF rule asset を再 import しない
- `conf/sites.json` / `conf/scheduled-tasks.json` / `conf/upstream-runtime.json`
  は、空 DB の seed / export file として扱う。bootstrap 後の正は normalized
  DB row
- runtime env injection は主に次だけに絞る
  - `WAF_CONFIG_FILE`
  - `WAF_PROXY_AUDIT_FILE`
  - `persistent_storage.backend=s3` の場合の `AWS_ACCESS_KEY_ID` /
    `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` / `AWS_REGION` /
    `AWS_DEFAULT_REGION`
  - `security_audit.key_source=env` を使う場合の security-audit key override
- 埋め込み `Settings` 画面は DB `app_config` を編集する。listener / runtime /
  storage policy / observability 系の変更を反映するには、container を
  recreate / restart する

site-managed ACME は、`Sites` 画面で site ごとに `tls.mode=acme` を選びます。
ACME cache は `persistent_storage` の `acme/` namespace に保存されます。
single-instance で local backend を使うなら `/app/data/persistent` を mount
し、replicated / node replacement を前提にするなら **S3 backend または共有
mount** を使ってください。Azure Blob Storage / Google Cloud Storage backend
は、provider adapter が入るまで fail-closed です。

proxy engine 設定は、systemd 配備と同じく現在 `tukuyomi_proxy` 固定です。

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

server-side に閉じ込める値は次のとおりです。

- `admin.session_secret`
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` / `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD`
  を使う場合の初期 owner bootstrap credential
- 必要なら security-audit の encryption / HMAC key
- replicated immutable rollout を意図的に試すなら、frontend replica では
  `admin.read_only=true`、scheduled-task 実行は dedicated singleton role
- 既定 posture は `admin.external_mode=api_only_external`。remote admin API が
  不要なら `deny_external` に絞る
- non-loopback listener で `full_external` に上書きする場合は、front-side の
  allowlist / auth を必須として扱う
- `admin.trusted_cidrs` を public network へ広げた場合も埋め込み管理 UI / API
  はその trusted source へ再露出される。起動時の warning だけに頼らない
- base WAF と CRS asset は import 後 DB `waf_rule_assets`。image-baked file は
  seed material であり runtime authority ではない
- managed bypass override rule は DB `override_rules`。`extra_rule` の値は
  logical compatibility reference として残る

## 4.10　Platform 別の対応

ここからは platform ごとの具体的な topology です。`docs/build/` 以下の
sample artifact は、4.6.2 節の deployment image（`/app/tukuyomi`）を前提に
書かれています。`server/Dockerfile` を使う場合は、scheduler sidecar sample
の `PROXY_BIN=/app/tukuyomi` を `PROXY_BIN=/app/server` に置き換えてください。

### 4.10.1　ECS / Fargate

1 task 内に次の 2 container を置きます。

- `coraza`
- `scheduled-task-runner`

ECS service 側も single-instance に固定します。

- `desiredCount=1`
- rollout で revision を重ねない
  - 例: `minimumHealthyPercent=0`
  - 例: `maximumPercent=100`

サンプル artifact:

- `docs/build/ecs-single-instance.task-definition.example.json`
- `docs/build/ecs-single-instance.service.example.json`

サンプルでは次を別 EFS mount として分けています。

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`
- `/app/data/php-fpm`

task-definition sample では `admin.listen_addr` 用に `9091/tcp` も宣言して
いますが、ECS service の load balancer 側は、意図的に private admin target
group を追加しない限り `9090` のままにしてください。

将来 replicated immutable frontend へ切る場合の前提:

- public frontend service は `admin.read_only=true`
- scheduler ownership を frontend task set の外へ出す
- scheduled task は、各 replica ではなく dedicated scheduler task 1 個だけが
  持つ

dedicated scheduler artifact:

- `docs/build/ecs-replicated-frontend-scheduler.task-definition.example.json`
- `docs/build/ecs-replicated-frontend-scheduler.service.example.json`

### 4.10.2　AKS / GKE / 一般的な Kubernetes

Deployment は次で固定します。

- `replicas: 1`
- `strategy: Recreate`
- 1 Pod に 2 container

ここで `Recreate` を使うのは、mutable single-instance model で **rollout 中に
2 Pod を一瞬でも重ねないため** です。

サンプル: `docs/build/kubernetes-single-instance.example.yaml`

このサンプルでは次を別 PVC として分けています。

- `tukuyomi-conf`
- `tukuyomi-scheduled-tasks`
- `tukuyomi-audit`
- `tukuyomi-persistent`
- `tukuyomi-php-fpm`

サービス定義としては、次の 2 つが含まれます。

- public 用 `Service` on `9090`
- internal 用 `tukuyomi-admin` `Service` on `9091`

admin Service は、private cluster network、または separate internal
ingress / LB の背後だけで使ってください。

将来 frontend Pod を複数にする場合のルール:

- frontend Pod は `admin.read_only=true`
- config 変更は rollout 経由
- `scheduled-task-runner` は各 replica 同居ではなく、dedicated singleton
  workload に移す

dedicated scheduler artifact:
`docs/build/kubernetes-replicated-frontend-scheduler.example.yaml`

### 4.10.3　Azure Container Apps

次の設定で single-instance に寄せます。

- `activeRevisionsMode: Single`
- `minReplicas: 1`
- `maxReplicas: 1`
- 同じ revision に 2 container

サンプル: `docs/build/azure-container-apps-single-instance.example.yaml`

サンプルでは Container Apps environment 側に、次の Azure Files storage 定義
がすでにある前提になっています。

- `proxyconf`
- `proxyscheduledtasks`
- `proxyaudit`
- `proxypersistent`
- `proxyphpfpm`

Azure Container Apps sample は primary ingress を 1 つだけ持ちます。
`admin.listen_addr` を有効にする場合も、この first slice では admin port は
**private path のまま** にし、別途 internal exposure を外側で組んでください。

将来 frontend instance を複数にするときのルール:

- `admin.read_only=true` を入れる
- scheduler owner は 1 個だけ
- 各 frontend replica に scheduled task を持たせない

dedicated scheduler artifact:
`docs/build/azure-container-apps-scheduler-singleton.example.yaml`

### 4.10.4　ローカル検証 / operator reference

repository に同梱された Docker Compose 導線は、同じ topology をローカルで
確認するための reference として残しています。

```bash
make compose-up-scheduled-tasks
```

platform manifest に落とす前に、まずこのローカル topology で確認する運用が
自然です。

## 4.11　典型的な通信経路

cloud では通常、次の経路になります。

```text
client -> ALB / nginx / ingress -> tukuyomi container -> app container/service
```

前段がある場合は、DB `app_config` の **trusted proxy range をその前段だけ
に絞って** ください。

`tukuyomi` 自体を direct public entrypoint にして built-in HTTP/3 を有効に
する場合は、listener port の **TCP / UDP を両方** 開けてください。

## 4.12　補足メモ

- 埋め込み Gateway / Center UI は image build 時に生成され、runtime では build
  しません。
- `scripts/install_crs.sh` は image build 時でも startup 時でも実行できます。
- runtime で policy file を変更したい場合は `/app/conf` を mount してください。
  WAF/CRS asset は `/app/data/tmp` staging から DB へ import します。
- repository 同梱の `docker-compose.yml` には、`scheduled-tasks` profile 配下
  で `scheduled-task-runner` sidecar が入ります。
- 現在の sidecar 実装は明示的です。image 内の proxy バイナリを
  `run-scheduled-tasks` 付きで呼び、次の minute 境界まで sleep します。
- failure policy も明示的です。`run-scheduled-tasks` が non-zero を返したら
  sidecar も non-zero で終了し、fault を握り潰さずに container restart policy
  に渡します。
- `coraza` image には MaxMind の `geoipupdate` が `/app/bin/geoipupdate` として
  同梱されます。image-first の managed country refresh では
  `/app/server update-country-db` を直接使えます。
- ローカル compose 導線は proxy-owned path だけを前提にしています。

  ```bash
  make compose-up-scheduled-tasks
  ```

- 生の compose コマンド:

  ```bash
  PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  ```

- `artisan schedule:run` のような application command を動かすには、
  application tree を `coraza` と `scheduled-task-runner` の両方に mount する
  必要があります。override file の例は
  `docs/build/docker-compose.scheduled-tasks.app.example.yml` を参照してください。

- app tree を足した compose 例:

  ```bash
  SCHEDULED_TASK_APP_ROOT=/srv/myapp \
  SCHEDULED_TASK_APP_MOUNT=/app/workloads/myapp \
  docker compose \
    -f docker-compose.yml \
    -f docs/build/docker-compose.scheduled-tasks.app.example.yml \
    --profile scheduled-tasks up -d --build coraza scheduled-task-runner
  ```

- `make gateway-preview-up` では preview 専用の scheduler sidecar も一緒に
  起動します。
- 既定の preview は毎回初期化されます。`gateway-preview-up` のたびに preview
  専用 SQLite DB を作り直すため、古い preview task、listener 変更、DB row は
  引き継ぎません。

- preview 用 DB state を保持したいときはこうです。

  ```bash
  GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
  GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
  ```

- `GATEWAY_PREVIEW_PERSIST=1` は、`data/<dirname(storage.db_path)>/tukuyomi-gateway-preview.db`
  を保持します（例: `storage.db_path` が `db/tukuyomi.db` なら、preview DB は
  `data/db/tukuyomi-gateway-preview.db`）。
- `gateway-preview-up` は、preview DB に保存された active preview `app_config`
  から publish port を導出します。初回起動時だけ `conf/config.json` と
  `GATEWAY_PREVIEW_PUBLIC_ADDR` / `GATEWAY_PREVIEW_ADMIN_ADDR` の override を
  土台にします。single listener なら public listener port を、split listener
  なら public / admin の両方を publish します。healthcheck は split 時は
  admin listener を優先します。

- split preview の bootstrap 例:

  ```bash
  GATEWAY_PREVIEW_PERSIST=1 \
  GATEWAY_PREVIEW_PUBLIC_ADDR=:80 \
  GATEWAY_PREVIEW_ADMIN_ADDR=:9090 \
  make gateway-preview-up
  ```

  確認先:
  - public proxy: `http://127.0.0.1:80`
  - admin UI: `http://127.0.0.1:9090/tukuyomi-ui`
  - admin API: `http://127.0.0.1:9090/tukuyomi-api`

- preview listener 設定で `localhost:80`, `127.0.0.1:80`, `[::1]:9090` のような
  loopback bind は使わないでください。container 内 loopback bind と host
  publish が噛み合わないため、preview は明示エラーで止めます。
- `Settings` から listener を保存した後に preview で反映を確認するときは、
  `GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down && GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up`
  を使ってください。listener 変更自体は preview DB に残りますが、
  `docker compose restart` では changed port publish は作り直されません。
- scheduler fault は、sidecar の exit / restart と container logs で追います。
  恒久 fault は restart churn として見える想定です。
- scheduled task の command line が `/app/data/php-fpm/binaries/php85/php` の
  ような bundled PHP path を指す場合は、その scheduler container にも
  `/app/data/php-fpm` を mount してください。
- platform health endpoint は `/healthz` on `9090` です。
- custom container path ではなく package 済みバイナリを確認したい場合は、
  release tarball 同梱の `testenv/release-binary/` が最短です。
- rollout 前にこの sample container 導線をローカルで検証するなら
  `make container-deployment-smoke` を、container platform 全体の契約まで確認
  するなら `make container-platform-smoke` を、preview persistence と
  split-port parity だけを個別に回すなら `make gateway-preview-smoke` を
  使ってください。

## 4.13　次章への橋渡し

ここまでで、systemd 配備（第3章）とコンテナ配備（本章）の 2 つの公式経路を
通り抜けました。どちらの形態でも、tukuyomi の **runtime authority は DB**、
**JSON は seed / import / export 素材**、という分担は変わりません。

第III部「リバースプロキシ」（第5・6章）では、この configuration plane の上で
**実際の routing がどう構成されるか** ── Routes / Upstreams / Backend Pools
の三層モデル、`Backends` 画面での runtime 操作、そして upstream HTTP/2 の扱い
── を順に見ていきます。
