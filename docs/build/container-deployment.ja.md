# Container Deployment

この手順は、コンテナを前提とした `tukuyomi` の配備向けです。

- ECS
- AKS
- GKE
- Azure Container Apps
- 一般的な Docker ／ Kubernetes 環境

## サポート階層

コンテナプラットフォーム向けのサポートは 3 段階で整理しています。

### Tier 1: ミュータブルなシングルインスタンス

現時点で公式にサポートしているのはこの形態です。

- 配備単位は 1 つだけ
- 公開する `coraza` コンテナが 1 つ
- 内部用の `scheduled-task-runner` サイドカーが 1 つ
- 次の書き込み可能パスを共有する
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - ローカルの `persistent_storage` を使う場合は `/app/data/persistent`
  - 同梱ランタイムを使う場合は `/app/data/php-fpm`
- 管理 UI からのライブな変更を許可する

以下の ECS ／ AKS ／ GKE ／ Azure Container Apps の説明は、この Tier 1 を前提にしています。

### Tier 2: イミュータブルな複製ロールアウト

この形態はまだ仕様が確定していません。

- フロントエンドレプリカを複数化する対応は今後実施
- 設定変更はライブな管理操作ではなく、ロールアウト前提
- そのフロントエンドレプリカでは `admin.read_only=true` を必須とする
- スケジューラの所有権も、各フロントエンドレプリカと同居ではなくシングルトンロールへ分離する必要あり

残りのガードが揃うまでは、複製＋ミュータブルな管理配備を公式経路としては扱いません。

### Tier 3: 分散型のミュータブルクラスター

この形態は非対応です。

- 分散構成への設定伝播なし
- リーダー選出なし
- クラスター全体でのスケジューラ所有権なし
- マルチライターなミュータブルランタイムモデルなし

## 現時点の公式トポロジ

コンテナプラットフォームでは、現状の公式トポロジを次のとおり固定しています。

`client -> ALB / ingress / platform ingress -> coraza`

これに加えて、同じ配備単位内に次を配置します。

`scheduled-task-runner`

運用上の条件:

- 稼働単位は常に 1 つ
- ロールアウト時にリビジョンを重ねない
- `coraza` と `scheduled-task-runner` は同じ書き込み可能なランタイムパスを共有する
- プラットフォームの ingress ／ロードバランサに公開するのは `coraza` のみ

## 公開／管理リスナー分離

公開プロキシのリスナーを `:80` ／ `:443` に置きつつ、管理 UI／API を別の高位ポートに分離したい場合は、DB `app_config` の `admin.listen_addr` を設定します。

サンプル:

- [config.split-listener.example.json](config.split-listener.example.json)

オペレーターコントラクト:

- `server.listen_addr` は引き続き公開リスナー
- `admin.listen_addr` を設定すると、管理 UI／API／認証は公開リスナーから分離されます
- 管理エンドポイントへの到達可否は、引き続き `admin.external_mode` と `admin.trusted_cidrs` で決まります
- 組み込み TLS ／ HTTP リダイレクト ／ HTTP/3 は、現バージョンでは公開リスナー専用です
- リスナー分離とソースガードは別物なので混同しないでください
- コンテナプラットフォームでは、意図的にプライベートネットワークに公開する場合を除き、公開リスナーのみを公開／ルーティングしてください

## コンテナのリロード／ローリングアップデート

コンテナ内でプロセスを再 exec するのではなく、プラットフォームのロールアウトとして扱います。

- レディネスは公開リスナーで判定する
- 旧タスク／Pod を外す前に新タスク／Pod を起動する
- ingress ／ロードバランサから旧タスク／Pod への新規コネクションを止める
- 旧タスク／Pod は少なくとも `server.graceful_shutdown_timeout_sec` 以上は残す
- 通常の Docker ／ Kubernetes コンテナでは、systemd のソケットアクティベーションには依存しない
- HTTP/3 はプロセス入れ替えをまたいだ QUIC コネクションの継続性を保証しないため、タスク／Pod 入れ替え中にクライアント側で再接続が発生し得ます

## イミュータブルな複製形態

イミュータブルな複製フロントエンドへ意図的に寄せる場合は、シングルインスタンスのサイドカーモデルをそのまま複製せず、ロールを明示的に分離します。

フロントエンドレプリカのロール:

- HTTP の処理のみを担う
- プラットフォーム ingress 配下で複数レプリカを持てる
- `admin.read_only=true` を設定する
- スケジュールタスクの実行は持たない

専用スケジューラのロール:

- シングルトンのまま
- 同じ `run-scheduled-tasks` ループを実行
- 公開 ingress を持たない
- フロントエンドと同じソースを正として、次をマウントする
  - `/app/conf`
  - `/app/data/scheduled-tasks`
  - `/app/audit`
  - ローカルの `persistent_storage` を使う場合は `/app/data/persistent`
  - 同梱ランタイムを使う場合は `/app/data/php-fpm`

これは分散型のミュータブルランタイムをサポートする意図ではありません。フロントエンドを複製する際に、スケジューラ所有権を明示的に切り出すための構成です。

## ビルドの選択肢

実務上は次の 2 通りがあります。

### 1. リポジトリの Dockerfile をそのまま使う

事前に埋め込みの Gateway ／ Center UI を更新します。

```bash
make build
docker build -f server/Dockerfile -t tukuyomi:local server
```

この方法では、リポジトリの Dockerfile と、更新済みの `server/internal/handler/admin_ui_dist`、`server/internal/center/center_ui_dist` をそのまま使用します。

### 2. UI とバイナリをイメージ内でビルドする配備用 Dockerfile を使う

サンプル:

- [Dockerfile.example](Dockerfile.example)

ビルド:

```bash
docker build -f docs/build/Dockerfile.example -t tukuyomi:deploy .
```

この方法では、Gateway ／ Center UI のビルド、Go バイナリのビルド、ランタイム設定のコピー、CRS インストールまでをイメージビルド内で完結させます。

## 配備アーティファクトの生成

クラウド／コンテナプラットフォーム向けは、`make install` ではなくマニフェストを生成し、レビューしたうえで各プラットフォームの apply フローに渡します。

```bash
make deploy-render TARGET=container-image IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=ecs IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=kubernetes IMAGE_URI=registry.example.com/tukuyomi:1.1.0
make deploy-render TARGET=azure-container-apps IMAGE_URI=registry.example.com/tukuyomi:1.1.0
```

出力先は既定で `dist/deploy/<target>/` です。

- `container-image` は配備用 Dockerfile とローカルビルド用ヘルパーを生成します。レジストリへの push は行いません
- `ecs` はシングルインスタンス用のタスク／サービスと、複製スケジューラ用のアーティファクトを生成します。AWS API は呼び出しません
- `kubernetes` はシングルインスタンスと専用スケジューラ用の YAML を生成します。`kubectl apply` は実行しません
- `azure-container-apps` はシングルインスタンスとシングルトンスケジューラ用の YAML を生成します。Azure API は呼び出しません
- 既存の出力を置き換える場合は `DEPLOY_RENDER_OVERWRITE=1` を指定します

## 共有書き込みパス

公式の「ミュータブルなシングルインスタンス」運用で最低限必要な書き込み可能パスは次のとおりです。

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`（`persistent_storage.backend=local` の場合）

一時的なローカル状態を許容しない場合は、これらをプラットフォーム側でマウントしてください。

`/options`、`/runtime-apps`、またはスケジュール実行する PHP CLI ジョブで同梱の PHP ランタイムを使う場合は、`/app/data/php-fpm` もマウントしてください。
内部レスポンスキャッシュストアをノード入れ替え後も残したい場合は、`cache_store.store_dir` に合わせて `/app/cache/response` などもマウントしてください。これはあくまでキャッシュであり、DB ／ランタイムの正となるソースではありません。

WAF／CRS のインポート素材は `/app/data/tmp` 配下にステージングし、DB `waf_rule_assets` へインポートします。ランタイムは、マウントしたルールディレクトリではなく DB 上の有効な WAF／CRS アセットを読み込みます。

## 設定とシークレット

`tukuyomi` は `conf/config.json` を DB 接続のブートストラップに使用し、その後のオペレーター管理のアプリ／プロキシ設定は正規化済み DB テーブルから読み込みます。

典型的な本番パターン:

- `conf/config.json` は `storage.db_driver`、`storage.db_path`、`storage.db_dsn` 用に、シークレットマネージャー／構成管理から生成
- `seeds/conf/` は空 DB 向けの同梱シード一式としてマウントまたはイメージにベイクします。`conf/proxy.json` や各種ポリシーファイルなどの設定済みファイルがある場合はそちらが優先されます
- 初回起動前に `make db-migrate`、`make crs-install` の順で WAF ルールアセットをインストール／インポートし、その後に残りのシード素材用として `make db-import` を実行します。`db-import` は WAF ルールアセットを再インポートしません
- `conf/sites.json`、`conf/scheduled-tasks.json`、`conf/upstream-runtime.json` は、空 DB 向けのシード／エクスポートファイルとして扱います。ブートストラップ後に正となるのは、正規化済みの DB レコードです
- 主に必要なランタイム env 注入は次のものだけです
  - `WAF_CONFIG_FILE`
  - `WAF_PROXY_AUDIT_FILE`
  - `persistent_storage.backend=s3` の場合のみ `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN`、`AWS_REGION` ／ `AWS_DEFAULT_REGION`
  - `security_audit.key_source=env` を使う場合のセキュリティ監査鍵のオーバーライド
- 埋め込みの `Settings` 画面は DB `app_config` を編集します。リスナー／ランタイム／ストレージポリシー／オブザーバビリティ系の変更を反映するには、コンテナを再作成または再起動してください

サイト管理 ACME は、`Sites` 画面でサイトごとに `tls.mode=acme` を選択します。
ACME のキャッシュは `persistent_storage` の `acme/` 名前空間に保存します。シングルインスタンスでローカルバックエンドを使うのであれば `/app/data/persistent` をマウントし、複製運用やノード入れ替えを前提にする場合は S3 バックエンドまたは共有マウントを使用してください。Azure Blob Storage ／ Google Cloud Storage バックエンドは、プロバイダーアダプタが導入されるまでフェイルクローズします。

プロキシエンジンの選択も、再起動が必要な設定面の 1 つです。

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は組み込みエンジンで、同一のパーサー、トランスポート、ルーティング、ヘルスチェック、リトライ、TLS、キャッシュ、ルートのレスポンスヘッダー、1xx 情報レスポンス、トレーラー、ストリーミングフラッシュ挙動、ネイティブ Upgrade／WebSocket トンネル、レスポンスサニタイズパイプラインを保持したまま、Tukuyomi 独自のレスポンスブリッジを使用します
- レガシーな `net_http` ブリッジは削除済みです。`tukuyomi_proxy` 以外のエンジン値は設定検証で拒否されます
- HTTP/1.1 と明示的なアップストリーム HTTP/2 モードは、Tukuyomi ネイティブのアップストリームトランスポートを使用します。HTTPS の `force_attempt` は、ALPN で `h2` が選ばれなかった場合のみネイティブ HTTP/1.1 へフォールバックします
- Upgrade ／ WebSocket のハンドシェイクリクエストは `tukuyomi_proxy` 内で処理します。`101 Switching Protocols` 後の WebSocket フレームペイロードはトンネルデータです
- 本番ロールアウト前にコンテナを再ビルド／再起動し、実トラフィックでベンチマークを取ってください
- `waf.engine.mode` は現状、利用可能な `coraza` エンジンのみを受け付けます。`mod_security` は将来のアダプタ用に予約された既知のモードですが、アダプタが組み込まれるまではフェイルクローズで拒否されます

サーバー側に閉じ込めるべき値:

- `admin.session_secret`
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` ／ `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` を使う場合の初期オーナーブートストラップ用クレデンシャル
- 必要に応じてセキュリティ監査用の暗号鍵／HMAC 鍵
- イミュータブルな複製ロールアウトを意図的に試す場合は、フロントエンドレプリカで `admin.read_only=true` を設定し、スケジュールタスクの実行は専用シングルトンロールに切り出してください
- `tukuyomi` の既定方針は `admin.external_mode=api_only_external` です。リモート管理 API が不要であれば `deny_external` を使用してください
- 非ループバックリスナー上で `full_external` に上書きする場合は、フロント側の許可リスト／認証を必須として扱ってください
- `admin.trusted_cidrs` を公開／包括的なネットワークまで広げた場合、埋め込みの管理 UI／API はその信頼ソースに対しても再公開され、起動時には警告が出るのみです
- ベース WAF と CRS のアセットは、インポート後は DB `waf_rule_assets` を正として保持します。イメージにベイクされたファイルはシード素材であり、ランタイムの参照元ではありません
- マネージドなバイパスのオーバーライドルールは DB `override_rules` です。`extra_rule` の値は、論理的な互換参照として残ります

## プラットフォーム別の対応

以下のサンプルは、[Dockerfile.example](Dockerfile.example) でビルドした配備用イメージを前提にしています。このイメージのバイナリパスは `/app/tukuyomi` です。

`server/Dockerfile` を使う場合は、スケジューラサイドカーのサンプルにある `PROXY_BIN=/app/tukuyomi` を `PROXY_BIN=/app/server` に置き換えてください。

### ECS / Fargate

1 タスク内に次の 2 コンテナを配置します。

- `coraza`
- `scheduled-task-runner`

ECS サービス側もシングルインスタンスに固定します。

- `desiredCount=1`
- ロールアウト時にリビジョンを重ねない
  - 例: `minimumHealthyPercent=0`
  - 例: `maximumPercent=100`

サンプルアーティファクト:

- [ecs-single-instance.task-definition.example.json](ecs-single-instance.task-definition.example.json)
- [ecs-single-instance.service.example.json](ecs-single-instance.service.example.json)

サンプルでは、次を別々の EFS マウントとして分けています。

- `/app/conf`
- `/app/data/scheduled-tasks`
- `/app/audit`
- `/app/data/persistent`
- `/app/data/php-fpm`

タスク定義のサンプルでは、`admin.listen_addr` 用に `9091/tcp` も宣言しています。
ただし ECS サービスのロードバランサは、意図的にプライベート用の管理ターゲットグループを追加しない限り `9090` のままにしてください。

将来、イミュータブルな複製フロントエンドに切り替える場合は、次を前提にしてください。

- 公開フロントエンドサービスは `admin.read_only=true`
- スケジューラの所有権はフロントエンドのタスクセットの外へ出す
- スケジュールタスクは各レプリカではなく、専用スケジューラタスク 1 つだけが保持する

専用スケジューラ用アーティファクト:

- [ecs-replicated-frontend-scheduler.task-definition.example.json](ecs-replicated-frontend-scheduler.task-definition.example.json)
- [ecs-replicated-frontend-scheduler.service.example.json](ecs-replicated-frontend-scheduler.service.example.json)

### AKS / GKE / 一般的な Kubernetes

Deployment は次のとおり固定します。

- `replicas: 1`
- `strategy: Recreate`
- 1 Pod に 2 コンテナ

ここで `Recreate` を使うのは、ミュータブルなシングルインスタンスモデルのまま、ロールアウト中に 2 Pod を一瞬でも重ねないためです。

サンプルアーティファクト:

- [kubernetes-single-instance.example.yaml](kubernetes-single-instance.example.yaml)

サンプルでは、次を別々の PVC として分けています。

- `tukuyomi-conf`
- `tukuyomi-scheduled-tasks`
- `tukuyomi-audit`
- `tukuyomi-persistent`
- `tukuyomi-php-fpm`

サンプルには次も含めています。

- 公開用 `Service` `9090`
- 内部用 `tukuyomi-admin` `Service` `9091`

管理用 Service は、プライベートクラスターネットワーク、または別系統の内部 ingress／LB の背後でのみ使用してください。

将来、フロントエンド Pod を複数化する場合は、次を守ってください。

- フロントエンド Pod は `admin.read_only=true`
- 設定変更はロールアウト経由
- `scheduled-task-runner` は各レプリカと同居させず、専用シングルトンワークロードへ移す

専用スケジューラ用アーティファクト:

- [kubernetes-replicated-frontend-scheduler.example.yaml](kubernetes-replicated-frontend-scheduler.example.yaml)

### Azure Container Apps

次の設定でシングルインスタンスに寄せます。

- `activeRevisionsMode: Single`
- `minReplicas: 1`
- `maxReplicas: 1`
- 同一リビジョンに 2 コンテナ

サンプルアーティファクト:

- [azure-container-apps-single-instance.example.yaml](azure-container-apps-single-instance.example.yaml)

サンプルは、Container Apps 環境側に次の Azure Files ストレージ定義が既に存在することを前提にしています。

- `proxyconf`
- `proxyscheduledtasks`
- `proxyaudit`
- `proxypersistent`
- `proxyphpfpm`

Azure Container Apps のサンプルは、引き続きプライマリ ingress を 1 つだけ持ちます。
`admin.listen_addr` を有効にする場合も、現バージョンでは管理ポートをプライベート経路のままにし、別系統の内部公開は外側で構成してください。

将来、フロントエンドインスタンスを複数に寄せる場合は、次が前提です。

- `admin.read_only=true` を設定する
- スケジューラのオーナーは 1 つだけにする
- 各フロントエンドレプリカにスケジュールタスクを持たせない

専用スケジューラ用アーティファクト:

- [azure-container-apps-scheduler-singleton.example.yaml](azure-container-apps-scheduler-singleton.example.yaml)

### ローカル検証 ／ オペレーターリファレンス

リポジトリ同梱の compose 導線は、同じトポロジをローカルで確認するためのリファレンスとして残しています。

```bash
make compose-up-scheduled-tasks
```

プラットフォームのマニフェストへ落とし込む前に、まずこのローカルトポロジで確認する運用が自然です。

## 典型的な通信経路

クラウド環境では通常次のようになります。

`client -> ALB / nginx / ingress -> tukuyomi container -> app container / service`

前段が存在する場合は、DB `app_config` の信頼プロキシレンジをその前段だけに絞ってください。

`tukuyomi` 自体を直接の公開エントリポイントとし、組み込み HTTP/3 を有効にする場合は、リスナーポートの TCP／UDP を両方開放してください。

## 補足

- 埋め込みの Gateway ／ Center UI はイメージビルド時に生成され、ランタイムでビルドされることはありません
- `scripts/install_crs.sh` は、イメージビルド時にも起動時にも実行できます
- ランタイムでポリシーファイルを変更したい場合は `/app/conf` をマウントしてください。WAF／CRS アセットは `/app/data/tmp` のステージングから DB へインポートします
- リポジトリ同梱の `docker-compose.yml` には、`scheduled-tasks` プロファイル配下に `scheduled-task-runner` サイドカーが含まれます
- 現在のサイドカー実装は明示的です。イメージ内のプロキシバイナリを `run-scheduled-tasks` 付きで呼び出し、次の minute 境界までスリープします
- 障害時のポリシーも明示的です。`run-scheduled-tasks` が non-zero を返した場合は、サイドカーも non-zero で終了し、障害を握り潰さずにコンテナの再起動ポリシーへ委ねます
- `coraza` イメージには、MaxMind の `geoipupdate` が `/app/bin/geoipupdate` として同梱されます
- イメージ前提のマネージド国別データベース更新では、`/app/server update-country-db` を直接利用できます
- ローカル compose 導線は、プロキシ所有のパスのみを前提としています。

```bash
make compose-up-scheduled-tasks
```

- 生の compose コマンドは次のとおりです。

```bash
PUID="$(id -u)" GUID="$(id -g)" docker compose --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- `artisan schedule:run` のようなアプリケーションコマンドを動かすには、アプリケーションツリーを `coraza` と `scheduled-task-runner` の両方にマウントする必要があります
- オーバーライドファイルの例:
  [docker-compose.scheduled-tasks.app.example.yml](docker-compose.scheduled-tasks.app.example.yml)
- アプリツリーを追加した compose 例:

```bash
SCHEDULED_TASK_APP_ROOT=/srv/myapp \
SCHEDULED_TASK_APP_MOUNT=/app/workloads/myapp \
docker compose \
  -f docker-compose.yml \
  -f docs/build/docker-compose.scheduled-tasks.app.example.yml \
  --profile scheduled-tasks up -d --build coraza scheduled-task-runner
```

- `make gateway-preview-up` では、プレビュー専用のスケジューラサイドカーも一緒に起動します
- 既定のプレビューは毎回初期化されます
  - `gateway-preview-up` のたびにプレビュー専用 SQLite DB を作り直すため、古いプレビュー時のタスク、リスナー変更、DB レコードは引き継ぎません
- プレビュー用の DB 状態を保持したい場合は次のとおりです。

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down
```

- `GATEWAY_PREVIEW_PERSIST=1` では次が保持されます。
  - `data/<dirname(storage.db_path)>/tukuyomi-gateway-preview.db`
  - 例えば `storage.db_path` が `db/tukuyomi.db` であれば、プレビュー DB は `data/db/tukuyomi-gateway-preview.db` です
- `gateway-preview-up` は、プレビュー DB に保存された有効なプレビュー `app_config` から公開ポートを導出します
  - 初回起動時のみ、`conf/config.json` と `GATEWAY_PREVIEW_PUBLIC_ADDR` ／ `GATEWAY_PREVIEW_ADMIN_ADDR` のオーバーライドを土台にします
  - シングルリスナーであれば公開リスナーのポートを公開
  - リスナー分離の場合は公開／管理の両方を公開
  - ヘルスチェックはリスナー分離時には管理リスナーを優先します
- リスナー分離プレビューのブートストラップ例:

```bash
GATEWAY_PREVIEW_PERSIST=1 \
GATEWAY_PREVIEW_PUBLIC_ADDR=:80 \
GATEWAY_PREVIEW_ADMIN_ADDR=:9090 \
make gateway-preview-up
```

- このときの確認先は次のとおりです。
  - 公開プロキシ: `http://127.0.0.1:80`
  - 管理 UI: `http://127.0.0.1:9090/tukuyomi-ui`
  - 管理 API: `http://127.0.0.1:9090/tukuyomi-api`
- プレビューのリスナー設定では、`localhost:80`、`127.0.0.1:80`、`[::1]:9090` のようなループバックバインドは使用しないでください
  - コンテナ内のループバックバインドとホスト側の publish が噛み合わないため、プレビューは明示的なエラーで停止します
- `Settings` からリスナーを保存した後、プレビューで反映を確認するときは、`GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-down && GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up` を使用してください
  - リスナー変更自体はプレビュー DB に残りますが、`docker compose restart` ではポート公開の差分は再生成されません
- スケジューラの障害は、サイドカーの exit ／再起動とコンテナログから追跡します。恒久的な障害は、再起動チャーンとして観測される想定です
- スケジュールタスクのコマンドラインが `/app/data/php-fpm/binaries/php85/php` のような同梱 PHP のパスを指す場合は、そのスケジューラコンテナにも `/app/data/php-fpm` をマウントしてください
- プラットフォームのヘルスエンドポイントは `9090` 上の `/healthz` です
- カスタムコンテナのパスではなく、パッケージ済みバイナリで確認したい場合は、リリース tarball 同梱の `testenv/release-binary/` が最短経路です
- ロールアウト前に、このサンプルコンテナ導線をローカル検証する場合は `make container-deployment-smoke` を使用してください
- ロールアウト前に、コンテナプラットフォーム全体の契約まで確認する場合は `make container-platform-smoke` を使用してください
  ここでは、スケジュールタスクの所有権、複製時の read-only 前提、サンプルアーティファクトのパースまでを検証します
- プレビューの永続化と、リスナー分離時のポート整合性のみを個別に確認する場合は `make gateway-preview-smoke` を使用してください
