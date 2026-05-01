# 運用リファレンス

このドキュメントは、以前 `README.ja.md` に直接書いていた運用向け詳細をまとめたものです。

## 実行時設定

`.env` は Docker ／実行時の差分のみに使用します。`data/conf/config.json` は DB 接続のブートストラップ用であり、DB を開いた後のアプリ／プロキシ／ランタイム／ポリシー挙動は、正規化済みの DB テーブルから読み込みます。

### Docker ／ローカル MySQL（任意）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `MYSQL_PORT` | `13306` | `mysql` プロファイル利用時に、ローカル MySQL コンテナ `3306` へ割り当てるホスト側ポート。 |
| `MYSQL_DATABASE` | `tukuyomi` | ローカル MySQL コンテナで初期作成する DB 名。 |
| `MYSQL_USER` | `tukuyomi` | ローカル MySQL コンテナで作成するアプリ用ユーザー。 |
| `MYSQL_PASSWORD` | `tukuyomi` | `MYSQL_USER` のパスワード。 |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | root パスワード。 |
| `MYSQL_TZ` | `UTC` | コンテナのタイムゾーン。 |

### `data/conf/config.json` ／ DB `app_config`

`data/conf/config.json` は、DB を開く前に必要となる `storage.db_driver`、`storage.db_path`、`storage.db_dsn` を提供します。その他のプロダクト全体に関わる設定は、ブートストラップ／インポート後に DB `app_config` へ保存します。

主なブロック:

| ブロック | 役割 |
| --- | --- |
| `server` | リスナー、タイムアウト、バックプレッシャー、TLS、HTTP/3、公開／管理リスナー分離 |
| `runtime` | `gomaxprocs`、`memory_limit_mb` など Go ランタイム制御 |
| `admin` | UI／API パス、セッション、外部公開方針、信頼 CIDR、管理面のレート制限 |
| `paths` | rules、bypass、country、rate、bot、semantic、CRS、sites、tasks、アーティファクトの配置 |
| `proxy` | ロールバック履歴と、プロセス全体のプロキシエンジン制御 |
| `crs` | CRS 有効化フラグ |
| `storage` | DB のみのランタイムストア（`sqlite`、`mysql`、`pgsql`）、保持期間、同期間隔、ログファイルローテーションの上限 |
| `fp_tuner` | 外部プロバイダーのエンドポイント、承認、タイムアウト、監査 |
| `request_metadata` | `header` ／ `mmdb` など接続元国の解決方法 |
| `observability` | OTLP トレーシング設定 |

コンテナ起動で通常必要なのは次のとおりです。

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `WAF_CONFIG_FILE` | `conf/config.json` | 起動時の設定パス。 |
| `WAF_LISTEN_PORT` | `9090` | compose ヘルパー／ヘルスチェック用ポート。`server.listen_addr` と一致させます。 |

### 受信タイムアウトの区分

- 公開 HTTP/1.1 のデータプレーンリスナーは、Tukuyomi ネイティブの HTTP/1.1 サーバーが処理します。管理リスナー、HTTP リダイレクトリスナー、HTTP/3 ヘルパーは、引き続き分離したコントロール／エッジヘルパーです
- `server.read_header_timeout_sec` はリクエストラインとヘッダーのみを対象とします
- `server.read_timeout_sec` はリクエストライン＋ヘッダー＋ボディ全体に対する受信側の読み取り予算です
- `server.write_timeout_sec` はレスポンス書き込みの上限です。slow client がデータプレーンの goroutine を保持し続けることなくクローズします
- `server.idle_timeout_sec` は keep-alive のリクエスト間アイドル時間の上限です
- `server.graceful_shutdown_timeout_sec` は、デプロイ／リロード時に稼働中のコネクションをドレインする上限時間です。超過後は強制クローズします
- TLS 公開リスナーは、このネイティブサーバー経路では HTTP/1.1 をアドバタイズします。HTTP/3 は有効時も専用の HTTP/3 リスナーで処理します

### 過負荷時のバックプレッシャー

```json
"server": {
  "max_concurrent_requests": 96,
  "max_queued_requests": 0,
  "queued_request_timeout_ms": 0,
  "max_concurrent_proxy_requests": 80,
  "max_queued_proxy_requests": 32,
  "queued_proxy_request_timeout_ms": 100
}
```

- `max_concurrent_requests` はプロセス全体の上限
- `max_concurrent_proxy_requests` はデータプレーンの上限
- キューは、対応する `max_concurrent_* > 0` の場合のみ有効
- キューに入った成功応答には次が付与されます。
  - `X-Tukuyomi-Overload-Queued: true`
  - `X-Tukuyomi-Overload-Queue-Wait-Ms`
- 拒否時はキュー由来の理由を含む `503` を返します

### 組み込み TLS 終端（任意）

```json
"server": {
  "listen_addr": ":9443",
  "http3": {
    "enabled": true,
    "alt_svc_max_age_sec": 86400
  },
  "tls": {
    "enabled": true,
    "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
    "key_file": "/etc/tukuyomi/tls/privkey.pem",
    "min_version": "tls1.2",
    "redirect_http": true,
    "http_redirect_addr": ":9080"
  }
}
```

要点:

- `server.tls.enabled=false` が既定です
- `server.http3.enabled=true` には組み込み TLS が必要です
- HTTP/3 は `server.listen_addr` と同じ番号のポートを UDP で使用します
- `server.tls.redirect_http=true` を指定すると、平文 HTTP リスナーが追加されます
- ACME 自動 TLS は、サイトごとの `tls.mode=acme` で選択します。ACME のアカウント鍵、チャレンジトークン、証明書キャッシュは `persistent_storage` の `acme/` 名前空間に保存されます
- ACME HTTP-01 を使用するため、ポート 80 を `server.tls.http_redirect_addr` へ到達させてください。Let's Encrypt の `staging` ／ `production` は、サイトごとの ACME 環境設定で選択します
- `paths.site_config_file` の既定は `conf/sites.json` です。DB を正とするランタイムでは、これは空 DB 向けのシード／エクスポートパスであり、稼働中の正となるソースではありません

### 永続ファイルストレージ

`persistent_storage` は、DB ではなくバイト列として永続化するランタイムアーティファクト（ACME キャッシュなど）の配置先です。

```json
{
  "persistent_storage": {
    "backend": "local",
    "local": {
      "base_dir": "data/persistent"
    }
  }
}
```

- `local` は単一ノード、またはオペレーターが用意した共有マウント向けです
- S3 の設定対象は、プロバイダー名、バケット、リージョン、エンドポイント、プレフィックスなどの非機密情報のみです。MinIO 等の S3 互換エンドポイントでは `force_path_style=true` を使用します
- API キー、シークレットキー、クライアントシークレット、トークン、接続文字列は JSON ／ DB に保存しません。AWS ／ Azure ／ GCP の認証は、env、マネージド ID、Workload Identity、ADC など、プラットフォーム側で供給します
- S3 バックエンドは、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、任意の `AWS_SESSION_TOKEN`、`AWS_REGION` ／ `AWS_DEFAULT_REGION` をランタイムの env から読み込みます
- Azure Blob Storage ／ Google Cloud Storage は、プロバイダーアダプタが導入されるまでフェイルクローズします。ローカルへ暗黙にフォールバックすることはありません

S3 互換バックエンドの例:

```json
{
  "persistent_storage": {
    "backend": "s3",
    "s3": {
      "bucket": "tukuyomi-runtime",
      "region": "us-east-1",
      "endpoint": "http://minio:9000",
      "prefix": "prod",
      "force_path_style": true
    }
  }
}
```

MinIO 連携テストは通常の回帰テストではスキップされます。実行する場合は、既存のバケットを用意し、`TUKUYOMI_MINIO_S3_ENDPOINT`、`TUKUYOMI_MINIO_S3_BUCKET`、`AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY` を設定してください。

TLS 証明書の選択は TLS ハンドシェイク時点で完了するため、ルートのホスト／パス判定よりも前に決まります。

### 管理面の基本

- `admin.session_secret` はサーバー側のみで保持します
- CLI ／自動化処理では、ユーザー単位の個人アクセストークンを使用します
- 管理 UI は、ユーザー名／パスワードでのサインインと、DB ベースのセッションクッキーを使用します
- `Settings` は `Save config only` で保存されます。リスナー／ランタイム／ストレージ系の変更は再起動が必要です

### ホストネットワークのハードニング（L3／L4 の基本）

`tukuyomi` は L7 ゲートウェイです。上流の DDoS 防御の代替ではありません。

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`

```conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 対称ルーティング前提。非対称ルーティングや複数 NIC ／トンネル環境では 2 を検討
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

適用:

```bash
sudo sysctl --system
```

## 管理ダッシュボード

管理 UI は Go バイナリから `/tukuyomi-ui` として配信されます。

主な画面:

| パス | 役割 |
| --- | --- |
| `/status` | ランタイムステータス、設定スナップショット、リスナートポロジ |
| `/logs` | WAF ／セキュリティログ閲覧 |
| `/rules` | ランタイムの WAF ルール順、ベースルール編集、CRS 切り替え |
| `/bypass` ／ `/country-block` ／ `/rate-limit` | DB 同期ポリシーの編集 |
| `/ip-reputation` ／ `/bot-defense` ／ `/semantic` | リクエスト時のセキュリティ制御 |
| `/notifications` | 集約アラートの設定 |
| `/cache` | キャッシュルールと内部キャッシュストア |
| `/proxy-rules` | Runtime Apps が所有しない直接アップストリーム／バックエンドプール／ルートの編集と、validate ／ probe ／ dry-run ／ apply ／ rollback |
| `/backends` | 直接指定のアップストリームバックエンドオブジェクト一覧。直接指定された名前付きアップストリームはランタイムでの有効化／ドレイン／無効化／重みオーバーライドに対応し、Runtime App が生成したターゲットは Runtime Apps 側で扱います |
| `/sites` | サイトオーナーシップと TLS バインディング |
| `/options` | ランタイムインベントリ、オプションのアーティファクト、GeoIP ／国別 DB 管理 |
| `/runtime-apps` | static ／ `php-fpm` ／ `psgi` アプリケーションのランタイムリスナー、docroot、ランタイム、生成バックエンド管理 |
| `/scheduled-tasks` | cron 形式のコマンドタスクと前回実行ステータス |
| `/settings` | DB `app_config` 編集（再起動が必要な設定を含む） |

UI のサンプルは `docs/images/ui-samples/` にあります。

### 起動

```bash
make env-init
make db-migrate
make crs-install
make compose-up
```

管理 UI は `http://localhost:${CORAZA_PORT:-9090}/tukuyomi-ui` で開きます。

### よく使う Make ターゲット

```bash
make help
make build
make check
make smoke
make smoke-extended
make ci-local
make ci-local-extended
make deployment-smoke
make release-binary-smoke VERSION=v0.8.1
make http3-public-entry-smoke
make compose-down
```

### 関連ガイド

- バイナリ配備: [../build/binary-deployment.ja.md](../build/binary-deployment.ja.md)
- コンテナ配備: [../build/container-deployment.ja.md](../build/container-deployment.ja.md)
- リクエスト時セキュリティプラグイン: [../request_security_plugins.ja.md](../request_security_plugins.ja.md)
- 回帰テストマトリクス: [../operations/regression-matrix.ja.md](../operations/regression-matrix.ja.md)
- ベンチマークベースライン: [../operations/benchmark-baseline.ja.md](../operations/benchmark-baseline.ja.md)
- アップストリーム HTTP/2: [../operations/upstream-http2.ja.md](../operations/upstream-http2.ja.md)
- HTTP/3 公開エントリスモークテスト: [../operations/http3-public-entry-smoke.ja.md](../operations/http3-public-entry-smoke.ja.md)
- WAF チューニング: [../operations/waf-tuning.ja.md](../operations/waf-tuning.ja.md)
- 誤検知チューナー API 仕様: [../operations/fp-tuner-api.ja.md](../operations/fp-tuner-api.ja.md)
- PHP ランタイム ／ Runtime Apps: [../operations/php-fpm-vhosts.ja.md](../operations/php-fpm-vhosts.ja.md)
- スケジュールタスク: [../operations/php-scheduled-tasks.ja.md](../operations/php-scheduled-tasks.ja.md)
- DB 運用: [../operations/db-ops.ja.md](../operations/db-ops.ja.md)

## プロキシのルーティングとトランスポート

アップストリームの障害時の応答:

- `error_html_file` と `error_redirect_url` の両方が未設定の場合は、既定の `502 Bad Gateway`
- `error_html_file` 設定時は、HTML を受け付けるクライアントへメンテナンスページを返し、それ以外には平文の `503` を返します
- `error_redirect_url` 設定時は、`GET` ／ `HEAD` をリダイレクトし、それ以外には平文の `503` を返します

ルーティングモデル:

- `routes[]` は `priority` の昇順で先頭マッチ
- 選択順序:
  1. 明示的な `routes[]`
  2. DB `sites` のドメイン由来で生成されたホストフォールバックルート
  3. `default_route`
  4. `upstreams[]`
- ホストマッチは完全一致と `*.example.com`
- パスマッチは `exact`、`prefix`、`regex`
- `upstreams[]` は Runtime Apps が所有しない、直接指定のバックエンドノードカタログです。各行は静的 `url` か `discovery` のどちらか一方を使用します
- `backend_pools[]` は名前付きアップストリームメンバーから、ルート単位のバランシングセットを構成します
- `action.backend_pool` はバランシング向けの標準ルートバインディングです
- `action.upstream` は、直接指定のアップストリーム名、またはサーバー側で生成された Runtime App アップストリーム名を参照できます
- `action.canary_upstream` と `action.canary_weight_percent` で、ルートレベルのカナリアを設定できます
- `action.host_rewrite`、`action.path_rewrite.prefix`、`action.query_rewrite` で outbound のリライトを設定します
- `action.request_headers`、`action.response_headers` で上限付きのヘッダー制御を行います
- `response_header_sanitize` は最終的なレスポンスヘッダーの安全性ゲートです
- 構造化エディタは、運用フローを次の順序で表示します
  1. `Upstreams`
  2. `Backend Pools`
  3. `Routes` ／ `Default route`
- `Upstreams` の各行には専用の `Probe` があり、設定済みのアップストリームを 1 件ずつ疎通確認します
- `Runtime Apps` は、実効ランタイムに対してランタイムリスナー用の生成バックエンドを公開します
- `Runtime Apps` は、設定済みアップストリームの URL を書き換えません。設定済みの `primary` は `Proxy Rules > Upstreams` に表示される URL のままです
- `generated_target` はサーバー所有の Runtime App マテリアライズ状態であり、通常はオペレーター入力ではありません
- PHP-FPM ／ PSGI ／静的アプリのリスナー設定は `Runtime Apps`、公開トラフィックのルーティングは `Proxy Rules` で管理します

### プロキシエンジン

DB `app_config` の `proxy.engine.mode` は、プロセス全体のプロキシエンジンを表します。
対応するエンジンは Tukuyomi ネイティブプロキシのみです。この変更にはプロセス再起動が必要です。

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は組み込みエンジンで、WAF ／ルーティング選定後に Tukuyomi のレスポンスブリッジを使用します。同一の HTTP パーサー、アップストリームトランスポート、ヘルスチェック、リトライ、TLS、HTTP/2、キャッシュ、ルートのレスポンスヘッダー、1xx 情報レスポンス、トレーラー、ストリーミングフラッシュ挙動、ネイティブ Upgrade ／ WebSocket トンネル、レスポンスサニタイズ経路を保持します
- レガシーな `net_http` ブリッジは削除済みです。`proxy.engine.mode` に `tukuyomi_proxy` 以外を指定すると、設定検証で拒否されます
- HTTP/1.1 と明示的なアップストリーム HTTP/2 モードは、Tukuyomi ネイティブのアップストリームトランスポートを使用します。HTTPS の `force_attempt` は、ALPN で `h2` が選ばれなかった場合のみネイティブ HTTP/1.1 へフォールバックします
- Upgrade ／ WebSocket のハンドシェイクリクエストは `tukuyomi_proxy` 内で処理します。`101 Switching Protocols` 後の WebSocket フレームペイロードはトンネルデータであり、HTTP WAF 検査の入力にはなりません
- ランタイムでの可視化は、`/tukuyomi-api/status` の `proxy_engine_mode` と `Settings -> Runtime Inventory` で確認できます

### WAF エンジン

DB `app_config` の `waf.engine.mode` は、プロセス全体の WAF エンジンを表します。
現在のビルドで稼働可能なのは Coraza のみですが、エンジンカタログは明示しており、将来のアダプタを登録できる前提となっています。

```json
{
  "waf": {
    "engine": {
      "mode": "coraza"
    }
  }
}
```

- `coraza` はこのビルドで利用可能な唯一のエンジンです
- `mod_security` は将来用に予約された既知のエンジンモードですが、ModSecurity アダプタが組み込まれていないビルドでは利用できません。設定検証はフェイルクローズで拒否します
- 未知の `waf.engine.mode` は設定検証で拒否されます
- ランタイムでの可視化は、`/tukuyomi-api/status` の `waf_engine_mode` ／ `waf_engine_modes` と `Settings -> Runtime Inventory` で確認できます
- 左ナビゲーションは `Security > Coraza` をエンジン固有として扱い、有効な WAF エンジンが Coraza ではない場合は表示しません。`Security > Request Controls` は Tukuyomi のリクエストポリシーであるため、表示は維持されます
- `Bypass Rules` はリクエスト制御です。ただし `extra_rule` の参照は Coraza 由来で DB マネージドな `.conf` スニペットであるため、有効な WAF エンジンが Coraza ではない場合は利用できません。フルバイパスのエントリは引き続き適用されます

### ランタイムでのバックエンド操作

- 正規化済みの `upstream_runtime` DB ドメインが、直接アップストリーム ／ DNS ディスカバリからマテリアライズされたバックエンドキー単位で、オプトインのランタイムオーバーライドを保持します。`data/conf/upstream-runtime.json` は空 DB 向けのシード／エクスポートパスです
- `Backends` は直接指定のアップストリームバックエンドオブジェクトを一覧表示しつつ、次のランタイム操作の操作盤となります
  - `enabled`
  - `draining`
  - `disabled`
  - 正の `weight_override`
- オーバーライドが無いバックエンドは、DB `proxy_rules` の設定どおりに動作します。`data/conf/proxy.json` はそのシード／インポート／エクスポート素材です
- ランタイム操作の対象は、静的な直接アップストリームと DNS ディスカバリでマテリアライズされたターゲットです
- Runtime App が生成したターゲットは `Runtime Apps` 側で扱い、`Backends` には表示されません
- ルートに直書きされた URL と Runtime App が生成したターゲットは、ランタイム操作の対象外です
- `draining` ／ `disabled` ／ `unhealthy` のバックエンドは、新規ターゲット選定から外されます
- `proxy_access` ログには、選択されたバックエンドのランタイム状態として次が出力されます
  - `selected_upstream_admin_state`
  - `selected_upstream_health_state`
  - `selected_upstream_effective_selectable`
  - `selected_upstream_effective_weight`
  - `selected_upstream_inflight`
- ブロックされたリクエストには、選択バックエンドのフィールドは出力しません

通常の `http://` ／ `https://` アップストリームへのプロキシでは、自動的に次を付与します。

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

さらに `emit_upstream_name_request_header=true` を有効にすると、次のヘッダーも付与できます。

- `X-Tukuyomi-Upstream-Name`

これは内部のオブザーバビリティ用ヘッダーです。`[proxy]` は受信側に存在する同名ヘッダーを一度除去し、最終ターゲットが `Proxy Rules > Upstreams` の設定済みの名前付きアップストリームであった場合にのみ付け直します。

これらのランタイム管理ヘッダーは、ルートレベルの `request_headers` から上書きできません。

### 最小アップストリーム例

```json
{
  "upstreams": [
    { "name": "primary", "url": "http://app.internal:8080", "weight": 1, "enabled": true }
  ],
  "load_balancing_strategy": "round_robin",
  "hash_policy": "cookie",
  "hash_key": "session",
  "expose_waf_debug_headers": false
}
```

### 動的 DNS バックエンドディスカバリ

バックエンドアドレスを DNS が管理するコンテナ／Kubernetes 環境では、`upstreams[].discovery` を使用します。Routes ／ Backend Pools は従来どおり、正規のアップストリーム名を参照します。ランタイムは上限付きの間隔で DNS を解決し、解決結果をバックエンドターゲットとしてマテリアライズします。後続のルックアップが失敗した場合は、最後に成功したターゲットセットを保持します。

```json
{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "record_types": ["A", "AAAA"],
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    },
    {
      "name": "api-srv",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns_srv",
        "service": "http",
        "proto": "tcp",
        "name": "api.default.svc.cluster.local",
        "scheme": "https",
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ]
}
```

- `type=dns` は A ／ AAAA レコードを解決します。`hostname`、`scheme`、`port` が必須です
- `type=dns_srv` は `_service._proto.name` を解決し、SRV のポートを使用します
- `scheme` は `http` ／ `https` のみです。`fcgi` ／ `static` はディスカバリ対象外です
- DNS はリクエストごとには解決しません。更新間隔は `refresh_interval_sec` で制御します
- 初回ルックアップが失敗し、直近の成功結果も無い場合、そのアップストリームは選択可能ターゲット 0 となります
- `Backends` とヘルスステータスから、マテリアライズされたターゲットとディスカバリエラーを確認できます

### 最小ルート単位バックエンドプール例

```json
{
  "upstreams": [
    { "name": "localhost1", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true },
    { "name": "localhost2", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true },
    { "name": "localhost3", "url": "http://127.0.0.1:9081", "weight": 1, "enabled": true },
    { "name": "localhost4", "url": "http://127.0.0.1:9082", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-localhost", "strategy": "round_robin", "members": ["localhost1", "localhost2"] },
    { "name": "site-app", "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ],
  "routes": [
    { "name": "site-localhost", "priority": 10, "match": { "hosts": ["localhost"] }, "action": { "backend_pool": "site-localhost" } },
    { "name": "site-app", "priority": 20, "match": { "hosts": ["app"] }, "action": { "backend_pool": "site-app" } }
  ]
}
```

### バックエンドプールのスティッキーセッション

`backend_pools[].sticky_session` は、プロキシが署名付きの affinity クッキーを発行する機能です。
`hash_policy=cookie` が既存のアプリクッキーをハッシュ入力に使うだけなのに対し、`sticky_session` ではロードバランサ用クッキーをプロキシ自身が発行・更新します。

```json
{
  "backend_pools": [
    {
      "name": "site-api",
      "strategy": "round_robin",
      "members": ["api-a", "api-b"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 86400,
        "path": "/",
        "secure": true,
        "http_only": true,
        "same_site": "lax"
      }
    }
  ]
}
```

- 有効なスティッキークッキーは、ラウンドロビン、least-conn、ハッシュ選択よりも優先されます
- 無効・期限切れ・改ざん・未知・無効化済み・ドレイン中・unhealthy のスティッキーターゲットは無視されます
- クッキー値は署名されており、選択されたターゲットの識別子と有効期限のみを保持します。バックエンド URL は含めません
- 署名鍵はプロセスローカルで、起動時に生成されます。再起動後の古いクッキーは安全に拒否され、次のレスポンスで更新されます
- `same_site=none` を指定する場合は `secure=true` が必須です

```json
{
  "routes": [
    {
      "name": "service-a-prefix",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "service-a",
        "host_rewrite": "service-a.internal",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}
```

### dry-run の例

```bash
curl -sS \
  -H "Authorization: Bearer ${WAF_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

ルート関連ログ:

- `proxy_route`
- `original_host`、`original_path`、`original_query`
- `rewritten_host`、`rewritten_path`、`rewritten_query`
- `selected_route`
- `proxy_route` はルート分類後、WAF ／最終ターゲット選定の前に出力されるため、`selected_upstream` ／ `selected_upstream_url` は出力しません
- `proxy_access` および選定後のトランスポートログは、最終ターゲットが確定した後でのみ `selected_upstream` ／ `selected_upstream_url` を出力します

リクエストフロー:

- リクエストメタデータの解決
- ルート分類とリライト計画
- 国別ブロック ／リクエストセキュリティプラグイン ／レート制限 ／ WAF
- 最終ターゲットの選定
- プロキシトランスポート、または直接の static ／ php-fpm 配信

## 管理 API

スキーマの詳細は [../api/admin-openapi.yaml](../api/admin-openapi.yaml) を参照してください。

主なエンドポイント群:

| グループ | 例 |
| --- | --- |
| ランタイムステータス／メトリクス | `/status`、`/metrics` |
| ログ ／エビデンス | `/logs/read`、`/logs/stats`、`/logs/security-audit*`、`/logs/download` |
| ルール ／ CRS | `/rules*`、`/crs-rule-sets*` |
| ポリシーファイル | `/bypass-rules*`、`/country-block-rules*`、`/rate-limit-rules*`、`/ip-reputation*`、`/notifications*`、`/bot-defense-rules*`、`/semantic-rules*` |
| 誤検知チューナー | `/fp-tuner/propose`、`/fp-tuner/apply` |
| キャッシュ | `/cache-rules*`、`/cache-store*` |
| PHP ／ Runtime Apps ／タスク | `/php-runtimes*`、`/runtime-apps*`、`/scheduled-tasks*` |
| サイト ／プロキシルーティング | `/sites*`、`/proxy-rules*` |
| GeoIP 国別 DB 更新 | `/request-country-mode`、`/request-country-db*`、`/request-country-update*` |

`GET /tukuyomi-api/status` では次を確認できます。

- リスナー ／ランタイムの開示情報
- TLS ／ HTTP3 の状態
- サイトのランタイム状態
- アップストリームの HA ／ランタイム状態
- リクエストセキュリティのカウンタと設定スナップショット

## ポリシーファイルとセキュリティ制御

### WAF バイパス ／特殊ルール

`paths.bypass_file` の既定は `conf/waf-bypass.json` です。

```json
{
  "default": {
    "entries": [
      { "path": "/assets/" },
      { "path": "/about/user.php" }
    ]
  },
  "hosts": {
    "example.com": {
      "entries": [
        { "path": "/search", "extra_rule": "orders-preview.conf" }
      ]
    }
  }
}
```

マネージドな `extra_rule` の本体は DB `override_rules` に保存し、`Rules` > Advanced > `Bypass snippets` で編集します。`conf/rules` ディレクトリへのフォールバックはありません。起動時のベース WAF ルールセットには混入させず、バイパスエントリから論理的な `extra_rule` 名で参照されたときのみロードします。
ホストスコープの優先順序は、完全一致の `host:port`、次にホスト名のみ、最後に `default` です。ホスト固有のスコープは default をマージせず置き換えます。

### 国別ブロック

`paths.country_block_file` の既定は `conf/country-block.json` です。

- JSON フィールドは `default.blocked_countries` と任意の `hosts.<host>.blocked_countries`
- 値は ISO-3166 alpha-2 の国コードと `UNKNOWN`
- マッチした場合は WAF より前で `403`
- 国の解決は `request_metadata_resolvers` が担当します
- `header` モードは `X-Country-Code` を使用します
- `mmdb` モードは、DB マネージドな国別 MMDB アセットをランタイムへロードして解決します
- ホストスコープの優先順序は、完全一致の `host:port`、次にホスト名のみ、最後に `default`

### レート制限

`paths.rate_limit_file` の既定は `conf/rate-limit.json` です。

要点:

- JSON 形式で `default_policy` と `rules` を指定します
- `key_by` は `ip`、`country`、`ip_country`、`session`、`ip_session`, `jwt_sub`、`ip_jwt_sub` を指定可能です
- アダプティブスロットリングで、ボット ／セマンティックリスクを利用できます
- フィードバックにより、持続的な不正使用をボット防御の隔離へ昇格できます

### IP レピュテーション

`paths.ip_reputation_file` の既定は `conf/ip-reputation.json` です。

- ローカルファイルと HTTP ／ HTTPS フィードに対応します
- インラインの許可リストは、フィード由来のブロックよりも優先されます
- リクエスト時セキュリティの順序は `ip_reputation -> bot_defense -> semantic` です

### WebSocket のスコープ

- HTTP の Upgrade ハンドシェイクは、通常のリクエストと同様に検査されます
- アップグレード後のフレームはパススルーで、WAF ／ボディ検査は行いません

### 管理面のハードニング

- `admin.external_mode`: `deny_external`、`api_only_external`、`full_external`
- `admin.trusted_cidrs` で信頼ピアを定義します
- `admin.trust_forwarded_for=true` は、直接ピアが信頼対象である場合のみ有効です
- `admin.rate_limit` で管理面専用のスロットルを追加できます

### オブザーバビリティ

- `/metrics` は TLS、アップストリーム HA、レート制限、セマンティック、リクエストセキュリティのカウンタを公開します
- WAF ／アクセスイベントは DB を正として保持されます。セキュリティ監査は別系統のファイル／エビデンスストリームとして残り、ファイルローテーション設定はファイルベースの監査／レガシーログストリームに適用されます
- 任意の OTLP トレーシングは `observability.tracing` で設定します

### 通知

`paths.notification_file` の既定は `conf/notifications.json` です。

- リクエスト単位ではなく、集約された状態遷移を通知します
- `webhook`、`email` に対応します
- `/notifications/test` でテスト通知を送信できます
- `/notifications/status` でシンク／ランタイムの状態を確認できます

### ボット防御

`paths.bot_defense_file` の既定は `conf/bot-defense.json` です。

主な機能:

- 不審な UA に対するチャレンジ
- 振る舞い検知
- ブラウザ／デバイステレメトリのクッキー
- 初回リクエストのヘッダーシグナル
- 直接 HTTPS 向けの TLS フィンガープリントのヒューリスティック
- 連続違反時の隔離
- パス対応のオーバーライド
- 全体／フロー単位の `dry_run`

### セマンティックセキュリティ

`paths.semantic_file` の既定は `conf/semantic.json` です。

- 適用ステージは `off | log_only | challenge | block`
- 時間方向のシグナルを含むリクエストスコアリング
- `semantic_anomaly` ログには `reason_list` と `score_breakdown` が含まれます

### セキュリティ監査ログ

`security_audit` は、リクエスト単位の署名付き監査ログを追加する機能です。

- 判定チェーンの JSON は `paths.security_audit_file`
- 暗号化されたエビデンスのブロブは `paths.security_audit_blob_dir`
- ボディ保持はオプトインかつ上限付き
- 完全性検証は `/logs/security-audit/verify`

### ルール ／ CRS の編集

- `/rules` は Coraza CRS アセットとベース WAF ルールアセットをランタイムの順序で表示します
- `/rules` は有効な DB ベースのベースルールアセットを編集します
- ベース WAF ルールアセットは無効化できます。無効化されたアセットは編集可能なまま、稼働中の WAF ロードセットからは外れます
- `/rules` は、論理的な `rules/crs/rules/*.conf` 名を持つ DB ベースの CRS アセットを切り替えます
- 保存に成功すると、WAF はホットリロードされます
- リロードに失敗した場合は、自動でロールバックします

## ログとキャッシュ

### ログの取得

```bash
curl -s -H "Authorization: Bearer <your-personal-access-token>" \
     "http://<host>/tukuyomi-api/logs/read?tail=100&country=JP" | jq .
```

### キャッシュ機能

キャッシュルールと内部キャッシュストアの設定は、DB テーブルでバージョン管理されます。
`data/conf/cache-rules.json` は、引き続き空 DB 向けのシード／インポート素材です。
内部キャッシュストア設定は、正規化済みのレコードが無いときに DB の既定値からシードされ、`data/conf/cache-store.json` は明示的に DB を介さないフォールバック実行時のみ意味を持ちます。

例:

```json
{
  "default": {
    "rules": [
      {
        "kind": "ALLOW",
        "match": { "type": "prefix", "value": "/_next/static/chunks/" },
        "methods": ["GET", "HEAD"],
        "ttl": 600,
        "vary": ["Accept-Encoding"]
      },
      {
        "kind": "DENY",
        "match": { "type": "prefix", "value": "/tukuyomi-api/" }
      }
    ]
  },
  "hosts": {
    "admin.example.com": {
      "rules": [
        {
          "kind": "DENY",
          "match": { "type": "prefix", "value": "/" },
          "methods": ["GET", "HEAD"],
          "ttl": 600
        }
      ]
    }
  }
}
```

動作概要:

- ホストごとのキャッシュスコープは default スコープへマージされず、マッチ時には置き換えられます
- マッチしたレスポンスは、内部のファイルベースキャッシュに保存可能です
- 任意で、上限付きの L1 メモリキャッシュを有効化できます
- `POST /tukuyomi-api/cache-store/clear` で即時に全削除できます
- 認証付きのトラフィックや、アップストリームのレスポンスに `Set-Cookie` を含むものは保存しません

確認用ヘッダー:

- `X-Tukuyomi-Cacheable: 1`
- `X-Accel-Expires: <seconds>`
- `X-Tukuyomi-Cache: MISS|HIT`
