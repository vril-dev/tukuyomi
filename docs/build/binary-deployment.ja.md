# Binary Deployment

この手順は、Linux ホスト上で `tukuyomi` をシングルバイナリとして `systemd` 管理で動かす前提です。

想定環境:

- オンプレ Linux サーバー
- VPS
- VM
- EC2

## ビルド

作業端末またはビルドホストで実行します。

```bash
make setup
make build
```

生成物は `bin/tukuyomi` です。

Gateway ／ Center UI のビルドには Node.js 24 LTS と npm 11+ が必要です。Makefile は既定で `tools/npm-node24.sh` を使うため、ローカルに Node 24／npm 11 があればそれを使い、無ければ Docker イメージ `node:24-alpine` にフォールバックします。このラッパーを意図的に差し替える場合のみ `NPM=/path/to/npm` を指定してください。

埋め込みの Gateway ／ Center UI を更新済みで、Go バイナリだけを再ビルドしたい場合は次を使います。

```bash
make go-build
```

再現性のあるリリースアーティファクトを作る場合は次を使います。

```bash
make release-linux-all VERSION=v0.8.0
```

## One-shot install

Linux ホストへ直接導入する場合は、次の 1 コマンドでビルド、ランタイムツリーの作成、DB マイグレーション、WAF／CRS アセットのインポート、初回 DB シード投入、systemd ユニットの配置までを実行できます。
`INSTALL_ROLE` を省略した場合は `gateway` です。

```bash
make install TARGET=linux-systemd
```

Center をコントロールプレーンホストへ導入する場合は次を使います。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

同じホスト上の Gateway front の背後に Center を置く場合は、protected Center role を使います。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center-protected
```

主なオーバーライド:

```bash
make install TARGET=linux-systemd \
  INSTALL_ROLE=gateway \
  PREFIX=/opt/tukuyomi \
  INSTALL_ENABLE_SCHEDULED_TASKS=0 \
  INSTALL_DB_SEED=auto
```

挙動:

- `PREFIX` の既定値は `/opt/tukuyomi`
- `INSTALL_ROLE=gateway` は `tukuyomi.service`、`tukuyomi.env`、`conf/config.json`、WAF／CRS アセットのインポート、Gateway 用初回 DB シード、スケジュールタスク用タイマーを対象にします
- Gateway インストールは `runtime.process_model=supervised` を書き込みます。スーパーバイザーが TCP リスナーを所有し、レディネス確認後に初期ワーカーをアクティブ化します。既存 Gateway 設定に対しては、インストール時に `runtime.process_model` のみをピンポイントで更新します。レガシーなシングルプロセス Gateway からの初回移行は、リスナーの所有者が変わるため通常のサービス再起動が必要です。HTTP/3 は UDP ハンドオフ実装が完了するまで拒否されます
- `INSTALL_ROLE=center` は `tukuyomi-center.service`、`tukuyomi-center.env`、`conf/config.center.json` を対象とし、DB マイグレーションのみを実行します。WAF／CRS インポート、Gateway シード、スケジュールタスクは実行しません
- `INSTALL_ROLE=center-protected` は `tukuyomi.service` と `tukuyomi-center.service` の両方を導入します。Center は loopback で待ち受け、Gateway seed は `/center-ui` と `/center-api` を `http://127.0.0.1:9092` へ転送します。Gateway の IoT / Edge device authentication を有効化し、対応する Center 承認もローカルで bootstrap します。scheduled-task timer は導入しません
- `PREFIX` が実行ユーザーのホーム配下にある場合、`INSTALL_CREATE_USER=auto` は実行ユーザーをそのままランタイムユーザーとし、`useradd` は実行しません
- ホーム配下にインストールしたランタイムツリーは、その login ユーザーとプライマリグループの所有になります
- `/opt/tukuyomi` などのシステムパスの場合、既定では `tukuyomi` システムユーザー／グループを作成または再利用します
- システムパスへのサービスアカウント運用では、配備ルートと `bin/`、`scripts/`、`conf/` は root 管理、`db/`、`audit/`、`cache/`、`data/` はランタイムユーザーが書き込み可能になります
- ロールごとの設定／env ファイルは既定では上書きしません
- ホストインストールで権限が必要な操作のみ `sudo` を使用します。ビルドは通常ユーザーのまま実行できます
- 初回作成する env ファイルと systemd ユニットは `PREFIX` に合わせて生成されます
- ロール用の設定ファイルは root 所有 `0640` とし、サービスグループに読み取りのみを与えます
- env ファイルはシークレットを含む前提で root 所有 `0640` のまま保持します
- `INSTALL_DB_SEED=auto` は SQLite DB がまだ存在しない初回のみ `db-import` を実行します
- 初回 DB シードでは `primary` という既定アップストリームが作成されます。プロキシにトラフィックを流す前に、実際のバックエンドエンドポイントへ調整してください
- 既存 DB がある状態での再実行時は、DB マイグレーションと WAF／CRS アセットのリフレッシュを行います
- MySQL ／ PostgreSQL の空 DB を初期投入する場合は `INSTALL_DB_SEED=always` を明示してください
- スケジュールタスク用タイマーは既定で有効化します。このホストでスケジュールタスクを実行しない場合は `INSTALL_ENABLE_SCHEDULED_TASKS=0` を指定してください
- スモーク／パッケージステージング用に `DESTDIR=<tmp> INSTALL_ENABLE_SYSTEMD=0` が利用できます

ログインユーザーで明示的に動作させる場合の例:

```bash
make install TARGET=linux-systemd \
  PREFIX="$HOME/tukuyomi" \
  INSTALL_USER="$(id -un)" \
  INSTALL_GROUP="$(id -gn)" \
  INSTALL_CREATE_USER=0
```

ECS ／ Kubernetes ／ Azure Container Apps 向けは、ホストインストールではなく `make deploy-render` を使います。詳細は [container-deployment.ja.md](container-deployment.ja.md) を参照してください。

## 実行レイアウト

バイナリは、作業ディレクトリ配下に次のレイアウトを前提としています。

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/db/
/opt/tukuyomi/audit/
/opt/tukuyomi/cache/
/opt/tukuyomi/data/persistent/
/opt/tukuyomi/data/tmp/
```

バンドルに同梱されるブートストラップ／サンプル:

- `conf/config.json`
- `conf/crs-disabled.conf`
- `scripts/update_country_db.sh`

初回 DB インポート前に、必要に応じてオペレーターが配置するシード／インポートファイル:

- `conf/cache-rules.json`
- `conf/waf-bypass.json`
- `conf/waf-bypass.sample.json`
- `conf/country-block.json`
- `conf/rate-limit.json`
- `conf/bot-defense.json`
- `conf/semantic.json`
- `conf/notifications.json`
- `conf/ip-reputation.json`
- `conf/scheduled-tasks.json`
- `conf/upstream-runtime.json`
- `make crs-install` で `data/tmp/...` 配下にステージングする WAF／CRS インポート素材

これらは空 DB の初期投入や、インポート／エクスポート用の素材です。対応する正規化済み DB レコードが存在するようになった後は、ランタイムは正規化済みドメインを DB から直接読み込み、ファイルの復元を起動条件にしません。インポート後の本番起動で必要なのは、DB ブートストラップ用 `conf/config.json` と DB レコードのみです。

初回 DB インポート前に使う PHP-FPM 関連の追加物:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

インポート後、同梱の PHP-FPM を使う場合は実行ファイル本体のバンドルは必要ですが、`inventory.json`、`vhosts.json`、`runtime.json`、`modules.json` はランタイムの参照元ではありません。

スケジュールタスクの実行状態は次を使用します。

- `data/scheduled-tasks/`

マネージド GeoIP 国別データベース更新も使う場合の追加物:

- `scripts/update_country_db.sh`

配置例:

```bash
sudo install -d -m 755 \
  /opt/tukuyomi/bin \
  /opt/tukuyomi/conf \
  /opt/tukuyomi/db \
  /opt/tukuyomi/audit \
  /opt/tukuyomi/cache/response \
  /opt/tukuyomi/data/persistent \
  /opt/tukuyomi/data/tmp \
  /opt/tukuyomi/seeds/conf \
  /opt/tukuyomi/scripts

sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo install -m 755 scripts/update_country_db.sh /opt/tukuyomi/scripts/update_country_db.sh
sudo cp -R seeds/conf/. /opt/tukuyomi/seeds/conf/

sudo install -o root -g tukuyomi -m 640 data/conf/config.json /opt/tukuyomi/conf/config.json

sudo install -o root -g tukuyomi -m 640 /dev/null /opt/tukuyomi/conf/crs-disabled.conf
```

注意:

- `data/conf/*.bak` は本番へ持ち込まないでください
- `config.json` は DB 接続のブートストラップ用です。リリースサンプルは `storage` ブロックのみを保持しています
- `conf/proxy.json` は DB `proxy_rules` の任意のシード／インポート／エクスポート素材です
- `conf/sites.json` は DB `sites` の任意のシード／インポート／エクスポート素材です
- 公開リリースバンドルには `conf/config.json` と、空 DB 向けランタイムシードである `seeds/conf/config-bundle.json` が同梱されます
- `conf/proxy.json` やポリシー JSON など設定済みファイルが存在しない場合、`make db-import` は `seeds/conf/config-bundle.json` を読み込み、その後ビルトインの互換デフォルトへフォールバックします
- 既定のベース WAF ルールシードは、`make crs-install` が `seeds/waf/rules/tukuyomi.conf` から一時ステージングして DB へインポートします
- CRS ファイルは DB `waf_rule_assets` 向けの一時インポート素材であり、`make crs-install` が `data/tmp` でステージングとクリーンアップを行います
- config bundle 内の sites、scheduled tasks、upstream runtime、policy、cache rules、WAF bypass、PHP-FPM/PSGI マニフェストは、DB ブートストラップ後は DB のシード／エクスポート用アーティファクトです
- 本番では `storage.db_driver`、`storage.db_path`、`storage.db_dsn` 用の `config.json` を、シークレットマネージャー／構成管理から生成・マウントしてください
- 初回起動前に `make db-migrate`、`make crs-install` の順で WAF ルールアセットをインストール／インポートし、その後に残りのシード素材用として `make db-import` を実行します。`db-import` は WAF ルールアセットを再インポートしません
- 埋め込みの `Settings` 画面は DB `app_config` を編集します。リスナー／ランタイム／ストレージポリシー／オブザーバビリティ系の変更後はサービスを再起動してください
- 公開リリースバンドルには、`Options -> GeoIP Update -> Update now` 用の同梱バイナリ `bin/geoipupdate` が含まれます
- `GEOIPUPDATE_BIN` を使うと、同梱アップデータのパスをオーバーライドできます
- マネージド国別データベース更新の公式ラッパーは `./scripts/update_country_db.sh` です
- マネージド GeoIP 国別 DB、`GeoIP.conf`、更新ステータスは DB を正として保持します。`data/geoip` フォールバックディレクトリは配備しません
- マネージドなバイパスのオーバーライドルールは DB `override_rules` です。`conf/rules` フォールバックディレクトリは配備しません
- WAF ／アクセスイベントは DB `waf_events` へ直接書き込みます。`paths.log_file` は古い `waf-events.ndjson` を明示的に取り込む場合のみ使用するレガシーインポート元です
- `extra_rule` の値は、DB マネージドなオーバーライドルールへの論理的な互換参照として残ります

## 永続バイトストレージ

DB ではなくファイル／オブジェクトとして保持するランタイムアーティファクトは `persistent_storage` で管理します。
現在の主用途は、サイト管理 ACME のアカウント鍵、チャレンジトークン、証明書キャッシュです。

既定はローカルバックエンドです。

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

- シングルノードのオンプレ／VPS では、`/opt/tukuyomi/data/persistent` をバックアップ対象にしてください
- スケールアウトやノード入れ替えを前提にする場合は、ローカルバックエンドではなく S3 バックエンドか共有マウントを使用してください
- S3 バックエンドでは、バケット／リージョン／エンドポイント／プレフィックスなどの非機密情報のみを DB `app_config` に保存します
- `AWS_ACCESS_KEY_ID`、`AWS_SECRET_ACCESS_KEY`、`AWS_SESSION_TOKEN` は env ／プラットフォームのシークレット注入経由で渡します
- Azure Blob Storage ／ Google Cloud Storage は、プロバイダーアダプタが導入されるまでフェイルクローズし、ローカルへ暗黙にフォールバックすることはありません

サイト管理 ACME は、`Sites` 画面でサイトごとに `tls.mode=acme` を選択します。
`production` ／ `staging` は Let's Encrypt の本番 CA ／ステージング CA の選択で、アカウントメールは任意です。
HTTP-01 チャレンジを使うため、`server.tls.redirect_http=true` と `server.tls.http_redirect_addr=:80`、または同等のポート 80 転送を用意してください。

プロキシエンジン設定は、現在 DB `app_config` 上で `tukuyomi_proxy` 固定です。

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
- 本番展開前に、実ワークロードでベンチマークを取ってください
- `waf.engine.mode` は現状、利用可能な `coraza` エンジンのみを受け付けます。`mod_security` は将来のアダプタ用に予約された既知のモードですが、アダプタが組み込まれるまではフェイルクローズで拒否されます

## 公開／管理リスナー分離

公開プロキシを `:80` ／ `:443` で公開しつつ、埋め込みの管理 UI／API を別の高位ポートに分離したい場合は、`admin.listen_addr` を設定します。

サンプル:

- [config.split-listener.example.json](config.split-listener.example.json)

典型例:

```json
{
  "server": {
    "listen_addr": ":443",
    "tls": {
      "enabled": true,
      "redirect_http": true,
      "http_redirect_addr": ":80"
    }
  },
  "admin": {
    "listen_addr": ":9091",
    "external_mode": "deny_external"
  }
}
```

オペレーターコントラクト:

- `server.listen_addr` は引き続き公開リスナー
- `admin.listen_addr` を設定すると、管理 UI／API／認証は公開リスナーから分離されます
- `admin.external_mode` と `admin.trusted_cidrs` は、管理リスナー上でも引き続き機能します
- 組み込み TLS ／ HTTP リダイレクト ／ HTTP/3 は、現バージョンでは公開リスナー専用です
- `admin.listen_addr` は `server.listen_addr` および `server.tls.http_redirect_addr` と衝突できません

## オプションの PHP-FPM ランタイムバンドル

バイナリ配備先で `/options` と `/runtime-apps` を使いたい場合は、ランタイムバンドルをビルドして配置します。

標準レイアウト `/opt/tukuyomi` を使用する場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85
```

別の配備先にステージングする場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85 DEST=/srv/tukuyomi
```

`make install PREFIX="$HOME/tukuyomi"` などでログインユーザーのホーム配下にインストールした場合は、コピー先にも同じ配備先を指定します。この場合は通常 `sudo` は不要です。

```bash
make php-fpm-build RUNTIME=php85
make php-fpm-copy RUNTIME=php85 DEST="$HOME/tukuyomi"
```

補足:

- `php-fpm-copy` は `data/php-fpm/binaries/<runtime_id>/` をバイナリ配備ツリーへ同期します。PHP-FPM JSON マニフェストを削除する前に、`make db-import` でインベントリ／モジュールメタデータをインポートしてください
- 配置後は、Options の Runtime Inventory で Refresh するか、必要に応じて `tukuyomi` を再起動してください
- 不要になったステージング済みランタイムバンドルは、`sudo make php-fpm-prune RUNTIME=php85` で削除できます。DB の Runtime App 参照と実行中の pid を確認してから、`binaries/<runtime_id>` と `runtime/<runtime_id>` を削除します
- `data/php-fpm/runtime/` はコピー対象ではなく、`tukuyomi` 起動後に Runtime App 定義から生成されます
- Docker が必要なのは `php-fpm-build` のビルド時のみです。バンドル配置後の `tukuyomi` 実行時には Docker は不要です
- PHP ／ベースイメージライブラリ ／ PECL 拡張のセキュリティ更新は、バンドルを再ビルドしたうえで再配置する必要があります

## env ファイル

`/etc/tukuyomi/tukuyomi.env` のような env ファイルを使用します。

テンプレート:

- [tukuyomi.env.example](tukuyomi.env.example)

主に見直す値:

- `WAF_CONFIG_FILE`
- `WAF_PROXY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_BLOB_DIR`

必要な場合のみ使用するセキュリティ監査鍵のオーバーライド:

- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY`
- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID`
- `WAF_SECURITY_AUDIT_HMAC_KEY`
- `WAF_SECURITY_AUDIT_HMAC_KEY_ID`

`persistent_storage.backend=s3` の場合のみ必要となる S3 認証情報:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_REGION` ／ `AWS_DEFAULT_REGION`

## 過負荷チューニング

過負荷制御は DB `app_config` の `server` 配下で調整します。

- `max_concurrent_requests` はプロセス全体のガードです
- `max_concurrent_proxy_requests` はデータプレーンのガードです
- キュー設定は、対応する `max_concurrent_*` が `0` より大きい場合のみ有効になります
- `max_queued_proxy_requests` と `queued_proxy_request_timeout_ms` を使うと、プロキシ側のバーストを無制限の待ちにせず短時間で吸収できます
- `max_queued_requests` の既定値は `0` です。管理／API リクエストを待たせる意図がない限り、`0` か十分小さな値に保ってください
- プロキシが飽和している間も管理／API のヘッドルームを残したい場合は、`max_concurrent_requests` を `max_concurrent_proxy_requests` より大きく設定してください
- `/tukuyomi-api/status` の `server_overload_global` ／ `server_overload_proxy` と、`/tukuyomi-api/metrics` の `tukuyomi_overload_*` を監視してください

## シークレットの取り扱い

- `admin.session_secret` は管理対象のアプリ設定に保持し、ブラウザへ露出しないでください
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` ／ `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` は、管理ユーザーテーブルが空の状態での初回オーナーブートストラップにのみ使用してください
- ブラウザ操作するオペレーターはユーザー名／パスワードでサインインし、同一オリジンの DB ベースセッションクッキーを受け取ります
- CLI ／自動化処理では、共有の管理 API キーではなくユーザー単位の個人アクセストークンを使用してください
- `tukuyomi` の既定方針は `admin.external_mode=api_only_external` です。リモート管理 API が不要であれば `deny_external` にしてください
- 非ループバックリスナー上で `admin.external_mode=full_external` を使う場合は、起動時の警告だけに頼らず、フロント側で許可リスト／認証を追加してください
- `admin.trusted_cidrs` を公開／包括的なネットワークまで広げた場合、埋め込みの管理 UI／API はその信頼ソースに対しても再公開され、起動時には警告が出るのみです
- `security_audit.key_source=env` を使用する場合に限り、暗号鍵と HMAC 鍵を env ファイル側に置いてください

## systemd

サンプルユニット:

- [tukuyomi.service.example](tukuyomi.service.example)
- [tukuyomi-center.service.example](tukuyomi-center.service.example)
- [tukuyomi.socket.example](tukuyomi.socket.example)
- [tukuyomi-admin.socket.example](tukuyomi-admin.socket.example)
- [tukuyomi-redirect.socket.example](tukuyomi-redirect.socket.example)
- [tukuyomi-http3.socket.example](tukuyomi-http3.socket.example)
- [tukuyomi-scheduled-tasks.service.example](tukuyomi-scheduled-tasks.service.example)
- [tukuyomi-scheduled-tasks.timer.example](tukuyomi-scheduled-tasks.timer.example)
- [tukuyomi.env.example](tukuyomi.env.example)
- [tukuyomi-center.env.example](tukuyomi-center.env.example)

Gateway 用のサンプルユニットは、`User=tukuyomi` のまま `AmbientCapabilities=CAP_NET_BIND_SERVICE` を付与し、`:80` ／ `:443` のような低位ポートのバインドを root 常駐なしで行う前提です。
Center 用のユニットは `tukuyomi center` を起動し、既定では低位ポートのバインドケーパビリティを必要としません。
無停止のバイナリ入れ替えが必要な場合は、systemd のソケットアクティベーションを推奨します。
ソケットユニットが公開／管理／リダイレクト／HTTP/3 リスナーを保持するため、サービスプロセスのシャットダウン／再起動とリスナーバインドのレースを切り離せます。

登録例:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi.env.example /etc/tukuyomi/tukuyomi.env
sudo install -m 644 docs/build/tukuyomi.service.example /etc/systemd/system/tukuyomi.service
sudo install -m 644 docs/build/tukuyomi-scheduled-tasks.service.example /etc/systemd/system/tukuyomi-scheduled-tasks.service
sudo install -m 644 docs/build/tukuyomi-scheduled-tasks.timer.example /etc/systemd/system/tukuyomi-scheduled-tasks.timer
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi
sudo systemctl enable --now tukuyomi-scheduled-tasks.timer
sudo systemctl status tukuyomi
```

Center の登録例:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi-center.env.example /etc/tukuyomi/tukuyomi-center.env
sudo install -m 644 docs/build/tukuyomi-center.service.example /etc/systemd/system/tukuyomi-center.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi-center
sudo systemctl status tukuyomi-center
```

初回起動後は、Center `Settings` から単体 listen address、API/UI base path、
manual TLS の証明書／鍵設定を永続化できます。listener と TLS の変更は
`tukuyomi-center` の再起動後に反映されます。

ソケットアクティベーションの登録例:

```bash
sudo install -m 644 docs/build/tukuyomi.socket.example /etc/systemd/system/tukuyomi.socket
sudo install -m 644 docs/build/tukuyomi-admin.socket.example /etc/systemd/system/tukuyomi-admin.socket
sudo install -m 644 docs/build/tukuyomi-redirect.socket.example /etc/systemd/system/tukuyomi-redirect.socket
sudo install -m 644 docs/build/tukuyomi-http3.socket.example /etc/systemd/system/tukuyomi-http3.socket
sudo mkdir -p /etc/systemd/system/tukuyomi.service.d
sudo install -m 644 docs/build/tukuyomi.service.socket-activation.conf.example /etc/systemd/system/tukuyomi.service.d/socket-activation.conf
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi.socket
sudo systemctl enable --now tukuyomi.service
```

有効化するソケットユニットは、実効値の DB `app_config` と一致するものだけにしてください。
`ListenStream` ／ `ListenDatagram` は、`server.listen_addr`、`admin.listen_addr`、`server.tls.http_redirect_addr`、HTTP/3 UDP ポートと一致している必要があります。
プロセスは継承したソケットアドレスを検証し、不一致の場合はフェイルクローズします。

admin、redirect、HTTP/3 のソケットユニットを有効化する場合は、サービスのドロップインで対応する `Sockets=` 行のコメントアウトを外してください。これにより、`systemctl restart tukuyomi.service` の際にも同じ継承ディスクリプタを使用し、直接バインドへ戻ることを防ぎます。

無停止入れ替え:

```bash
sudo install -m 755 build/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo systemctl restart tukuyomi.service
```

ソケットアクティベーションが有効な場合、systemd が待ち受けソケットを保持し、旧プロセスは受け付け済みの HTTP リクエストをドレインしながら、新プロセスが同じディスクリプタで起動します。
`SIGTERM`、`SIGINT`、`SIGHUP` のいずれもグレースフルシャットダウンを開始します。
Upgrade ／ WebSocket のような長期接続もトラッキングし、`server.graceful_shutdown_timeout_sec` まで待機したうえで、タイムアウト後に強制クローズします。
HTTP/3 UDP ソケットのハンドオフには対応しますが、既存の QUIC 接続はプロセス入れ替えをまたいで維持されません。

## 補足

- サンプルユニットは `WorkingDirectory=/opt/tukuyomi` を使用するため、相対パスの `conf/`、`audit/`、`data/tmp/` は配備ルート内に収まります
- `server.graceful_shutdown_timeout_sec` の既定値は `30` です。デプロイ中も WebSocket を長く維持する運用であれば、値を引き上げてください
- スケジュールタスク用サービスも同じ作業ディレクトリと env ファイルを使用するため、`run-scheduled-tasks` から本体サービスと同じ `conf/` ／ `data/scheduled-tasks/` を参照できます
- サンプルユニットは `CAP_NET_BIND_SERVICE` を付与しているため、`server.listen_addr=:443` や `server.tls.http_redirect_addr=:80` の直接バインドに対応します
- リスナー分離配備では `admin.listen_addr=:9091` のような高位ポートを使うのが一般的なため、管理リスナー用に追加のケーパビリティは不要です
- `admin.listen_addr` はあくまでポート分離のみで、到達可否は引き続き `admin.external_mode` と `admin.trusted_cidrs` で制御します
- 現バージョンのリスナー分離では、`admin.listen_addr` 側に組み込み TLS はありません。信頼できるプライベートネットワーク、またはフロントプロキシでの TLS 終端を前提にしてください
- このケーパビリティは低位ポートのバインド用に限られます。`php-fpm` を `www-data` など `tukuyomi` 以外の UID／GID へ切り替える場合は、引き続き root 起動が必要です
- `tukuyomi` を直接公開し、組み込み HTTP/3 を有効にする場合は、リスナーポートの TCP／UDP を両方開放してください
- 展開済みのリリースバンドルでは、`testenv/release-binary/` が最短のスモーク導線です
- ロールアウト前にこのステージングランタイム導線をローカル検証する場合は、`make binary-deployment-smoke` を使用してください
