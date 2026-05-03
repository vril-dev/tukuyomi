# 第3章　バイナリ配備（systemd）

本章では、Linux ホスト上で tukuyomi を **single binary + systemd 管理** で動かす
配備手順を扱います。想定環境はオンプレ Linux サーバ、VPS、各種クラウド VM
（EC2 / GCE / Azure VM など）です。コンテナ配備は次の第4章で扱います。

第2章の preview と違い、本章で扱うのは **本番運用に耐える形での配備** です。
service ユーザの作成、`/opt/tukuyomi` 以下の実行レイアウト、systemd ユニット、
socket activation、PHP-FPM bundle、env file での secret 受け渡し、overload
backpressure のチューニングまで、ひととおり押さえます。

## 3.1　配備の全体像

systemd 配備は、大きく次の流れで進みます。

1. ソースから tukuyomi バイナリを build する
2. `make install TARGET=linux-systemd` で、build 〜 systemd ユニット配置までを
   一括実行する
3. 必要に応じて split listener、PHP-FPM bundle、socket activation を追加する
4. env file と DB `app_config` を、本番値で上書きする
5. service を起動・有効化する

`make install` を使えば 1 〜 5 の主要部分はほぼ自動で進みます。本章ではまず
`make install` の挙動を理解し、その後で「`make install` で何が決まり、何を
あとから手で調整するか」を 1 つずつ確認していきます。

## 3.2　Build

まず、build host または作業端末で tukuyomi バイナリを build します。

```bash
make setup
make build
```

生成物は `bin/tukuyomi` です。Gateway / Center の管理 UI はバイナリに埋め込み
build されます。

UI をすでに更新済みで、Go バイナリだけ作り直したい場合は次のコマンドを使います。

```bash
make go-build
```

再現性のある release artifact を作るときは、バージョンを明示します。

```bash
make release-linux-all VERSION=v0.8.0
```

## 3.3　One-shot install: `make install TARGET=linux-systemd`

Linux ホストへ直接インストールする場合は、次の 1 行で **build → runtime tree
作成 → DB migrate → WAF/CRS asset import → 初回 DB seed → systemd ユニット
配置** までが一括で実行されます。

```bash
make install TARGET=linux-systemd
```

`INSTALL_ROLE` を省略した場合、role は `gateway` です。Center を control plane
ホストに入れるときは、明示的に指定します。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center
```

Center を同じホスト上の Gateway security front 経由で公開したい場合は、
protected Center role を使います。

```bash
make install TARGET=linux-systemd INSTALL_ROLE=center-protected
```

主な override は次のように渡します。

```bash
make install TARGET=linux-systemd \
  INSTALL_ROLE=gateway \
  PREFIX=/opt/tukuyomi \
  INSTALL_ENABLE_SCHEDULED_TASKS=0 \
  INSTALL_DB_SEED=auto
```

それぞれの挙動を順に確認していきます。

### 3.3.1　PREFIX と runtime user

- `PREFIX` の既定は `/opt/tukuyomi` です。
- `PREFIX` がインストール実行ユーザの home 配下にある場合、`INSTALL_CREATE_USER=auto`
  はそのユーザを runtime user として使い、`useradd` を実行しません。
- home 配下に置いた runtime tree は、その login user / primary group が所有者に
  なります。
- `/opt/tukuyomi` のような system path にインストールする場合、既定では
  `tukuyomi` という system user / group を作成（または再利用）します。
- system path に service account 運用で配置すると、deployment root と `bin/`、
  `scripts/`、`conf/` は **root 管理**、`db/`、`audit/`、`cache/`、`data/` は
  **runtime user 書き込み可** という権限分離になります。

build そのものは通常の user で実行できます。`sudo` が必要になるのは、host
install のうち権限を要する操作（system user 作成、`/opt/tukuyomi` への書き込み、
systemd ユニット配置）だけです。

### 3.3.2　role ごとの挙動

`INSTALL_ROLE` で、ホストに入る形が変わります。

| 対象 | gateway | center | center-protected |
|---|---|---|---|
| service unit | `tukuyomi.service` | `tukuyomi-center.service` | 両方 |
| env file | `tukuyomi.env` | `tukuyomi-center.env` | 両方 |
| config | `conf/config.json` | `conf/config.center.json` | 両方 |
| WAF/CRS import | 実行する | 実行しない | Gateway front 用に実行する |
| 初回 gateway DB seed | 実行する | 実行しない | Center route 入りで実行する |
| scheduled-task timer | 実行する | 実行しない | 実行しない |
| DB migration | 実行する | 実行する | 両方の DB に実行する |

Center 側は WAF/CRS import や scheduled tasks を持たない点がポイントです。
Center は Gateway を承認・管理する control plane なので、edge データプレーンの
資産は持ちません。

`center-protected` は、Center を同一ホストの Gateway front の背後に置くための
パッケージ済み role です。Center は loopback listener のまま動かし、Gateway
front の初期 seed には `/center-ui` と `/center-api` を
`http://127.0.0.1:9092` へ転送する path-scoped route を入れます。導入時には
Gateway の IoT / Edge device authentication も有効化し、同じホスト上で Center
承認済みの device として bootstrap します。Gateway の private key は Gateway DB
にのみ残り、Center には public key identity だけが入ります。既存 DB に異なる
device trust がある場合は、黙って置き換えず bootstrap を失敗させます。

Center process 側の API path を非公開名にしたい場合は
`INSTALL_CENTER_API_BASE_PATH` に内部 path を指定し、
`INSTALL_CENTER_GATEWAY_API_BASE_PATH` は Gateway で公開する path のままにします。
Gateway route は公開 path で match し、upstream へ渡すときに Center 側 path へ
rewrite します。

tukuyomi Gateway を前段に置かず Center を直接露出する場合は、送信元 IP allowlist
を明示的に設定してください。Center UI client と Gateway/device API は既定では
任意の送信元を許可します。管理 API は既定で loopback と private/local CIDR を
許可します。この制御は `X-Forwarded-For` ではなく socket の送信元アドレスで判定します。

### 3.3.3　DB seed の挙動

- `INSTALL_DB_SEED=auto`（既定）は、SQLite DB がまだ存在しない初回だけ
  `db-import` を実行します。
- 初回 DB seed では、`primary` という名前の default upstream が作成されます。
  proxy に traffic を流す前に、これを実際の backend endpoint に向けて調整して
  ください。
- 既存 DB がある状態で再実行した場合は、DB migrate と WAF/CRS asset refresh
  だけを行います。
- MySQL / PostgreSQL の空 DB を初期投入する場合は、`INSTALL_DB_SEED=always` を
  明示的に指定してください。

### 3.3.4　scheduled tasks の有効化

scheduled-task timer は既定で有効化されます。このホストで scheduled tasks を
実行しない（たとえば replicated frontend で別の singleton scheduler ホスト側で
だけ走らせる）場合は、次のように指定します。

```bash
make install TARGET=linux-systemd INSTALL_ENABLE_SCHEDULED_TASKS=0
```

scheduled tasks の配備 pattern については第12章で改めて扱います。

### 3.3.5　secret 入りファイルの権限

- role の config file は root 所有・`0640` で配置されます。service group には
  読み取りだけを渡します。
- env file は secret を含める前提で、root 所有・`0640` のまま保持します。
- 既存の env file / config file がある場合、`make install` は **既定では上書き
  しません**。

### 3.3.6　package staging / smoke 用途

CI のパッケージ staging や smoke 用に、systemd 連携を切ったまま staged tree を
作りたいことがあります。その場合は次のように指定します。

```bash
DESTDIR=<tmp> INSTALL_ENABLE_SYSTEMD=0 make install TARGET=linux-systemd
```

### 3.3.7　login user で動かす

system user を作らず、自分の login user で `$HOME/tukuyomi` 配下に動かしたい場合
の例です。

```bash
make install TARGET=linux-systemd \
  PREFIX="$HOME/tukuyomi" \
  INSTALL_USER="$(id -un)" \
  INSTALL_GROUP="$(id -gn)" \
  INSTALL_CREATE_USER=0
```

なお、ECS / Kubernetes / Azure Container Apps 向けは、host install ではなく
`make deploy-render` を使います。詳しくは次章「コンテナ配備」を参照して
ください。

## 3.4　実行レイアウト

`make install` は、`PREFIX` 配下に次のような runtime tree を作ります。

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/db/
/opt/tukuyomi/audit/
/opt/tukuyomi/cache/
/opt/tukuyomi/data/persistent/
/opt/tukuyomi/data/tmp/
```

bundle 同梱の bootstrap / example は次のとおりです。

- `conf/config.json`
- `conf/crs-disabled.conf`
- `scripts/update_country_db.sh`

初回 DB import 前に、必要に応じて operator が配置する seed / import file は
次のとおりです。

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
- `make crs-install` で `data/tmp/...` 以下に stage する WAF/CRS の import material

ここで強く意識しておきたいのが、第1章でも触れた **「DB が runtime authority、
JSON は seed / import / export 素材」** というルールです。これらの JSON は
**初期投入と import / export の I/O 用** であり、対応する DB row が入った
あとは、runtime は file の存在を起動条件にしません。**import 後の本番起動で
runtime が必要とするのは、`conf/config.json` と DB row だけ** です。

### 3.4.1　PHP-FPM 関連の初期物

PHP-FPM Runtime Apps を使う場合、初回 DB import 前に次を配置します。

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

import 後、bundled PHP-FPM を使う場合、executable bundle 自体は引き続き必要
ですが、`inventory.json` / `vhosts.json` / `runtime.json` / `modules.json` は
runtime authority ではなくなります（DB が正本になります）。

### 3.4.2　Scheduled tasks 用ディレクトリ

scheduled-task の実行状態は次に置かれます。

- `data/scheduled-tasks/`

GeoIP country DB の managed 自動更新を使う場合は、追加で次を配置します。

- `scripts/update_country_db.sh`

### 3.4.3　手動配置の例

`make install` を使わずに手で配置する場合、たとえば次のようになります。

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

### 3.4.4　配置時の注意点

- `data/conf/*.bak` を本番に持ち込まないでください。
- `config.json` は **DB 接続 bootstrap** です。release sample は `storage` block
  だけを保持します。
- `conf/proxy.json` は DB `proxy_rules` の任意 seed / import / export material
  です。
- `conf/sites.json` は DB `sites` の任意 seed / import / export material です。
- public release bundle は、`conf/config.json` と空 DB 向け runtime seed の
  `seeds/conf/config-bundle.json` を同梱します。
- `conf/proxy.json` や policy JSON など configured file が無いときは、
  `make db-import` は `seeds/conf/config-bundle.json` を読み、それも無ければ built-in 互換
  default に fallback します。
- 既定の base WAF rule seed は、`make crs-install` が
  `seeds/waf/rules/tukuyomi.conf` から一時 stage して DB へ import します。
- CRS file は DB `waf_rule_assets` 向けの一時 import material です。
  `make crs-install` が `data/tmp` で staging と cleanup を行います。
- `sites.json` / `scheduled-tasks.json` / `upstream-runtime.json`、policy JSON、
  cache-rules JSON、WAF bypass JSON、PHP-FPM JSON manifest は、DB bootstrap
  以後はすべて DB seed / export artifact です。
- 本番では、`storage.db_driver` / `storage.db_path` / `storage.db_dsn` 用に
  `config.json` を **secret manager または config management から render / mount**
  してください。
- 初回起動前に `make db-migrate` → `make crs-install` の順で WAF rule asset を
  install / import し、その後で残りの seed material 用に `make db-import` を
  実行します。`db-import` は WAF rule asset を再 import しません。
- 埋め込み `Settings` 画面は DB `app_config` を編集します。listener / runtime /
  storage policy / observability 系の変更後は、service を restart してください。
- public release bundle には `Options → GeoIP Update → Update now` 用の
  companion `bin/geoipupdate` が同梱されます。`GEOIPUPDATE_BIN` で bundled
  updater path を override できます。
- managed country refresh の official wrapper は `./scripts/update_country_db.sh`
  です。
- managed GeoIP country DB、`GeoIP.conf`、update status はすべて DB-backed
  です。`data/geoip` fallback directory は配備しません。
- managed bypass override rule は DB `override_rules` に保存します。
  `conf/rules` fallback directory は配備しません。
- WAF / access event は DB `waf_events` へ直接書き込みます。`paths.log_file` は
  古い `waf-events.ndjson` を明示的に取り込むときだけの legacy import source
  です。
- `extra_rule` の値は DB-managed override rule への logical compatibility
  reference として残ります。

## 3.5　永続 byte storage

DB ではなく file / object として保持する runtime artifact は、`persistent_storage`
block で管理します。現在の主用途は **site-managed ACME の account key、challenge
token、証明書 cache** です。

既定は local backend です。

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

- single-node のオンプレ / VPS では、`/opt/tukuyomi/data/persistent` をバック
  アップ対象にしてください。
- scale-out や node replacement を前提にする場合は、local backend ではなく
  **S3 backend か共有 mount** を使います。
- S3 backend では、bucket / region / endpoint / prefix などの **非秘密情報
  だけ** を DB `app_config` に保存します。
- `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN` は env
  または platform の secret injection で渡します。
- Azure Blob Storage / Google Cloud Storage は、provider adapter が入るまで
  fail-closed のままで、local への暗黙 fallback は行いません。

site-managed ACME は、`Sites` 画面で site ごとに `tls.mode=acme` を選びます。
`production` / `staging` は Let's Encrypt の本番 CA / staging CA の選択で、
account email は任意です。HTTP-01 challenge を使うため、
`server.tls.redirect_http=true` と `server.tls.http_redirect_addr=:80`、
または同等の port 80 forwarding を用意してください。

proxy engine 設定は、現在 DB `app_config` 上で `tukuyomi_proxy` 固定です。

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は built-in engine で、parser / transport / routing / health
  / retry / TLS / cache / route response headers / 1xx informational responses
  / trailers / streaming flush behavior / native Upgrade / WebSocket tunnel /
  response-sanitize pipeline を維持したまま、Tukuyomi 独自の response bridge を
  使います。
- legacy `net_http` bridge は削除済みです。`tukuyomi_proxy` 以外の engine 値は
  config validation で拒否されます。
- HTTP/1.1 と明示的な upstream HTTP/2 mode は、Tukuyomi native upstream
  transport を使います。HTTPS `force_attempt` は、ALPN で `h2` が選ばれない
  場合だけ native HTTP/1.1 へ fallback します。
- Upgrade / WebSocket handshake request は `tukuyomi_proxy` 内で処理します。
  `101 Switching Protocols` 後の WebSocket frame payload は tunnel data です。
- 本番展開前には、実 workload で benchmark してください（第17章）。
- `waf.engine.mode` は現在、`coraza` engine だけを受け付けます。`mod_security`
  は将来 adapter 用の既知 mode ですが、adapter が compile されるまでは
  fail-closed で拒否されます。

## 3.6　public/admin listener 分離

public proxy を `:80` / `:443` に置きつつ、埋め込み admin UI / API を別の high
port に分けたい場合は、`admin.listen_addr` を設定します。typical は次のような
構成です。

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

サンプル全体は `docs/build/config.split-listener.example.json` を参照してください。

operator contract は次のとおりです。

- `server.listen_addr` は public listener のままです。
- `admin.listen_addr` を入れると、admin UI / API / auth は public listener から
  外れます。
- `admin.external_mode` と `admin.trusted_cidrs` は admin listener 上でも継続
  して効きます。
- built-in TLS / HTTP redirect / HTTP/3 は、この slice では public listener
  専用です。
- `admin.listen_addr` は `server.listen_addr` および
  `server.tls.http_redirect_addr` と衝突できません。

## 3.7　Optional PHP-FPM Runtime Bundle

binary 配備先で `/options` と `/runtime-apps` を使いたい場合は、PHP-FPM の
runtime bundle を build して配置します。

標準レイアウト `/opt/tukuyomi` の場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85
```

別の配備先に stage する場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85 DEST=/srv/tukuyomi
```

`make install PREFIX="$HOME/tukuyomi"` などで login user の home 配下に入れた
場合は、copy 側も同じ配備先を指定します。この場合は通常 `sudo` は不要です。

```bash
make php-fpm-build RUNTIME=php85
make php-fpm-copy RUNTIME=php85 DEST="$HOME/tukuyomi"
```

PHP-FPM bundle を扱うときの補足は次のとおりです。

- `php-fpm-copy` は `data/php-fpm/binaries/<runtime_id>/` を、binary 配備ツリー
  へ同期します。PHP-FPM JSON manifest を削除する前に、`make db-import` で
  inventory / module metadata を import してください。
- 配置後は Options の Runtime Inventory で Refresh するか、必要に応じて
  `tukuyomi` を restart してください。
- 不要になった staged runtime bundle は、`sudo make php-fpm-prune RUNTIME=php85`
  で削除できます。DB の Runtime App 参照と実行中 pid を確認したうえで、
  `binaries/<runtime_id>` と `runtime/<runtime_id>` を消してください。
- `data/php-fpm/runtime/` はコピー対象ではなく、`tukuyomi` 起動後に Runtime
  App 定義から生成されます。
- Docker が必要なのは `php-fpm-build` の build 時だけです。bundle 配置後の
  `tukuyomi` 実行時には Docker は不要です。
- PHP / base image library / PECL extension の security update は、bundle を
  rebuild して再配置する必要があります。

## 3.8　Environment File

`/etc/tukuyomi/tukuyomi.env` のような env file を使います。テンプレートは
`docs/build/tukuyomi.env.example` です。

主に見直す値は次のとおりです。

- `WAF_CONFIG_FILE`
- `WAF_PROXY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_BLOB_DIR`

必要な場合だけ使う security-audit key の override:

- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY`
- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID`
- `WAF_SECURITY_AUDIT_HMAC_KEY`
- `WAF_SECURITY_AUDIT_HMAC_KEY_ID`

`persistent_storage.backend=s3` を使う場合だけ必要な S3 credential:

- `AWS_ACCESS_KEY_ID`
- `AWS_SECRET_ACCESS_KEY`
- `AWS_SESSION_TOKEN`
- `AWS_REGION` / `AWS_DEFAULT_REGION`

## 3.9　Overload Tuning

overload backpressure は DB `app_config` の `server` block で調整します。

- `max_concurrent_requests` は process-wide guard です。
- `max_concurrent_proxy_requests` は data-plane guard です。
- queue 設定は、対応する `max_concurrent_*` が `0` より大きい場合のみ有効です。
- `max_queued_proxy_requests` と `queued_proxy_request_timeout_ms` を使うと、
  proxy burst を unbounded wait にせず、短く吸収できます。
- `max_queued_requests` の既定値は `0` です。admin / API request を待たせたい
  意図がない限り、`0` か very small な値に保ってください。
- proxy saturation 中も admin / API の headroom を残したい場合は、
  `max_concurrent_requests` を `max_concurrent_proxy_requests` より大きく
  しておきます。
- 監視は `/tukuyomi-api/status` の `server_overload_global` /
  `server_overload_proxy` と、`/tukuyomi-api/metrics` の `tukuyomi_overload_*`
  を使います。

## 3.10　Secret Handling

tukuyomi の secret 取り扱いに関する原則は次のとおりです。

- `admin.session_secret` は managed app config に置き、ブラウザに露出させない
  ように扱います。
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` / `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` は、
  admin user table が空の **初回 owner bootstrap だけ** に使います。
- ブラウザ operator は username / password で sign in し、same-origin の
  DB-backed session cookie を受け取ります。
- CLI / 自動化は、shared admin API key ではなく **user ごとの personal access
  token** を使います。
- `tukuyomi` の既定 posture は `admin.external_mode=api_only_external` です。
  remote admin API が不要なら `deny_external` に絞ってください。
- non-loopback listener で `admin.external_mode=full_external` を使う場合は、
  起動時 warning だけに頼らず、front-side の allowlist / auth を必ず追加して
  ください。
- `admin.trusted_cidrs` を public / catch-all network まで広げた場合も、
  埋め込み管理 UI / API は trusted source へ再露出されます。起動時は warning
  のみで止まらない、という点に注意してください。
- `security_audit.key_source=env` を使うときだけ、暗号鍵と HMAC 鍵を env file
  に置きます。

## 3.11　systemd ユニット

systemd 配備で使う sample ユニットは、`docs/build/` 以下に揃っています。

- `tukuyomi.service.example`
- `tukuyomi-center.service.example`
- `tukuyomi.socket.example`
- `tukuyomi-admin.socket.example`
- `tukuyomi-redirect.socket.example`
- `tukuyomi-http3.socket.example`
- `tukuyomi-scheduled-tasks.service.example`
- `tukuyomi-scheduled-tasks.timer.example`
- `tukuyomi.env.example`
- `tukuyomi-center.env.example`

gateway sample ユニットは、`User=tukuyomi` のまま `AmbientCapabilities=CAP_NET_BIND_SERVICE`
を付け、`:80` / `:443` のような low port bind を **root 常駐なし** で行う前提
です。Center ユニットは `tukuyomi center` を起動し、既定では low port bind
capability を必要としません。

Center 単体 listener の初期値は `tukuyomi-center.env` に置き、初回起動後は
Center の `Settings` から編集できます。対象は Center listen address、API/UI
base path、manual TLS の証明書／鍵 path です。listener と TLS の変更は
`tukuyomi-center` の再起動後に反映されます。

graceful binary replacement が必要な場合は、systemd の **socket activation**
を推奨します。socket unit が public / admin / redirect / HTTP3 listener を
保持するため、service process の shutdown / restart と、listener bind race を
分離できます。

### 3.11.1　gateway の登録例

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

### 3.11.2　Center の登録例

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 640 docs/build/tukuyomi-center.env.example /etc/tukuyomi/tukuyomi-center.env
sudo install -m 644 docs/build/tukuyomi-center.service.example /etc/systemd/system/tukuyomi-center.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi-center
sudo systemctl status tukuyomi-center
```

### 3.11.3　socket activation の登録例

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

socket activation を有効化するときの注意点は次のとおりです。

- 有効化する socket unit は、**effective DB `app_config` と一致するもの
  だけ** にしてください。
- `ListenStream` / `ListenDatagram` は `server.listen_addr` /
  `admin.listen_addr` / `server.tls.http_redirect_addr` / HTTP/3 UDP port と
  一致している必要があります。
- process は inherited socket address を検証し、不一致なら fail-closed します。
- admin / redirect / HTTP/3 の socket unit を有効化する場合、service drop-in の
  対応する `Sockets=` 行を uncomment してください。これにより
  `systemctl restart tukuyomi.service` でも、同じ inherited descriptor を使い、
  direct bind に戻らないようにできます。

### 3.11.4　Graceful replacement

```bash
sudo install -m 755 build/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo systemctl restart tukuyomi.service
```

socket activation 有効時は、systemd が listening socket を保持し、旧 process は
accepted HTTP request を drain しながら、新 process が同じ descriptor で起動
します。`SIGTERM` / `SIGINT` / `SIGHUP` はすべて graceful shutdown を起動します。
Upgrade / WebSocket のような long-lived connection も tracking して、
`server.graceful_shutdown_timeout_sec` まで待ち、timeout 後に force close
します。HTTP/3 UDP socket handoff には対応しますが、既存 QUIC connection は
process replacement をまたいでは維持されません。

## 3.12　補足メモ

- sample ユニットは `WorkingDirectory=/opt/tukuyomi` を使うため、相対 `conf/`
  / `audit/` / `data/tmp/` は deployment root 内に収まります。
- `server.graceful_shutdown_timeout_sec` の既定値は `30` です。deploy 中も
  WebSocket を長時間維持する運用なら、値を引き上げてください。
- scheduled-task service も同じ working directory と env file を使うため、
  `run-scheduled-tasks` から main service と同じ `conf/` / `data/scheduled-tasks/`
  を参照できます。
- sample ユニットは `CAP_NET_BIND_SERVICE` を付けるので、`server.listen_addr=:443`
  や `server.tls.http_redirect_addr=:80` の direct bind に対応します。
- split-listener deployment では、`admin.listen_addr=:9091` のような high port
  を使うのが通例なので、admin listener 用の追加 capability は不要です。
- `admin.listen_addr` は port 分離だけを行います。到達可否は引き続き
  `admin.external_mode` と `admin.trusted_cidrs` で制御してください。
- Gateway の split listener では、`admin.listen_addr` 側に built-in TLS
  はありません。trusted private network か、front proxy 側で TLS を terminate
  する前提で運用してください。Center 単体には Center `Settings` 側に
  manual TLS listener 設定があります。
- `CAP_NET_BIND_SERVICE` は **low port bind 用だけ** の capability です。
  `php-fpm` を `www-data` など `tukuyomi` 以外の UID/GID へ切り替えるには、
  引き続き root 起動が必要です。
- `tukuyomi` を直接公開し、built-in HTTP/3 を有効化する場合は、listener port の
  TCP / UDP を両方開けてください。
- 展開済みの release bundle では、`testenv/release-binary/` が最短の smoke 導線
  です。
- rollout 前にこの staged-runtime 導線をローカルで検証するなら、
  `make binary-deployment-smoke` を使います。

## 3.13　次章への橋渡し

ここまでで、Linux ホストへの systemd 配備の全体像、`make install` の挙動、
実行レイアウト、永続 byte storage、split listener、PHP-FPM bundle、env file、
overload tuning、secret 取り扱い、systemd unit の登録と socket activation を
ひととおり押さえました。

次章では、同じ tukuyomi をコンテナとして運用する場合の Tier 区分、
Tier ごとの推奨 topology、ECS / Kubernetes / Azure Container Apps の deploy
artifact、共有 writable path、config と secret の供給経路、を扱います。
