# 付録B　リリースノート

本付録には、本書の基準バージョンを含む直近リリースのリリースノート抜粋を、
書籍向けに整えて収録します。新しい順に **v1.3.0** → **v1.2.0** →
**v1.1.0** の順で並べています。以後の正式なリリースノートは、GitHub
Releases のリリースタグを一次情報としてください。

本書は **v1.3.0 を基準** に書いています。Remote SSH は v1.3.0 で運用者向けの章として追加しました。
Center / IoT・Edge enrollment が登場するのは v1.2.0 からです。v1.1.0 は、
その 1 つ前の重要なリリース（DB-backed runtime authority、admin 認証の刷新、
`make install` の整備）として併載しています。

---

# B 部1　v1.3.0 リリースノート

> 基準バージョン: v1.2.x

v1.3.0 では、Center 管理下の Gateway に **Remote SSH** を追加しました。
本書の **第17章** が扱う機能で、Gateway のインバウンド SSH ポートを公開せずに、
Center 経由で短時間の保守セッションを開けるようにします。

## B1.1　主な変更

- Center の選択中デバイスメニューに **Remote SSH Web Terminal** を追加しました。
- `tukuyomi remote-ssh` による **CLI handoff** は引き続き利用できます。
- Center は Remote SSH セッションの状態、接続方式、接続理由、TTL、時刻情報、
  Gateway 接続、運用者接続、終了理由、強制終了を記録します。
- Gateway は、Center が署名し、承認済みデバイスに割り当てた待機中セッションの場合だけ、
  組み込み SSH サーバーを動かします。
- Web Terminal セッションごとに、ブラウザー側のターミナル履歴行数を設定できます。
- 運用者は Center から待機中または接続中のセッションを強制終了できます。

## B1.2　運用上の注意

- Remote SSH は Center / Gateway の両方で既定では無効です。
- Remote SSH を使うには、Gateway が Center で approved（承認済み）状態になっている
  必要があります。
- Web Terminal のセッション取得は Gateway から Center へのステータスのポーリング間隔に依存します。
  ポーリング 1 回分程度の待ち時間は正常に起こりえます。
- TTL とアイドルタイムアウトは、ブラウザーが開いたままでもセッションを閉じます。
- ブラウザーのスクロールバックは表示履歴であり、監査記録ではありません。
- Gateway は実行ユーザーが設定されていない限り、root としてシェルを起動しません。

## B1.3　互換性と移行

- CLI / Web Terminal セッションを区別するため、DB migration で Remote SSH の operator mode を追加しました。
- Remote SSH を無効のままにしている既存 Gateway のプロキシトラフィックの挙動は
  変わりません。
- 緊急運用や自動化向けに、CLI 導線は引き続きサポートします。

---

# B 部2　v1.2.0 リリースノート

> 基準バージョン: v1.1.8

v1.2.0 では、**Tukuyomi Center**、**IoT / Edge enrollment**、**device approval
workflow** を追加しました。あわせて install role と frontend build の安全性も
整理しています。本書の **第16章** が前提にしている機能の本体は、このリリースで
入っています。

## B2.1　主な変更

- **同じ single binary に Center mode を追加** しました。host install 時に
  `INSTALL_ROLE` を選択することで、Gateway / Center を分けて導入できます。
- **Center UI を追加** しました。login、status、user account 管理、device
  enrollment approval を扱えます。
- **Gateway に IoT / Edge mode を追加** しました。有効化すると、local
  Gateway identity が Center で承認されるまでプロキシトラフィックは
  ロックされます。
- Center の **one-time enrollment token** を追加しました。Gateway は
  Ed25519 の device identity を生成し、署名付き enrollment request を
  Center へ送信します。
- Center の **registered device lifecycle** を追加しました。承認解除と、
  revoked device の archive に対応しています。
- **revoked された Gateway が新しい token で同じ device identity のまま
  再承認申請** できるようにしました。
- local 検証用に **`make center-preview-up`**、**`make gateway-preview-up`**、
  **`make fleet-preview-up`** を追加しました。
- frontend dependency lock を更新し、**npm audit findings を解消**しました。
  Gateway UI は page ごとに code split し、Vite の chunk-size warning も
  解消しています。

## B2.2　運用上の注意

- **IoT / Edge mode はデフォルト OFF** です。Web / VPS 環境では、
  この Gateway を edge device として Center 承認したい場合だけ有効にして
  ください。
- IoT / Edge mode では、device が **未承認の間 Gateway の public proxy
  path は traffic を拒否** します。local recovery 用の admin UI / API は
  引き続き利用できます。
- Center approval は **まだ push channel ではありません**。Gateway は UI
  操作または設定した polling interval で Center device state を refresh
  します。
- enrollment token は **one-time secret** です。Center は作成時だけ token
  を表示します。紛失した場合は、古い token を復元せず **新しい token を
  作成** してください。
- Gateway は生成した **device private key を local に保存** します。Center
  には **public key fingerprint と approval state** を保存します。
- Gateway / Center に表示する **public key fingerprint は、DER encoded
  Ed25519 public key の SHA-256 を lowercase hex** にした値です。
- local state が `pending` または `approved` の Gateway は、誤って
  replacement token を消費しないよう **enrollment request を拒否** します。
- Gateway が **再承認申請できる** のは、`revoked` / `archived` / `failed`
  / `product_changed` などの replacement state の場合だけです。
- enrollment token を revoke すると、その token で登録された device も
  revoke します。ただし、audit retention のため **archive 済み device は
  戻しません**。
- **Archive は revoked device を default の registered-device list から
  隠します**。audit trail の削除ではありません。
- `tukuyomi center` は **Gateway と別 process mode** ですが、binary は
  Gateway と同じ single binary です。

## B2.3　デプロイ

- **`make install TARGET=linux-systemd INSTALL_ROLE=gateway`** で Gateway を
  install します。
- **`make install TARGET=linux-systemd INSTALL_ROLE=center`** で Center を
  install します。
- `INSTALL_ROLE` の default は **既存互換のため `gateway`** です。
- installer は role に応じた **systemd unit と runtime environment file**
  を生成します。
- preview flow は **Gateway / Center / fleet に分かれました**。
  - `make gateway-preview-up`
  - `make center-preview-up`
  - `make fleet-preview-up`
- **`GATEWAY_PREVIEW_PERSIST=1`** を指定すると、Gateway preview の DB /
  config state を preview restart 間で保持します。
- **`CENTER_PREVIEW_PERSIST=1`** を指定すると、Center preview の DB state
  を preview restart 間で保持します。

## B2.4　Admin UI

- Gateway Options に **IoT / Edge mode**、**Center enrollment status**、
  **Center URL**、**enrollment token entry**、**Center status refresh** を
  追加しました。
- Gateway Options で IoT / Edge status refresh の **Center polling interval**
  を設定できます。
- Gateway は device approval state に応じて、プロキシトラフィックが **available
  / locked のどちらかを表示** します。
- **Center UI は Gateway admin UI と同じ visual style** に揃えました。
- **Center Status は device overview counts** に絞りました。
- **Center Device Approvals** で enrollment token、pending approval、
  registered device、revoked device、archived device を管理できます。
- **Center User** で username、email、password、personal access token を
  管理できます。
- **Gateway と Center のブラウザーセッションは分離** しました。同じブラウザーで
  両 UI に同時ログインできます。

## B2.5　Build / Development

- Gateway / Center UI build は **Node.js 24 LTS** と **`npm >=11`** を要求
  します。
- **`.nvmrc` は Node 24** を指すようにしました。
- CI はすでに Node 24 を使用しており、sample deployment Dockerfile も
  Node 24 で UI を build します。
- Gateway UI routes を **lazy load** し、大きな admin page が初期 JavaScript
  bundle を膨らませないようにしました。
- dependency lock 更新後、Gateway / Center UI の
  `npm audit --audit-level=moderate` は **0 findings** です。

## B2.6　ドキュメント

- Center token 作成、Gateway approval request、Center approval、status
  refresh、re-approval の **device enrollment operation docs** を追加しま
  した。
- root README に IoT / Edge enrollment と Center install flow を追記しま
  した。
- binary deployment docs に **`INSTALL_ROLE=gateway|center`** を追記しま
  した。
- **Center service / env deployment example** を追加しました。
- 古い product-family comparison pages を削除しました。**Tukuyomi は
  separate product name ではなく、Gateway / Center / Web / IoT capability
  を持つ 1 製品** として記載します。

## B2.7　互換性と移行

- **v1.2.0 の起動前に DB migration が必要** です。
- 新しい DB schema は **Center enrollment token、Gateway edge device
  identity、Center status cache、device revocation、device archive state**
  を追加します。
- `INSTALL_ROLE` の default は `gateway` なので、**既存 Gateway install
  command はそのまま Gateway install として動きます**。
- `edge.enabled=false` の間、**既存の non-IoT traffic behavior は変わり
  ません**。
- bundled config example には `edge.enabled` を明示し、default は **false**
  です。
- **Node 18 での UI build はサポート外** です。`.nvmrc` と package
  `engines` に従い Node 24 LTS を使ってください。

## B2.8　既知の制限

- Center の現時点の範囲は **device enrollment と approval** です。Gateway
  config push、log collection、Gateway binary upgrade management は **まだ
  実装していません**。
- Center state refresh は **polling base** です。Center から Gateway への
  即時 push はこの release では **未実装** です。
- device approval による proxy path protection は、**IoT / Edge mode が
  有効な場合だけ動作** します。

---

# B 部3　v1.1.0 リリースノート

> 基準バージョン: v1.0.1

v1.1.0 では、**実行時設定を DB 管理へ移行**し、デプロイ手順の安全性を
高め、**複数環境での運用に向けた土台** を整えました。本書を通じて
繰り返し触れてきた「DB が runtime authority、JSON は seed / import /
export」というルールが、このリリースで明確に確立しています。

## B3.1　主な変更

- **正規化済みの実行時設定は、DB を正として扱う** ようになりました。
  `config.json` は主に DB 接続など、起動に必要な最小設定を保持します。
- **WAF rule asset は DB-backed asset として管理** します。base rule asset
  と、operator が追加する asset の両方を扱えます。
- proxy path への影響を抑えるため、**WAF event の保存を非同期化** しました。
- Admin access は **static admin API key を廃止** し、**DB-backed admin
  user による認証**（Argon2id password hash、signed browser session、
  CSRF protection）に移行しました。
- **Sites でサイトごとの ACME TLS 設定** を持てるようになりました。
  production / staging の選択と、任意の account email を設定できます。
- **ACME cache material の永続化先として、local と S3 を利用** できます。
  Azure Blob / GCS は設定項目としては存在しますが、この build では adapter
  が未実装のため、選択すると validation error になります。
- 本番用シードデータは **`seeds/conf/config-bundle.json`** に配置しました。初回取り込み
  データを調整する場合は、Go コードではなく bundle domain を編集してください。
- Linux host install 用に **`make install TARGET=linux-systemd`** を追加
  しました。container platform 向けには **`make deploy-render`** で
  deployment artifact を生成できます。

## B3.2　運用上の注意

- policy / rule domain の **file-backed runtime fallback は active runtime
  path から外しました**。`data/conf/rules`、`data/rules`、`data/geoip` の
  復元に頼らず、DB import flow で restore または seed してください。
- Coraza が filesystem view を必要とする WAF rule material は、**`data/tmp`
  配下へ stage** します。
- `conf/config.json` は **最小構成を維持** してください。storage bootstrap
  設定は必要ですが、policy と runtime domain は DB に保存します。
- **ローカル環境での検証に限り**、`admin.allow_insecure_defaults` を明示
  してください。
- `TUKUYOMI_ADMIN_BOOTSTRAP_USERNAME` と
  `TUKUYOMI_ADMIN_BOOTSTRAP_PASSWORD` から **初期管理者アカウント** を
  作成します。管理者ユーザーがすでに存在する場合はスキップします。
- 初期 DB 取り込みデータを調整する場合は `seeds/conf/config-bundle.json` を編集してください。
  取り込み後は、正規化された DB 上のデータが実行時設定の正となります。
- `make ui-preview-up` は、Git 管理外のプレビュー専用設定
  `conf/config.ui-preview.json` を生成し、ランダムなセッションシークレット
  を設定します。Git 管理対象の起動用設定を弱めたり書き換えたりはしません。
- persistent storage の provider credential は、**environment または
  platform identity** から読みます。**JSON config には保存しません**。
- login user の home directory 配下へ install する場合、installer は既定で
  そのユーザを runtime user にし、`useradd` を skip します。
  `/opt/tukuyomi` などの system prefix では、引き続き `tukuyomi` system
  user を既定にします。
- **初回 install seed では、`primary` という default upstream が作成** され
  ます。proxy に traffic を流す前に、実際の backend endpoint へ変更して
  ください。

## B3.3　Admin UI

- Admin UI は **username / password でログイン** し、ブラウザ向けの **署名
  付きセッション Cookie** を発行します。
- **Rules / Rule Sets は、DB-backed asset と Coraza の責務に合わせて再構成**
  しました。
- Security navigation は、**Coraza 固有の設定と request control** を分け
  ました。
- **Logs は新しい順に表示** します。list の copy action は削除し、狭い画面
  では横 scroll で確認できるようにしました。
- Cache Rules の save / error feedback は、**対象 action の近くに表示**
  します。
- **Sites で、site-level automatic TLS 用の ACME 設定** を編集できます。
- **Settings で persistent storage 設定、admin セッション状態、operator の
  identity メタデータ** を管理できます。credential は保存しません。

## B3.4　デプロイ

- **`make install TARGET=linux-systemd`** は、build、runtime tree 作成、
  DB migration、WAF / CRS asset import、必要に応じた初回 DB seed、systemd
  unit 配置まで行います。
- **`make deploy-render`** は、container image、ECS、Kubernetes、Azure
  Container Apps 向けの deployment artifact を生成します。
- **`make ui-preview-up`** は、admin UI のビルド・同期、プレビュー用
  bootstrap config の生成、preview SQLite DB のリセット・シード、
  `coraza` とスケジュールタスクランナーの起動を行います。
- PHP-FPM runtime bundle は **`make php-fpm-build RUNTIME=<id>`** で build
  し、**`make php-fpm-copy`** で installed tree へ配置できます。
- runtime layout は、**persistent data / temporary material / cache /
  audit output / DB file の責務を分離** しました。

## B3.5　修正

- DB-backed runtime への移行後も、**PHP runtime inventory の auto-discovery
  が残る** ように修正しました。
- vhost load 前の PHP runtime cleanup により installed runtime が消えない
  よう、**load order を修正** しました。
- managed GeoIP update では、**country edition だけを active country DB と
  して扱う** ように修正しました。
- **cache store runtime directory の prepare と mount behavior** を修正
  しました。
- home directory prefix へ install する場合の **runtime user 選択** を修正
  しました。
- installed DB に対象 policy domain の active version がまだ無い場合でも、
  **DB-backed policy 画面の初回保存が conflict にならない** ように修正
  しました。
- Cache Rules の host scope 編集で、**Host 入力中に editor が remount され
  て focus が外れない** ように修正しました。
- SMTP notification の address validation で、**`host:port` が無い値を正しく
  拒否** するように修正しました。
- Scheduled Tasks のスモークテストは、**binary / compose / preview** の各
  パスで、タスクの状態と stdout / stderr ログ出力の両方を検証するように
  しました。
- 起動用設定に `admin.session_secret` がない場合でも、**`make ui-preview-up`
  がプレビュー専用設定で起動できる** ように修正しました。

## B3.6　互換性と移行

- **v1.1.0 の起動前に DB migration が必要** です。
- admin 認証マイグレーションで **`admin_users` / `admin_sessions` /
  `admin_api_tokens`** が追加されます。**既存の static admin API キーは
  UI ログインには使えなくなりました**。
- **file seed material は初回 import または明示 import workflow では利用
  できます** が、import 後の active runtime は DB-backed として扱って
  ください。
- **`admin.session_secret` を変更すると、ブラウザセッションと、旧シーク
  レットで HMAC pepper された admin トークンは無効** になります。
- **Azure Blob / GCS persistent storage 設定は、将来の adapter 用の予約
  項目** です。この build で選択すると validation error になります。

---

以上で、tukuyomi v1.3.0 / v1.2.0 / v1.1.0 のリリースノートと、本書の本編 + 付録
A / B をすべて収めました。

本書の更新は、上流リポジトリ内の **`README.ja.md` および
`docs/**/*.ja.md`** を一次情報として追従します。記述に齟齬を見つけた場合は、
上流ドキュメントを優先してください。
