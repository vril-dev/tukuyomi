# tukuyomi

Coraza + CRS WAFプロジェクト

[English](README.md) | [日本語](README.ja.md)

## 概要

このプロジェクトは、Coraza WAF と OWASP Core Rule Set (CRS) を組み合わせた
軽量かつ強力なアプリケーション防御システム「tukuyomi」です。

## tukuyomi エコシステム

`tukuyomi` は tukuyomi セキュリティスイートの OSS 基盤です。  
各コンポーネントのビルド済みバイナリは公開配布用 [`tukuyomi-releases`](https://github.com/vril-dev/tukuyomi-releases/releases) リポジトリから配布します。  
リポジトリ全体の releases ページはプロダクトファミリー全体の一覧で、下表は各コンポーネントの最新 tag release へ直接リンクします。  
それらのページに GitHub が自動生成する source archive は `tukuyomi-releases` リポジトリ自身のものです。

| コンポーネント | 概要 | ライセンス | 配布 |
|---|---|---|---|
| tukuyomi | nginx + Coraza WAF（本リポジトリ） | Apache-2.0 | OSS |
| tukuyomi-proxy | シングルバイナリWAF/Proxy（nginx不要） | MIT | [`v0.7.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.7.6) |
| tukuyomi-edge | IoTエッジデバイス向けシングルバイナリ | MIT | [`v0.12.6`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.12.6) |
| tukuyomi-center | IoTセンター管理向けシングルバイナリ | MIT | [`v0.6.4`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.6.4) |
| tukuyomi-verify | 検証・テストツール | MIT | [`v0.1.5`](https://github.com/vril-dev/tukuyomi-releases/releases/tag/v0.1.5) |

### バイナリ最新バージョン

| コンポーネント | バージョン | 更新日 |
|---|---|---|
| tukuyomi-proxy | v0.7.6 | 2026-04-02 |
| tukuyomi-edge | v0.12.6 | 2026-04-02 |
| tukuyomi-center | v0.6.4 | 2026-04-02 |
| tukuyomi-verify | v0.1.5 | 2026-04-02 |

> バージョン表はリリース毎に更新します。

## 製品ポジショニング

`tukuyomi` はこのファミリーの Docker 前提 WAF スタックです。`tukuyomi-proxy` と `tukuyomi-edge` と同じ中核セキュリティ機能を持ちますが、リバースプロキシと TLS 入口は主に `nginx` 側に委ねます。

| 項目 | `tukuyomi` | `tukuyomi-proxy` | `tukuyomi-edge` |
| --- | --- | --- | --- |
| 実行形態 | Docker / compose | single binary または Docker | single binary / `systemd` |
| リバースプロキシ + route | `nginx` 前段、内蔵 route editor なし | 内蔵 gateway + route editor | 内蔵 gateway + route editor |
| 中核セキュリティ制御 | IP reputation / bot / semantic / rate / country | IP reputation / bot / semantic / rate / country | IP reputation / bot / semantic / rate / country |
| Device / center 機能 | × | × | device auth + center link |
| キャッシュ + bypass | `nginx` キャッシュ + bypass rules | 内部キャッシュ + bypass rules | 内部キャッシュ + bypass rules |
| TLS + 管理 UI | `nginx` TLS + 別 frontend path | built-in TLS + 内蔵管理 UI | built-in TLS + 内蔵管理 UI |
| DB / マルチノード | 共有 DB 対応 | 共有 DB 対応 | ローカルノード指向 |
| Host hardening | × | × | experimental L3/L4 host hardening |

凡例と詳細な比較表は [docs/product-comparison.ja.md](docs/product-comparison.ja.md) を参照してください。

---

## ルールファイルについて

本リポジトリには、ライセンス順守のため OWASP CRS 本体は同梱していません。  
代わりに、初期状態で動作可能な最小ベースルール `data/rules/tukuyomi.conf` を同梱しています。

### セットアップ手順

以下のコマンドで CRS を取得・配置してください（デフォルト: `v4.23.0`）。

```bash
./scripts/install_crs.sh
```

バージョン指定例:

```bash
./scripts/install_crs.sh v4.23.0
```

`data/rules/crs/crs-setup.conf` は必要に応じて編集してください（`Paranoia Level` や `anomaly` スコアなど）。

### Preset クイックスタート

ゼロから設定を起こさず、最小の事前設定をそのまま使い始める場合は次を実行します。

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

ローカル開発の外へ出す前に `WAF_APP_URL`, `WAF_API_KEY_PRIMARY`, `VITE_API_KEY` を差し替えてください。

---

## 環境変数

`.env` ファイルで挙動を制御可能です。

### Docker / ローカル MySQL（任意）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `MYSQL_PORT` | `13306` | MySQL コンテナ `3306` に割り当てるホスト側ポート（`mysql` profile 有効時）。 |
| `MYSQL_DATABASE` | `tukuyomi` | ローカル MySQL コンテナで初期作成するDB名。 |
| `MYSQL_USER` | `tukuyomi` | ローカル MySQL コンテナで作成するアプリ用ユーザー。 |
| `MYSQL_PASSWORD` | `tukuyomi` | `MYSQL_USER` のパスワード。 |
| `MYSQL_ROOT_PASSWORD` | `tukuyomi-root` | ローカル MySQL コンテナの root パスワード。 |
| `MYSQL_TZ` | `UTC` | コンテナのタイムゾーン。 |

### Nginx

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `NGX_CORAZA_UPSTREAM` | `server coraza:9090;` | Coraza（Goサーバ）の upstream 定義。`server host:port;` を複数行で並べれば簡易ロードバランス可。 |
| `NGX_BACKEND_RESPONSE_TIMEOUT` | `60s` | 上流（Coraza）からの応答タイムアウト。`proxy_read_timeout` に反映。 |
| `NGX_CORAZA_ADMIN_URL` | `/tukuyomi-admin/` | 管理UIの公開パス。末尾スラッシュ必須。このパスに来たリクエストをフロント（`web:5173`）へプロキシ。 |
| `NGX_CORAZA_API_BASEPATH` | `/tukuyomi-api/` | 管理APIのベースパス。末尾スラッシュ推奨。このパス配下は nginx 側で常に非キャッシュ扱い。 |

### WAF / Go（Coraza ラッパー）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `WAF_APP_URL` | `http://host.docker.internal:3000` | 透過先アプリの URL（ALB/ECS 等の本番では適宜変更）。 |
| `WAF_PROXY_ERROR_HTML_FILE` | (空) | 透過先障害時に返す任意の保守 HTML ファイル。 |
| `WAF_PROXY_ERROR_REDIRECT_URL` | (空) | 透過先障害時に使う任意の redirect 先。 |
| `WAF_LOG_FILE` | (空) | WAFログの出力先。未設定なら標準出力。 |
| `WAF_BYPASS_FILE` | `conf/waf.bypass` | バイパス/特別ルール定義ファイルのパス。 |
| `WAF_BOT_DEFENSE_FILE` | `conf/bot-defense.conf` | Bot defense challenge 設定ファイル（JSON）。管理画面から編集可能。 |
| `WAF_SEMANTIC_FILE` | `conf/semantic.conf` | Semanticヒューリスティック設定ファイル（JSON）。管理画面から編集可能。 |
| `WAF_COUNTRY_BLOCK_FILE` | `conf/country-block.conf` | 国別ブロック定義ファイル（1行1国コード、例: `JP`, `US`, `UNKNOWN`）。 |
| `WAF_RATE_LIMIT_FILE` | `conf/rate-limit.conf` | レート制限定義ファイル（JSON）。管理画面から編集可能。 |
| `WAF_IP_REPUTATION_FILE` | `conf/ip-reputation.conf` | IP reputation 設定ファイル（JSON）。管理画面から編集可能。 |
| `WAF_RULES_FILE` | `rules/tukuyomi.conf` | 使用するルールファイル（カンマ区切りで複数指定も可）。 |
| `WAF_CRS_ENABLE` | `true` | CRSを読み込むかどうか。`false` ならベースルールのみ。 |
| `WAF_CRS_SETUP_FILE` | `rules/crs/crs-setup.conf` | CRSセットアップ設定ファイル。 |
| `WAF_CRS_RULES_DIR` | `rules/crs/rules` | CRS本体ルール（`*.conf`）のディレクトリ。 |
| `WAF_CRS_DISABLED_FILE` | `conf/crs-disabled.conf` | CRS本体の無効化ファイル一覧。1行1ファイル名で指定。 |
| `WAF_FP_TUNER_MODE` | `mock` | FPチューナーのプロバイダモード。`mock` はフィクスチャ/生成提案、`http` は `WAF_FP_TUNER_ENDPOINT` へPOST。 |
| `WAF_FP_TUNER_ENDPOINT` | (空) | `http` モード時の外部LLMプロキシのHTTPエンドポイント。 |
| `WAF_FP_TUNER_API_KEY` | (空) | `WAF_FP_TUNER_ENDPOINT` 向け Bearer トークン。 |
| `WAF_FP_TUNER_MODEL` | (空) | プロバイダへ渡す任意のモデル識別子。 |
| `WAF_FP_TUNER_TIMEOUT_SEC` | `15` | プロバイダ呼び出し時のHTTPタイムアウト（秒）。 |
| `WAF_FP_TUNER_MOCK_RESPONSE_FILE` | `conf/fp-tuner-mock-response.json` | `mock` モードで使うレスポンスフィクスチャのパス。 |
| `WAF_FP_TUNER_REQUIRE_APPROVAL` | `true` | `simulate=false` の適用時に承認トークンを必須化するか。 |
| `WAF_FP_TUNER_APPROVAL_TTL_SEC` | `600` | 承認トークンの有効期限（秒）。 |
| `WAF_FP_TUNER_AUDIT_FILE` | `logs/coraza/fp-tuner-audit.ndjson` | propose/apply 操作の監査ログ出力先。 |
| `WAF_STORAGE_BACKEND` | `file` | ストレージバックエンド選択。`file` は従来のファイル運用、`db` はDBログストア + 設定/ルールBlob同期を有効化。 |
| `WAF_DB_DRIVER` | `sqlite` | `WAF_STORAGE_BACKEND=db` 時のDBドライバ。対応値: `sqlite` / `mysql`（ログストア・設定/ルールBlob用途で実装済み）。 |
| `WAF_DB_ENABLED` | `false` | 互換用フラグ。`WAF_STORAGE_BACKEND` 未指定時のみ参照され、`true` で `db`、`false` で `file` にマップ。 |
| `WAF_DB_DSN` | (空) | ネットワークDB向けDSN（例: MySQL）。`WAF_DB_DRIVER=mysql` 時は必須。sqliteは `WAF_DB_PATH` を利用。 |
| `WAF_DB_PATH` | `logs/coraza/tukuyomi.db` | `WAF_STORAGE_BACKEND=db` かつ `WAF_DB_DRIVER=sqlite` 時に利用するSQLiteファイルパス。 |
| `WAF_DB_RETENTION_DAYS` | `30` | DBストア `waf_events` の保持日数。これより古い行は同期時に削除。`0` で削除無効（設定Blobは削除対象外）。 |
| `WAF_DB_SYNC_INTERVAL_SEC` | `0` | DB→実行時設定の定期同期間隔（秒）。`0` で無効、`1` 以上で複数Corazaノード間の定期整合を有効化。 |
| `WAF_STRICT_OVERRIDE` | `false` | 特別ルール読み込み失敗時の挙動。`true`で即終了、`false`で警告のみ継続。 |
| `WAF_API_BASEPATH` | `/tukuyomi-api` | 管理APIのベースパス（Go側のルーティング基準）。 |
| `WAF_API_KEY_PRIMARY` | `…` | 管理API用の主キー（`X-API-Key`）。 |
| `WAF_API_KEY_SECONDARY` | (空) | 予備キー（ローテーション時の切替用。未使用なら空でOK）。 |
| `WAF_API_AUTH_DISABLE` | (空) | 認証無効化フラグ。運用では空（false相当）推奨。テストで無効化したいときのみ truthy 値。 |
| `WAF_API_CORS_ALLOWED_ORIGINS` | `https://admin.example.com,http://localhost:5173` | CORSを許可する Origin 一覧（カンマ区切り）。未設定なら CORS 無効（同一オリジンのみ）。 |
| `WAF_ALLOW_INSECURE_DEFAULTS` | (空) | 弱いAPIキーや認証無効化を許可する開発用フラグ。本番では設定しない。 |

透過先障害時レスポンスの挙動:
- `WAF_PROXY_ERROR_HTML_FILE` と `WAF_PROXY_ERROR_REDIRECT_URL` の両方が未設定なら、ラッパーは既定の `502 Bad Gateway` を返し、ブラウザでは簡素な標準エラーページが表示されます。
- `WAF_PROXY_ERROR_HTML_FILE` を設定すると、HTML を受け取るクライアントにはその保守ページを返し、それ以外には plain text の `503 Service Unavailable` を返します。
- `WAF_PROXY_ERROR_REDIRECT_URL` を設定すると、`GET` / `HEAD` はその URL へ redirect し、それ以外のメソッドには plain text の `503 Service Unavailable` を返します。
- `WAF_PROXY_ERROR_HTML_FILE` と `WAF_PROXY_ERROR_REDIRECT_URL` は排他的です。アプリごとにどちらか一方を選んでください。

### 管理UI（React / Vite）

| 変数名 | 例 | 説明 |
| --- | --- | --- |
| `VITE_CORAZA_API_BASE` | `http://localhost/tukuyomi-api` | ブラウザから叩く API のフル/相対ベース。リバースプロキシの都合に合わせて指定。 |
| `VITE_APP_BASE_PATH` | `/tukuyomi-admin` | 管理UIのルートパス（`react-router` の basename）。 |
| `VITE_API_KEY` | `…` | 管理UIが API へ付与する `X-API-Key`。通常は `WAF_API_KEY_PRIMARY` と同値。 |

起動時に `WAF_API_KEY_PRIMARY` が短すぎる/既知の弱い値の場合、Corazaプロセスは安全側で起動失敗します。  
ローカル検証だけ一時的に緩和したい場合は `WAF_ALLOW_INSECURE_DEFAULTS=1` を利用してください。

## Host Network Hardening（L3/L4 対策の基礎）

tukuyomi はアプリケーション層（L7）の保護に特化しています。  
回線帯域を埋めるような大規模な L3/L4 volumetric 攻撃は、tukuyomi 単体では防げません。  
インターネット公開環境では、ISP / CDN / Load Balancer / scrubbing service などの upstream 側対策を併用してください。

以下の Linux カーネル設定は、SYN flood や spoofed source への耐性を高めるためのホスト側 hardening 例です。  
upstream 側の DDoS 対策の代替ではありません。

`/etc/sysctl.d/99-tukuyomi-network-hardening.conf`

```conf
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 4096
net.core.somaxconn = 4096

net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# 対称ルーティング前提。非対称ルーティングや複数 NIC / トンネル環境では 2 を検討
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
```

適用:

```bash
sudo sysctl --system
```

注意:

- `rp_filter=1` は非対称ルーティング環境では通信断の原因になります
- `tcp_syncookies` は SYN flood 時の fallback であり、帯域枯渇そのものは防げません
- firewall / nftables / iptables の rate limit は実トラフィックに合わせて個別設計してください

---

## 管理ダッシュボード

`web/tukuyomi-admin/` 以下には、React + Vite による管理UIが含まれています。

### 主な画面と機能

| パス | 説明 |
| --- | --- |
| `/status` | WAFの動作状況、設定の確認 |
| `/logs` | WAFログの取得・表示 |
| `/rules` | 使用中のベースルールファイル（`rules/tukuyomi.conf` など）の閲覧・編集 |
| `/rule-sets` | CRS本体ルール（`rules/crs/rules/*.conf`）の有効/無効切替 |
| `/bypass` | バイパス設定の閲覧・編集（waf.bypassを直接操作） |
| `/country-block` | 国別ブロック設定の閲覧・編集（country-block.conf を直接操作） |
| `/rate-limit` | レート制限設定の閲覧・編集（rate-limit.conf を直接操作） |
| `/ip-reputation` | IP reputation feed と CIDR override の閲覧・編集（`conf/ip-reputation.conf` を直接操作） |
| `/notifications` | 集計通知設定の閲覧・編集（`conf/notifications.conf` を直接操作） |
| `/bot-defense` | Bot defense設定の閲覧・編集（bot-defense.conf を直接操作） |
| `/semantic` | Semantic Security設定の閲覧・編集（semantic.conf を直接操作） |
| `/cache` | Cache Rules の可視化・編集（cache.conf の表編集／Raw編集、Validate/Save対応） |

### 画面キャプチャ

#### Dashboard
![Dashboard](docs/images/admin-dashboard-overview.png)

#### Rules Editor
![Rules Editor](docs/images/admin-rules-editor.png)

#### Rule Sets
![Rule Sets](docs/images/admin-rule-sets.png)

#### Bypass Rules
![Bypass Rules](docs/images/admin-bypass-rules.png)

#### Country Block
![Country Block](docs/images/admin-country-block.png)

#### Rate Limit
![Rate Limit](docs/images/admin-rate-limit.png)

#### Notifications
![Notifications](docs/images/admin-notifications.png)

#### Cache Rules
![Cache Rules](docs/images/admin-cache-rules.png)

#### Logs
![Logs](docs/images/admin-logs.png)

### ライブラリ

* coraza 3.3.3
* nginx 1.27
* go 1.26.0
* React 19
* Vite 7
* Tailwind CSS
* react-router-dom
* ShadCN UI（TailwindベースUI）

### 起動方法

```bash
make setup
make compose-build
make web-up
make compose-up
```

環境変数 `.env` に `VITE_APP_BASE_PATH` および `VITE_CORAZA_API_BASE` を定義することで、ルートパスを変更できます。

#### 任意: ローカル MySQL コンテナ（profile: `mysql`）

将来の DB ドライバ検証用に、ローカル MySQL コンテナを起動できます:

```bash
make mysql-up
```

MySQL をDBログ/設定運用で使う場合は、`WAF_STORAGE_BACKEND=db`・`WAF_DB_DRIVER=mysql`・`WAF_DB_DSN`（例: `tukuyomi:tukuyomi@tcp(mysql:3306)/tukuyomi?charset=utf8mb4&parseTime=true`）を設定してください。

複数ノード運用では `WAF_DB_SYNC_INTERVAL_SEC`（例: `10`）を設定すると、各ノードが `config_blobs` から定期的に実行時ファイルを同期し、内容差分がある場合のみ reload します。

スケールアウト運用では、共有MySQLを使う `db + mysql` を標準構成にしてください。`file` と `db + sqlite` は基本的に単一ノード運用/ローカル検証向けです。

### WAF回帰テスト（GoTestWAF）

ローカルで回帰テストを実行:

```bash
make gotestwaf-file
```

前提条件:

- Docker と Docker Compose が利用可能であること
- スクリプトが `coraza` と `nginx` を自動で build/up すること
- 既定のホスト公開ポートは `HOST_CORAZA_PORT=19090` と `HOST_NGINX_PORT=18080`
- 互換のため `HOST_OPENRESTY_PORT` も引き続き利用可能
- 初回実行時は GoTestWAF イメージ取得のため時間がかかる場合があること

デフォルトの合否基準は `MIN_BLOCKED_RATIO=70` です。追加基準は任意で指定できます:

```bash
MIN_TRUE_NEGATIVE_PASSED_RATIO=95 MAX_FALSE_POSITIVE_RATIO=5 MAX_BYPASS_RATIO=30 ./scripts/run_gotestwaf.sh
```

レポート出力先は `data/logs/gotestwaf/` です:

- JSONフルレポート: `gotestwaf-report.json`
- Markdownサマリ: `gotestwaf-report-summary.md`
- Key-Valueサマリ: `gotestwaf-report-summary.txt`

### デプロイ例

実用向けのサンプル構成を以下に用意しています:

- `examples/nextjs`（Next.js フロントエンド）
- `examples/wordpress`（WordPress + 高パラノイア CRS 設定）
- `examples/api-gateway`（REST API + 厳しめレート制限プロファイル）

共通の起動手順は `examples/README.md` を参照してください。`examples/api-gateway`、`examples/nextjs`、`examples/wordpress` には `PROTECTED_HOST=protected.example.test ./smoke.sh` があり、repo ルートからは `./scripts/ci_example_smoke.sh <example>` で Docker smoke も回せます。
repo ルートの統一入口として使うなら、`make example-smoke EXAMPLE=api-gateway` または `make example-smoke-all` も利用できます。

### FPチューナー（モック）送受信テスト

外部LLMの契約を確定していない段階でも、送信→受信→適用までをテストできます:

```bash
./scripts/test_fp_tuner_mock.sh
```

既定では `simulate` 適用（`SIMULATE=1`）です。実際に追記してホットリロードする場合:

```bash
SIMULATE=0 ./scripts/test_fp_tuner_mock.sh
```

### FPチューナー（HTTPスタブ）送受信テスト

`http` モードをローカルスタブで検証する場合:

```bash
./scripts/test_fp_tuner_http.sh
```

このスクリプトは次を自動実行します:

- `127.0.0.1:${MOCK_PROVIDER_PORT:-18091}` に一時的なプロバイダスタブを起動
- `WAF_FP_TUNER_MODE=http` で `coraza` を起動/再ビルド
- `propose` / `apply` の契約を確認
- 外部送信前にマスキング済みペイロードであることを検証

既定のAPI公開ポートは `HOST_CORAZA_PORT=19090` です（`:80` は使用しません）。

### FPチューナー（コマンドブリッジ）送受信テスト

外部ツール連携（将来的な Codex CLI / Claude Code 連携を含む）向けに、`command` モードのブリッジ検証も可能です:

```bash
./scripts/test_fp_tuner_bridge_command.sh
```

関連スクリプト:

- `scripts/fp_tuner_provider_bridge.py`: ローカルHTTPブリッジ（`/propose`）
- `scripts/fp_tuner_provider_cmd_example.sh`: サンプルのコマンドプロバイダ（stdin JSON -> stdout JSON）
- `scripts/fp_tuner_provider_openai.sh`: OpenAI互換API向けコマンドプロバイダ（stdin JSON -> API呼び出し -> stdout JSON）
- `scripts/fp_tuner_provider_claude.sh`: Claude Messages API向けコマンドプロバイダ（stdin JSON -> API呼び出し -> stdout JSON）

独自コマンドに差し替える場合:

```bash
BRIDGE_COMMAND="/path/to/your-provider-command.sh" ./scripts/test_fp_tuner_bridge_command.sh
```

OpenAIコマンドプロバイダの利用例:

```bash
export FP_TUNER_OPENAI_API_KEY="<your-api-key>"
export FP_TUNER_OPENAI_MODEL="<your-model-name>"

BRIDGE_COMMAND="./scripts/fp_tuner_provider_openai.sh" ./scripts/test_fp_tuner_bridge_command.sh
```

OpenAIコマンドプロバイダのローカルモックテスト:

```bash
./scripts/test_fp_tuner_openai_command.sh
```

Claudeコマンドプロバイダの利用例:

```bash
export FP_TUNER_CLAUDE_API_KEY="<your-api-key>"
export FP_TUNER_CLAUDE_MODEL="claude-sonnet-4-6"

BRIDGE_COMMAND="./scripts/fp_tuner_provider_claude.sh" ./scripts/test_fp_tuner_bridge_command.sh
```

Claudeコマンドプロバイダのローカルモックテスト:

```bash
./scripts/test_fp_tuner_claude_command.sh
```

### FPチューナー（管理UI）運用フロー

管理画面（`/fp-tuner`）で、最近の `waf_block` ログから対象イベントを1件選択して提案生成できます。

基本フロー:

1. 管理UIの `FP Tuner` を開く
2. `Pick From Recent waf_block Logs` で調整対象の行の `Use` を押す
3. 自動反映されたイベント項目（`path` / `rule_id` / `matched_variable` / `matched_value`）を確認
4. `Propose` を実行し、`proposal.rule_line` を必要に応じて編集
5. `Apply` を実行（まず `simulate`、必要なら承認トークン付きで実適用）

1回の提案で送る外部プロバイダ向け入力は選択した1イベントのみです（送信量を抑制）。

---

## API管理エンドポイント（/tukuyomi-api）

### エンドポイント一覧

リクエスト/レスポンスの詳細スキーマは [docs/api/admin-openapi.yaml](docs/api/admin-openapi.yaml) にまとめています（OpenAPI 3.0 / Swagger互換）。

| メソッド | パス | 説明 |
| --- | --- | --- |
| GET | `/tukuyomi-api/status` | 現在のWAF設定状態を取得 |
| GET | `/tukuyomi-api/metrics` | rate limit / semantic の実行カウンタを Prometheus 形式で出力 |
| GET | `/tukuyomi-api/logs/read` | WAFログ（tail）を取得（`country` クエリで国別フィルタ可） |
| GET | `/tukuyomi-api/logs/stats` | WAFブロック統計 + 時間別seriesを取得（`hours` / `scan` クエリ対応） |
| GET | `/tukuyomi-api/logs/download` | 3種類のログファイル（`waf` / `accerr` / `intr`）をZIPでまとめてダウンロード |
| GET | `/tukuyomi-api/rules` | ルールファイル一覧を取得（複数対応） |
| POST | `/tukuyomi-api/rules:validate` | 指定ルールファイルの構文検証（保存なし） |
| PUT | `/tukuyomi-api/rules` | 指定ルールファイルを保存し、WAFベースルールをホットリロード（`If-Match`対応） |
| GET | `/tukuyomi-api/crs-rule-sets` | CRS本体ルール一覧と有効/無効状態を取得 |
| POST | `/tukuyomi-api/crs-rule-sets:validate` | CRS本体ルール選択の検証（保存なし） |
| PUT | `/tukuyomi-api/crs-rule-sets` | CRS本体ルール選択を保存し、ホットリロード（`If-Match`対応） |
| GET | `/tukuyomi-api/bypass-rules` | バイパス設定ファイルの内容を取得 |
| POST | `/tukuyomi-api/bypass-rules:validate` | 送信内容の構文・検証のみ（保存なし） |
| PUT | `/tukuyomi-api/bypass-rules` | バイパス設定ファイルを上書き保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/country-block-rules` | 国別ブロック設定ファイルの内容を取得 |
| POST | `/tukuyomi-api/country-block-rules:validate` | 国別ブロック設定の構文検証のみ（保存なし） |
| PUT  | `/tukuyomi-api/country-block-rules` | 国別ブロック設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/rate-limit-rules` | レート制限設定ファイルの内容を取得 |
| POST | `/tukuyomi-api/rate-limit-rules:validate` | レート制限設定の構文検証のみ（保存なし） |
| PUT  | `/tukuyomi-api/rate-limit-rules` | レート制限設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/notifications` | 集計通知設定ファイルの内容を取得 |
| GET  | `/tukuyomi-api/notifications/status` | 通知ランタイム状態と active alert を取得 |
| POST | `/tukuyomi-api/notifications/validate` | 通知設定の構文検証のみ（保存なし） |
| POST | `/tukuyomi-api/notifications/test` | 現在設定でテスト通知を送信 |
| PUT  | `/tukuyomi-api/notifications` | 通知設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/ip-reputation` | IP reputation 設定と runtime status を取得 |
| POST | `/tukuyomi-api/ip-reputation:validate` | IP reputation 設定の構文検証のみ（保存なし） |
| PUT  | `/tukuyomi-api/ip-reputation` | IP reputation 設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/bot-defense-rules` | Bot defense設定ファイルの内容を取得 |
| POST | `/tukuyomi-api/bot-defense-rules:validate` | Bot defense設定の構文検証のみ（保存なし） |
| PUT  | `/tukuyomi-api/bot-defense-rules` | Bot defense設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/semantic-rules` | Semantic設定と実行統計を取得 |
| POST | `/tukuyomi-api/semantic-rules:validate` | Semantic設定の構文検証のみ（保存なし） |
| PUT  | `/tukuyomi-api/semantic-rules` | Semantic設定ファイルを保存（`If-Match` に `ETag` を指定して楽観ロック） |
| GET  | `/tukuyomi-api/verify-manifest` | 外部WAF検証ランナー向けの verification manifest 雛形を出力 |
| POST | `/tukuyomi-api/fp-tuner/propose` | リクエスト入力（`event` または `events[]`）または最新 `waf_block` / `semantic_anomaly` ログからFP調整案を生成 |
| POST | `/tukuyomi-api/fp-tuner/apply` | 調整案の検証/適用（既定は `simulate=true`、実適用は承認トークン必須設定可） |
| GET  | `/tukuyomi-api/cache-rules` | cache.conf の現在内容（Raw + 構造化）と `ETag` を返す |
| POST | `/tukuyomi-api/cache-rules:validate` | 送信内容の構文・検証のみ（保存なし） |
| PUT | `/tukuyomi-api/cache-rules` | cache.conf を保存（`If-Match` に `ETag` を指定して楽観ロック） |


ログやルールが設定されていない場合は `500` で `{"error": "...説明..."}` を返します。

---

## WAFバイパス・特別ルール設定について

tukuyomiでは、CorazaによるWAF検査を特定のリクエストに対して除外（バイパス）したり、特定のルールのみを適用する機能を備えています。

### バイパスファイルの指定

環境変数 `WAF_BYPASS_FILE` で除外・特別ルール定義ファイルを指定します。デフォルトは `conf/waf.bypass` です。

### ファイル記述形式

```text
# 通常のバイパス指定
/about/
/about/user.php

# 特別ルール適用（WAFバイパスせず、指定ルールを使用）
/about/admin.php rules/admin-rule.conf

# コメント（先頭 #）
#/should/be/ignored.php rules/test.conf
```

### UIからの編集

管理ダッシュボード `/bypass` 画面から、`waf.bypass` ファイルの内容を直接編集・保存できます。
この画面では、全体の設定内容をテキスト形式で表示・編集し、保存ボタンで即時適用できます。

### 国別ブロック設定

管理ダッシュボード `/country-block` から、`WAF_COUNTRY_BLOCK_FILE`（既定: `conf/country-block.conf`）を編集できます。  
1行に1つの国コードを記述します（例: `JP`, `US`, `UNKNOWN`）。  
該当する国コードのアクセスは WAF 前段で `403` になります。

### レート制限設定

管理ダッシュボード `/rate-limit` から、`WAF_RATE_LIMIT_FILE`（既定: `conf/rate-limit.conf`）を編集できます。  
設定は JSON 形式で、`default_policy` と `rules` を管理します。  
超過時は `action.status`（通常 `429`）を返し、`Retry-After` ヘッダを付与します。

### IP Reputation 設定

管理ダッシュボード `/ip-reputation` から、`WAF_IP_REPUTATION_FILE`（既定: `conf/ip-reputation.conf`）を編集できます。
request-time security plugin は `ip_reputation -> bot_defense -> semantic` の順で WAF より前に実行されます。
静的な allow/block CIDR と、任意の feed refresh を設定できます。
plugin 作成手順は [`docs/request_security_plugins.md`](docs/request_security_plugins.md) を参照してください。

#### JSONパラメータ早見表（何を変えるとどうなるか）

| パラメータ | 例 | 影響 |
| --- | --- | --- |
| `enabled` | `true` / `false` | レート制限全体の有効/無効。`false` なら全リクエストを素通し。 |
| `allowlist_ips` | `["127.0.0.1/32", "10.0.0.5"]` | 一致IPは常に制限対象外。CIDRと単体IPの両方を指定可。 |
| `allowlist_countries` | `["JP", "US"]` | 一致国コードは常に制限対象外。 |
| `session_cookie_names` | `["session", "sid"]` | `key_by` が session 系のときに参照する Cookie 名。 |
| `jwt_header_names` | `["Authorization"]` | JWT subject 抽出に使うヘッダ名。 |
| `jwt_cookie_names` | `["token", "access_token"]` | JWT subject 抽出に使う Cookie 名。 |
| `adaptive_enabled` | `true` / `false` | semantic リスクスコアが高いクライアントだけ制限を自動で厳しくする。 |
| `adaptive_score_threshold` | `6` | adaptive 制御を開始する最小リスクスコア。 |
| `adaptive_limit_factor_percent` | `50` | adaptive 時に `limit` へ掛ける割合。 |
| `adaptive_burst_factor_percent` | `50` | adaptive 時に `burst` へ掛ける割合。 |
| `default_policy.enabled` | `true` | デフォルトポリシー自体の有効/無効。 |
| `default_policy.limit` | `120` | ウィンドウ期間内の基本許可回数。 |
| `default_policy.burst` | `20` | `limit` に上乗せする瞬間許容量。実効上限は `limit + burst`。 |
| `default_policy.window_seconds` | `60` | カウント窓の秒数。短いほど厳密、長いほど緩やか。 |
| `default_policy.key_by` | `"ip"` | 集計キー。`ip` / `country` / `ip_country` / `session` / `ip_session` / `jwt_sub` / `ip_jwt_sub`。 |
| `default_policy.action.status` | `429` | 超過時のHTTPステータス。`4xx/5xx`のみ。 |
| `default_policy.action.retry_after_seconds` | `60` | `Retry-After` ヘッダ秒数。`0` なら次ウィンドウまでの残秒を自動計算。 |
| `rules[]` | 下記参照 | 条件一致時に `default_policy` より優先して適用。先頭から順に評価。 |
| `rules[].match_type` | `"prefix"` | ルールの一致方式。`exact` / `prefix` / `regex`。 |
| `rules[].match_value` | `"/login"` | 一致対象。`match_type` に応じて完全一致/前方一致/正規表現。 |
| `rules[].methods` | `["POST"]` | 対象メソッド限定。空なら全メソッド対象。 |
| `rules[].policy.*` |  | ルール一致時に使う制限値（`default_policy` と同じ意味）。 |

#### 運用でよくやる調整

- 全体を一時停止したい: `enabled=false`
- 短時間スパイクに強くしたい: `burst` を増やす
- ログイン単位・ユーザー単位に分けたい: `key_by="session"` または `key_by="jwt_sub"`
- 怪しいクライアントだけ厳しくしたい: `adaptive_enabled=true`
- ログインだけ厳しくしたい: `rules` に `match_type=prefix`, `match_value=/login`, `methods=["POST"]` を追加
- 同一IP内で国別に分けたい: `key_by="ip_country"`
- 特定拠点を除外したい: `allowlist_ips` または `allowlist_countries` に追加

#### 推奨設定

- 一般公開トラフィック: `default_policy.key_by="ip"` を基本にする
- 安定した session cookie があるブラウザのログイン/フォーム: `key_by="session"` を使う
- 安定して信頼できる JWT `sub` を持つ認証 API: `key_by="jwt_sub"` を使う
- adaptive 制御はまずログインや更新系パスから有効化する: `adaptive_enabled=true`, `adaptive_score_threshold=6`, `adaptive_limit_factor_percent=50`, `adaptive_burst_factor_percent=50`

巨大な JWT header/cookie 値は `jwt_sub` 抽出対象から除外され、base64 decode や JSON parse は行いません。

#### 監視ポイント

- `/tukuyomi-api/metrics` で rate-limit の blocked / adaptive カウンタ増加を確認する
- `/tukuyomi-api/metrics` で login / write 系パス周辺の semantic action カウンタを確認する
- 調整時はログの `rl_key_hash`, `adaptive`, `risk_score`, `reason_list`, `score_breakdown` を見る

### Notifications 設定

管理ダッシュボード `/notifications` から、`WAF_NOTIFICATION_FILE`（既定: `conf/notifications.conf`）を編集できます。
通知は既定で無効で、ブロック 1 件ごとではなく、集計された状態遷移だけを送ります。

- upstream 通知は、proxy error の集計に応じて `quiet -> active -> escalated -> quiet(recovered)` で遷移します
- security 通知は、`waf_block`, `rate_limited`, `semantic_anomaly`, `bot_challenge`, `ip_reputation` の集計に応じて `quiet -> active -> escalated -> quiet(recovered)` で遷移します
- sink は `webhook` と `email` をサポートします
- `POST /tukuyomi-api/notifications/test` で現在設定のテスト通知を送れます
- `GET /tukuyomi-api/notifications/status` で active alert、sink 数、最終 dispatch error を確認できます

#### JSONパラメータ早見表

| パラメータ | 例 | 影響 |
| --- | --- | --- |
| `enabled` | `true` / `false` | 通知配送全体の ON/OFF。既定は `false`。 |
| `cooldown_seconds` | `900` | 同じ alert key / state で再送するまでの最小秒数。 |
| `sinks[].type` | `"webhook"` / `"email"` | 配送方式。 |
| `sinks[].enabled` | `true` / `false` | 個別 sink の ON/OFF。 |
| `sinks[].webhook_url` | `"https://hooks.example.invalid/tukuyomi"` | webhook 配送先 URL。 |
| `sinks[].headers` | `{"X-Tukuyomi-Token":"..."}` | 任意の webhook header。 |
| `sinks[].smtp_address` | `"smtp.example.invalid:587"` | email sink が使う SMTP relay。 |
| `sinks[].from` / `sinks[].to` | `"alerts@example.invalid"` / `["secops@example.invalid"]` | email の送信元と送信先。 |
| `upstream.window_seconds` | `60` | proxy error を集計する窓秒数。 |
| `upstream.active_threshold` | `3` | upstream alert を `quiet` から `active` に進める件数。 |
| `upstream.escalated_threshold` | `10` | upstream alert を `active` から `escalated` に進める件数。 |
| `security.window_seconds` | `300` | security event を集計する窓秒数。 |
| `security.active_threshold` | `20` | security alert を `quiet` から `active` に進める件数。 |
| `security.escalated_threshold` | `100` | security alert を `active` から `escalated` に進める件数。 |
| `security.sources` | `["waf_block","rate_limited"]` | 集計対象にする security event 種別。 |

#### 推奨設定

- `POST /tukuyomi-api/notifications/test` で疎通確認できるまでは通知を有効化しない
- 最初は webhook を優先する。Slack / Teams 連携は多くの場合 webhook sink で吸収できる
- public reverse proxy では upstream 通知を先に有効化して、backend 障害を per-request 通知なしで検知する
- security 通知は、rate-limit / semantic のしきい値調整が終わってから有効化する

例:

```json
{
  "enabled": false,
  "cooldown_seconds": 900,
  "sinks": [
    {
      "name": "primary-webhook",
      "type": "webhook",
      "enabled": false,
      "webhook_url": "https://hooks.example.invalid/tukuyomi",
      "timeout_seconds": 5
    }
  ],
  "upstream": {
    "enabled": true,
    "window_seconds": 60,
    "active_threshold": 3,
    "escalated_threshold": 10
  },
  "security": {
    "enabled": true,
    "window_seconds": 300,
    "active_threshold": 20,
    "escalated_threshold": 100,
    "sources": ["waf_block", "rate_limited", "semantic_anomaly", "bot_challenge"]
  }
}
```

### Bot Defense 設定

管理ダッシュボード `/bot-defense` から、`WAF_BOT_DEFENSE_FILE`（既定: `conf/bot-defense.conf`）を編集できます。  
有効時は、対象パスの GET リクエストに対して（`mode` に応じて）challenge レスポンスを返し、通過後に通常処理へ進みます。

#### JSONパラメータ早見表

| パラメータ | 例 | 影響 |
| --- | --- | --- |
| `enabled` | `true` / `false` | Bot challenge の全体ON/OFF。 |
| `mode` | `"suspicious"` | `suspicious` は UA 条件一致時のみ、`always` は一致パスを常に challenge。 |
| `path_prefixes` | `["/", "/login"]` | challenge 対象のパス前方一致。 |
| `exempt_cidrs` | `["127.0.0.1/32"]` | challenge 除外する送信元 IP/CIDR。 |
| `suspicious_user_agents` | `["curl", "wget"]` | `suspicious` モードで使う UA 部分一致。 |
| `challenge_cookie_name` | `"__tukuyomi_bot_ok"` | challenge 通過に使う Cookie 名。 |
| `challenge_secret` | `"long-random-secret"` | challenge トークン署名シークレット（空ならプロセス起動ごとに一時生成）。 |
| `challenge_ttl_seconds` | `86400` | challenge トークン有効期限（秒）。 |
| `challenge_status_code` | `429` | challenge 応答時の HTTP ステータス（`4xx/5xx`）。 |

### Semantic Security 設定

管理ダッシュボード `/semantic` から、`WAF_SEMANTIC_FILE`（既定: `conf/semantic.conf`）を編集できます。  
これは機械学習ではなくルールベースのヒューリスティック検知で、`off | log_only | challenge | block` の段階制御に対応します。

#### JSONパラメータ早見表

| パラメータ | 例 | 影響 |
| --- | --- | --- |
| `enabled` | `true` / `false` | semantic スコアリング全体の有効/無効。 |
| `mode` | `"challenge"` | 実行モード。`off` / `log_only` / `challenge` / `block`。 |
| `exempt_path_prefixes` | `["/healthz"]` | 一致パスは semantic 検査をスキップ。 |
| `log_threshold` | `4` | anomaly ログを出す最小スコア。 |
| `challenge_threshold` | `7` | `challenge` モードで challenge 応答にする最小スコア。 |
| `block_threshold` | `9` | `block` モードで `403` にする最小スコア。 |
| `max_inspect_body` | `16384` | semantic が検査するリクエストボディ最大バイト数。 |
| `temporal_window_seconds` | `10` | IP ごとの時系列観測に使うスライディングウィンドウ秒数。 |
| `temporal_max_entries_per_ip` | `128` | IP ごとに保持する観測数の上限。 |
| `temporal_burst_threshold` | `20` | `temporal:ip_burst` を発火させるリクエスト数閾値。 |
| `temporal_burst_score` | `2` | `temporal:ip_burst` 発火時に加点するスコア。 |
| `temporal_path_fanout_threshold` | `8` | `temporal:ip_path_fanout` を発火させる distinct path 数。 |
| `temporal_path_fanout_score` | `2` | `temporal:ip_path_fanout` 発火時に加点するスコア。 |
| `temporal_ua_churn_threshold` | `4` | `temporal:ip_ua_churn` を発火させる distinct User-Agent 数。 |
| `temporal_ua_churn_score` | `1` | `temporal:ip_ua_churn` 発火時に加点するスコア。 |

`semantic_anomaly` ログには `reason_list` と `score_breakdown` が入り、`/tukuyomi-api/metrics` では rate limit / semantic の実行カウンタを取得できます。

### ルールファイル編集（複数対応）

管理ダッシュボード `/rules` では、アクティブなベースルールセットを選択して編集できます（`WAF_RULES_FILE` と、CRS有効時は `crs-setup.conf` + 有効化されている `WAF_CRS_RULES_DIR` の `*.conf`）。  
保存時はサーバ側で構文検証した後に反映され、Coraza のベースルールセットをホットリロードします。  
リロード失敗時は自動でロールバックされます。

### CRSルールセット切替

管理ダッシュボード `/rule-sets` では、`rules/crs/rules/*.conf` の各ファイルを有効/無効で切り替えられます。  
状態は `WAF_CRS_DISABLED_FILE` に保存され、保存時にWAFをホットリロードします。

### 優先順位

* 特別ルールが優先されます（同じパスにバイパス設定があっても無視）
* ルールファイルが存在しない場合

  * `WAF_STRICT_OVERRIDE=true` のときは即時強制終了（log.Fatalf）
  * `false` または未設定時はログ出力して通常ルールで処理継続

### 例

```text
/about/                    # /about/ 以下すべてバイパス
/about/admin.php rules/special.conf  # admin.php だけは WAF で特別ルール適用
```

### 注意

* ルール記述はファイル上で上から順に評価されます
* `extraRuleFile` を指定した行が優先されます
* コメント行（`#`で始まる）は無視されます

---

## ログの確認

本システムのログは API 経由で取得できます。

```bash
curl -s -H "X-API-Key: <your-api-key>" \
     "http://<host>/tukuyomi-api/logs/read?src=waf&tail=100&country=JP" | jq .
```

* src: ログ種別 (waf, accerr, intr)
* tail: 取得件数
* country: 国コード（例: `JP`, `US`, `UNKNOWN`。未指定または`ALL`で全件）
  * Cloudflare配下では `CF-IPCountry` ヘッダを利用します。未取得時は `UNKNOWN` になります。

API キーは .env で設定した API_KEY を使用してください。
実運用環境ではアクセス制限や認証を必ず設定してください。

## キャッシュ機能

キャッシュ対象のパスやTTLを動的に設定できる機能を追加しました。

### 設定ファイル
キャッシュ設定は `/data/conf/cache.conf` に記述します。  
設定変更はホットリロードに対応しており、ファイル保存後すぐに反映されます。

#### 記述例

```bash
# 静的アセット（CSS/JS/画像）を10分キャッシュ
ALLOW prefix=/_next/static/chunks/ methods=GET,HEAD ttl=600 vary=Accept-Encoding

# 特定HTMLページ群を5分キャッシュ（正規表現）
ALLOW regex=^/about/.*.html$ methods=GET ttl=300

# API全域禁止（安全側）
DENY prefix=/tukuyomi-api/

# 認証ユーザーのプロフィールはキャッシュ禁止（正規表現）
DENY regex=^/users/[0-9]+/profile

# その他はデフォルトでキャッシュ禁止
```

- ALLOW: キャッシュ許可（TTLは秒単位、Varyは任意）
- DENY: キャッシュ対象外
- メソッドは `GET` または `HEAD` を推奨（POST等はキャッシュされません）

フィールド説明
- prefix: 指定パスで始まる場合にマッチ
- regex: 正規表現でマッチ（`^`や`$`を使って指定可能）
- methods: 対象HTTPメソッド（カンマ区切り）
- ttl: キャッシュ時間（秒）
- vary: nginxに渡すVaryヘッダ値（カンマ区切り）

### 動作概要

- Go側でルールに一致したレスポンスに `X-Tukuyomi-Cacheable` と `X-Accel-Expires` を付与
- nginx がこれらのヘッダを元にキャッシュを管理
- 認証付きリクエスト、Cookieあり、APIパスはデフォルトでキャッシュされません
- `Set-Cookie` を含む上流レスポンスは保存されません（共有キャッシュ誤配信防止）

### 確認方法

- レスポンスヘッダに以下が含まれているか確認
  - `X-Tukuyomi-Cacheable: 1`
  - `X-Accel-Expires: <秒数>`
- nginx の `X-Cache-Status` ヘッダでキャッシュヒット状況を確認可能（MISS/HIT/BYPASS 等）

---

## 管理画面のアクセス制限について

本プロジェクトにはデフォルトでアクセス制限機能は含まれていません。  
管理画面（NGX_CORAZA_ADMIN_URL で公開されるパス）を利用する場合は、必ず Basic 認証や IP 制限などのアクセス制御を設定してください。

---

## 品質ゲート（CI）

GitHub Actions の `ci` ワークフローで以下を検証します。

- `go test ./...`（`coraza/src`）
- `docker compose config` の妥当性確認
- MySQL ログストア統合テスト（`docker compose --profile mysql up -d mysql` + `go test ./internal/handler -run TestLogsStatsMySQLStoreAggregatesAndIngestsIncrementally`）
- `./scripts/run_gotestwaf.sh`（`waf-test` マトリクス、`MIN_BLOCKED_RATIO=70`、`WAF_DB_ENABLED=false/true`）

運用では、以下をブランチ保護の Required Checks に設定してください。

- `ci / go-test`
- `ci / mysql-logstore-test`
- `ci / compose-validate`
- `ci / waf-test (file)`
- `ci / waf-test (sqlite)`

---

## 誤検知チューニング運用

誤検知の削減手順は以下を参照してください。

- `docs/operations/waf-tuning.md`
- `docs/operations/fp-tuner-api.md`

## DB運用

SQLite 運用手順は以下を参照してください。

- `docs/operations/db-ops.md`

---

## tukuyomi とは？

**tukuyomi** は、nginx + Coraza WAF をベースとした OSS WAF **mamotama** を前身として発展したプロダクトです。

名前は **「護りたまえ」(mamoritamae)** という言葉に由来し、
*「守護を与えよ」* という意味を持ちます。

mamotama が「保護」を核心に据えていたのに対し、
tukuyomi はより構造的でインテリジェントなアプローチを体現しています——
Webシステムに秩序・可観測性・制御をもたらすことを目指しています。
