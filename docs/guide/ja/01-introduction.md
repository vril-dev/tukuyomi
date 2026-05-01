# 第1章　tukuyomi 入門

本章では、tukuyomi がどのような位置づけの製品で、なぜ「single-binary の
application-edge control plane」と呼べるのかを概観します。具体的な設定や
Make ターゲットは第2章以降で扱うので、ここでは全体像と用語の地図づくりを
目的とします。

## 1.1　tukuyomi の立ち位置

tukuyomi は、**Web の前段に置く edge コンポーネント** と、**そこから先のアプリ
ケーション実行レイヤ** を、1 つの Go バイナリに統合した製品です。具体的には、
次の役割を 1 つのプロセスで担います。

- リバースプロキシ（routing と transport）
- Coraza WAF + OWASP CRS による検査
- レート制御 / 国別制御 / Bot 対策 / セマンティック検査 / IP reputation
- 管理 UI / 管理 API（埋め込み済み）
- 任意の static hosting / PHP-FPM / PSGI runtime
- 任意の scheduled jobs（PHP CLI バンドル付き）
- 任意の Tukuyomi Center による IoT / Edge デバイス identity 登録

これらを単一バイナリに束ねている結果、**tukuyomi を 1 台 deploy すれば、Web の
前段に必要なものがほぼ揃う**、という構造になっています。

![管理画面トップ](../../images/ui-samples/01-status.png)

## 1.2　なぜ「single-binary の application-edge control plane」なのか

tukuyomi 自身は、自分自身の位置づけを **single-binary の application-edge
control plane** と表現しています。この言い回しは少し長いので、3 つに分けて
意味を確認しておきます。

### single-binary

tukuyomi は Go で書かれた単一バイナリとして配布します。Gateway 機能と、Center
機能（中央管理側）の双方を、同じバイナリに含めています。どちらの役割で動くかは、
インストール時の `INSTALL_ROLE` や、起動時の設定で決まります。

その結果、

- 配備対象が「1 つのバイナリと 1 つの設定ファイル」に集約される
- `make install TARGET=linux-systemd` 1 行で、ビルド・インストール・DB
  マイグレーション・WAF/CRS アセット import・systemd ユニット投入までが終わる
- コンテナ image も自前で持っており、systemd 配備とコンテナ配備の両対応が
  最初から組み込まれている

という構造になります。

### application-edge

`application-edge` という言葉には、tukuyomi の責務範囲を明示する意図があります。

tukuyomi が扱うのは、**アプリケーションの直前** に位置する edge です。CDN や
グローバルロードバランサのような「インターネットそのものの前段」ではなく、
**アプリケーションプロセスの直前**、すなわち PHP-FPM や Perl/Starman、Go アプリ、
Node アプリなど、自分が運用しているアプリケーションのすぐ前にある層を引き受けます。

そのため、tukuyomi の機能は、

- アプリケーションごとの routing
- アプリケーションごとの WAF tuning（誤検知の狭い緩和）
- アプリケーションプロセス（PHP-FPM / PSGI）そのもののライフサイクル管理

といった、**「特定のアプリケーション」と「特定のアプリケーション」を区別して扱う**
運用に最適化されています。

### control plane

`control plane` は、tukuyomi のもう 1 つの設計の柱です。tukuyomi は、ランタイム
挙動の正本を **DB に集約** しています。

- WAF / CRS のルール資産（`waf_rule_assets`）
- proxy ルートと transport 設定（`proxy_*`）
- Runtime Apps の vhost 設定（`vhosts` / `vhost_*`）
- managed bypass（`override_rules`）
- PHP-FPM / PSGI runtime の inventory（`php_runtime_*` / `psgi_runtime_*`）
- グローバル / listener / admin / storage / paths の各 block（`app_config_*`）

これらは、UI / API から書き換え、DB に保存し、tukuyomi 本体がそれを読んで動きます。
JSON ファイル（`proxy.json` / `sites.json` / `scheduled-tasks.json` ほか）は、
**空 DB に対する seed**、および **import / export の素材** という位置づけに整理
されています。runtime authority は DB 側です。

この構造により、

- ランタイム挙動の変更は UI/API 経由でアトミックに行える
- 設定の差分は DB の version 管理で追える
- 複数 host での import / export は JSON を介して行える

という運用性を実現しています。これが「control plane」と呼んでいる理由です。

## 1.3　tukuyomi が扱う典型的なシーン

tukuyomi が想定する運用のシーンを、いくつか具体的に見ておきます。第2章以降で
扱うトピックの「地図」として使ってください。

### Web/VPS 上の WAF + リバースプロキシ

もっとも基本的な使い方です。1 台の Linux ホスト（VPS でも、ベアメタルでも、
クラウド VM でも）に tukuyomi を `make install TARGET=linux-systemd` でインス
トールし、TLS 終端、HTTP/3、WAF、レート制御、リバースプロキシまでを 1 プロセスで
担います。

このとき、IoT / Edge mode は OFF のまま使います。

### コンテナ／Kubernetes 上の WAF + リバースプロキシ

ECS / Fargate、Kubernetes（AKS / GKE）、Azure Container Apps などのコンテナ
プラットフォーム上で動かす配備形態です。tukuyomi は **single-instance（mutable）**、
**replicated（immutable rolling update）**、**distributed（mutable cluster）**
の 3 段階のサポート tier を持ち、それぞれに合った deployment 例を提供します。

### 既存 PHP / Movable Type 環境の置き換え

PHP-FPM や PSGI（Movable Type など）を伴う既存サーバを、edge ごと tukuyomi に
寄せるケースです。tukuyomi は、PHP-FPM / PSGI runtime の inventory と vhost を
DB で管理し、Runtime Apps として起動します。`Proxy Rules` から、その runtime が
listen する target に向けて routing する、という形になります。

### Center 承認付きの IoT / Edge ゲートウェイ

もうひとつ、用途は限定的ですが特徴的なのが、Tukuyomi Center で承認された
device identity を必要とする IoT / Edge 配備モードです。Gateway は Ed25519 の
device identity をローカルで生成し、Center が発行した enrollment token を添えて
署名付きの登録申請を Center に送ります。Center 側で operator が承認することで、
その Gateway は正式な identity を獲得します。

このモードは Web/VPS 配備では基本的に OFF にしておき、IoT / Edge 配備のときだけ
ON にする optional な機能です。詳細は第16章で扱います。

## 1.4　設定の正本 ── DB と JSON の役割分担

第1章の最後に、tukuyomi の運用全体を貫く重要なルールを 1 つだけ確認しておきます。

> **ランタイム挙動の正本は DB。JSON ファイルは空 DB 向け seed と import/export
> 素材であり、runtime authority ではない。**

具体的には、tukuyomi の設定材料は次のように分かれています。

- `.env`：Docker 実行差分のみ
- `data/conf/config.json`：DB 接続を開く前に必要な bootstrap 設定（`storage`
  block を中心にしたごく薄い JSON）
- DB `app_config_*`：global runtime / listener / admin / storage policy / path
  などの product-wide 設定
- DB `proxy_*`：live の proxy transport / routing 設定
- DB `vhosts` / `vhost_*`：live の Runtime Apps 設定
- DB `waf_rule_assets`：base WAF と CRS の rule / data asset
- DB `override_rules`：managed bypass の rule body
- DB `php_runtime_*` / `psgi_runtime_*`：PHP-FPM / PSGI runtime の inventory
- `seeds/conf/*.json`：空 DB 向けに同梱される本番 seed set
- `data/conf/proxy.json`、`sites.json`、`upstream-runtime.json`、
  `scheduled-tasks.json` など：seed / import / export の素材
- `data/php-fpm/*.json`、`data/psgi/*.json`：PHP-FPM / PSGI 用の seed / import /
  export 素材

ポイントは次の 2 つです。

1. **本番起動後に runtime が読むのは DB であって JSON ではない**。`make crs-install`
   や `make db-import` は、必要な rule asset と config を DB へ取り込み、
   そのあとは DB が正本になります。
2. **JSON ファイル群は import / export の I/O 専用**。新しい host を立てるときに
   seed として撒く、別の host から状態を持ってくる、運用変更を git で扱う、と
   いった用途に使います。

このルールは、第3章以降で何度も登場します。「設定をどこに書くか」で迷ったら、
まずこの分担表に立ち戻ってください。

## 1.5　次章への橋渡し

ここまでで、tukuyomi が **「アプリケーション直前の edge を、DB を正本とした
control plane として 1 バイナリに束ねた製品」** であることを共有できました。

第2章では、いきなり本番構成を組む前に、ローカルマシンで preview を起動し、
Gateway UI と Gateway API に到達するところまでを実際に試します。tukuyomi に
触れたことがない読者は、第2章で手を動かしてから第3章以降に進むと、設定 key の
イメージがつかみやすくなります。
