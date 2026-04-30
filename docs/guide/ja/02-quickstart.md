# 第2章　クイックスタート

本章では、ローカル環境で tukuyomi の preview を起動し、Gateway UI と Gateway API に
ブラウザから到達するところまでを通して試します。tukuyomi のソースを clone した
ばかりの状態を起点に、最短経路で「動いている tukuyomi」に触れることを目的と
します。

本格的な配備（systemd / Docker / ECS / Kubernetes）は第3章・第4章で扱います。
この章で確認した preview を、それらの章を読みながら本番構成へ広げていく、という
位置づけです。

## 2.1　前提条件

本章は、ローカルの開発マシンで preview を試す前提で書きます。次のものが用意
できていれば、そのまま進めて構いません。

- Linux または WSL2（macOS でも動きますが、本書は Linux を想定します）
- Go の build に必要な toolchain（`make`、Go コンパイラ、Node.js）
- `make` / `git`

WAF や CRS のルール資産は、`make` ターゲットが必要なものをすべて自動的に揃えます。
事前に手動で配置する必要はありません。

## 2.2　ルールファイルと初期セットアップの考え方

具体的なコマンドに入る前に、tukuyomi のセットアップが「何を、どこに、どの順番で
用意するか」を理解しておきます。

tukuyomi は、ライセンスの都合上、リポジトリに OWASP CRS 本体を同梱していません。
代わりに、起動に必要な最小ベースルールの seed が `seeds/waf/rules/` に同梱されて
います。

通常 runtime 用の手順は次のとおりです。

1. **DB schema を作る**（`make db-migrate`）
2. **CRS の seed file を配置する**
3. **WAF の rule asset を DB へ import する**（`make crs-install`）

この 1〜3 をひとまとめにして実行する shortcut も用意されており、preview 起動コ
マンドはその shortcut を内部で呼んでいます。読者が手で 1〜3 を順番に叩く必要は
ありません。

```bash
make db-migrate
make crs-install
```

## 2.3　Preset を適用する

tukuyomi では、よくある初期構成を **preset** という単位で同梱しています。preview を
起動する際は、まず最小 preset を適用しておきます。

```bash
make preset-apply PRESET=minimal
make preset-check PRESET=minimal
```

`minimal` preset が配置するのは、次の 2 ファイルだけです。

- `.env`
- `data/conf/config.json`

つまり、**preset がやっているのは「最小限の bootstrap 設定の配置」だけ** です。
proxy ルートや site の設定は、preset 適用時点では DB にも JSON にも入っていません。

> **補足：JSON が無いときの fallback**
>
> `conf/proxy.json` や `conf/sites.json` を用意していない状態でも、`make db-import`
> は壊れません。まず `seeds/conf/` を読み、それも無ければ互換 default に fallback
> します。preview を試すだけなら、ここを意識しなくて構いません。

## 2.4　Preview を起動する

ここからは、Gateway UI と Gateway のローカル runtime フローだけを試したいときに
使う `preview` ターゲットを使います。

```bash
make gateway-preview-up
```

このコマンド 1 本で、次のすべてが順番に走ります。

1. `make db-migrate` で DB schema を作成
2. CRS seed file が無ければ配置
3. WAF rule asset を DB へ import
4. preview 用に Gateway を起動

つまり、ここまでで第2.2 節に書いた「DB schema → seed → import」の 1〜3 が
**自動的に実行される** わけです。

起動が成功すると、ブラウザから次の URL に到達できます。

- Gateway UI: `http://localhost:9090/tukuyomi-ui`
- Gateway API: `http://localhost:9090/tukuyomi-api`

最初に `tukuyomi-ui` を開くと、設定済みの管理者でログインを求められます。
`minimal` preset が用意した初期 credential を入力すると、ステータス画面（第1章で
掲示したスクリーンショットの画面）が表示されます。

## 2.5　Preview の状態を保持したいとき

`make gateway-preview-up` は **既定では preview 専用 SQLite DB を毎回初期化** します。
preview 用の設定ファイルもあわせて初期化されるため、`down → up` のたびに
クリーンな状態から始まります。

「preview で作った設定を残したまま再起動したい」というときは、環境変数で persist
モードを指定します。

```bash
GATEWAY_PREVIEW_PERSIST=1 make gateway-preview-up
```

この場合は、preview 用の設定と DB 状態が `gateway-preview-down` と
`gateway-preview-up` の間で保持されます。

## 2.6　Gateway UI の歩き方（最初に見ておく画面）

Gateway UI には、運用上よく使う画面がひととおり揃っています。最初の preview
セッションでは、次の順に開いておくと、その後の章の内容と結びつきやすくなります。

1. **Status**（最初に開かれる画面）
   - WAF / proxy / runtime の現在の健全性、最近のリクエストの傾向、
     overload backpressure の状態などをひとめで確認できます。
2. **Logs**
   - WAF event ログ（DB `waf_events`）と、リクエストのタイムラインが見える画面です。
     誤検知チューニングのときに最初に開く画面でもあります（第7章）。
3. **Rules**
   - DB に取り込まれた base WAF と CRS の rule asset が一覧されます。
4. **Override Rules**
   - WAF 誤検知に対する **狭い緩和** を、managed bypass として登録する画面です
     （第7章）。
5. **Proxy Rules**
   - Routes / Upstreams / Backend Pools の三層を編集する画面です（第5章）。
6. **Backends**
   - direct named upstream を、drain / disable / weight override する運用画面
     です（第5章）。
7. **Sites**
   - site ownership と TLS binding を編集する画面です（第15章）。
8. **Cache Rules / Country Block / Rate Limit / Bot Defense / Semantic Security
   / IP Reputation / Notifications**
   - 各種リクエスト境界の制御を扱う画面です。第7〜9章で順次扱います。
9. **vhosts**
   - PHP-FPM / PSGI の Runtime Apps を編集する画面です（第10〜11章）。
10. **Scheduled Tasks**
    - scheduled jobs を編集・実行する画面です（第12章）。
11. **Options / Settings**
    - listener / admin / storage / paths などの product-wide 設定を編集します。
      `app_config_*` テーブルに保存されます（付録A）。
12. **FP Tuner**
    - WAF 誤検知を AI 助言で削減する FP Tuner の操作画面です（第8章）。

第2章の preview では、すべての画面を細かく操作する必要はありません。「どの章で
どの画面が出てくるか」を、UI で軽く下見しておくのが目的です。

## 2.7　Preview の停止と片付け

preview を止めるときは次のコマンドを使います。

```bash
make gateway-preview-down
```

`GATEWAY_PREVIEW_PERSIST=1` を指定していなければ、ここで preview 用 DB と設定
ファイルがクリアされます。次回 `make gateway-preview-up` を叩くと、また clean な
状態から始まります。

## 2.8　Preview から本番へ向かう前に

preview が動いたら、次の 2 点を意識しながら第3章以降に進んでください。

1. preview と本番では、**起動経路が異なります**。本番は systemd ユニット
   またはコンテナで起動し、`data/conf/config.json` と DB row が正本になります。
   preview のように毎回 DB を初期化しません。
2. preview と本番で**共通**なのは、**DB が runtime authority であるという
   構造**です。preview で UI から触った設定は、本番 deployment でも
   同じ画面・同じテーブルに対する操作になります。

第3章では、systemd 配備の場合に `make install TARGET=linux-systemd` が
具体的に何をするか、第4章ではコンテナ配備の Tier 区分と典型 topology を扱います。
preview で UI に触れた感覚を持ったまま読むと、設定 key の意味がつかみやすく
なります。
