# 第16章　IoT / Edge デバイス登録

第VI部の最後の章では、tukuyomi が optional として持っている **IoT / Edge
デバイス登録（device-auth-enrollment）** を扱います。これは、Tukuyomi
Gateway から **Tukuyomi Center へ device identity を登録する** ための
ワークフローで、edge / device 向けの control が必要な deployment 向けの
機能です。

## 16.1　この機能を有効にすべき範囲

最初に大事な前置きです。

> **すべての Web / VPS deployment で IoT / Edge mode を有効にする必要は
> ありません。**

通常の Web / VPS deployment は、`IoT / Edge Mode` を **OFF のまま** で
構いません。本章で扱う device authentication / Center 承認は、

- 工場出荷後に設置場所で identity を取得する **edge ゲートウェイ**
- 多数の **IoT デバイス** を中央承認のもとで運用する **fleet 管理**

といった、deployment 単位で **device identity を中央で確認したい** ケースの
ための機能です。Web の前段に WAF + reverse proxy として置く一般用途では、
本章の手順は読み飛ばして構いません。

![Center login 画面](../../images/ui-samples/22-center-login.png)

## 16.2　役割

仕組みを動かす登場人物は次の 3 つです。

- **Center**
  - **enrollment token** を発行する
  - pending な device enrollment request を **承認または拒否** する
- **Gateway**
  - **local device identity**、**private key**、**enrollment request** を
    所有する
- **enrollment token**
  - 一時的な登録 secret
  - Gateway は Center へ **一度送信するだけ** で、ローカルには保存しない

`Gateway` が「**自分は誰か（identity）**」を所有し、`Center` が「**この
Gateway を信用するかどうか**」を決める、という分担です。

## 16.3　運用フロー

`Center` 側と `Gateway` 側を行ったり来たりするので、順番を間違えないよう
注意してください。

![Center の Device Approvals 画面](../../images/ui-samples/24-center-device-approvals.png)

1. Center を起動または開く
2. `Device Approvals` を開く
3. **`Create enrollment token`** で enrollment token を作成する
4. **token をすぐ控える**。Center は full token を再表示しない
5. Gateway の `Options` を開く
6. **`IoT / Edge Mode` を有効** にする
7. mode を保存し、**Gateway を再起動** して実行中 process に
   `edge.enabled=true` を読み込ませる
8. `Center Enrollment` に **Center URL** と **enrollment token** を入力する
9. 固定の ID が必要でなければ `Device ID` は **空のまま** にする
10. 複数 key を意図的に管理しない限り `Key ID` は **`default` のまま** に
    する
11. **`Request Center approval`** を実行する
12. Center の `Device Approvals` へ戻る
13. pending device を **承認または拒否** する

申請送信後、Gateway の status は Center で承認されるまで **`pending`** に
なります。

### 16.3.1　承認済みになるまで proxy はロックされる

`edge.enabled=true` かつ device approval が必須の場合、**Gateway の public
proxy は local Center status が `approved` のときだけ開きます**。

具体的には、次のいずれかの状態では proxy の request path は **`503` を返し
ます**。

- `pending`
- `rejected`
- `revoked`
- `product_changed`
- `failed`
- unknown
- identity 未設定

通常の Web / VPS deployment は `IoT / Edge Mode` を OFF のままにするため、
この `503` には **当たりません**。

### 16.3.2　承認後のステータス更新

![Center の Status 画面](../../images/ui-samples/23-center-status.png)

Center でデバイスを承認したあとは、Gateway が Center をポーリングし、
ローカルにキャッシュしているデバイスステータスを更新します。既定の間隔は
30 秒です。すぐ反映したい場合は、Gateway の `Options > Center Enrollment`
に戻り、**`Check Center status`** を実行してください。Gateway は Center へ
**署名付きステータスリクエスト** を送り、ローカルキャッシュを更新します。

このステータス更新経路は、今後の **承認解除** や **product ID / token
切り替え** にも使います。現在の認可状態は **Center が所有** します。
Gateway は更新後のステータスが `approved` 以外であれば、プロキシを
**ロック** します。

### 16.3.3　Center 管理のデバイス画面

登録済みデバイスを管理するには、**`Device Approvals > Registered devices > Manage`** を開きます。
対象デバイスを選択すると、左メニューの `Device Approvals` 配下に、そのデバイス専用の管理画面が表示されます。

![Center の Device Status 画面](../../images/ui-samples/26-center-device-status.png)

`Device Status` では、承認状態、最後のステータス確認時刻、Gateway から報告されたプラットフォーム情報、設定スナップショットの履歴を確認できます。
snapshot table には、マスク済みの Gateway JSON payload が上限付きで保存され、必要に応じて表示またはダウンロードできます。

この Center snapshot は、Gateway Status の `Download config` で取得するファイルとは別物です。Status export は seed／restore 用の `config-bundle.json` artifact で、Center snapshot はデバイス identity、revision metadata、domain ごとの `etag`／`raw` を持つ署名付き fleet status payload です。

![Center の Runtime 画面](../../images/ui-samples/27-center-runtime.png)

`Runtime` では、Gateway から報告された platform target に対応するランタイム配布物を管理します。Center は、その target 向けに PHP-FPM または PSGI のランタイム配布物を build し、圧縮済み artifact として保存したうえで Gateway に割り当てることができます。
同じ platform target 向けの artifact がすでに作成済みであれば、再ビルドせずに既存の artifact を選択して割り当てることもできます。

Runtime の変更は、Center UI/API の操作だけでは Gateway に即時反映されません。Center には **pending runtime requests** として登録され、Gateway が署名付きステータスポーリングで取得したタイミングで処理されます。
Gateway は、受け取った変更要求の artifact metadata と platform target を検証し、圧縮済み artifact をダウンロードしたうえで、Gateway ローカルの runtime をインストールまたは削除します。pending request は、Gateway が取得する前であれば Center から取り消せます。
runtime の削除は、Center と Gateway の両側で安全確認を行います。Center UI は最新の runtime inventory をもとに危険な削除要求を無効化し、Gateway 側でも local runtime file を削除する直前に、Runtime App からの参照と実行中プロセスの有無を再確認します。

## 16.4　Preview URL

fleet preview で Gateway 設定と Center token / approval 状態を再起動後も
残したい場合は、**両方の preview DB を永続化** します。

```bash
GATEWAY_PREVIEW_PERSIST=1 CENTER_PREVIEW_PERSIST=1 make fleet-preview-up
```

`INSTALL_ROLE=center-protected` と同じ topology を preview する場合は、Center
protected preview を有効にします。

```bash
CENTER_PROTECTED_PREVIEW=1 \
GATEWAY_PREVIEW_PERSIST=1 \
CENTER_PREVIEW_PERSIST=1 \
make fleet-preview-up
```

この mode では、Center は別 process のまま動き、Gateway が `/center-ui` と
`/center-api` を共有 Docker preview network 上の Center へ転送する route を
seed します。Center は Gateway 経由の `http://localhost:9090/center-ui` から
開きます。protected preview では Gateway の IoT / Edge mode も有効化し、preview
Center DB に対する Center 承認も bootstrap します。

Center process 側の API path を非公開名にする場合は、
`CENTER_PREVIEW_GATEWAY_API_BASE_PATH` は Gateway で公開する path のままにし、
`CENTER_PREVIEW_API_BASE_PATH` に Center 側 path を指定します。Gateway は公開 route
を Center 側 path へ rewrite してから転送します。

`GATEWAY_PREVIEW_PERSIST=1` の場合、この protected route は Gateway preview
DB が作成されるタイミングでのみ seed されます。既存の永続 Gateway preview
DB がすでにある場合は、その preview DB をリセットするか、`Proxy Rules` から
route を追加してください。

Gateway が preview container 内で動いている場合、**Center URL に
`http://localhost:9092` を指定しない** でください。Gateway container 内の
`localhost` は **Gateway 自身を指す** からです。

preview では、host 側から到達できる Center URL を使います。

```text
http://host.docker.internal:9092
```

Docker runtime が `host.docker.internal` を提供しない場合は、preview /
container 側に **host-gateway mapping を設定** するか、到達可能な Center
address を指定してください。

## 16.5　Center URL ルール

Gateway が受け付ける Center URL には、いくつかの制約があります。

- **HTTP または HTTPS** のみ
- **userinfo credential は指定不可**
- path は **空 / `/` / `/v1/enroll` のみ** 受け付ける
- Gateway は enrollment request の送信先を Center の **`/v1/enroll`** へ
  正規化する

local preview や信頼済み test network 以外では、**HTTPS を使ってください**。

## 16.6　Identity と Fingerprint

local identity が存在しない場合、Gateway は **Ed25519 key pair** を生成
します。

- **private key**: Gateway DB に保存
- **public key**: enrollment request で Center へ送る

`Public key fingerprint` は次の形式です。

```text
Ed25519 public key
 -> x509 PKIX DER
 -> SHA-256
 -> lowercase hex
```

つまり、**raw の Ed25519 32 bytes ではなく、PKIX DER public key bytes の
SHA-256 hash** です。Center 側でも同じ計算で fingerprint を確認できる
ように、形式が固定されています。

## 16.7　Local Identity の制約

Gateway は現在、**1 つの local device identity** を所有します。local
identity がすでにある場合、後続の enrollment request は **同じ `Device ID`
と `Key ID`** を使う必要があります。

別値を指定した場合、Gateway は **device private key を黙って差し替えない**
ため、enrollment request を **拒否** します。これは「気づかないうちに鍵が
入れ替わる」事故を防ぐための設計です。

## 16.8　Token の扱い

enrollment token を扱うときの方針は次のとおりです。

- enrollment token は **secret として扱う**
- factory batch や rollout batch では、**短期限または低 use count** の token
  を推奨
- rollout window が終わった token は **revoke する**
- **Gateway は Center URL と local identity state を保存するが、enrollment
  token は保存しない**
- enrollment token は **登録時の proof** であり、**runtime authorization
  は Gateway が cache する Center device status で判断する**

つまり、enrollment token は「**最初の登録 1 回限りの鍵**」であり、その後の
authorization 判定には使われない、という分離です。

## 16.9　Troubleshooting

実運用でよく見るエラーと対処を、まとめておきます。

| 症状 | 原因と対処 |
|---|---|
| `localhost:9092` で `connect: connection refused` | Gateway が container 内で自分自身へ接続している。**`host.docker.internal:9092`** または到達可能な Center address を使う |
| `edge device authentication is not enabled in the running process` | `IoT / Edge Mode` を保存後、**Gateway を再起動** していない |
| `enrollment token is required` | Center で作成した token を Gateway の **`Center Enrollment`** に貼り付けていない |
| `invalid enrollment token` | token が誤り / revoke 済み / 期限切れ / use count 上限到達 / 別 Center DB の token のいずれか |
| `local device identity already exists with a different device_id/key_id` | 既存 local identity の値を使うか、意図的に **local Gateway identity state を reset** する |

通常の外部 Center 登録では、supported operator entrypoint は Gateway の
**`Options > Center Enrollment`** 画面、または同画面が使う admin API です。
`INSTALL_ROLE=center-protected` と `CENTER_PROTECTED_PREVIEW=1` は同一 owner の
ローカル構成だけの例外で、enrollment token なしに Gateway identity と Center
承認を bootstrap します。

## 16.10　ここまでの整理

- 通常の Web / VPS deployment では **IoT / Edge Mode は OFF のまま**。
- enrollment は **Center が token 発行 → Gateway が申請 → Center が承認**
  の 3 ステップ。
- `edge.enabled=true` かつ未承認なら、Gateway の **public proxy は `503`** を
  返す。
- Gateway は **Ed25519 key pair** を local 生成。fingerprint は **PKIX DER
  → SHA-256 → lowercase hex**。
- enrollment token は **登録時の proof のみ**。runtime authorization は
  Center 由来の device status で行う。

## 16.11　次章への橋渡し

第VI部はこれで終わりです。第VII部「性能と回帰検証」では、tukuyomi が
標準で持っている **benchmark と回帰確認の枠組み** を扱います。第17章では、
`make bench-proxy` / `make bench-waf` / `make smoke` 系の役割と保証
マトリクス、release-binary smoke、推奨される confidence ladder までを
整理します。
