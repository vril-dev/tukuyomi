[English](device-auth-enrollment.md) | [日本語](device-auth-enrollment.ja.md)

# IoT / Edge デバイス登録

この文書は、Tukuyomi Gateway から Tukuyomi Center へ device identity を登録する
現在の enrollment workflow をまとめます。

現時点の実装は、Gateway が所有する device identity を Center 承認付きで登録する
範囲です。すべての Web/VPS deployment で IoT / Edge mode を有効にするものでは
ありません。edge/device 向け control が必要な deployment だけ有効にしてください。

## 役割

- Center は enrollment token を発行し、pending の device enrollment request を承認または拒否します。
- Gateway は local device identity、private key、enrollment request を所有します。
- enrollment token は一時的な登録 secret です。Gateway は Center へ一度送信するだけで、ローカルには保存しません。

## 運用フロー

1. Center を起動または開く
2. `Device Approvals` を開く
3. `Create enrollment token` で enrollment token を作成する
4. token をすぐ控える。Center は full token を再表示しません
5. Gateway の `Options` を開く
6. `IoT / Edge Mode` を有効にする
7. mode を保存し、Gateway を再起動して実行中 process に `edge.enabled=true` を読み込ませる
8. `Center Enrollment` に Center URL と enrollment token を入力する
9. 固定の ID が必要でなければ `Device ID` は空のままにする
10. 複数 key を意図的に管理しない限り `Key ID` は `default` のままにする
11. `Request Center approval` を実行する
12. Center の `Device Approvals` へ戻る
13. pending device を承認または拒否する

申請送信後、Gateway の status は Center で承認されるまで `pending` になります。

`edge.enabled=true` かつ device approval が必須の場合、Gateway の public proxy は
local Center status が `approved` のときだけ開きます。`pending`、`rejected`、
`revoked`、`product_changed`、`failed`、unknown、identity 未設定の場合、proxy の
request path は `503` を返します。通常の Web/VPS deployment は `IoT / Edge Mode`
を OFF のままにするため影響を受けません。

Center で device を承認した後、Gateway は Center を polling して local cache の status を
更新します。default interval は 30 秒で、`edge.device_auth.status_refresh_interval_sec`
で調整します。`0` にした場合だけ手動 refresh になります。すぐ反映したい場合は Gateway の
`Options > Center Enrollment` で `Check Center status` を実行してください。この status
経路は今後の承認解除や product ID / token 切り替えにも使います。現在の authorization state
は Center が所有し、Gateway は refresh 後に `approved` 以外の status なら proxy をロックします。

## Preview URL

fleet preview で Gateway 設定と Center token / approval 状態を再起動後も残す場合は、
両方の preview DB を永続化します。

```bash
GATEWAY_PREVIEW_PERSIST=1 CENTER_PREVIEW_PERSIST=1 make fleet-preview-up
```

Gateway が preview container 内で動いている場合、Center URL に
`http://localhost:9092` を指定しないでください。Gateway container 内の
`localhost` は Gateway 自身を指します。

preview では、host 側から到達できる Center URL を使います。

```text
http://host.docker.internal:9092
```

Docker runtime が `host.docker.internal` を提供しない場合は、preview/container 側に
host-gateway mapping を設定するか、到達可能な Center address を指定してください。

## Center URL ルール

Gateway が受け付ける Center URL は HTTP または HTTPS です。userinfo credential は
指定できません。path は空、`/`、または `/v1/enroll` のみ受け付けます。
Gateway は enrollment request の送信先を Center の `/v1/enroll` へ正規化します。

local preview や信頼済み test network 以外では HTTPS を使ってください。

## Identity と Fingerprint

local identity が存在しない場合、Gateway は Ed25519 key pair を生成します。
private key は Gateway DB に保存され、public key は enrollment request で Center へ送られます。

`Public key fingerprint` は次の形式です。

```text
Ed25519 public key
 -> x509 PKIX DER
 -> SHA-256
 -> lowercase hex
```

raw の Ed25519 32 bytes ではなく、PKIX DER public key bytes の SHA-256 hash です。

## Local Identity の制約

Gateway は現在 1 つの local device identity を所有します。local identity が既にある場合、
後続の enrollment request は同じ `Device ID` と `Key ID` を使う必要があります。
別値を指定した場合、device private key を黙って差し替えないため Gateway は拒否します。

## Token の扱い

- enrollment token は secret として扱ってください。
- factory batch や rollout batch では、短期限または低 use count の token を推奨します。
- rollout window が終わった token は revoke してください。
- enrollment token を revoke すると、その token で承認済みになった registered device も
  `revoked` になります。Center は監査用に device record を残しますが、Gateway は次回
  `Check Center status` 後に proxy traffic をロックします。同じ token の pending
  enrollment request も同時に reject されるため、後から承認されることはありません。
- Gateway は Center URL と local identity state を保存しますが、enrollment token は保存しません。
- enrollment token は登録時の proof です。runtime authorization は Gateway が cache する
  Center device status で判断します。

## Status Polling

Gateway は proxy request ごとに Center へ問い合わせません。request path は local に cache
された device status だけを参照します。background poller は次の条件をすべて満たす場合だけ
その cache を bounded interval で更新します。

- `edge.enabled=true`
- `edge.device_auth.enabled=true`
- `edge.device_auth.status_refresh_interval_sec > 0`
- local device identity が存在する
- local identity に Center URL が設定されている

poller は起動時に 1 回即時実行し、enrollment request 成功直後にも即 wake されます。
そのため、新規登録済み Gateway が初回 Center status check まで interval 全体を待つことはありません。

承認や revoke を操作しながら確認する場合は短い interval、多数の Gateway を 1 つの Center
へ集約する場合は長めの interval にしてください。

## Troubleshooting

- `localhost:9092` で `connect: connection refused`: Gateway が container 内で自分自身へ接続しています。`host.docker.internal:9092` または到達可能な Center address を使ってください。
- `edge device authentication is not enabled in the running process`: `IoT / Edge Mode` を保存後、Gateway を再起動してください。
- `enrollment token is required`: Center で作成した token を Gateway の `Center Enrollment` に貼り付けてください。
- `invalid enrollment token`: token が誤り、revoke 済み、期限切れ、use count 上限到達、または別 Center DB の token です。
- `local device identity already exists with a different device_id/key_id`: 既存 local identity の値を使うか、意図的に local Gateway identity state を reset してください。

enrollment 用の `make` コマンドはまだありません。現在の supported operator entrypoint は
Gateway の `Options > Center Enrollment`、またはその画面が使う admin API です。
