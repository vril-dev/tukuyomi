[English](device-auth-enrollment.md) | [日本語](device-auth-enrollment.ja.md)

# IoT ／ Edge デバイス登録

この文書は、Tukuyomi Gateway から Tukuyomi Center へデバイス識別子を登録する、現在の登録ワークフローをまとめたものです。

現時点の実装は、Gateway が所有するデバイス識別子を Center 承認付きで登録し、承認後に Gateway が署名付きの設定スナップショットを Center へ送信するところまでです。すべての Web ／ VPS 配備で IoT ／ Edge モードを有効化することを意図したものではありません。
エッジ／デバイス向けの制御が必要な配備でのみ有効にしてください。

## 役割

- Center は登録トークンを発行し、保留中のデバイス登録申請を承認または拒否します
- Gateway はローカルのデバイス識別子、秘密鍵、登録申請を所有します
- 登録トークンは一時的な登録用シークレットです。Gateway は Center へ一度送信するだけで、ローカルには保存しません

## 運用フロー

1. Center を起動する、または開く
2. `Device Approvals` を開く
3. `Create enrollment token` で登録トークンを作成する
4. トークンをすぐに控える。Center はトークン全体を再表示しません
5. Gateway の `Options` を開く
6. `IoT / Edge Mode` を有効にする
7. モードを保存し、Gateway を再起動して稼働中プロセスに `edge.enabled=true` を読み込ませる
8. `Center Enrollment` に Center の URL と登録トークンを入力する
9. 固定の ID が必要でなければ、`Device ID` は空のままにする
10. 複数の鍵を意図的に管理しない限り、`Key ID` は `default` のままにする
11. `Request Center approval` を実行する
12. Center の `Device Approvals` へ戻る
13. 保留中のデバイスを承認、または拒否する

申請送信後、Gateway のステータスは Center で承認されるまで `pending` になります。

`edge.enabled=true` かつデバイス承認が必須となっている場合、Gateway の公開プロキシは、ローカルにキャッシュされた Center ステータスが `approved` のときのみ開きます。`pending`、`rejected`、`revoked`、`product_changed`、`failed`、未知、識別子が未設定の状態では、プロキシのリクエスト経路は `503` を返します。通常の Web ／ VPS 配備では `IoT / Edge Mode` を OFF のままにするため、影響は受けません。

Center でデバイスを承認した後、Gateway は Center をポーリングしてローカルキャッシュのステータスを更新します。既定の間隔は 30 秒で、`edge.device_auth.status_refresh_interval_sec` で調整できます。`0` を指定した場合のみ手動更新になります。即座に反映したい場合は、Gateway の `Options > Center Enrollment` で `Check Center status` を実行してください。このステータス経路は、今後の承認解除や、product ID ／トークンの切り替えにも使用します。現在の認可状態は Center が所有しており、Gateway は更新後のステータスが `approved` 以外であれば、プロキシをロックします。

## プレビュー URL

fleet プレビューで、Gateway 設定と Center のトークン／承認状態を再起動後も保持したい場合は、両方のプレビュー DB を永続化します。

```bash
GATEWAY_PREVIEW_PERSIST=1 CENTER_PREVIEW_PERSIST=1 make fleet-preview-up
```

Gateway がプレビューコンテナ内で動作している場合、Center URL に `http://localhost:9092` を指定しないでください。Gateway コンテナ内の `localhost` は、Gateway 自身を指してしまいます。

プレビューでは、ホスト側から到達可能な Center URL を使用します。

```text
http://host.docker.internal:9092
```

Docker ランタイムが `host.docker.internal` を提供しない場合は、プレビュー／コンテナ側に host-gateway マッピングを設定するか、到達可能な Center のアドレスを指定してください。

## Center URL のルール

Gateway が受け付ける Center URL は HTTP または HTTPS です。userinfo のクレデンシャルは指定できません。パスは空、`/`、または `/v1/enroll` のいずれかのみ受け付けます。
Gateway は登録申請の送信先を、Center の `/v1/enroll` へ正規化します。

ローカルプレビューや信頼済みテストネットワーク以外では、HTTPS を使用してください。

## 識別子とフィンガープリント

ローカル識別子が存在しない場合、Gateway は Ed25519 鍵ペアを生成します。
秘密鍵は Gateway の DB に保存され、公開鍵は登録申請として Center へ送信されます。

`Public key fingerprint` は次の形式です。

```text
Ed25519 public key
 -> x509 PKIX DER
 -> SHA-256
 -> lowercase hex
```

Ed25519 の生 32 バイトではなく、PKIX DER の公開鍵バイト列の SHA-256 ハッシュです。

## ローカル識別子の制約

Gateway は現在、1 つのローカルデバイス識別子のみを所有します。ローカル識別子が既に存在する場合、後続の登録申請でも同じ `Device ID` と `Key ID` を使用する必要があります。
異なる値を指定した場合、デバイス秘密鍵を黙って差し替えることを避けるため、Gateway は申請を拒否します。

## トークンの取り扱い

- 登録トークンはシークレットとして扱ってください
- 出荷バッチやロールアウトバッチでは、有効期限が短い、もしくは利用回数が少ないトークンを推奨します
- ロールアウトのウィンドウが終了したトークンは revoke してください
- 登録トークンを revoke すると、そのトークンで承認済みとなった登録済みデバイスも `revoked` になります。Center は監査用にデバイスレコードを残しますが、Gateway は次回の `Check Center status` 後にプロキシのトラフィックをロックします。同じトークンに紐づく保留中の登録申請も同時に reject されるため、後から承認されることはありません
- Gateway は Center URL とローカルの識別子状態を保存しますが、登録トークンは保存しません
- 登録トークンは登録時の証明用です。実行時の認可は、Gateway がキャッシュしている Center のデバイスステータスで判定します

## ステータスポーリング

Gateway はプロキシのリクエストごとに Center へ問い合わせを行いません。リクエスト経路ではローカルキャッシュ済みのデバイスステータスだけを参照します。バックグラウンドのポーラーは、次の条件をすべて満たす場合のみ、上限付きの間隔でそのキャッシュを更新します。

- `edge.enabled=true`
- `edge.device_auth.enabled=true`
- `edge.device_auth.status_refresh_interval_sec > 0`
- ローカルにデバイス識別子が存在する
- ローカル識別子に Center URL が設定されている

ポーラーは起動時に 1 回即時実行され、登録申請の成功直後にも即時に起動されます。
そのため、新規登録済みの Gateway が初回の Center ステータスチェックまで、設定間隔全体を待つことはありません。

承認や revoke を操作しながら確認する場合は短い間隔を、多数の Gateway を 1 つの Center に集約する場合は長めの間隔を設定してください。

## 設定スナップショットの同期

更新後の Center ステータスが `approved` の場合、Gateway は現在の Gateway 設定から、上限付きでマスク済みの JSON スナップショットを作成し、同じ署名付きデバイスチャネルで Center へ送信します。
スナップショットはリビジョンが変化した場合のみ送信されます。

この同期は、プロキシのホットパスから切り離されています。

- Gateway はリクエストごとに Center へ問い合わせを行いません
- プロキシのリクエスト経路は、ローカルキャッシュの承認状態のみを参照します
- スナップショットの送信は、承認後の Center ステータス更新の経路で実行されます
- スナップショットの送信に失敗した場合、Gateway のデバイス認証ステータスにエラーを記録しますが、デバイス承認を迂回したり、プロキシのトラフィックをアンロックしたりはしません

Center は登録済みデバイスごとに最新のスナップショットを保持します。デバイスがスナップショットを送信済みであれば、Center の `Device Approvals > Registered devices > Manage > Config download` からダウンロードできます。

スナップショットのペイロードは 2 MiB が上限です。fleet 検査に必要なランタイム／設定ドメインは含めますが、登録トークンやローカルのデバイス秘密鍵は含めません。

## トラブルシューティング

- `localhost:9092` で `connect: connection refused`: Gateway がコンテナ内で自分自身へ接続しようとしています。`host.docker.internal:9092` または到達可能な Center のアドレスを使用してください
- `edge device authentication is not enabled in the running process`: `IoT / Edge Mode` を保存後に、Gateway を再起動してください
- `enrollment token is required`: Center で作成したトークンを、Gateway の `Center Enrollment` に貼り付けてください
- `invalid enrollment token`: トークンが誤っている、revoke 済み、期限切れ、利用回数の上限に到達済み、または別の Center DB のトークンです
- `local device identity already exists with a different device_id/key_id`: 既存のローカル識別子の値を使うか、意図的にローカル Gateway の識別子状態をリセットしてください

登録用の `make` コマンドはまだ用意していません。現状サポートしているオペレーターの操作起点は、Gateway の `Options > Center Enrollment`、またはその画面が使用する管理 API です。
