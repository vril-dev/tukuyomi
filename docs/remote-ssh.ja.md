# Remote SSH

Remote SSH は、Gateway にインバウンドポートを公開せず、承認済み Gateway へ
短時間の保守セッションを開くための機能です。

運用者の操作方法は 2 つあります。

- **Web Terminal**: Center UI からブラウザー上のターミナルを開く、通常の対話操作向けの方法です。
- **CLI handoff**: `tukuyomi remote-ssh` を使い、手元の SSH クライアントから接続する方法です。緊急対応、自動化、手元の SSH 設定を使いたい場合のために残しています。

どちらも、Center のセッション管理、Gateway から Center へのアウトバウンド接続、デバイスポリシー、TTL、監査ログを同じ仕組みで使います。

## セキュリティモデル

- Remote SSH は、Center と Gateway の両方で既定では無効です。
- Center は、承認済みデバイス、有効なデバイスポリシー、接続理由、TTL、認証済みの管理者セッションまたはトークンを要求します。
- Gateway は、固定された Center の Ed25519 署名鍵で署名された待機中セッションだけを受け付けます。
- Gateway は Center へアウトバウンド接続し、`tukuyomi` プロセス内の組み込み SSH サーバーを使ってセッションを処理します。
- Web Terminal は Center が管理する使い捨て Ed25519 運用者鍵を使い、ブラウザーの WebSocket 経由で PTY の入出力を中継します。
- CLI 接続では、`tukuyomi remote-ssh` が生成する使い捨て Ed25519 公開鍵を使います。
- CLI は Center 経由で Gateway の SSH ホスト公開鍵を取得し、一時的な `known_hosts` を作成してから、実行すべき SSH コマンドを表示します。
- Center と CLI は、Remote SSH で既定では HTTPS を要求します。HTTP は、ローカル検証用の明示的なオプションを指定した場合だけ利用できます。
- Gateway は `remote_ssh.gateway.embedded_server.run_as_user` が未設定の場合、root としてシェルを起動しません。
- Gateway は `tukuyomi` プロセスの環境変数をそのまま引き継がず、最小限の環境でシェルを起動します。
- ポート転送、SFTP、SCP、SSH エージェント転送、任意の SSH サブシステムは有効化しません。

## 設定

Center 側の例:

```json
{
  "edge": {
    "enabled": true
  },
  "remote_ssh": {
    "center": {
      "enabled": true,
      "max_ttl_sec": 900,
      "idle_timeout_sec": 300,
      "max_sessions_total": 16,
      "max_sessions_per_device": 1
    }
  }
}
```

Gateway 側では、まず認証済みの Center 管理者セッションから Center の署名公開鍵を取得します。

```sh
curl "$CENTER/center-api/remote-ssh/signing-key" \
  -H "Authorization: Bearer $TUKUYOMI_ADMIN_TOKEN"
```

返ってきた `public_key` を、各 Gateway の `remote_ssh.gateway.center_signing_public_key` に設定します。

```json
{
  "edge": {
    "enabled": true
  },
  "remote_ssh": {
    "gateway": {
      "enabled": true,
      "center_signing_public_key": "ed25519:REPLACE_WITH_CENTER_PUBLIC_KEY",
      "center_tls_ca_bundle_file": "conf/center-ca.pem",
      "center_tls_server_name": "center.example.local",
      "embedded_server": {
        "enabled": true,
        "shell": "/bin/sh",
        "working_dir": "/",
        "run_as_user": "tukuyomi"
      }
    }
  }
}
```

この署名公開鍵が設定されていない Gateway は、Remote SSH セッションを受け付けません。

Center がパブリック CA または ACME の証明書を使っている場合、
`center_tls_ca_bundle_file` は省略できます。閉域網や自己署名証明書を使う場合は、
Center CA 証明書を PEM バンドルに入れて各 Gateway へ配布してください。
Gateway が IP アドレスで Center へ接続し、証明書は DNS 名で発行されている場合は、
`center_tls_server_name` を指定します。

Center-protected Gateway を初期設定する場合は、同じ信頼設定を Gateway 設定へ書き込めます。

```sh
tukuyomi bootstrap-center-protected-gateway \
  --center-url "https://center.example.local" \
  --center-ca-bundle "conf/center-ca.pem" \
  --center-server-name "center.example.local"
```

## Center UI での操作

![Center の Remote SSH 画面](images/ui-samples/28-center-remote-ssh.png)

1. `Device Approvals` を開きます。
2. 登録済み Gateway を選び、`Manage` を開きます。
3. 選択中デバイスのメニューから `Remote SSH` を開きます。
4. `Center service` が有効であることを確認します。
5. デバイスポリシーを有効化し、`Max TTL seconds` を設定して保存します。
6. `Web terminal` に接続理由と TTL を入力します。
7. ブラウザー側に残すスクロールバック行数を変えたい場合は、`Scrollback rows` を調整します。
8. `Open terminal` を押します。

Center は、待機中の Remote SSH セッションを作成します。ブラウザーの WebSocket 接続はすぐ開きますが、Gateway が次回の署名付きステータスのポーリングでそのセッションを取得するまで待機します。ポーリング間隔が 30 秒の場合、最大でおおむねポーリング 1 回分と SSH 接続準備分の待ち時間が発生します。

Gateway が接続すると、ターミナルに `Terminal connected.` と表示され、PTY を操作できるようになります。

開いている Web Terminal は `Close terminal` で閉じます。Sessions の表には最近のセッションが表示され、`active` または `pending` のセッションはステータス欄から強制終了できます。

`Scrollback rows` は、ブラウザーが保持するターミナルの過去行数です。サーバー側に操作内容を記録する機能ではありません。操作内容を永続的に残す必要がある場合は、別途監査記録機能として設計してください。

## CLI での操作

Center API からデバイスポリシーを有効化します。

```sh
curl -X PUT "$CENTER/center-api/devices/$DEVICE/remote-ssh/policy" \
  -H "Authorization: Bearer $TUKUYOMI_ADMIN_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"enabled":true,"max_ttl_sec":900,"require_reason":true,"allowed_run_as_user":"tukuyomi"}'
```

手元の運用端末でトンネルを起動します。

```sh
export TUKUYOMI_ADMIN_TOKEN="$TOKEN"
tukuyomi remote-ssh \
  --center "https://center.example.com" \
  --center-ca-bundle "conf/center-ca.pem" \
  --center-server-name "center.example.local" \
  --device "$DEVICE" \
  --reason "maintenance"
```

このコマンドは、実際に使うローカルの `ssh` コマンドを表示します。SSH セッションが有効な間は、`tukuyomi remote-ssh` を起動したままにしてください。

Center がパブリック CA の証明書を使い、URL のホスト名と証明書が一致している場合は、
`--center-ca-bundle` と `--center-server-name` を省略できます。

HTTP の Center URL を使うローカル検証では、`--allow-insecure-http` を指定するか、
`TUKUYOMI_REMOTE_SSH_ALLOW_INSECURE_HTTP=1` を設定します。本番 Gateway では使わないでください。

## 運用上の注意

- Remote SSH のセッション取得は、Gateway から Center へのステータスのポーリング間隔に依存します。`Open terminal` 後に短い待ち時間が出るのは正常です。ポーリング間隔を大きく超えて待ち続ける場合は、異常として調査してください。
- TTL に到達すると、ターミナルが開いたままでもセッションは閉じます。
- 通信が止まったセッションは、アイドルタイムアウトで閉じます。
- Center からセッションを強制終了すると、接続中の Web Terminal または CLI の中継接続は閉じられ、デバイスごとのセッション上限も解放されます。
- Center の署名鍵をローテーションした場合は、Gateway 側の信頼設定を更新する必要があります。Center 管理下の承認済み Gateway は、承認元の Center から鍵を更新できます。
