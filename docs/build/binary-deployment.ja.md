# Binary Deployment

この手順は、Linux ホスト上でバイナリを `systemd` 管理で動かす前提です。

想定環境:

- オンプレ Linux サーバ
- VPS
- VM
- EC2

## Build

作業端末または build host で実行:

```bash
make setup
make ui-build-sync
make go-build
```

生成物は `bin/tukuyomi` です。

repo 上で手順どおりの smoke を再実行したい場合は、次を使います。

```bash
make binary-deployment-smoke
```

注意:

- build-time の管理UI値は `VITE_APP_BASE_PATH` と `VITE_CORAZA_API_BASE` だけです
- 管理 secret は server 側に残し、browser は起動後に `/tukuyomi-api/auth/login` で same-origin session cookie を取得します

## 実行レイアウト

バイナリは、作業ディレクトリ配下に次を前提とします。

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/rules/
/opt/tukuyomi/logs/
```

最低限必要な config:

- `conf/cache.conf`
- `conf/waf.bypass`
- `conf/country-block.conf`
- `conf/rate-limit.conf`
- `conf/bot-defense.conf`
- `conf/semantic.conf`
- `conf/notifications.conf`
- `rules/tukuyomi.conf`
- `rules/crs/crs-setup.conf`
- `rules/crs/rules/*.conf`

任意または自動生成:

- `conf/log-output.json` は無ければ初回起動時に生成されます
- `conf/crs-disabled.conf` は空で開始でき、CRS toggle 操作時に書き込まれます

配置例:

```bash
sudo install -d -m 755 /opt/tukuyomi/bin /opt/tukuyomi/conf /opt/tukuyomi/rules /opt/tukuyomi/logs/coraza /opt/tukuyomi/logs/nginx
sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo rsync -a data/conf/ /opt/tukuyomi/conf/
sudo rsync -a data/rules/ /opt/tukuyomi/rules/
sudo touch /opt/tukuyomi/conf/crs-disabled.conf
```

## Environment File

`/etc/tukuyomi/tukuyomi.env` のような env file を使います。

template:

- [tukuyomi.env.example](tukuyomi.env.example)

最低限見直す値:

- `WAF_APP_URL`
- `WAF_RULES_FILE`
- `WAF_BYPASS_FILE`
- `WAF_API_KEY_PRIMARY`
- `WAF_API_KEY_SECONDARY`
- `WAF_ADMIN_SESSION_SECRET`
- `WAF_ADMIN_SESSION_TTL_SEC`
- `WAF_UI_BASEPATH`
- `WAF_API_BASEPATH`
- `WAF_TRUSTED_PROXY_CIDRS`
- `WAF_COUNTRY_HEADER_NAMES`
- `WAF_FORWARD_INTERNAL_RESPONSE_HEADERS`
- `WAF_LOG_OUTPUT_FILE`
- `WAF_CRS_ENABLE`
- `WAF_CRS_SETUP_FILE`
- `WAF_CRS_RULES_DIR`
- `WAF_CRS_DISABLED_FILE`
- `WAF_STORAGE_BACKEND`
- `WAF_DB_DRIVER`
- `WAF_DB_DSN` または `WAF_DB_PATH`
- `WAF_ADMIN_EXTERNAL_MODE`
- `WAF_ADMIN_TRUSTED_CIDRS`

前段がある場合の経路は:

`client -> ALB/nginx/HAProxy/Cloudflare -> tukuyomi -> app`

とし、`WAF_TRUSTED_PROXY_CIDRS` はその前段 range に限定してください。
`WAF_TRUSTED_PROXY_CIDRS` は admin exposure を決めません。tukuyomi の既定 posture は `WAF_ADMIN_EXTERNAL_MODE=api_only_external` で、埋め込み管理UIは trusted/private な直結 peer に限定しつつ、認証付き管理APIは untrusted external からも到達可能なままです。remote admin API が不要なら `WAF_ADMIN_EXTERNAL_MODE=deny_external` を使い、front layer が private ではない source IP で tukuyomi に接続する場合は `WAF_ADMIN_TRUSTED_CIDRS` にその range を設定してください。

## Secret Handling

- `WAF_API_KEY_PRIMARY`, `WAF_API_KEY_SECONDARY`, `WAF_ADMIN_SESSION_SECRET`, `WAF_DB_DSN`, `WAF_FP_TUNER_API_KEY` は server 側 env file にだけ置いてください
- 埋め込み管理UIに build-time secret は不要です
- browser operator は 1 回 sign in して same-origin session cookie を受け取れば、その後は通常の Admin UI を使えます
- CLI / 自動化は従来どおり `X-API-Key` を使えます

## systemd

sample unit:

- [tukuyomi.service.example](tukuyomi.service.example)

登録例:

```bash
sudo install -d -m 755 /etc/tukuyomi
sudo install -m 644 docs/build/tukuyomi.env.example /etc/tukuyomi/tukuyomi.env
sudo chown root:root /etc/tukuyomi/tukuyomi.env
sudo chmod 600 /etc/tukuyomi/tukuyomi.env
sudo install -m 644 docs/build/tukuyomi.service.example /etc/systemd/system/tukuyomi.service
sudo systemctl daemon-reload
sudo systemctl enable --now tukuyomi
sudo systemctl status tukuyomi
```

## Notes

- sample unit は `WorkingDirectory=/opt/tukuyomi` を使うので、相対 `conf/`, `rules/`, `logs/` がそのまま機能します
- `make binary-deployment-smoke` は unauthenticated session 状態、正しい login、invalid session 拒否、CSRF 強制、logout まで検証します
- 実行中に設定を書き換えたい場合は、`conf/` と `rules/` はバイナリ外で保持してください
- DB バックエンドの複数ノード運用へ進む場合は、SQLite ではなく MySQL を推奨します
