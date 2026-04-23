# Binary Deployment

この手順は、Linux ホスト上で `tukuyomi` を single binary として `systemd` 管理で動かす前提です。

想定環境:

- オンプレ Linux サーバ
- VPS
- VM
- EC2

## Build

作業端末または build host で実行:

```bash
make setup
make build
```

生成物は `bin/tukuyomi` です。

埋め込み Admin UI をすでに更新済みで、Go バイナリだけ欲しい場合は:

```bash
make go-build
```

再現性のある release artifact を作る場合は:

```bash
make release-linux-all VERSION=v0.8.0
```

## 実行レイアウト

バイナリは、作業ディレクトリ配下に次を前提とします。

```text
/opt/tukuyomi/bin/tukuyomi
/opt/tukuyomi/conf/
/opt/tukuyomi/seed/
/opt/tukuyomi/db/
/opt/tukuyomi/audit/
/opt/tukuyomi/cache/
/opt/tukuyomi/logs/
/opt/tukuyomi/rules/
```

bundle 同梱の bootstrap/example:

- `conf/config.json`
- `seed/proxy.json`
- `seed/sites.json`
- `conf/crs-disabled.conf`
- `scripts/update_country_db.sh`

初回 DB import 前に operator が必要に応じて配置する seed/import file:

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
- `conf/rules/*.conf`
- `make crs-install` で stage する `rules/crs/...`

これらは空 DB の初期投入、または import/export 用です。対応する normalized DB row が存在する後は
runtime は normalized domain を DB から直接読み込み、file の復元を起動条件にしません。
import 後の本番起動で必要なのは DB bootstrap 用の `conf/config.json` と DB row です。

初回 DB import 前に使う PHP-FPM 追加物:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

import 後、bundled PHP-FPM を使う場合は executable bundle 自体は必要ですが、
`inventory.json`、`vhosts.json`、`runtime.json`、`modules.json` は runtime
authority ではありません。

`/scheduled-tasks` 実行状態も使う場合の追加物:

- `data/scheduled-tasks/`

managed bypass override rule を import する場合の任意 seed:

- `conf/rules/*.conf`（`make db-import` 前のみ）

managed GeoIP country update も使う場合の追加物:

- `scripts/update_country_db.sh`

配置例:

```bash
sudo install -d -m 755 \
  /opt/tukuyomi/bin \
  /opt/tukuyomi/conf \
  /opt/tukuyomi/seed \
  /opt/tukuyomi/db \
  /opt/tukuyomi/audit \
  /opt/tukuyomi/cache/response \
  /opt/tukuyomi/logs/waf \
  /opt/tukuyomi/rules \
  /opt/tukuyomi/scripts \
  /opt/tukuyomi/logs/proxy

sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo install -m 755 scripts/update_country_db.sh /opt/tukuyomi/scripts/update_country_db.sh

sudo install -m 644 data/conf/config.json /opt/tukuyomi/conf/config.json
for f in proxy.json sites.json; do
  sudo install -m 644 "data/seed/${f}" "/opt/tukuyomi/seed/${f}"
done

sudo touch /opt/tukuyomi/conf/crs-disabled.conf
```

注意:

- `data/conf/*.bak` は本番へ持っていかないでください
- `config.json` は DB 接続 bootstrap と DB `app_config` の seed/export material です
- `seed/proxy.json` は DB `proxy_rules` の seed/import/export material です
- `seed/sites.json` は DB `sites` の seed/import/export material です
- public release bundle が example seed として同梱するのは `conf/config.json` と `seed/proxy.json` / `seed/sites.json` だけで、他の seed/import material は必要時に operator が用意します
- 既定の base WAF rule seed は binary に compile されています
- CRS file は DB `waf_rule_assets` 向けの一時 import material であり、`make crs-install` が staging と cleanup を行います
- `sites.json`、`scheduled-tasks.json`、`upstream-runtime.json`、policy JSON、
  cache-rules JSON、WAF bypass JSON、PHP-FPM JSON manifest は DB bootstrap
  後は DB seed/export artifact です
- 本番では `storage.db_driver`、`storage.db_path`、`storage.db_dsn` 用に `config.json` を secret manager / config management から render / mount してください
- 初回起動前に `make db-migrate`、`make crs-install` の順で WAF rule asset を install/import し、その後残りの seed material 用に `make db-import` を実行します
- embedded `Settings` 画面は DB `app_config` を編集します。listener/runtime/storage policy/observability 系の変更後は service を restart してください
- public release bundle には `Options -> GeoIP Update -> Update now` 用の companion `bin/geoipupdate` が同梱されます
- `GEOIPUPDATE_BIN` を使えば bundled updater path を override できます
- managed country refresh 用の official wrapper は `./scripts/update_country_db.sh` です
- managed GeoIP country DB、`GeoIP.conf`、update status は `make db-import` 後は DB-backed です。main repo に `data/geoip` を置く必要はありません
- managed bypass override rule は DB `override_rules` です。`conf/rules/*.conf` は新規DB import時だけ使う operator-provided seed です
- `extra_rule` の値は DB-managed override rule への logical compatibility reference として残ります

proxy engine 選択は restart-required な DB `app_config` 設定です:

```json
{
  "proxy": {
    "engine": {
      "mode": "tukuyomi_proxy"
    }
  }
}
```

- `tukuyomi_proxy` は built-in engine で、同じ parser、transport、routing、health、retry、TLS、cache、route response headers、1xx informational responses、trailers、streaming flush behavior、native Upgrade/WebSocket tunnel、response-sanitize pipeline を維持したまま Tukuyomi 独自の response bridge を使います
- legacy `net_http` bridge は削除済みです。`tukuyomi_proxy` 以外の engine 値は config validation で拒否します
- HTTP/1.1 と明示的な upstream HTTP/2 mode は Tukuyomi native upstream transport を使います。HTTPS `force_attempt` は ALPN で `h2` が選ばれない場合だけ native HTTP/1.1 へ fallback します
- Upgrade/WebSocket handshake request は `tukuyomi_proxy` 内で処理します。`101 Switching Protocols` 後の WebSocket frame payload は tunnel data です
- 本番展開前に実 workload で benchmark してください

## public/admin listener 分離

public proxy を `:80` / `:443` に置きつつ、embedded admin UI/API を別の
high port に分けたい場合は `admin.listen_addr` を設定します。

sample:

- [config.split-listener.example.json](config.split-listener.example.json)

典型例:

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

operator contract:

- `server.listen_addr` は public listener のまま
- `admin.listen_addr` を入れると admin UI/API/auth は public listener から外れる
- `admin.external_mode` と `admin.trusted_cidrs` は admin listener 上でも継続
- built-in TLS / HTTP redirect / HTTP/3 はこの slice では public listener 専用
- `admin.listen_addr` は `server.listen_addr` と `server.tls.http_redirect_addr` に衝突できません

## Optional PHP-FPM Runtime Bundles

binary 配備先で `/options` と `/vhosts` を使いたい場合は、runtime bundle を build して配置します。

標準レイアウト `/opt/tukuyomi` を使う場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85
```

別の配備先に stage する場合:

```bash
make php-fpm-build RUNTIME=php85
sudo make php-fpm-copy RUNTIME=php85 DEST=/srv/tukuyomi
```

補足:

- `php-fpm-copy` は `data/php-fpm/binaries/<runtime_id>/` を binary 配備ツリーへ同期します。PHP-FPM JSON manifest を削除する前に `make db-import` で inventory/module metadata を import してください
- 不要になった staged runtime bundle は `sudo make php-fpm-prune RUNTIME=php85` で削除できます。DB vhost 参照と実行中 pid を確認してから `binaries/<runtime_id>` と `runtime/<runtime_id>` を消します
- `data/php-fpm/runtime/` はコピー対象ではなく、`tukuyomi` 起動後に vhost 定義から生成されます
- Docker が必要なのは `php-fpm-build` の build 時だけです。bundle 配置後の `tukuyomi` 実行時には Docker は不要です
- PHP / base image library / PECL extension の security update は bundle を rebuild して再配置する必要があります

## Environment File

`/etc/tukuyomi/tukuyomi.env` のような env file を使います。

template:

- [tukuyomi.env.example](tukuyomi.env.example)

主に見直す値:

- `WAF_CONFIG_FILE`
- `WAF_PROXY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_FILE`
- `WAF_SECURITY_AUDIT_BLOB_DIR`

必要な場合だけ使う security-audit key override:

- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY`
- `WAF_SECURITY_AUDIT_ENCRYPTION_KEY_ID`
- `WAF_SECURITY_AUDIT_HMAC_KEY`
- `WAF_SECURITY_AUDIT_HMAC_KEY_ID`

## Overload Tuning

overload 制御は DB `app_config` の `server` 配下で調整します:

- `max_concurrent_requests` は process-wide guard です。
- `max_concurrent_proxy_requests` は data-plane guard です。
- queue 設定は、対応する `max_concurrent_*` が `0` より大きいときだけ有効です。
- `max_queued_proxy_requests` と `queued_proxy_request_timeout_ms` で、proxy burst を unbounded wait にせず短く吸収できます。
- `max_queued_requests` の既定値は `0` です。admin/API request を待たせたい意図がない限り、`0` か very small に保ってください。
- proxy saturation 中も admin/API の headroom を残したい場合は、`max_concurrent_requests` を `max_concurrent_proxy_requests` より大きくしてください。
- `/tukuyomi-api/status` の `server_overload_global` / `server_overload_proxy` と、`/tukuyomi-api/metrics` の `tukuyomi_overload_*` を監視してください。

## Secret Handling

- `admin.api_key_primary`、`admin.api_key_secondary`、`admin.session_secret` は managed app config に置き、browser へは出さないでください
- browser operator は 1 回 sign in すると same-origin session cookie を受け取ります
- CLI / 自動化は従来どおり `X-API-Key` を使えます
- `tukuyomi` の既定 posture は `admin.external_mode=api_only_external` です。remote admin API が不要なら `deny_external` にしてください
- non-loopback listener で `admin.external_mode=full_external` を使う場合は、起動 warning だけに頼らず front-side の allowlist/auth を追加してください
- `admin.trusted_cidrs` を public / catch-all network まで広げた場合も、埋め込み管理UI/API はその trusted source へ再露出され、起動時は warning のみです
- `security_audit.key_source=env` を使う場合だけ、暗号鍵と HMAC 鍵を env file 側へ置いてください

## systemd

sample unit:

- [tukuyomi.service.example](tukuyomi.service.example)
- [tukuyomi.socket.example](tukuyomi.socket.example)
- [tukuyomi-admin.socket.example](tukuyomi-admin.socket.example)
- [tukuyomi-redirect.socket.example](tukuyomi-redirect.socket.example)
- [tukuyomi-http3.socket.example](tukuyomi-http3.socket.example)
- [tukuyomi-scheduled-tasks.service.example](tukuyomi-scheduled-tasks.service.example)
- [tukuyomi-scheduled-tasks.timer.example](tukuyomi-scheduled-tasks.timer.example)

sample unit は `User=tukuyomi` のまま `AmbientCapabilities=CAP_NET_BIND_SERVICE` を付け、`:80` / `:443` のような low port bind を root 常駐なしで行う前提です。
graceful binary replacement が必要な場合は systemd socket activation を推奨します。
socket unit が public/admin/redirect/HTTP3 listener を保持するため、service process
の shutdown / restart と listener bind race を分離できます。

登録例:

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

socket activation 登録例:

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

有効化する socket unit は effective DB `app_config` と一致するものだけにしてください。
`ListenStream` / `ListenDatagram` は `server.listen_addr`, `admin.listen_addr`,
`server.tls.http_redirect_addr`, HTTP/3 UDP port と一致する必要があります。
process は inherited socket address を検証し、不一致なら fail closed します。

admin, redirect, HTTP/3 の socket unit を有効化する場合は、service drop-in の
対応する `Sockets=` 行を uncomment してください。これにより
`systemctl restart tukuyomi.service` でも同じ inherited descriptor を使い、
direct bind に戻らないようにします。

graceful replacement:

```bash
sudo install -m 755 build/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo systemctl restart tukuyomi.service
```

socket activation 有効時は、systemd が listening socket を保持し、旧 process は
accepted HTTP request を drain しながら、新 process が同じ descriptor で起動します。
`SIGTERM`, `SIGINT`, `SIGHUP` はすべて graceful shutdown を起動します。
Upgrade/WebSocket のような long-lived connection も tracking して
`server.graceful_shutdown_timeout_sec` まで待ち、timeout 後に force close します。
HTTP/3 UDP socket handoff は対応しますが、既存 QUIC connection は process replacement
をまたいで維持されません。

## Notes

- sample unit は `WorkingDirectory=/opt/tukuyomi` を使うので、相対 `conf/`, `rules/`, `logs/` がそのまま機能します
- `server.graceful_shutdown_timeout_sec` の既定値は `30` です。deploy 中も WebSocket を長く維持する運用なら値を引き上げてください
- scheduled-task service も同じ working directory と env file を使うので、`run-scheduled-tasks` から main service と同じ `conf/` / `data/scheduled-tasks/` を見られます
- sample unit は `CAP_NET_BIND_SERVICE` を付けるので、`server.listen_addr=:443` や `server.tls.http_redirect_addr=:80` の direct bind に対応します
- split-listener deployment では `admin.listen_addr=:9091` のような high port を使うのが普通なので、admin listener 用の追加 capability は不要です
- `admin.listen_addr` は port 分離だけで、到達可否は引き続き `admin.external_mode` と `admin.trusted_cidrs` で制御します
- first slice の split listener では `admin.listen_addr` 側に built-in TLS はありません。trusted private network か front proxy の TLS terminate を前提にしてください
- この capability は low port bind 用だけです。`php-fpm` を `www-data` など `tukuyomi` 以外の UID/GID へ切り替えるには、引き続き root 起動が必要です
- `tukuyomi` を直接公開し、built-in HTTP/3 を有効にする場合は listener port の TCP/UDP を両方開けてください
- 展開済み release bundle では、`testenv/release-binary/` が最短の smoke 導線です
- rollout 前にこの staged-runtime 導線をローカルで検証するなら `make binary-deployment-smoke` を使ってください
