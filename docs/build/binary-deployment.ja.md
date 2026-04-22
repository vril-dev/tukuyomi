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
/opt/tukuyomi/rules/
/opt/tukuyomi/logs/
```

最低限必要な runtime file:

- `conf/config.json`
- `conf/proxy.json`
- `conf/sites.json`
- `conf/cache-store.json`
- `conf/cache-rules.json`
- `conf/waf-bypass.json`
- `conf/waf-bypass.sample.json`
- `conf/country-block.json`
- `conf/rate-limit.json`
- `conf/bot-defense.json`
- `conf/semantic.json`
- `conf/notifications.json`
- `conf/ip-reputation.json`
- `rules/tukuyomi.conf`
- `rules/crs/crs-setup.conf`
- `rules/crs/rules/*.conf`

PHP-FPM の `/options` と `/vhosts` も使う場合の追加物:

- `data/php-fpm/binaries/<runtime_id>/`
- `data/php-fpm/inventory.json`
- `data/php-fpm/vhosts.json`

`/scheduled-tasks` も使う場合の追加物:

- `conf/scheduled-tasks.json`

managed bypass override rule も使う場合の追加物:

- `conf/rules/*.conf`

managed GeoIP country update も使う場合の追加物:

- `data/geoip/`
- `scripts/update_country_db.sh`

配置例:

```bash
sudo install -d -m 755 \
  /opt/tukuyomi/bin \
  /opt/tukuyomi/conf \
  /opt/tukuyomi/data/geoip \
  /opt/tukuyomi/rules \
  /opt/tukuyomi/scripts \
  /opt/tukuyomi/logs/coraza \
  /opt/tukuyomi/logs/proxy

sudo install -m 755 bin/tukuyomi /opt/tukuyomi/bin/tukuyomi
sudo install -m 755 scripts/update_country_db.sh /opt/tukuyomi/scripts/update_country_db.sh

for f in config.json proxy.json sites.json scheduled-tasks.json cache-store.json cache-rules.json waf-bypass.json waf-bypass.sample.json country-block.json rate-limit.json bot-defense.json semantic.json notifications.json ip-reputation.json; do
  sudo install -m 644 "data/conf/${f}" "/opt/tukuyomi/conf/${f}"
done

if [[ -d data/conf/rules ]]; then
  sudo install -d -m 755 /opt/tukuyomi/conf/rules
  for f in data/conf/rules/*; do
    [[ -f "${f}" ]] || continue
    sudo install -m 644 "${f}" "/opt/tukuyomi/conf/rules/$(basename "${f}")"
  done
fi

if [[ -f data/geoip/README.md ]]; then
  sudo install -m 644 data/geoip/README.md /opt/tukuyomi/data/geoip/README.md
fi

sudo install -m 644 data/rules/tukuyomi.conf /opt/tukuyomi/rules/tukuyomi.conf
sudo install -d -m 755 /opt/tukuyomi/rules/crs
sudo DEST_DIR=/opt/tukuyomi/rules/crs ./scripts/install_crs.sh
sudo touch /opt/tukuyomi/conf/crs-disabled.conf
```

注意:

- `data/conf/*.bak` は本番へ持っていかないでください
- `tukuyomi` の server-side 設定の主契約は `conf/config.json` です
- 本番では `config.json` を secret manager / config management から render / mount してください
- embedded `Settings` 画面も同じ `conf/config.json` を global settings として編集しますが、この導線は `Save config only` です。listener/runtime/storage/observability 系の変更後は service を restart してください
- public release bundle には `Options -> GeoIP Update -> Update now` 用の companion `bin/geoipupdate` が同梱されます
- `GEOIPUPDATE_BIN` を使えば bundled updater path を override できます
- managed country refresh 用の official wrapper は `./scripts/update_country_db.sh` です
- `data/geoip/country.mmdb`, `data/geoip/GeoIP.conf`, `data/geoip/update-status.json` は operator-managed runtime artifact なので、generic な release bundle へ bake しないでください
- managed bypass override rule は `conf/rules/*.conf` 配下に置き、`Rules -> Override Rules` から編集します。これは `waf-bypass.json` の `extra_rule` で参照された時だけ load されます
- release bundle には harmless な standalone sample として `conf/rules/search-endpoint.conf` も含まれます
- その参照例として `conf/waf-bypass.sample.json` も同梱します

proxy engine 選択も restart-required な `conf/config.json` 設定です:

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

- `php-fpm-copy` は `data/php-fpm/binaries/<runtime_id>/` を binary 配備ツリーへ同期し、`inventory.json` / `vhosts.json` が無ければ初期ファイルを作成します
- 不要になった staged runtime bundle は `sudo make php-fpm-prune RUNTIME=php85` で削除できます。`vhosts.json` 参照と実行中 pid を確認してから `binaries/<runtime_id>` と `runtime/<runtime_id>` を消します
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

overload 制御は `conf/config.json` の `server` 配下で調整します:

- `max_concurrent_requests` は process-wide guard です。
- `max_concurrent_proxy_requests` は data-plane guard です。
- queue 設定は、対応する `max_concurrent_*` が `0` より大きいときだけ有効です。
- `max_queued_proxy_requests` と `queued_proxy_request_timeout_ms` で、proxy burst を unbounded wait にせず短く吸収できます。
- `max_queued_requests` の既定値は `0` です。admin/API request を待たせたい意図がない限り、`0` か very small に保ってください。
- proxy saturation 中も admin/API の headroom を残したい場合は、`max_concurrent_requests` を `max_concurrent_proxy_requests` より大きくしてください。
- `/tukuyomi-api/status` の `server_overload_global` / `server_overload_proxy` と、`/tukuyomi-api/metrics` の `tukuyomi_overload_*` を監視してください。

## Secret Handling

- `admin.api_key_primary`、`admin.api_key_secondary`、`admin.session_secret` は `conf/config.json` に置き、browser へは出さないでください
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

有効化する socket unit は `conf/config.json` と一致するものだけにしてください。
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
