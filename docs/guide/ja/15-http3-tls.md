# 第15章　HTTP/2、HTTP/3 と TLS

第14章までで listener topology の現在の判断と、その背後の根拠を共有しま
した。本章では、**public listener 経路で TLS、受信側 HTTP/2、HTTP/3 をどう扱うか**
を扱います。具体的には次の 5 トピックです。

1. built-in TLS termination の有効化と各種 option
2. TLS binding ACME（Let's Encrypt 自動証明書更新）
3. HTTPS public listener の受信側 HTTP/2 ALPN
4. built-in HTTP/3 と `Alt-Svc` の挙動
5. HTTP/3 public-entry smoke で確認すべきこと

## 15.1　Built-in TLS Termination

tukuyomi は **built-in TLS termination** を持っています。前段に nginx や
ALB を挟まず、`tukuyomi` 自身を direct HTTPS entrypoint として使えます。

DB `app_config` の `server` block に、次のような TLS 設定を入れます。

```json
{
  "server": {
    "listen_addr": ":9443",
    "http2": {
      "enabled": true
    },
    "http3": {
      "enabled": true,
      "alt_svc_max_age_sec": 86400
    },
    "tls": {
      "enabled": true,
      "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
      "key_file":  "/etc/tukuyomi/tls/privkey.pem",
      "min_version": "tls1.2",
      "redirect_http": true,
      "http_redirect_addr": ":9080"
    }
  }
}
```

要点は次のとおりです。

- `server.tls.enabled=false` が **既定**。
- `server.http2.enabled=true` には built-in TLS が必要。この設定は
  client から Gateway への HTTPS ALPN だけを制御し、Gateway から upstream
  への transport は変更しない。
- `server.http3.enabled=true` には built-in TLS が必須。
- HTTP/3 は `server.listen_addr` と **同じ numeric port を UDP で** 使う。
- legacy の単一 listener 構成では、`server.tls.redirect_http=true` を入れると
  plain HTTP listener が追加される（`http_redirect_addr` で listen address を指定）。
- `server.public_listeners` を使うと、`:9090` を残したまま `:80` の HTTP 行と
  `:443` の HTTPS 行を追加する段階移行ができます。HTTPS 確認後に HTTP を
  redirect したい場合は、`http_behavior=redirect` の HTTP listener 行で表現します。
- ACME 自動 TLS は TLS binding で選びます。ACME account key、
  challenge token、証明書 cache は **`persistent_storage` の `acme/`
  namespace** に保存されます。
- Sites はルーティング用の設定で、`default_upstream` が必須です。TLS binding
  は Host/SNI 名に対する証明書設定であり、Sites や Proxy Rules から独立して
  紐づきます。
- ACME HTTP-01 を使うため、port 80 を Gateway の HTTP listener に到達させること。
- Let's Encrypt の `staging` / `production` は TLS binding ごとに選択します。
- `paths.site_config_file` の既定は `conf/sites.json`。**DB-backed runtime
  では空 DB の seed / export path** であり、live source of truth ではない
  （第13章のルール）。
- `paths.tls_binding_config_file` の既定は `conf/tls-bindings.json`。DB-backed
  runtime ではこれも seed / export path です。

## 15.2　Inbound Timeout Boundary

TLS とは直接の関係は薄いですが、HTTPS / HTTP/3 を direct entrypoint として
公開するなら、**inbound timeout の境界** を理解しておくべきです。

- public data-plane listener は、Tukuyomi native server が処理する。HTTP/1.1
  が既定で、`server.http2.enabled=true` の場合は HTTPS public listener が
  ALPN で HTTP/2 も受ける。admin listener、HTTP redirect listener、HTTP/3
  helper は分離した control / edge helper のまま。
- `server.read_header_timeout_sec` は **request line と header のみ** に
  対する timeout。
- `server.read_timeout_sec` は **request line + header + body 全体** の
  inbound read budget。
- `server.write_timeout_sec` は **response write の上限**。slow client は
  data-plane goroutine を保持し続けず close する。
- `server.idle_timeout_sec` は keep-alive の **request 間 idle 時間** の
  上限。
- `server.graceful_shutdown_timeout_sec` は deploy / reload 時に live
  connection を drain する上限時間。**超過後は force close** する。
- TLS public listener は既定で **HTTP/1.1 を advertise** する。
  `server.http2.enabled=true` の場合は `h2` と `http/1.1` を advertise する。
  HTTP/3 は有効時も **専用の HTTP/3 listener** で処理される。
- 明示的な `server.public_listeners` は、現時点では HTTP/1.1 / HTTPS の
  段階移行向けです。`server.http3.enabled` と同時には有効化しません。

## 15.3　TLS Binding ACME

TLS binding ACME は、`TLS` 画面で **`mode=acme`** を選びます。
`production` と `staging` は Let's Encrypt の本番 CA / staging CA の選択で、
account email は任意です。

ACME を使う場合の前提:

- HTTP-01 challenge を使うため、**DNS 名がこの Gateway に向き、port 80 が
  外部から到達可能** である必要がある。`server.public_listeners` を使う場合は、
  `:80` の HTTP listener 行を有効にします。通常の転送や redirect より先に
  ACME challenge path が処理されます。
- `:443` の HTTPS listener は、`Settings` の `Listener & Network` で
  `protocol=https` の public listener row として追加します。`Enable built-in TLS
  on the public listener` を有効にして保存した後、Gateway の再起動が必要です。
- TLS binding の `Hosts` には、ブラウザーでアクセスする DNS 名を設定します。
  `https://<IP アドレス>/...` は証明書のホスト名と一致しないため警告になります。
- 本番 CA に切り替える前に `staging` で challenge と HTTPS 到達性を確認します。
  `staging` 証明書で確認したブラウザーは警告状態を保持することがあるため、
  `production` へ切り替えた後は新しいタブやシークレットウィンドウでも確認します。
- 取得した証明書 cache、ACME account key、challenge token は
  **`persistent_storage` の `acme/` namespace** に保存される。
- single-node の VPS / オンプレでは、`persistent_storage.local.base_dir`
  （既定 `data/persistent`）を **backup 対象** にしておく。
- replicated や node replacement を前提にするなら、**S3 backend または
  共有 mount** にしておく。Azure Blob / GCS は provider adapter が入る
  までは fail-closed。

第3章 3.5 節で扱った永続 byte storage の話と同じものを、ここでは「ACME
証明書がどこに行くか」という観点から再確認している、ということです。

## 15.4　HTTPS Public Listener の受信側 HTTP/2

受信側 HTTP/2 は listener 単位の設定であり、Routing や upstream の設定では
ありません。有効化は次のように行います。

```json
{
  "server": {
    "http2": {
      "enabled": true
    },
    "tls": {
      "enabled": true
    }
  }
}
```

有効化すると、HTTPS public listener が ALPN で `h2` と `http/1.1` を提示します。
ブラウザーや API client は HTTP/2 で Tukuyomi に接続できますが、Tukuyomi の
背後にあるアプリケーションは PHP-FPM、PSGI、HTTP/1.1 upstream のままで構いません。

これは upstream HTTP/2 とは別の設定です。

- `server.http2.enabled`: client -> Gateway の HTTPS listener
- `upstreams[].http2_mode`: Gateway -> 名前付き upstream
- `action.upstream_http2_mode`: Gateway -> route に直接指定した upstream URL

PHP-FPM と PSGI は HTTP upstream transport ではないため、upstream HTTP/2 mode
の対象外です。

## 15.5　Built-in HTTP/3

HTTP/3 を有効化する典型形は次です。

```json
{
  "server": {
    "listen_addr": ":443",
    "http2": {
      "enabled": true
    },
    "http3": {
      "enabled": true,
      "alt_svc_max_age_sec": 86400
    },
    "tls": {
      "enabled": true,
      "cert_file": "/etc/tukuyomi/tls/fullchain.pem",
      "key_file":  "/etc/tukuyomi/tls/privkey.pem",
      "redirect_http": true,
      "http_redirect_addr": ":80"
    }
  }
}
```

挙動の要点:

- HTTP/3 は **`listen_addr` と同じ numeric port を UDP で** 使う。たとえば
  `:443` なら **TCP/443 と UDP/443 を両方** open する必要がある。
- `server.http2.enabled=true` の場合、TLS public listener が HTTP/2 /
  HTTP/1.1 を扱い、HTTP/3 は **専用 listener** が扱う。
- HTTPS 応答に `Alt-Svc` を付与し、`alt_svc_max_age_sec` で advertise の
  TTL を制御する。
- HTTP/3 は **process replacement をまたいだ QUIC connection continuity を
  保証しない**（第4章 4.4 節）。task / pod 入れ替え中に client reconnect が
  発生し得る。

container 配備で HTTP/3 を有効化する場合は、listener port の **TCP / UDP
を両方 open** することを忘れないようにしてください（第4章 4.11 節）。

## 15.6　HTTP/3 Public-Entry Smoke

HTTP/3 の経路は環境依存が強いため、tukuyomi は **専用の smoke コマンド** を
用意しています。

```bash
make http3-public-entry-smoke
```

### 15.6.1　何を検証するか

この smoke は、一時的なローカル runtime を次の条件で起動します。

- **built binary**
- **built-in TLS を有効化**
- **built-in HTTP/3 を有効化**
- `127.0.0.1` と `localhost` 用の一時 self-signed certificate
- routed traffic 用のローカル echo upstream

これにより、次を保証します。

- **HTTPS listener が healthy になる**
- **HTTPS 応答に `Alt-Svc` が付く**
- HTTPS 入口でも routed proxy traffic が通る
- **`/tukuyomi-api/status` が `server_http3_enabled=true` と
  `server_http3_advertised=true` を返す**
- **live runtime に対して actual HTTP/3 request over UDP が成功する**

### 15.6.2　なぜ専用コマンドにしているか

この smoke は、次の前提があるため `make smoke` / `make deployment-smoke` /
`make ci-local` には **混ぜていません**。

- **TLS runtime の起動**
- **ローカルホスト上の UDP 利用可否**
- **一時 self-signed certificate**
- **Go 製の HTTP/3 probe**

release readiness や operator validation には有用ですが、通常の高速 smoke
に入れるには環境依存が強いためです。

### 15.6.3　前提条件

- Go toolchain
- Docker は **不要**
- `curl`, `jq`, `python3`, `rsync`, `install`
- ローカル UDP loopback が使えること

### 15.6.4　推奨タイミング

次のいずれかを変更した後に回すのが推奨です。

- `server.http3.*`
- built-in TLS listener の挙動
- `Alt-Svc` の扱い
- HTTPS / HTTP/3 listener pair に影響しうる startup 変更

また、`tukuyomi` を **direct HTTPS / HTTP/3 entrypoint として案内する前**
の専用確認にも向いています。前段に LB がある構成では smoke 自体は通りやすい
ですが、direct 公開の構成では一度ここを叩いておくと安心です。

## 15.7　ここまでの整理

- built-in TLS は `server.tls.enabled=true` で有効化、`http3.enabled=true`
  には TLS が必須。HTTP/3 は **同 numeric port を UDP** で使う。
- ACME 自動 TLS は TLS binding で設定し、HTTP-01 のため **port 80 の到達性が
  必須**。証明書 cache は
  `persistent_storage` の `acme/` namespace。
- inbound timeout は `read_header_timeout_sec` / `read_timeout_sec` /
  `write_timeout_sec` / `idle_timeout_sec` / `graceful_shutdown_timeout_sec`
  の 5 段階で boundary を作る。
- HTTP/3 を direct 公開するときは **TCP / UDP の両方** を開ける。
- HTTP/3 の確認は **`make http3-public-entry-smoke`** を別に回す。
  通常 smoke には混ぜない。

## 15.7　次章への橋渡し

第VI部はあと 2 章です。次の第16章では、Web / VPS の通常配備では OFF にして
おく optional 機能、**IoT / Edge デバイス登録（device-auth-enrollment）** を
扱います。Tukuyomi Center で承認された device identity を必要とする
deployment 向けの手順です。続く第17章では、その上に乗る **Remote SSH** を
扱います。
