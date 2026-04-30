# 第5章　ルーティング、Upstream、Backend Pool

第3・4 章で tukuyomi の **配備** をひととおり押さえました。本章からは、配備
した tukuyomi が **実際の HTTP request をどう routing するか** に踏み込みます。

tukuyomi の routing は、`Routes`、`Upstreams`、`Backend Pools` という
**3 つの構成要素** が、明確な役割分担をもって積み重なる形になっています。
本章ではまずこの 3 層モデルを概観し、それから request 1 本が tukuyomi の
内部でどの順で処理されるか、`Backends` 画面で何ができるか、Dynamic DNS
Discovery と Sticky Sessions の動作、`dry-run` の使い方、までを見ていきます。

## 5.1　3 層モデル ── Routes / Upstreams / Backend Pools

tukuyomi の `Proxy Rules` 画面は、operator workflow を次の順で見せます。

1. **Upstreams**: direct backend node の catalog
2. **Backend Pools**: named upstream をまとめた route 単位の balancing group
3. **Routes** / **Default route**: host / path / method などの match と、
   その先の binding（pool または upstream）

それぞれの責務を 1 つずつ確認します。

### 5.1.1　Upstreams

`Upstreams` は、**Runtime Apps が所有しない direct backend node の catalog**
です。各行は次のいずれかを使います。

- 静的な `url`（例: `http://app.internal:8080`）
- DNS による `discovery`（次節で扱います）

各 upstream は `name` を持ち、これが Backend Pool や Route から参照される
**唯一の identifier** になります。

最小の例は次のとおりです。

```json
{
  "upstreams": [
    { "name": "primary", "url": "http://app.internal:8080", "weight": 1, "enabled": true }
  ],
  "load_balancing_strategy": "round_robin",
  "hash_policy": "cookie",
  "hash_key": "session",
  "expose_waf_debug_headers": false
}
```

`Upstreams` の各行には専用の `Probe` ボタンがあり、**panel 全体に対して
あいまいな target を撃つのではなく**、その行に書かれた configured upstream
1 件に対してだけ疎通確認を行います。誤検知の少ない operator UX を意識した
作りになっています。

なお、`Runtime Apps`（PHP-FPM / PSGI）が listen する target は、`Runtime
Apps` 側が server-owned で生成する **generated backend** として登場します。
これは `Upstreams` には現れず、また `Runtime Apps` は configured upstream URL
を書き換えません。`primary` という名の configured upstream は、Runtime Apps
で何かが生成されたあとも `Proxy Rules > Upstreams` に書いた URL のまま残り
ます。

### 5.1.2　Backend Pools

`Backend Pools` は、`Upstreams` で定義した **named upstream を組み合わせて
作る、route 単位の balancing group** です。`members[]` には upstream 名を
並べるだけで、URL や discovery 設定は再記述しません。

```json
{
  "backend_pools": [
    { "name": "site-localhost", "strategy": "round_robin", "members": ["localhost1", "localhost2"] },
    { "name": "site-app",       "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ]
}
```

`strategy` には `round_robin` / `least_conn` / `hash` などが用意されます。
hash strategy では `hash_policy` と `hash_key` を組み合わせて使います。

### 5.1.3　Routes と Default route

`routes[]` は `priority` 昇順の **first-match** で評価されます。route 選択順
全体は次のとおりです。

1. explicit `routes[]`
2. DB `sites` domain 由来の generated host fallback route
3. `default_route`
4. `upstreams[]`

route の match は、host と path の両方で書けます。

- host match: exact または `*.example.com` のサフィックス match
- path match: `exact` / `prefix` / `regex` の 3 種類

route の binding は次のいずれかです。

- `action.backend_pool`: balancing 標準の binding
- `action.upstream`: direct upstream 名（`Upstreams` に書いた行）または
  server-generated Runtime App upstream 名

加えて、route 単位で次の制御が書けます。

- `action.canary_upstream` と `action.canary_weight_percent`: route-level の
  canary
- `action.host_rewrite` / `action.path_rewrite.prefix` / `action.query_rewrite`:
  outbound rewrite
- `action.request_headers` / `action.response_headers`: bounded な header 制御

最後に、**`response_header_sanitize`** が最終的な response-header safety gate
として効きます。これは bypass できない構造的な safety です。

### 5.1.4　最小 route-scoped backend pool 例

3 層がすべて揃った最小の例は次のようになります。

```json
{
  "upstreams": [
    { "name": "localhost1", "url": "http://127.0.0.1:8081", "weight": 1, "enabled": true },
    { "name": "localhost2", "url": "http://127.0.0.1:8082", "weight": 1, "enabled": true },
    { "name": "localhost3", "url": "http://127.0.0.1:9081", "weight": 1, "enabled": true },
    { "name": "localhost4", "url": "http://127.0.0.1:9082", "weight": 1, "enabled": true }
  ],
  "backend_pools": [
    { "name": "site-localhost", "strategy": "round_robin", "members": ["localhost1", "localhost2"] },
    { "name": "site-app",       "strategy": "round_robin", "members": ["localhost3", "localhost4"] }
  ],
  "routes": [
    { "name": "site-localhost", "priority": 10, "match": { "hosts": ["localhost"] }, "action": { "backend_pool": "site-localhost" } },
    { "name": "site-app",       "priority": 20, "match": { "hosts": ["app"] },       "action": { "backend_pool": "site-app" } }
  ]
}
```

## 5.2　Request flow ── 1 本の request が辿る順序

route の match と binding をどう書くかを理解するうえで、request 1 本が
tukuyomi 内部で辿る順序を押さえておきます。

1. **request metadata resolution**
   - country / IP reputation / 各種 header から resolved metadata を作る
2. **route classification と rewrite planning**
   - `routes[]` の first-match を決定し、host / path / query rewrite を
     計画する
   - この時点で `proxy_route` log が emit される
   - `selected_upstream` / `selected_upstream_url` は **まだ確定していない**
     ので log には出さない
3. **country block / request-security plugins / rate limit / WAF**
   - 順に request を検査する
4. **final target selection**
   - backend pool の中から 1 つの target を選ぶ
5. **proxy transport または direct static / php-fpm serving**
   - 選ばれた target に対して proxy するか、static / PHP-FPM へ直接 serving
     する

`proxy_access` と post-selection の transport log は、4 で final target が
確定したあとに `selected_upstream` / `selected_upstream_url` を出します。
**route 段階の log（`proxy_route`）と、target 確定後の log（`proxy_access`）
は意味が違う** という点に注意してください。

### 5.2.1　Upstream failure 時の応答

upstream の failure 時に何を返すかは、route の `error_html_file` と
`error_redirect_url` の有無で変わります。

- 両方未設定: 既定の `502 Bad Gateway`
- `error_html_file` 設定時: HTML client にはメンテナンスページ、その他は
  plain text の `503`
- `error_redirect_url` 設定時: `GET` / `HEAD` を redirect、その他は
  plain text の `503`

## 5.3　Backends 画面 ── runtime での backend 操作

`Backends` 画面は、direct upstream backend object を一覧する画面であると
同時に、**runtime で backend を操作するための盤** でもあります。

操作対象になるのは次の 2 つです。

- `Upstreams` で定義した **static direct upstream**
- DNS discovery で **materialize された target**

可能な runtime 操作は、

- `enabled`
- `draining`
- `disabled`
- 正の `weight_override`

の 4 種類です。これらの override は、DB `upstream_runtime` ドメイン
（`data/conf/upstream-runtime.json` は seed / export）に保存されます。
override が無い backend は、DB `proxy_rules` の設定どおりに動きます。

ここで重要なのは「**何が `Backends` の操作対象になり、何がならないか**」
を区別することです。

| object | `Backends` で操作 |
|---|---|
| static direct upstream（`Upstreams` 行） | できる |
| DNS discovery で materialize された target | できる |
| Runtime App generated target | **できない**（`Runtime Apps` 側で扱う） |
| route 直書きの URL | できない |

つまり、Runtime Apps が動的に生成した backend は `Backends` には現れず、
`Runtime Apps` 画面の Process Lifecycle 制御がそれに相当します。route の
`action.upstream` に **直書きで URL を入れた** 場合も runtime 操作対象外で、
proxy rule 自体を編集することになります。

### 5.3.1　drain / disable / unhealthy の扱い

`draining` / `disabled` / `unhealthy` のどれかに該当する backend は、
**新規 target selection から外れます**。すでに張られている inflight な
connection はそのまま流れ、新規だけが他 backend に振り分けられます。

`proxy_access` log には、selected backend の runtime state として次の field
が出ます。

- `selected_upstream_admin_state`
- `selected_upstream_health_state`
- `selected_upstream_effective_selectable`
- `selected_upstream_effective_weight`
- `selected_upstream_inflight`

block された request には、これらの selected-backend 系 field は **出さない**
仕様です。

## 5.4　Forwarded ヘッダと観測用ヘッダ

通常の `http://` / `https://` upstream proxy では、tukuyomi が次の header を
**自動的に付与** します。

- `X-Forwarded-For`
- `X-Forwarded-Host`
- `X-Forwarded-Proto`

さらに、`emit_upstream_name_request_header=true` を有効化すると、次も
追加できます。

- `X-Tukuyomi-Upstream-Name`

これは内部 observability 用の header です。挙動には次の安全側仕様が入って
います。

- `[proxy]` は inbound 側の同名 header を **一度除去** してから付け直す
- 最終 target が **`Proxy Rules > Upstreams` の configured named upstream で
  あったとき** だけ付与される
- direct route URL や Runtime App generated target には **付与しない**
- route-level の `request_headers` から **上書きできない**

これらの runtime 管理 header は、route-level `request_headers` で override
不可、というのが基本ルールです。

## 5.5　Dynamic DNS Backend Discovery

container / Kubernetes 環境のように、backend address を **DNS が管理する**
ケースでは、`upstreams[].discovery` を使います。Routes / Backend Pools は
従来どおり canonical な upstream name を参照しますが、その背後の実 target
は DNS の解決結果から materialize されます。

```json
{
  "upstreams": [
    {
      "name": "app",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns",
        "hostname": "app.default.svc.cluster.local",
        "scheme": "http",
        "port": 8080,
        "record_types": ["A", "AAAA"],
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    },
    {
      "name": "api-srv",
      "enabled": true,
      "weight": 1,
      "discovery": {
        "type": "dns_srv",
        "service": "http",
        "proto": "tcp",
        "name": "api.default.svc.cluster.local",
        "scheme": "https",
        "refresh_interval_sec": 10,
        "timeout_ms": 1000,
        "max_targets": 32
      }
    }
  ]
}
```

discovery のルールは次のとおりです。

- `type=dns` は A / AAAA record を解決します。`hostname`、`scheme`、`port`
  が必須です。
- `type=dns_srv` は `_service._proto.name` を解決し、SRV の port を使います。
- `scheme` は `http` / `https` のみです。`fcgi` / `static` は discovery 対象
  外です。
- DNS は **request ごとに解決しません**。更新間隔は `refresh_interval_sec`
  で制御します。
- 初回 lookup が失敗し、last-good が無い場合、その upstream は **selectable
  target が 0** になります。
- 後続 lookup が失敗した場合は、**last-good target set を保持** します。
- materialized target と discovery error は、`Backends` と health status から
  確認できます。

## 5.6　Backend Pool Sticky Sessions

`backend_pools[].sticky_session` は、**proxy が署名付きの affinity Cookie を
発行する** 機能です。`hash_policy=cookie` がアプリ側 Cookie を hash 入力に
するだけなのに対し、`sticky_session` は load-balancer Cookie を proxy 自身が
発行・更新します。

```json
{
  "backend_pools": [
    {
      "name": "site-api",
      "strategy": "round_robin",
      "members": ["api-a", "api-b"],
      "sticky_session": {
        "enabled": true,
        "cookie_name": "tky_lb_site_api",
        "ttl_seconds": 86400,
        "path": "/",
        "secure": true,
        "http_only": true,
        "same_site": "lax"
      }
    }
  ]
}
```

挙動の要点は次のとおりです。

- 有効な sticky Cookie は、**round-robin / least-conn / hash selection より
  優先**されます。
- 次のいずれかに該当する sticky target は無視されます: invalid / expired /
  tampered / unknown / disabled / draining / unhealthy。
- Cookie 値は署名され、selected target identifier と expiry **だけ** を保持
  します。**backend URL は含めません**。
- 署名 key は **process-local** で起動時に生成されます。restart 後の古い
  Cookie は安全に拒否され、次の応答で更新されます。
- `same_site=none` を選ぶ場合は `secure=true` が必須です。

route から sticky pool を使う側の例は、第5.1 節の最小例どおりに `action.backend_pool`
を pool 名に向けるだけです。

## 5.7　Rewrite と route action の使い分け

route action では、outbound 側を bounded に整形できます。host / path / query
rewrite と header 制御を組み合わせると、たとえば次のような route が書けます。

```json
{
  "routes": [
    {
      "name": "service-a-prefix",
      "enabled": true,
      "priority": 10,
      "match": {
        "hosts": ["api.example.com"],
        "path": { "type": "prefix", "value": "/servicea/" }
      },
      "action": {
        "upstream": "service-a",
        "host_rewrite": "service-a.internal",
        "path_rewrite": { "prefix": "/service-a/" }
      }
    }
  ]
}
```

この route は、`api.example.com/servicea/...` への request を、host を
`service-a.internal` に書き換え、path prefix を `/servicea/` から
`/service-a/` に rewrite して、direct upstream `service-a` に流します。

## 5.8　dry-run で route を検証する

proxy rule に手を入れる前後で、**特定の host / path がどの route に
classify されるか** を試すには、`/tukuyomi-api/proxy-rules/dry-run` を使います。

```bash
curl -sS \
  -H "Authorization: Bearer ${WAF_ADMIN_TOKEN}" \
  -H "Content-Type: application/json" \
  -X POST \
  --data '{"host":"api.example.com","path":"/servicea/users"}' \
  http://127.0.0.1:8080/tukuyomi-api/proxy-rules/dry-run
```

`dry-run` は実際には request を流さず、route classification のみを試した
結果を返します。本番 traffic を流す前に、新しい route や rewrite が
意図どおりに当たるかを確認するのに有効です。

`dry-run` に関連して、route 周りの主な log field は次のとおりです。

- `proxy_route`
- `original_host` / `original_path` / `original_query`
- `rewritten_host` / `rewritten_path` / `rewritten_query`
- `selected_route`

`proxy_route` は route classification 後・final target selection 前 に出る
ため、selected upstream 系の field は持たない、という点を改めて意識して
ください。

## 5.9　次章への橋渡し

ここまでで、tukuyomi の routing がどう構成され、request がどう流れ、runtime
で backend をどう操作するか、までを通り抜けました。

次の第6章では、**選んだ backend に対して tukuyomi が話す upstream HTTP
プロトコル** ── HTTP/1.1、HTTP/2（TLS あり）、h2c upstream、混在 topology
での挙動 ── を扱います。
