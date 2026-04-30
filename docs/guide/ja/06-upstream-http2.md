# 第6章　Upstream HTTP/2 と h2c

第5章で routing の組み立てを通り抜けたので、本章では tukuyomi が
**選んだ upstream に対してどの HTTP プロトコルで話すか** を扱います。

具体的には、

- `force_http2` / `h2c_upstream` という runtime-wide のスイッチ
- `upstreams[].http2_mode` による named upstream 単位の制御
- direct route target に対する `action.upstream_http2_mode`
- HTTP / HTTPS が混在する topology の作り方

を順に整理します。HTTP/2 を「どこまで強く要求するか」「cleartext で話すか
TLS で話すか」を、レイヤーごとに分けて指定する設計が tukuyomi の特徴です。

## 6.1　モード一覧

`tukuyomi` は以前から `force_http2` を持っていましたが、これは「HTTP/2 へ
**厳密に固定** するスイッチ」と誤解されやすい設定でした。現在の operator
model では、次の 3 種類のモードを使い分けます。

### 6.1.1　`force_http2=false`

- dial、TLS、request write、response parse、connection reuse、trailers、
  Upgrade tunnel に **Tukuyomi native HTTP/1.1 upstream transport** を使う
- HTTPS upstream は、選択された upstream mode が HTTP/2 を明示しない限り
  **HTTP/1.1 のまま**
- HTTP upstream は HTTP/1.1 のまま

つまり「runtime-wide では HTTP/2 を要求しない」状態の既定値です。

### 6.1.2　`force_http2=true`

- HTTPS の ALPN negotiation に **Tukuyomi native HTTP/2 upstream transport**
  を使う
- `h2` と `http/1.1` を明示的に提示し、upstream が `h2` を選ばない場合は、
  **Go の client transport へ暗黙委譲しない**。代わりに、native HTTP/1.1
  transport へ **明示 fallback** する
- これは HTTPS upstream で HTTP/2 をより強く優先する設定であり、
  **すべての upstream request を必ず HTTP/2 にする保証ではありません**

つまり「HTTPS upstream は ALPN で `h2` が取れたら HTTP/2、取れなければ
HTTP/1.1」の挙動です。

### 6.1.3　`h2c_upstream=true`

- upstream transport を **Tukuyomi native prior-knowledge cleartext HTTP/2**
  に切り替える
- 影響対象は **runtime 配下の upstream traffic 全体**
  - primary upstream
  - named upstream
  - route に直接書いた upstream URL
  - active health check
- 設定される upstream は **すべて `http://` scheme** である必要がある
- `tls_client_cert` / `tls_client_key` とは併用できない
- 1 つの runtime で `http://` と `https://` を混在させる topology は
  **サポートしません**

`h2c_upstream` は、**trusted internal network 上で upstream が cleartext
HTTP/2 を明示的に期待しているとき** だけ使う想定です。HTTP/1.1 upgrade 方式
ではなく、最初から prior-knowledge で h2c を話します。

## 6.2　明示的な upstream mode による混在 topology

1 つの runtime で **HTTPS + ALPN と cleartext HTTP/2 を併用** したい場合は、
`h2c_upstream=false` を維持したまま、target に近い場所で mode を指定します。
これが現在の推奨パターンです。

### 6.2.1　named upstream の `http2_mode`

`upstreams[].http2_mode` を使います。

```json
{
  "upstreams": [
    { "name": "tls-app", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c-app", "url": "http://h2c.internal:8080",  "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}
```

`http2_mode` の値は次の 3 種類です。

| 値 | 挙動 |
|---|---|
| `default` | runtime-wide mode を継承する。`force_http2=false` では native HTTP/1.1 transport を使う |
| `force_attempt` | Tukuyomi native HTTP/2 ALPN transport を使い、ALPN で `h2` が選ばれない場合は native HTTP/1.1 へ明示 fallback |
| `h2c_prior_knowledge` | Tukuyomi native cleartext HTTP/2 transport を使う（`http://` upstream が必須） |

named upstream の mode は、active health check、passive health、retry、
`/status` の backend 情報まで一貫して追従します。`health_check_headers` や
`health_check_expected_body` / `health_check_expected_body_regex` を使う
active health check も、選ばれた backend と同じ mode に従います。

### 6.2.2　upstream TLS 制御

HTTPS upstream の TLS 挙動は、runtime-wide のデフォルトと named upstream の
override の 2 段階で指定できます。

runtime-wide の既定値:

- `tls_insecure_skip_verify`
- `tls_ca_bundle`
- `tls_min_version`
- `tls_max_version`
- `tls_client_cert` / `tls_client_key`
- `upstream_keepalive_sec`

named upstream 単位の override:

- `upstreams[].tls.server_name`
- `upstreams[].tls.ca_bundle`
- `upstreams[].tls.min_version`
- `upstreams[].tls.max_version`
- `upstreams[].tls.client_cert`
- `upstreams[].tls.client_key`

例として、runtime-wide で TLS 1.2+ と root CA を指定しつつ、特定の
`payments` upstream にだけ TLS 1.3 必須・client cert 付きの override を
入れる構成は次のようになります。

```json
{
  "tls_ca_bundle": "/etc/tukuyomi/pki/root-ca.pem",
  "tls_min_version": "tls1.2",
  "upstreams": [
    {
      "name": "payments",
      "url": "https://payments.internal:9443",
      "enabled": true,
      "http2_mode": "force_attempt",
      "tls": {
        "server_name": "payments.internal",
        "ca_bundle": "/etc/tukuyomi/pki/payments-ca.pem",
        "min_version": "tls1.3",
        "client_cert": "/etc/tukuyomi/pki/payments-client.pem",
        "client_key": "/etc/tukuyomi/pki/payments-client.key"
      }
    }
  ]
}
```

TLS 設定の前提は次のとおりです。

- runtime-wide TLS default は HTTPS upstream に適用され、named upstream の
  設定があればそれで上書きされる
- per-upstream TLS 設定は **`https://` upstream にだけ有効**
- この slice では direct absolute route target は runtime-wide TLS だけを
  使い、**per-route TLS override は未対応**
- `h2c_prior_knowledge` は引き続き `http://` 専用で、upstream TLS 設定は
  使わない

### 6.2.3　direct route target の `upstream_http2_mode`

route の target が **direct absolute upstream URL** のときだけ、
`action.upstream_http2_mode` または `action.canary_upstream_http2_mode` を
使います。

```json
{
  "routes": [
    {
      "name": "h2c-direct",
      "match": { "path": { "type": "prefix", "value": "/bench" } },
      "action": {
        "upstream": "http://h2c-direct.internal:8080",
        "upstream_http2_mode": "h2c_prior_knowledge"
      }
    }
  ]
}
```

direct route target に関する制約:

- route-level override は **named upstream reference には適用しない**
- direct route target は request 単位の扱いで、active health や
  `/status.backends` 用の managed backend state は作らない
- health 管理された混在 topology と安定した observability が必要なら、
  direct URL ではなく **named upstream** を使う

「実験的に 1 経路だけ h2c で叩きたい」というユースケースには direct route
target が便利ですが、本番運用で health と observability を求めるなら named
upstream に寄せるのが基本方針です。

## 6.3　Runtime で見える項目

Status API では、現在の HTTP/2 / h2c 関連設定を次の field で確認できます。

- `proxy_force_http2`
- `proxy_h2c_upstream`
- `proxy_upstream_http2_mode`
- `proxy_upstream_keepalive_sec`

`proxy_upstream_http2_mode` の取り得る値は、

- `default`
- `force_attempt`
- `h2c_prior_knowledge`

の 3 種類です。

## 6.4　運用指針

混在 topology の組み立てに迷ったら、次の方針が出発点になります。

- 単純な runtime-wide HTTPS 調整なら、`force_http2=true` を使う
- `h2c_upstream=true` は、**runtime 配下の upstream がすべて cleartext HTTP/2
  に対応しているとき** だけ使う
- HTTP と HTTPS が混在する upstream topology では、`h2c_upstream=false` を
  維持し、**`upstreams[].http2_mode` を使う**
- direct absolute HTTPS route target の TLS は runtime-wide default を使う。
  per-upstream TLS override は named upstream 向け
- route-level `*_http2_mode` は named upstream reference ではなく
  **direct absolute upstream URL 用**
- retry、passive health、active health check、header 付き / body match 付き
  health check は、選ばれた live target と同じ transport mode に追従する
- `upstream_keepalive_sec` で HTTP/1.1 / HTTPS / h2c upstream dial の TCP
  keepalive 間隔を制御できる。reload 後の実効値は `/status` で確認すること

## 6.5　次章への橋渡し

ここまでで、tukuyomi の **routing と upstream transport** に関する設計を
ひととおり押さえました。

第IV部「WAF と Request Security」では、第7章で **Coraza + CRS の誤検知を
どう運用上 tune するか**、第8章で AI 連携による **FP Tuner API** の使い方、
第9章で **request-time security plugin の plugin model** を扱います。
