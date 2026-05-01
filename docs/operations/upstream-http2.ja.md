# 上流 HTTP/2 モード

`tukuyomi` は以前から `force_http2` によって、HTTPS 上流サーバーとの HTTP/2 交渉を扱っていました。ただし、この設定は「すべての上流接続を厳密に HTTP/2 へ固定するスイッチ」と誤解されやすい名前です。

この文書では、現在の運用モデル、runtime 全体へ適用する平文 HTTP/2 設定、名前付き upstream と route 直指定 upstream を混在させる場合の考え方を整理します。

## モード

### `force_http2=false`

- 接続確立、TLS、リクエスト送信、レスポンス解析、接続再利用、trailer、Upgrade tunnel に Tukuyomi 組み込みの HTTP/1.1 上流向け transport を使う
- HTTPS upstream は、選択された upstream mode が HTTP/2 を明示しない限り HTTP/1.1 のまま通信する
- HTTP upstream も HTTP/1.1 のまま通信する

### `force_http2=true`

- HTTPS の ALPN 交渉に Tukuyomi 組み込みの HTTP/2 上流向け transport を使う
- `h2` と `http/1.1` を明示的に提示し、上流サーバーが `h2` を選ばない場合は Go 標準の client transport へ暗黙的に委譲せず、Tukuyomi 組み込みの HTTP/1.1 transport へ明示的にフォールバックする
- これは HTTPS upstream で HTTP/2 を強く優先する設定であり、すべての上流リクエストが必ず HTTP/2 になる保証ではない

### `h2c_upstream=true`

- upstream transport を Tukuyomi 組み込みの prior knowledge 方式の平文 HTTP/2、つまり h2c に切り替える
- 影響対象は runtime が扱う上流向け通信全体
  - primary upstream
  - 名前付き upstream
  - route に直接書いた upstream URL
  - active health check
- 設定される upstream はすべて `http://` スキームである必要がある
- `tls_client_cert` / `tls_client_key` とは併用できない
- 1 つの runtime で `http://` と `https://` を混在させる構成はサポートしない

`h2c_upstream` は、信頼済みの内部ネットワーク上で、上流サーバーが平文 HTTP/2 を明示的に待ち受けている場合だけを想定しています。HTTP/1.1 の Upgrade 方式ではありません。

## 明示的な upstream mode による混在構成

1 つの runtime で HTTPS + ALPN と平文 HTTP/2 を併用したい場合は、`h2c_upstream=false` を維持したまま、接続先に近い単位で mode を指定します。

### 名前付き upstream

`upstreams[].http2_mode` を使います:

```json
{
  "upstreams": [
    { "name": "tls-app", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c-app", "url": "http://h2c.internal:8080", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}
```

- `default` は runtime 全体の mode を継承する。`force_http2=false` では Tukuyomi 組み込みの HTTP/1.1 transport を使う
- `force_attempt` は Tukuyomi 組み込みの HTTP/2 ALPN transport を使い、ALPN で `h2` が選ばれない場合は HTTP/1.1 へ明示的にフォールバックする
- `h2c_prior_knowledge` は Tukuyomi 組み込みの平文 HTTP/2 transport を使うため、`http://` upstream が必要
- active health check、passive health、retry、`/status` の backend 情報は名前付き upstream の mode に追従する
- `health_check_headers` や `health_check_expected_body` / `health_check_expected_body_regex` を使う active health check も、選ばれた backend と同じ mode に従う

### upstream TLS 制御

runtime 全体の既定値:

- `tls_insecure_skip_verify`
- `tls_ca_bundle`
- `tls_min_version`
- `tls_max_version`
- `tls_client_cert` / `tls_client_key`
- `upstream_keepalive_sec`

名前付き upstream 単位の上書き:

- `upstreams[].tls.server_name`
- `upstreams[].tls.ca_bundle`
- `upstreams[].tls.min_version`
- `upstreams[].tls.max_version`
- `upstreams[].tls.client_cert`
- `upstreams[].tls.client_key`

例:

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

- runtime 全体の TLS 既定値は HTTPS upstream に適用される。名前付き upstream 側に TLS 設定があれば、その値で上書きされる
- upstream 単位の TLS 設定は `https://` upstream にだけ有効
- この対象範囲では、絶対 URL で直接指定した route target は runtime 全体の TLS 設定だけを使う。route 単位の TLS 上書きは未対応
- `h2c_prior_knowledge` は引き続き `http://` 専用で、upstream TLS 設定は使わない

### route 直指定 target

route の target が絶対 URL で直接指定した upstream の時だけ、`action.upstream_http2_mode` または `action.canary_upstream_http2_mode` を使います:

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

- route 単位の上書きは、名前付き upstream 参照には適用しない
- route 直指定 target はリクエスト単位で扱う。active health や `/status.backends` 用の管理対象 backend state は作らない
- health 管理された混在構成と安定した可観測性が必要な場合は、名前付き upstream を使う

## runtime で確認できる項目

Status API の主な項目:

- `proxy_force_http2`
- `proxy_h2c_upstream`
- `proxy_upstream_http2_mode`
- `proxy_upstream_keepalive_sec`

`proxy_upstream_http2_mode` の値:

- `default`
- `force_attempt`
- `h2c_prior_knowledge`

## 運用指針

- 単純に runtime 全体で HTTPS upstream の HTTP/2 優先度を上げたい場合は、`force_http2=true` を使う
- `h2c_upstream=true` は、runtime 配下の upstream がすべて平文 HTTP/2 に対応している時だけ使う
- HTTP と HTTPS が混在する upstream 構成では、`h2c_upstream=false` を維持し、`upstreams[].http2_mode` を使う
- 絶対 URL で直接指定した HTTPS route target の TLS は runtime 全体の既定値を使う。upstream 単位の TLS 上書きは名前付き upstream 向け
- route 単位の `*_http2_mode` は、名前付き upstream 参照ではなく、絶対 URL で直接指定した upstream 向け
- retry、passive health、active health check は、実際に選ばれた接続先と同じ transport mode に追従する
- ヘッダー指定 / body 条件付き health check も、同じ transport mode に追従する
- `upstream_keepalive_sec` で HTTP/1.1 / HTTPS / h2c upstream への TCP keepalive 間隔を制御できます。reload 後の実効値は `/status` で確認してください
