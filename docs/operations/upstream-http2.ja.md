# upstream HTTP/2 モード

`tukuyomi` は以前から `force_http2` によって HTTPS upstream の HTTP/2 negotiation を扱っていましたが、この設定は「厳密に HTTP/2 へ固定するスイッチ」と誤解されやすい状態でした。この文書では現在の operator model、runtime-wide の cleartext 拡張、named upstream / direct route target を混在させる形を整理します。

## モード

### `force_http2=false`

- dial、TLS、request write、response parse、connection reuse、trailers、Upgrade tunnel に Tukuyomi native HTTP/1.1 upstream transport を使う
- HTTPS upstream は、選択された upstream mode が HTTP/2 を明示しない限り HTTP/1.1 のまま
- HTTP upstream は HTTP/1.1 のまま

### `force_http2=true`

- HTTPS ALPN negotiation に Tukuyomi native HTTP/2 upstream transport を使う
- `h2` と `http/1.1` を明示的に提示し、upstream が `h2` を選ばない場合は Go の client transport へ暗黙委譲せず、native HTTP/1.1 transport へ明示 fallback する
- これは HTTPS upstream で HTTP/2 をより強く優先する設定であり、すべての upstream request を必ず HTTP/2 にする保証ではない

### `h2c_upstream=true`

- upstream transport を Tukuyomi native prior-knowledge cleartext HTTP/2 に切り替える
- 影響対象は runtime 配下の upstream traffic 全体
  - primary upstream
  - named upstream
  - route に直接書いた upstream URL
  - active health check
- 設定される upstream はすべて `http://` scheme である必要がある
- `tls_client_cert` / `tls_client_key` とは併用できない
- 1 つの runtime で `http://` と `https://` を混在させる topology はサポートしない

`h2c_upstream` は、trusted internal network 上で upstream が cleartext HTTP/2 を明示的に期待している場合だけを想定します。HTTP/1.1 upgrade 方式ではありません。

## 明示的な upstream mode による混在 topology

1 つの runtime で HTTPS + ALPN と cleartext HTTP/2 を併用したい場合は、`h2c_upstream=false` を維持したまま、target に近い場所で mode を指定します。

### named upstream

`upstreams[].http2_mode` を使います:

```json
{
  "upstreams": [
    { "name": "tls-app", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c-app", "url": "http://h2c.internal:8080", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}
```

- `default` は runtime-wide mode を継承する。`force_http2=false` では Tukuyomi native HTTP/1.1 transport を使う
- `force_attempt` は Tukuyomi native HTTP/2 ALPN transport を使い、ALPN で `h2` が選ばれない場合は native HTTP/1.1 へ明示 fallback する
- `h2c_prior_knowledge` は Tukuyomi native cleartext HTTP/2 transport を使うため、`http://` upstream が必要
- active health check、passive health、retry、`/status` の backend 情報は named upstream の mode に追従する
- `health_check_headers` や `health_check_expected_body` / `health_check_expected_body_regex` を使う active health check も、選ばれた backend と同じ mode に従う

### upstream TLS 制御

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

- runtime-wide TLS default は HTTPS upstream に適用され、named upstream の設定があればそれで上書きされる
- per-upstream TLS 設定は `https://` upstream にだけ有効
- この slice では direct absolute route target は runtime-wide TLS だけを使い、per-route TLS override は未対応
- `h2c_prior_knowledge` は引き続き `http://` 専用で、upstream TLS 設定は使わない

### direct route target

route の target が direct absolute upstream URL の時だけ、`action.upstream_http2_mode` または `action.canary_upstream_http2_mode` を使います:

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

- route-level override は named upstream reference には適用しない
- direct route target は request 単位の扱いで、active health や `/status.backends` 用の managed backend state は作らない
- health 管理された mixed topology と安定した observability が必要なら named upstream を使う

## runtime で見える項目

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

- 単純な runtime-wide HTTPS 調整なら `force_http2=true` を使う
- `h2c_upstream=true` は、runtime 配下の upstream がすべて cleartext HTTP/2 に対応している時だけ使う
- HTTP と HTTPS が混在する upstream topology では `h2c_upstream=false` を維持し、`upstreams[].http2_mode` を使う
- direct absolute HTTPS route target の TLS は runtime-wide default を使い、per-upstream TLS override は named upstream 向け
- route-level `*_http2_mode` は named upstream reference ではなく direct absolute upstream URL 用
- retry、passive health、active health check は選ばれた live target と同じ transport mode に追従する
- header 付き / body match 付き health check も同じ transport mode に追従する
- `upstream_keepalive_sec` で HTTP/1.1 / HTTPS / h2c upstream dial の TCP keepalive 間隔を制御できます。reload 後の実効値は `/status` で確認してください
