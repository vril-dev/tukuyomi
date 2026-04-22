# Upstream HTTP/2 Modes

`tukuyomi` already supported HTTPS upstream HTTP/2 negotiation through `force_http2`, but that knob was easy to misread as a strict protocol switch. This document defines the current operator model, the runtime-wide cleartext extension, and the mixed-topology shape for named upstreams and direct route targets.

## Modes

### `force_http2=false`

- Uses Tukuyomi's native HTTP/1.1 upstream transport for dial, TLS, request write, response parse, connection reuse, trailers, and Upgrade tunnels
- HTTPS upstreams stay on HTTP/1.1 unless the selected upstream mode explicitly requests HTTP/2
- HTTP upstreams remain HTTP/1.1

### `force_http2=true`

- Uses Tukuyomi's native HTTP/2 upstream transport for HTTPS ALPN negotiation
- Offers `h2` and `http/1.1` explicitly; if the upstream does not select `h2`, Tukuyomi falls back to the native HTTP/1.1 transport instead of silently delegating to Go's client transport
- This is a stronger preference for HTTPS upstreams, not a guarantee that every upstream request becomes HTTP/2

### `h2c_upstream=true`

- Switches the upstream transport to Tukuyomi's native prior-knowledge cleartext HTTP/2 transport
- Applies to all configured upstream traffic:
  - primary upstreams
  - named upstreams
  - direct route upstream URLs
  - active health checks
- Requires every configured upstream to use the `http://` scheme
- Cannot be combined with `tls_client_cert` / `tls_client_key`
- Does not support mixed `http://` + `https://` upstream topologies in one runtime

`h2c_upstream` is intended for trusted internal networks where the upstream explicitly expects cleartext HTTP/2. It is not an HTTP/1.1 upgrade mode.

## Mixed topologies with explicit upstream modes

If you need both HTTPS + ALPN and cleartext HTTP/2 in one runtime, keep `h2c_upstream=false` and configure the mode closer to the target.

### Named upstreams

Use `upstreams[].http2_mode`:

```json
{
  "upstreams": [
    { "name": "tls-app", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c-app", "url": "http://h2c.internal:8080", "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}
```

- `default` inherits the runtime-wide mode; with `force_http2=false`, it uses Tukuyomi's native HTTP/1.1 transport
- `force_attempt` uses Tukuyomi's native HTTP/2 ALPN transport, with explicit native HTTP/1.1 fallback when ALPN does not select `h2`
- `h2c_prior_knowledge` uses Tukuyomi's native cleartext HTTP/2 transport and therefore requires an `http://` upstream
- Active health checks, passive health state, retry attempts, and `/status` backend entries follow the named upstream mode
- Active health checks may also send `health_check_headers` and require `health_check_expected_body` or `health_check_expected_body_regex`; those checks use the same upstream mode as the selected backend

### Upstream TLS controls

Runtime-wide defaults:

- `tls_insecure_skip_verify`
- `tls_ca_bundle`
- `tls_min_version`
- `tls_max_version`
- `tls_client_cert` / `tls_client_key`
- `upstream_keepalive_sec`

Per-upstream overrides:

- `upstreams[].tls.server_name`
- `upstreams[].tls.ca_bundle`
- `upstreams[].tls.min_version`
- `upstreams[].tls.max_version`
- `upstreams[].tls.client_cert`
- `upstreams[].tls.client_key`

Example:

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

- Runtime-wide TLS defaults apply to HTTPS upstreams unless the named upstream overrides them
- Per-upstream TLS settings are valid only for `https://` upstreams
- Direct absolute route targets continue to use runtime-wide TLS settings in this slice; per-route TLS overrides are not supported
- `h2c_prior_knowledge` remains `http://` only and does not use upstream TLS settings

### Direct route targets

Use `action.upstream_http2_mode` or `action.canary_upstream_http2_mode` only when the route target is a direct absolute upstream URL:

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

- Route-level overrides do not apply to named upstream references
- Route-level direct targets stay request-scoped; they do not create managed backend state for active health or `/status.backends`
- Use named upstreams when you need health-managed mixed topologies with stable observability

## Runtime visibility

Status API fields:

- `proxy_force_http2`
- `proxy_h2c_upstream`
- `proxy_upstream_http2_mode`
- `proxy_upstream_keepalive_sec`

`proxy_upstream_http2_mode` values:

- `default`
- `force_attempt`
- `h2c_prior_knowledge`

## Operational guidance

- Use `force_http2=true` for simple runtime-wide HTTPS tuning
- Use `h2c_upstream=true` only when every upstream behind the runtime is cleartext HTTP/2 capable
- For mixed HTTP/HTTPS upstream topologies, keep `h2c_upstream=false` and configure `upstreams[].http2_mode`
- Use runtime-wide TLS defaults for direct absolute HTTPS route targets; per-upstream TLS overrides are for named upstreams
- Use route-level `*_http2_mode` only for direct absolute upstream URLs, not named upstream references
- Retry, passive health, and active health checks follow the same transport mode as the selected live target
- Header-based and body-matching health checks follow that same transport mode as well
- `upstream_keepalive_sec` controls the TCP keepalive interval used for HTTP/1.1, HTTPS, and h2c upstream dials; confirm the active value in `/status` after reload
