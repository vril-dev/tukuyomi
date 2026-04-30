# Chapter 6. Upstream HTTP/2 and h2c

Chapter 5 built the routing picture; this chapter covers **which HTTP
protocol tukuyomi speaks to the chosen upstream**.

Specifically:

- The runtime-wide switches `force_http2` and `h2c_upstream`.
- Per-named-upstream control via `upstreams[].http2_mode`.
- Direct-route-target control via `action.upstream_http2_mode`.
- How to compose mixed topologies that contain both HTTP and HTTPS
  upstreams.

The defining feature of tukuyomi here is that **how strongly to require
HTTP/2** and **whether to speak cleartext or TLS** are layered choices
that you make per layer.

## 6.1 The modes

`tukuyomi` has carried `force_http2` for a long time, but it was
frequently misread as "a switch that **strictly pins** to HTTP/2". The
current operator model splits the question into three modes.

### 6.1.1 `force_http2=false`

- Use the **Tukuyomi native HTTP/1.1 upstream transport** for dial,
  TLS, request write, response parse, connection reuse, trailers, and
  Upgrade tunnel.
- HTTPS upstreams **stay HTTP/1.1** unless the chosen upstream mode
  explicitly requires HTTP/2.
- HTTP upstreams stay HTTP/1.1.

This is the "do not require HTTP/2 runtime-wide" default.

### 6.1.2 `force_http2=true`

- Use the **Tukuyomi native HTTP/2 upstream transport** during HTTPS
  ALPN negotiation.
- Offer `h2` and `http/1.1` explicitly. If the upstream does not pick
  `h2`, **do not implicitly hand off to Go's client transport**;
  **explicitly fall back** to the native HTTP/1.1 transport.
- This biases HTTPS upstreams toward HTTP/2 more strongly. **It does
  not guarantee that every upstream request is HTTP/2.**

So the behavior is "HTTPS upstreams take HTTP/2 if ALPN selects `h2`,
otherwise HTTP/1.1".

### 6.1.3 `h2c_upstream=true`

- Switch the upstream transport to **Tukuyomi native prior-knowledge
  cleartext HTTP/2**.
- The scope is **all upstream traffic in the runtime**:
  - The primary upstream
  - Named upstreams
  - URLs written directly into routes
  - Active health checks
- Every configured upstream **must** use the `http://` scheme.
- Cannot be combined with `tls_client_cert` / `tls_client_key`.
- A single runtime **cannot** mix `http://` and `https://`.

`h2c_upstream` is for the case where a **trusted internal network
explicitly expects cleartext HTTP/2 on the upstream side**. It is not
the HTTP/1.1 upgrade flavor; it speaks h2c with prior knowledge.

## 6.2 Mixed topologies via explicit upstream mode

When you want **HTTPS + ALPN and cleartext HTTP/2 in the same runtime**,
keep `h2c_upstream=false` and specify the mode close to the target.
This is the recommended pattern today.

### 6.2.1 `http2_mode` on a named upstream

Use `upstreams[].http2_mode`:

```json
{
  "upstreams": [
    { "name": "tls-app", "url": "https://tls.internal:8443", "enabled": true, "http2_mode": "force_attempt" },
    { "name": "h2c-app", "url": "http://h2c.internal:8080",  "enabled": true, "http2_mode": "h2c_prior_knowledge" }
  ]
}
```

`http2_mode` takes one of three values:

| Value | Behavior |
|---|---|
| `default` | Inherit the runtime-wide mode. With `force_http2=false`, use the native HTTP/1.1 transport. |
| `force_attempt` | Use the Tukuyomi native HTTP/2 ALPN transport; explicitly fall back to native HTTP/1.1 when ALPN does not select `h2`. |
| `h2c_prior_knowledge` | Use the Tukuyomi native cleartext HTTP/2 transport. Requires `http://` upstream. |

The named-upstream mode is honored consistently by active health checks,
passive health, retry, and the `/status` backend information.
`health_check_headers`, `health_check_expected_body` /
`health_check_expected_body_regex` active health checks also follow the
chosen backend's mode.

### 6.2.2 Upstream TLS controls

HTTPS upstream TLS behavior is set in two layers — runtime-wide
defaults and per-named-upstream overrides.

Runtime-wide defaults:

- `tls_insecure_skip_verify`
- `tls_ca_bundle`
- `tls_min_version`
- `tls_max_version`
- `tls_client_cert` / `tls_client_key`
- `upstream_keepalive_sec`

Per-named-upstream overrides:

- `upstreams[].tls.server_name`
- `upstreams[].tls.ca_bundle`
- `upstreams[].tls.min_version`
- `upstreams[].tls.max_version`
- `upstreams[].tls.client_cert`
- `upstreams[].tls.client_key`

A configuration that sets TLS 1.2+ runtime-wide while overriding a
specific `payments` upstream to require TLS 1.3 with a client cert
might look like this:

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

TLS rules:

- The runtime-wide TLS defaults apply to HTTPS upstreams; per-named
  overrides take precedence.
- Per-upstream TLS settings apply **only to `https://` upstreams**.
- Direct absolute route targets use only the runtime-wide TLS in this
  slice; **per-route TLS overrides are not yet supported**.
- `h2c_prior_knowledge` is `http://` only and ignores upstream TLS
  settings.

### 6.2.3 `upstream_http2_mode` on a direct route target

Use `action.upstream_http2_mode` (or `action.canary_upstream_http2_mode`)
**only when the route's target is a direct absolute upstream URL**:

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

Direct route target constraints:

- The route-level override **does not apply to named upstream
  references**.
- Direct route targets are per-request and do not produce managed
  backend state for active health or `/status.backends`.
- For mixed topologies that need health management and stable
  observability, prefer **named upstreams** over direct URLs.

A direct route target is convenient when you experimentally want to
hit one path with h2c. For production setups that rely on health and
observability, the principle is to lean on named upstreams.

## 6.3 Runtime visibility

The Status API surfaces the current HTTP/2 / h2c-related settings:

- `proxy_force_http2`
- `proxy_h2c_upstream`
- `proxy_upstream_http2_mode`
- `proxy_upstream_keepalive_sec`

`proxy_upstream_http2_mode` takes one of:

- `default`
- `force_attempt`
- `h2c_prior_knowledge`

## 6.4 Operator guidance

If you are unsure how to compose a mixed topology, start from these
defaults:

- For a simple runtime-wide HTTPS tweak, use `force_http2=true`.
- Use `h2c_upstream=true` only when **every upstream in the runtime**
  speaks cleartext HTTP/2.
- For HTTP / HTTPS mixed topologies, keep `h2c_upstream=false` and use
  **`upstreams[].http2_mode`**.
- Direct absolute HTTPS route targets use the runtime-wide TLS
  default. Per-upstream TLS overrides are for named upstreams.
- Route-level `*_http2_mode` is **for direct absolute upstream URLs**,
  not named-upstream references.
- Retry, passive health, active health checks (including
  header-augmented and body-match checks) follow the same transport
  mode as the chosen live target.
- `upstream_keepalive_sec` controls TCP keepalive for HTTP/1.1 / HTTPS
  / h2c upstream dials. Confirm the effective value via `/status`
  after a reload.

## 6.5 Bridge to the next chapter

We have now covered tukuyomi's **routing and upstream transport** in
full.

Part IV — "WAF and request security" — covers how to **operationally
tune Coraza + CRS false positives** in Chapter 7, the AI-assisted
**FP Tuner API** in Chapter 8, and the **request-time security plugin
model** in Chapter 9.
